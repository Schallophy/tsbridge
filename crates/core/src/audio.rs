//! Voice: Opus in both directions, with the jitter/PLC handling tsclientlib
//! already provides.
//!
//! Capture and playback stay in the shell (AudioRecord/AudioTrack on Android,
//! AVAudioEngine on macOS, WASAPI elsewhere) because that is where echo
//! cancellation, noise suppression and device routing live. This module only
//! converts:
//!
//! ```text
//! mic PCM16 ──► encode ──► OutAudio ──► server
//! server ──► AudioHandler ──► mixed PCM16 ──► playback queue
//! ```
//!
//! Mixing happens inside `AudioHandler::fill_buffer`, which also applies each
//! talker's volume and drops clients that stopped sending.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use audiopus::coder::Encoder;
use audiopus::{Application, Bitrate, Channels, SampleRate};
use tsclientlib::audio::AudioHandler;
use tsclientlib::{ClientId, Connection};
use tsproto_packets::packets::{AudioData, CodecType, InAudioBuf, OutAudio, OutPacket};

use crate::handle::{Inner, FRAME_SAMPLES};

/// Where outgoing voice goes instead of the current channel.
///
/// Client and channel ids use the classic whisper packet; groups use the
/// new-protocol packet and are resolved by the server, so members who join
/// later still hear the target.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WhisperTargets {
    pub clients: Vec<u16>,
    pub channels: Vec<u64>,
    /// `(GroupWhisperType, GroupWhisperTarget, group id)`.
    pub groups: Vec<(u8, u8, u64)>,
}

impl WhisperTargets {
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty() && self.channels.is_empty() && self.groups.is_empty()
    }
}

/// One 20 ms frame as `tsclientlib` hands it back: **interleaved stereo**.
///
/// `AudioHandler` decodes with `Channels::Stereo`, so a frame is 960 samples per
/// channel — 1920 `f32` in total. Filling a mono-sized buffer instead would take
/// only half a frame per tick, which plays at half speed and sounds like someone
/// dragged the tape: exactly the "low pitch, slowed down" symptom.
const STEREO_FRAME_SAMPLES: usize = FRAME_SAMPLES * 2;

pub struct AudioEngine {
    encoder: Option<Encoder>,
    handler: AudioHandler<ClientId>,
    /// Opus packet counter. Wraps on purpose: it is a `u16` on the wire.
    sequence: u16,
    enabled: bool,
    /// Linear capture gain, applied before the silence gate and the encoder.
    /// The shell sends raw PCM so every platform gets the same clipping.
    gain: f32,
    /// Linear playback volume per remote client. Stored separately because a
    /// client may be configured before its first packet creates a queue.
    volumes: HashMap<ClientId, f32>,
    /// Empty means ordinary channel talk.
    whisper: WhisperTargets,
    mix: Vec<f32>,
}

impl AudioEngine {
    pub fn new() -> Self {
        let encoder = match Encoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip) {
            Ok(mut encoder) => {
                // 24 kbps mono is what the desktop client uses for voice; going
                // higher buys nothing on a channel codec that re-encodes anyway.
                if let Err(e) = encoder.set_bitrate(Bitrate::BitsPerSecond(24_000)) {
                    log::warn!("Could not set the Opus bitrate: {e}");
                }
                Some(encoder)
            }
            Err(e) => {
                log::error!("No Opus encoder available; voice will not be sent: {e}");
                None
            }
        };

        AudioEngine {
            encoder,
            handler: AudioHandler::new(),
            sequence: 0,
            enabled: true,
            gain: 1.0,
            volumes: HashMap::new(),
            whisper: WhisperTargets::default(),
            mix: vec![0.0; STEREO_FRAME_SAMPLES],
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        log::info!(
            "Voice transmit {}",
            if enabled { "enabled" } else { "muted" }
        );
    }

    /// Sets the capture gain. Clamped to the range the shells expose (20 %–400 %)
    /// so a bad value cannot blow the encoder input past the soft clip.
    pub fn set_gain(&mut self, gain: f32) {
        self.gain = gain.clamp(0.2, 4.0);
        log::info!("Microphone gain {:.2}", self.gain);
    }

    /// 0.0 = silent, 1.0 = unchanged. Applied on top of the jitter queue's own
    /// volume, which stays at the client's server-side default.
    pub fn set_user_volume(&mut self, client: ClientId, volume: f32) {
        let volume = volume.clamp(0.0, 2.0);
        self.volumes.insert(client, volume);
        if let Some(queue) = self.handler.get_mut_queues().get_mut(&client) {
            queue.volume = volume;
        }
    }

    pub fn set_whisper_targets(&mut self, targets: WhisperTargets) {
        self.whisper = targets;
    }

    /// Encodes one 20 ms frame and sends it. Silent frames are skipped: they cost
    /// bandwidth and would keep the speaking indicator lit.
    ///
    /// Returns whether a non-silent frame was sent, which is also the core's
    /// own "speaking" signal — the server never echoes our own voice back.
    pub fn transmit(&mut self, connection: &mut Connection, frame: &[i16]) -> bool {
        if !self.enabled {
            return false;
        }
        let scaled = scale_frame(frame, self.gain);
        let peak = scaled.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
        if peak < 120 {
            return false;
        }
        let Some(encoder) = self.encoder.as_mut() else {
            return false;
        };

        let mut encoded = [0u8; 1500];
        match encoder.encode(&scaled, &mut encoded) {
            Ok(len) => {
                let id = self.sequence;
                self.sequence = self.sequence.wrapping_add(1);
                for packet in outgoing_packets(&encoded[..len], id, &self.whisper) {
                    if let Err(e) = connection.send_audio(packet) {
                        log::warn!("Sending audio failed: {e}");
                    }
                }
                true
            }
            Err(e) => {
                log::warn!("Opus encode failed: {e}");
                false
            }
        }
    }

    /// Feeds one received packet into the jitter buffer and updates who is
    /// talking, so the UI can draw a speaking ring without a second timer.
    pub fn receive(&mut self, inner: &Arc<Inner>, packet: InAudioBuf) {
        // The sender is inside the packet, not next to it.
        let client = match packet.data().data() {
            AudioData::S2C { from, .. } => ClientId(*from),
            AudioData::S2CWhisper { from, .. } => ClientId(*from),
            _ => return,
        };
        if let Err(e) = self.handler.handle_packet(client, packet) {
            // Unsupported codec (CELT/Music modes) is normal on some servers.
            log::debug!("Ignoring audio packet from {}: {e}", client.0);
            return;
        }
        self.publish_talkers(inner);
    }

    /// Produces one playback frame per tick. Runs on a clock rather than on
    /// packet arrival so playback stays smooth when packets bunch up.
    pub fn tick(&mut self, inner: &Arc<Inner>) {
        // Apply configured volumes to queues that appeared after the setting.
        for (client, queue) in self.handler.get_mut_queues().iter_mut() {
            if let Some(volume) = self.volumes.get(client) {
                queue.volume = *volume;
            }
        }
        // `fill_buffer` fills up to `buf.len()` and does not clear it first.
        self.mix.iter_mut().for_each(|sample| *sample = 0.0);
        self.handler.fill_buffer(&mut self.mix);

        // Downmix L/R to the mono stream the phone plays. TS voice is mono to
        // begin with; the stereo split only exists inside the handler's decoder.
        let mut pcm = [0i16; FRAME_SAMPLES];
        for (index, slot) in pcm.iter_mut().enumerate() {
            let left = self.mix[index * 2];
            let right = self.mix[index * 2 + 1];
            let mono = (left + right) * 0.5;
            *slot = (mono.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        }
        inner.push_playback(&pcm);

        self.publish_talkers(inner);
    }

    fn publish_talkers(&self, inner: &Arc<Inner>) {
        let mut ids: Vec<i32> = self
            .handler
            .get_queues()
            .keys()
            .map(|id| id.0 as i32)
            .collect();
        ids.sort_unstable();
        inner.set_talking(ids);
    }
}

/// Applies capture gain before the silence gate and the encoder.
fn scale_frame(frame: &[i16], gain: f32) -> Cow<'_, [i16]> {
    if (gain - 1.0).abs() < f32::EPSILON {
        return Cow::Borrowed(frame);
    }
    Cow::Owned(
        frame
            .iter()
            .map(|&sample| soft_clip(sample as f32 * gain))
            .collect(),
    )
}

/// Soft-knee limiter: linear below half scale, smooth saturation above. The
/// same curve the Android reference applies, so a boosted microphone sounds
/// the same on every platform.
fn soft_clip(sample: f32) -> i16 {
    const LIMIT: f32 = i16::MAX as f32;
    let value = sample / LIMIT;
    let limited = if value > 0.5 {
        0.5 + 0.5 * (1.0 - 1.0 / (1.0 + (value - 0.5) * 2.0))
    } else if value < -0.5 {
        -(0.5 + 0.5 * (1.0 - 1.0 / (1.0 + (-value - 0.5) * 2.0)))
    } else {
        value
    };
    (limited.clamp(-1.0, 1.0) * LIMIT) as i16
}

/// One encoded frame as the outgoing packets it becomes. Empty targets are
/// ordinary channel voice; a mixed target list fans out one packet per group
/// plus one packet carrying the client/channel lists.
fn outgoing_packets(encoded: &[u8], id: u16, targets: &WhisperTargets) -> Vec<OutPacket> {
    if targets.is_empty() {
        return vec![OutAudio::new(&AudioData::C2S {
            id,
            codec: CodecType::OpusVoice,
            data: encoded,
        })];
    }

    let mut packets = Vec::new();
    if !targets.clients.is_empty() || !targets.channels.is_empty() {
        packets.push(OutAudio::new(&AudioData::C2SWhisper {
            id,
            codec: CodecType::OpusVoice,
            channels: targets.channels.clone(),
            clients: targets.clients.clone(),
            data: encoded,
        }));
    }
    for (whisper_type, target, target_id) in &targets.groups {
        packets.push(OutAudio::new(&AudioData::C2SWhisperNew {
            id,
            codec: CodecType::OpusVoice,
            whisper_type: *whisper_type,
            target: *target,
            target_id: *target_id,
            data: encoded,
        }));
    }
    packets
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsproto_packets::packets::PacketType;

    #[test]
    fn unity_gain_does_not_touch_the_samples() {
        let frame = [0i16, 1000, -1000, i16::MAX];
        assert_eq!(scale_frame(&frame, 1.0).as_ref(), frame);
    }

    #[test]
    fn a_boosted_loud_sample_is_soft_limited_not_wrapped() {
        let scaled = scale_frame(&[i16::MAX], 4.0);
        assert!(scaled[0] > 0);
        assert!(scaled[0] < i16::MAX);
    }

    #[test]
    fn ordinary_talk_is_one_channel_packet() {
        let packets = outgoing_packets(&[1, 2, 3], 7, &WhisperTargets::default());
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].header().packet_type(), PacketType::Voice);
    }

    #[test]
    fn whisper_targets_fan_out_one_packet_per_destination_group() {
        let targets = WhisperTargets {
            clients: vec![4],
            channels: vec![5],
            groups: vec![(0, 0, 6), (1, 1, 7)],
        };
        let packets = outgoing_packets(&[1, 2, 3], 7, &targets);
        assert_eq!(packets.len(), 3);
        assert!(packets
            .iter()
            .all(|p| p.header().packet_type() == PacketType::VoiceWhisper));
    }
}
