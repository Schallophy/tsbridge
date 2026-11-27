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
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
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

/// Level gate deciding which captured frames are worth encoding.
///
/// A hard "peak above N" check clips word tails: the last 50 ms of a sentence
/// fall below the line and vanish. This mirrors the desktop/Android gate:
/// open above -45 dBFS, stay open 3 dB lower, keep sending for 400 ms after
/// the level drops, and keep 300 ms of pre-speech frames so the onset is not
/// clipped when it opens.
struct VoiceGate {
    active: bool,
    /// Frames below the close line while active, counted in 20 ms frames.
    below_frames: u32,
    pre_roll: VecDeque<Vec<i16>>,
}

impl VoiceGate {
    const THRESHOLD_DB: f32 = -45.0;
    const HYSTERESIS_DB: f32 = 3.0;
    const HANGOVER_FRAMES: u32 = 20;
    const PRE_ROLL_FRAMES: usize = 15;

    fn new() -> Self {
        Self {
            active: false,
            below_frames: 0,
            pre_roll: VecDeque::with_capacity(Self::PRE_ROLL_FRAMES),
        }
    }

    /// Returns the frames to encode, in order; empty means stay silent.
    fn process(&mut self, frame: &[i16]) -> Vec<Vec<i16>> {
        let db = rms_db(frame);
        if !self.active {
            if db < Self::THRESHOLD_DB {
                self.push_pre_roll(frame);
                return Vec::new();
            }
            self.active = true;
            self.below_frames = 0;
            self.push_pre_roll(frame);
            return self.pre_roll.drain(..).collect();
        }
        if db >= Self::THRESHOLD_DB - Self::HYSTERESIS_DB {
            self.below_frames = 0;
            return vec![frame.to_vec()];
        }
        self.below_frames = self.below_frames.saturating_add(1);
        if self.below_frames < Self::HANGOVER_FRAMES {
            return vec![frame.to_vec()];
        }
        // Closed: this frame seeds the next pre-roll instead of disappearing.
        self.active = false;
        self.below_frames = 0;
        self.pre_roll.clear();
        self.push_pre_roll(frame);
        Vec::new()
    }

    fn push_pre_roll(&mut self, frame: &[i16]) {
        self.pre_roll.push_back(frame.to_vec());
        while self.pre_roll.len() > Self::PRE_ROLL_FRAMES {
            self.pre_roll.pop_front();
        }
    }

    fn reset(&mut self) {
        self.active = false;
        self.below_frames = 0;
        self.pre_roll.clear();
    }
}

fn rms_db(frame: &[i16]) -> f32 {
    if frame.is_empty() {
        return -120.0;
    }
    let energy: f64 = frame
        .iter()
        .map(|&sample| {
            let value = sample as f64;
            value * value
        })
        .sum();
    let rms = (energy / frame.len() as f64).sqrt();
    if rms <= 0.0 {
        -120.0
    } else {
        (20.0 * (rms / 32768.0).log10()) as f32
    }
}

/// Where a remote client sits relative to the listener.
///
/// The angle is a compass bearing in degrees: 0 is straight ahead, 90 is to the
/// right, 180 behind, 270 to the left. Distance is in the caller's own unit —
/// metres, tiles, whatever the shell draws — because only the ratio to
/// [`Position::FULL_VOLUME_DISTANCE`] matters for attenuation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    pub angle: f32,
    pub distance: f32,
}

impl Position {
    /// Inside this distance nothing is attenuated; beyond it the gain falls off.
    pub const FULL_VOLUME_DISTANCE: f32 = 1.0;
    /// At and beyond this distance a client is inaudible.
    pub const SILENT_DISTANCE: f32 = 8.0;

    /// The per-channel gains this position implies.
    ///
    /// Constant-power panning: `cos`/`sin` of the bearing rather than a linear
    /// fade, so a source crossing in front of the listener keeps the same
    /// perceived loudness instead of dipping in the middle. Distance is a linear
    /// falloff between the two bounds, which is what a small room sounds like;
    /// an inverse-square curve would make anyone a few metres away inaudible.
    pub fn gains(self) -> (f32, f32) {
        let distance_gain = if self.distance <= Self::FULL_VOLUME_DISTANCE {
            1.0
        } else if self.distance >= Self::SILENT_DISTANCE {
            0.0
        } else {
            let span = Self::SILENT_DISTANCE - Self::FULL_VOLUME_DISTANCE;
            1.0 - (self.distance - Self::FULL_VOLUME_DISTANCE) / span
        };

        // Bearing to a pan position in [-1, 1]: -1 hard left, 1 hard right.
        let pan = self.angle.to_radians().sin().clamp(-1.0, 1.0);
        // Equal-power: the two gains square to a constant, so the total energy
        // does not change as the source moves across the front.
        let angle = (pan + 1.0) * std::f32::consts::FRAC_PI_4;
        let left = angle.cos() * distance_gain;
        let right = angle.sin() * distance_gain;
        (left, right)
    }
}

/// Adds positioned queues into the mix buffer with their pan and volume applied.
///
/// Split out of [`AudioEngine::tick`] because the tick needs a live decoder to
/// run at all, and the arithmetic is what can be wrong: an off-by-one in the
/// channel index swaps left and right, and applying the volume twice makes a
/// positioned client twice as loud as an unpositioned one at the same distance.
///
/// `samples` is interleaved stereo, so even indices are the left channel.
fn mix_panned(
    mix: &mut [f32],
    captured: &[(ClientId, Vec<f32>)],
    positions: &HashMap<ClientId, Position>,
    volumes: &HashMap<ClientId, f32>,
) {
    for (client, samples) in captured {
        let Some(position) = positions.get(client) else {
            continue;
        };
        let volume = volumes.get(client).copied().unwrap_or(1.0);
        let (left, right) = position.gains();
        for (index, sample) in samples.iter().enumerate().take(mix.len()) {
            let gain = if index % 2 == 0 { left } else { right };
            mix[index] += sample * gain * volume;
        }
    }
}

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
    /// Where each remote client sits relative to the listener, for 3D panning.
    ///
    /// Absent means "no position", which is the ordinary case: the mix stays
    /// centred and nothing is attenuated. Storing the position rather than a
    /// precomputed gain pair keeps the distance curve in one place and lets a
    /// client move without recomputing anything here.
    positions: HashMap<ClientId, Position>,
    /// Empty means ordinary channel talk.
    whisper: WhisperTargets,
    gate: VoiceGate,
    mix: Vec<f32>,
    /// The playback mix being written to disk, if a recording is running.
    ///
    /// Recording the playback side rather than the microphone is deliberate:
    /// the microphone is already available to any screen recorder, and a
    /// recording of only yourself says nothing about the conversation.
    recorder: Option<crate::recording::Recorder>,
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
            positions: HashMap::new(),
            whisper: WhisperTargets::default(),
            gate: VoiceGate::new(),
            mix: vec![0.0; STEREO_FRAME_SAMPLES],
            recorder: None,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        if !enabled {
            // A pre-roll captured before the mute must not be sent after it.
            self.gate.reset();
        }
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

    /// Places one client in the 3D field, or clears its position with `None`.
    ///
    /// A client with no position is mixed centred and unattenuated, which is
    /// also what happens when 3D sound is off: the map being empty is the same
    /// as the feature being disabled, so there is no separate switch to get out
    /// of sync with the positions.
    pub fn set_position(&mut self, client: ClientId, position: Option<Position>) {
        match position {
            Some(position) => {
                self.positions.insert(client, position);
            }
            None => {
                self.positions.remove(&client);
            }
        }
    }

    /// Clears every position, turning 3D sound off without touching volumes.
    pub fn clear_positions(&mut self) {
        self.positions.clear();
    }

    pub fn is_spatial(&self) -> bool {
        !self.positions.is_empty()
    }

    /// Starts writing the playback mix to `path`.
    ///
    /// Replaces a recording already in progress: two recorders writing the same
    /// tick would interleave, and a shell that starts twice means to restart.
    pub fn start_recording(&mut self, path: &std::path::Path) -> Result<PathBuf, String> {
        let recorder = crate::recording::Recorder::create(path)?;
        let path = recorder.path().to_path_buf();
        self.recorder = Some(recorder);
        log::info!("Recording to {}", path.display());
        Ok(path)
    }

    /// Stops the recording and patches its header. `None` when nothing was
    /// running, which is not an error: a stop on an idle session is a no-op.
    pub fn stop_recording(&mut self) -> Option<Result<(PathBuf, u64), String>> {
        self.recorder.take().map(|recorder| recorder.stop())
    }

    pub fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// Seconds recorded so far, or 0 when nothing is running.
    pub fn recording_seconds(&self) -> u64 {
        self.recorder
            .as_ref()
            .map_or(0, |recorder| recorder.seconds())
    }

    /// Where the recording is going, or empty when nothing is running.
    pub fn recording_path(&self) -> String {
        self.recorder
            .as_ref()
            .map(|recorder| recorder.path().to_string_lossy().to_string())
            .unwrap_or_default()
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
        let frames = self.gate.process(scaled.as_ref());
        if frames.is_empty() {
            return false;
        }
        let Some(encoder) = self.encoder.as_mut() else {
            self.gate.reset();
            return false;
        };

        let mut sent = false;
        let mut encoded = [0u8; 1500];
        for frame in &frames {
            match encoder.encode(frame, &mut encoded) {
                Ok(len) => {
                    let id = self.sequence;
                    self.sequence = self.sequence.wrapping_add(1);
                    for packet in outgoing_packets(&encoded[..len], id, &self.whisper) {
                        if let Err(e) = connection.send_audio(packet) {
                            log::warn!("Sending audio failed: {e}");
                        }
                    }
                    sent = true;
                }
                Err(e) => log::warn!("Opus encode failed: {e}"),
            }
        }
        sent
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
        if !self.is_spatial() {
            // The common case: no 3D, so the handler's own mixing is enough and
            // nothing has to be panned.
            self.handler.fill_buffer(&mut self.mix);
        } else {
            // The handler merges each queue into the mix at its own volume and
            // the preprocessor hook is read-only, so a positioned queue is muted
            // for that merge and mixed back in here with its pan applied. The
            // handler still owns decoding, buffering and packet-loss handling.
            let muted: Vec<ClientId> = self
                .positions
                .keys()
                .filter(|client| self.handler.get_mut_queues().contains_key(client))
                .copied()
                .collect();
            for client in &muted {
                if let Some(queue) = self.handler.get_mut_queues().get_mut(client) {
                    queue.volume = 0.0;
                }
            }

            let mut captured: Vec<(ClientId, Vec<f32>)> = Vec::new();
            self.handler
                .fill_buffer_with_proc(&mut self.mix, |client, samples| {
                    if self.positions.contains_key(client) {
                        captured.push((*client, samples.to_vec()));
                    }
                });

            // Restore the volume the queue had, so the next tick and the
            // per-client volume setting are unaffected.
            for client in &muted {
                let volume = self.volumes.get(client).copied().unwrap_or(1.0);
                if let Some(queue) = self.handler.get_mut_queues().get_mut(client) {
                    queue.volume = volume;
                }
            }

            mix_panned(&mut self.mix, &captured, &self.positions, &self.volumes);
        }

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

        // The same frame the phone plays is what goes to disk, so a recording
        // sounds exactly like the call did. A write error ends the recording
        // rather than failing every tick: a full disk should not stop the voice.
        if let Some(recorder) = self.recorder.as_mut() {
            if let Err(e) = recorder.write(&pcm) {
                log::warn!("Recording stopped: {e}");
                self.recorder = None;
                inner.push_event(
                    crate::events::QueuedEvent::new("recording_stopped")
                        .str("reason", &e)
                        .bool("failed", true),
                );
            }
        }

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
    fn a_source_dead_ahead_is_centred_and_full_volume() {
        let (left, right) = Position {
            angle: 0.0,
            distance: 0.5,
        }
        .gains();
        // Equal-power panning puts a centred source at 1/sqrt(2) per channel, so
        // the pair squares to 1 and the loudness matches a hard-panned source.
        assert!((left - right).abs() < 1e-6, "{left} vs {right}");
        assert!((left * left + right * right - 1.0).abs() < 1e-5);
    }

    #[test]
    fn a_source_to_the_right_is_louder_on_the_right() {
        let (left, right) = Position {
            angle: 90.0,
            distance: 0.5,
        }
        .gains();
        assert!(right > left, "right {right} should exceed left {left}");
        assert!(left < 1e-5, "the left channel should be silent, got {left}");
    }

    #[test]
    fn a_source_to_the_left_is_louder_on_the_left() {
        let (left, right) = Position {
            angle: 270.0,
            distance: 0.5,
        }
        .gains();
        assert!(left > right, "left {left} should exceed right {right}");
        assert!(
            right < 1e-5,
            "the right channel should be silent, got {right}"
        );
    }

    #[test]
    fn distance_attenuates_and_ends_silent() {
        let near = Position {
            angle: 0.0,
            distance: Position::FULL_VOLUME_DISTANCE,
        }
        .gains();
        let far = Position {
            angle: 0.0,
            distance: Position::SILENT_DISTANCE,
        }
        .gains();
        assert!(near.0 > far.0, "near should be louder than far");
        assert_eq!(far, (0.0, 0.0));

        // Inside the full-volume radius nothing is attenuated.
        let inside = Position {
            angle: 0.0,
            distance: 0.0,
        }
        .gains();
        assert!((inside.0 - near.0).abs() < 1e-6);
    }

    /// A positioned queue reaches the mix with its gains applied, and the two
    /// channels land on the right side.
    #[test]
    fn a_right_handed_source_lands_louder_in_the_right_channel() {
        let mut mix = vec![0.0f32; 8];
        // Four stereo frames of the same value, so every left slot and every
        // right slot should come out identical within its channel.
        let samples: Vec<f32> = vec![1.0; 8];
        let mut positions = HashMap::new();
        positions.insert(
            ClientId(1),
            Position {
                angle: 90.0,
                distance: 0.5,
            },
        );

        mix_panned(
            &mut mix,
            &[(ClientId(1), samples)],
            &positions,
            &HashMap::new(),
        );

        for (index, value) in mix.iter().enumerate() {
            if index % 2 == 0 {
                assert!(*value < 1e-5, "left slot {index} should be silent: {value}");
            } else {
                assert!(*value > 0.99, "right slot {index} should be full: {value}");
            }
        }
    }

    /// Volume multiplies on top of the pan and is applied exactly once.
    #[test]
    fn volume_scales_the_panned_mix_once() {
        let samples = vec![1.0f32; 8];
        let mut positions = HashMap::new();
        positions.insert(
            ClientId(1),
            Position {
                angle: 0.0,
                distance: 0.0,
            },
        );
        let mut volumes = HashMap::new();
        volumes.insert(ClientId(1), 0.5);

        let mut mix = vec![0.0f32; 8];
        mix_panned(
            &mut mix,
            &[(ClientId(1), samples.clone())],
            &positions,
            &volumes,
        );

        // Centred at 0.5 volume: each channel is 1/sqrt(2) * 0.5.
        let expected = std::f32::consts::FRAC_1_SQRT_2 * 0.5;
        for value in &mix {
            assert!(
                (value - expected).abs() < 1e-5,
                "expected {expected}, got {value}"
            );
        }
    }

    /// A client with no position is not touched by the panned path: the caller
    /// only captures positioned queues, and this is the guard that keeps a
    /// stray entry from being added twice.
    #[test]
    fn an_unpositioned_client_contributes_nothing_here() {
        let samples = vec![1.0f32; 8];
        let mut mix = vec![0.0f32; 8];
        mix_panned(
            &mut mix,
            &[(ClientId(9), samples)],
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(mix.iter().all(|value| *value == 0.0));
    }

    /// Two positioned clients add up rather than replacing one another.
    #[test]
    fn two_sources_sum_in_the_mix() {
        let mut positions = HashMap::new();
        positions.insert(
            ClientId(1),
            Position {
                angle: 0.0,
                distance: 0.0,
            },
        );
        positions.insert(
            ClientId(2),
            Position {
                angle: 0.0,
                distance: 0.0,
            },
        );
        let samples = vec![1.0f32; 4];
        let mut mix = vec![0.0f32; 4];
        mix_panned(
            &mut mix,
            &[(ClientId(1), samples.clone()), (ClientId(2), samples)],
            &positions,
            &HashMap::new(),
        );

        // Each contributes 1/sqrt(2) per channel, so the sum is twice that.
        let expected = 2.0 * std::f32::consts::FRAC_1_SQRT_2;
        for value in &mix {
            assert!((value - expected).abs() < 1e-5, "got {value}");
        }
    }

    #[test]
    fn a_bearing_past_a_full_turn_still_pans_sanely() {
        // 450 degrees is 90 degrees plus a full turn; the result must match 90.
        let a = Position {
            angle: 450.0,
            distance: 0.5,
        }
        .gains();
        let b = Position {
            angle: 90.0,
            distance: 0.5,
        }
        .gains();
        assert!((a.0 - b.0).abs() < 1e-5 && (a.1 - b.1).abs() < 1e-5);
    }

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
    fn level(amplitude: i16) -> Vec<i16> {
        vec![amplitude; 16]
    }

    #[test]
    fn gate_stays_closed_and_keeps_a_bounded_pre_roll() {
        let mut gate = VoiceGate::new();
        // 150/32768 is about -46.8 dBFS, below the -45 dB opening line.
        for _ in 0..40 {
            assert!(gate.process(&level(150)).is_empty());
        }
        assert_eq!(gate.pre_roll.len(), VoiceGate::PRE_ROLL_FRAMES);
    }

    #[test]
    fn gate_flushes_the_pre_roll_when_voice_starts() {
        let mut gate = VoiceGate::new();
        for _ in 0..3 {
            assert!(gate.process(&level(0)).is_empty());
        }
        let sent = gate.process(&level(8000));
        assert_eq!(sent.len(), 4);
        assert!(gate.pre_roll.is_empty());
        assert!(gate.active);
    }

    #[test]
    fn gate_holds_through_the_hangover_then_closes() {
        let mut gate = VoiceGate::new();
        assert_eq!(gate.process(&level(8000)).len(), 1);
        // Around -46.8 dBFS: below the opening line, above the closing one.
        assert_eq!(gate.process(&level(150)).len(), 1);
        for _ in 0..VoiceGate::HANGOVER_FRAMES - 1 {
            assert_eq!(gate.process(&level(0)).len(), 1);
        }
        assert!(gate.process(&level(0)).is_empty());
        assert!(!gate.active);
        // The closing frame seeds the next pre-roll.
        assert_eq!(gate.pre_roll.len(), 1);
    }

    #[test]
    fn gate_starts_the_next_phrase_with_its_pre_roll() {
        let mut gate = VoiceGate::new();
        gate.process(&level(8000));
        for _ in 0..VoiceGate::HANGOVER_FRAMES {
            gate.process(&level(0));
        }
        // Stay silent long enough for the pre-roll to fill up again.
        for _ in 0..VoiceGate::PRE_ROLL_FRAMES * 2 {
            gate.process(&level(0));
        }
        let sent = gate.process(&level(8000));
        assert_eq!(sent.len(), VoiceGate::PRE_ROLL_FRAMES);
    }
}
