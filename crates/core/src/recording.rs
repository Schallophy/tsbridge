//! Writing the playback mix to a WAV file.
//!
//! TeamSpeak's desktop client has a "record" button in its tools menu. What it
//! records there is the local capture stream — your own microphone. This
//! records the **playback mix** instead: everything you hear, which on a phone
//! is the more useful of the two (the microphone is already available to any
//! screen recorder, and a recording of only yourself says nothing about the
//! conversation).
//!
//! The file is a plain 48 kHz mono 16-bit PCM WAV: the format the core already
//! produces for playback, no resampling, and one every player opens. It is
//! written incrementally, so a long call does not sit in memory, and the header
//! is patched on stop because the length is not known until then.

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Bytes of a 44-byte canonical WAV header.
const WAV_HEADER: usize = 44;

/// One open recording.
pub struct Recorder {
    file: BufWriter<File>,
    path: PathBuf,
    /// Frames written so far, for the header patch and the progress event.
    frames: u64,
}

impl Recorder {
    /// Opens `path` and writes a placeholder header.
    ///
    /// The header is filled in on [`stop`](Self::stop): the sizes are only known
    /// then, and a header with a wrong length is what makes a player show a
    /// truncated file.
    pub fn create(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let file =
            File::create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        let mut recorder = Recorder {
            file: BufWriter::new(file),
            path: path.to_path_buf(),
            frames: 0,
        };
        recorder
            .file
            .write_all(&[0u8; WAV_HEADER])
            .map_err(|e| format!("cannot write the header: {e}"))?;
        Ok(recorder)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Seconds recorded so far, at the fixed 48 kHz rate.
    pub fn seconds(&self) -> u64 {
        self.frames / 48_000
    }

    /// Appends one frame of mono PCM16.
    pub fn write(&mut self, samples: &[i16]) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(samples.len() * 2);
        for sample in samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        self.file
            .write_all(&bytes)
            .map_err(|e| format!("cannot write audio: {e}"))?;
        self.frames += samples.len() as u64;
        Ok(())
    }

    /// Patches the header and closes the file.
    pub fn stop(mut self) -> Result<(PathBuf, u64), String> {
        let data_bytes = self.frames * 2;
        let header = wav_header(data_bytes);
        self.file
            .flush()
            .map_err(|e| format!("cannot flush: {e}"))?;
        let mut file = self
            .file
            .into_inner()
            .map_err(|e| format!("cannot close {}: {e}", self.path.display()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("cannot seek: {e}"))?;
        file.write_all(&header)
            .map_err(|e| format!("cannot patch the header: {e}"))?;
        file.flush().map_err(|e| format!("cannot flush: {e}"))?;
        Ok((self.path.clone(), self.frames))
    }
}

/// A canonical 44-byte WAV header for 48 kHz mono 16-bit PCM.
fn wav_header(data_bytes: u64) -> [u8; WAV_HEADER] {
    const CHANNELS: u16 = 1;
    const RATE: u32 = 48_000;
    const BITS: u16 = 16;
    let block_align = CHANNELS * BITS / 8;
    let byte_rate = RATE * u32::from(block_align);
    // The RIFF chunk size counts everything after the first 8 bytes. A file
    // longer than 4 GB cannot be described by a 32-bit field; it is clamped
    // rather than wrapped, so a player shows a truncated file instead of a
    // garbage length.
    let riff_size = (36 + data_bytes).min(u64::from(u32::MAX)) as u32;
    let data_size = data_bytes.min(u64::from(u32::MAX)) as u32;

    let mut header = [0u8; WAV_HEADER];
    header[0..4].copy_from_slice(b"RIFF");
    header[4..8].copy_from_slice(&riff_size.to_le_bytes());
    header[8..12].copy_from_slice(b"WAVE");
    header[12..16].copy_from_slice(b"fmt ");
    header[16..20].copy_from_slice(&16u32.to_le_bytes());
    header[20..22].copy_from_slice(&1u16.to_le_bytes()); // PCM
    header[22..24].copy_from_slice(&CHANNELS.to_le_bytes());
    header[24..28].copy_from_slice(&RATE.to_le_bytes());
    header[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    header[32..34].copy_from_slice(&block_align.to_le_bytes());
    header[34..36].copy_from_slice(&BITS.to_le_bytes());
    header[36..40].copy_from_slice(b"data");
    header[40..44].copy_from_slice(&data_size.to_le_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_describes_48k_mono_16_bit() {
        let header = wav_header(0);
        assert_eq!(&header[0..4], b"RIFF");
        assert_eq!(&header[8..12], b"WAVE");
        assert_eq!(&header[12..16], b"fmt ");
        assert_eq!(u16::from_le_bytes([header[20], header[21]]), 1);
        assert_eq!(u16::from_le_bytes([header[22], header[23]]), 1);
        assert_eq!(
            u32::from_le_bytes([header[24], header[25], header[26], header[27]]),
            48_000
        );
        assert_eq!(u16::from_le_bytes([header[34], header[35]]), 16);
        assert_eq!(&header[36..40], b"data");
    }

    #[test]
    fn a_recorded_file_has_the_frames_it_was_given() {
        let path = std::env::temp_dir().join(format!(
            "tsbridge-rec-{}-{}.wav",
            std::process::id(),
            line!()
        ));
        let mut recorder = Recorder::create(&path).expect("create");
        recorder.write(&[0, 1, -1, 32767]).expect("write");
        recorder.write(&[0; 960]).expect("write");
        let (written, frames) = recorder.stop().expect("stop");
        assert_eq!(written, path);
        assert_eq!(frames, 964);

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(bytes.len(), WAV_HEADER + 964 * 2);
        // The patched data size is what a player reads the length from.
        assert_eq!(
            u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]),
            964 * 2
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn seconds_are_counted_at_the_fixed_rate() {
        let path = std::env::temp_dir().join(format!(
            "tsbridge-rec-sec-{}-{}.wav",
            std::process::id(),
            line!()
        ));
        let mut recorder = Recorder::create(&path).expect("create");
        recorder.write(&[0; 48_000]).expect("write a second");
        assert_eq!(recorder.seconds(), 1);
        recorder.stop().expect("stop");
        let _ = std::fs::remove_file(&path);
    }
}
