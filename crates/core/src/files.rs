//! File transfers.
//!
//! A transfer starts in the connection thread (it owns the `Connection`) and
//! then runs as a detached task: the TCP stream is handed to us by tsclientlib
//! as a `StreamItem`, and copying bytes off it must not block the event loop.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::events::QueuedEvent;
use crate::handle::Inner;

/// How often progress is reported. 256 KB is frequent enough for a smooth bar
/// without drowning the event queue on a fast link.
const PROGRESS_STEP: u64 = 256 * 1024;
const CHUNK: usize = 64 * 1024;

pub async fn download(
    inner: Arc<Inner>,
    name: String,
    total: u64,
    mut stream: TcpStream,
    local: PathBuf,
) {
    inner.push_event(
        QueuedEvent::new("transfer_started")
            .str("name", &name)
            .str("direction", "download")
            .long("total", total as i64),
    );

    if let Some(parent) = local.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            fail(
                &inner,
                &name,
                &format!("cannot create {}: {e}", parent.display()),
            );
            return;
        }
    }

    let mut file = match tokio::fs::File::create(&local).await {
        Ok(file) => file,
        Err(e) => {
            fail(
                &inner,
                &name,
                &format!("cannot create {}: {e}", local.display()),
            );
            return;
        }
    };

    let mut buffer = vec![0u8; CHUNK];
    let mut done: u64 = 0;
    let mut last_report: u64 = 0;

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if let Err(e) = file.write_all(&buffer[..read]).await {
                    fail(&inner, &name, &format!("write failed: {e}"));
                    return;
                }
                done += read as u64;
                if progress_due(done, last_report) {
                    last_report = done;
                    progress(&inner, &name, "download", done, total);
                }
            }
            Err(e) => {
                fail(&inner, &name, &format!("read failed: {e}"));
                return;
            }
        }
    }

    if let Err(e) = file.flush().await {
        fail(&inner, &name, &format!("flush failed: {e}"));
        return;
    }

    inner.push_event(
        QueuedEvent::new("transfer_done")
            .str("name", &name)
            .str("direction", "download")
            .str("local", local.to_string_lossy().to_string())
            .long("total", total as i64),
    );
}

pub async fn upload(
    inner: Arc<Inner>,
    name: String,
    seek: u64,
    mut stream: TcpStream,
    local: PathBuf,
) {
    let total = match tokio::fs::metadata(&local).await {
        Ok(meta) => meta.len(),
        Err(e) => {
            fail(
                &inner,
                &name,
                &format!("cannot read {}: {e}", local.display()),
            );
            return;
        }
    };

    inner.push_event(
        QueuedEvent::new("transfer_started")
            .str("name", &name)
            .str("direction", "upload")
            .long("total", total as i64),
    );

    let mut file = match tokio::fs::File::open(&local).await {
        Ok(file) => file,
        Err(e) => {
            fail(
                &inner,
                &name,
                &format!("cannot open {}: {e}", local.display()),
            );
            return;
        }
    };

    if seek > 0 {
        use tokio::io::AsyncSeekExt;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(seek)).await {
            fail(&inner, &name, &format!("seek failed: {e}"));
            return;
        }
    }

    let mut buffer = vec![0u8; CHUNK];
    let mut done = seek;
    let mut last_report = done;

    loop {
        match file.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if let Err(e) = stream.write_all(&buffer[..read]).await {
                    fail(&inner, &name, &format!("send failed: {e}"));
                    return;
                }
                done += read as u64;
                if progress_due(done, last_report) {
                    last_report = done;
                    progress(&inner, &name, "upload", done, total);
                }
            }
            Err(e) => {
                fail(&inner, &name, &format!("read failed: {e}"));
                return;
            }
        }
    }

    if let Err(e) = stream.shutdown().await {
        fail(&inner, &name, &format!("finish failed: {e}"));
        return;
    }

    inner.push_event(
        QueuedEvent::new("transfer_done")
            .str("name", &name)
            .str("direction", "upload")
            .long("total", total as i64),
    );
}

/// Whether a progress report is due, given how much has moved and when the last
/// one was sent.
///
/// Split out because the arithmetic is what can be wrong: reporting every chunk
/// floods the queue with a 64 KiB transfer, and never reporting leaves a shell
/// with a bar that does not move. `PROGRESS_STEP` is the threshold both
/// directions use.
fn progress_due(done: u64, last_report: u64) -> bool {
    done.saturating_sub(last_report) >= PROGRESS_STEP
}

fn progress(inner: &Arc<Inner>, name: &str, direction: &str, done: u64, total: u64) {
    inner.push_event(
        QueuedEvent::new("transfer_progress")
            .str("name", name)
            .str("direction", direction)
            .long("done", done as i64)
            .long("total", total as i64),
    );
}

fn fail(inner: &Arc<Inner>, name: &str, message: &str) {
    log::warn!("Transfer of {name} failed: {message}");
    inner.push_event(
        QueuedEvent::new("transfer_error")
            .str("name", name)
            .str("message", message),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report is sent once the threshold is crossed, not before.
    #[test]
    fn progress_is_throttled_to_the_step() {
        assert!(!progress_due(0, 0), "nothing has moved");
        assert!(!progress_due(PROGRESS_STEP - 1, 0), "just under the step");
        assert!(progress_due(PROGRESS_STEP, 0), "exactly at the step");
        assert!(progress_due(PROGRESS_STEP * 3, 0), "well past the step");
    }

    /// After a report, the next one waits for another full step.
    #[test]
    fn a_report_resets_the_counter() {
        let reported = PROGRESS_STEP * 2;
        assert!(!progress_due(reported + 1, reported));
        assert!(!progress_due(reported + PROGRESS_STEP - 1, reported));
        assert!(progress_due(reported + PROGRESS_STEP, reported));
    }

    /// A counter that somehow moves backwards does not panic or report.
    ///
    /// `done` is monotonic in the copy loop, but a wrapped or reset value must
    /// not underflow into a spurious report.
    #[test]
    fn a_backwards_counter_does_not_report() {
        assert!(!progress_due(0, PROGRESS_STEP));
        assert!(!progress_due(100, 1_000));
    }

    /// One chunk is smaller than the step, so a 64 KiB transfer sends nothing
    /// until it finishes — the `transfer_done` event covers the end.
    #[test]
    fn a_single_chunk_is_below_the_threshold() {
        assert!((CHUNK as u64) < PROGRESS_STEP);
    }
}
