//! The client handle a shell holds as an opaque pointer.
//!
//! One handle owns one connection thread. Every entry point borrows the handle
//! for the duration of the call and never blocks on the network: work is handed
//! to the connection thread through a command channel, and its results come back
//! through the event queue and the snapshot.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::events::QueuedEvent;
use crate::state::Snapshot;

/// Who a text message goes to.
#[derive(Debug, Clone, Copy)]
pub enum TextTarget {
    Server,
    Channel,
    Client(i32),
}

/// Work the host thread asks the connection thread to perform.
#[derive(Debug)]
pub enum Command {
    /// Close the connection and stop the thread.
    Disconnect,
    SendText {
        target: TextTarget,
        message: String,
    },
    Poke {
        client_id: i32,
        message: String,
    },
    JoinChannel {
        channel_id: i64,
        password: Option<String>,
    },
    SetInputMuted(bool),
    SetOutputMuted(bool),
    SetAway {
        away: bool,
        message: Option<String>,
    },
    SetNickname(String),
    ListFiles {
        channel_id: i64,
        path: String,
        password: Option<String>,
    },
    Download {
        channel_id: i64,
        path: String,
        local: String,
        password: Option<String>,
    },
    Upload {
        channel_id: i64,
        path: String,
        local: String,
        password: Option<String>,
        overwrite: bool,
    },
    /// Gate for the transmit path; capture keeps running either way.
    SetAudioEnabled(bool),
    /// Linear capture gain, applied before the silence gate and encoder.
    SetMicGain(f32),
    /// Linear playback volume for one remote client.
    SetUserVolume {
        client_id: i32,
        volume: f32,
    },
    /// Empty targets restore ordinary channel talk.
    SetWhisperTargets {
        clients: Vec<u16>,
        channels: Vec<u64>,
        /// `(GroupWhisperType, GroupWhisperTarget, group id)`.
        groups: Vec<(u8, u8, u64)>,
    },
}

pub struct Handle {
    inner: Arc<Inner>,
    /// Dropping this shuts the runtime down; the connection thread is detached
    /// from it and exits when the command channel closes.
    _runtime: Runtime,
}

pub struct Inner {
    connected: AtomicBool,
    events: Mutex<VecDeque<QueuedEvent>>,
    state: Mutex<Snapshot>,
    /// The identity in use, as the TS3 `counterVkey` string, once the connection
    /// thread has built or parsed one. Every shell reads this to persist it, and
    /// without it the server sees a new UID on every launch.
    identity: Mutex<Option<String>>,
    /// Snapshot JSON cached by revision, so a 20 ms poll that changes nothing
    /// does not re-serialize the member list.
    cached_json: Mutex<(u64, String)>,
    commands: mpsc::UnboundedSender<Command>,
    /// Captured PCM16 waiting for the encoder (written by the host thread).
    capture: Mutex<VecDeque<i16>>,
    /// Decoded PCM16 waiting for playback (written by the connection thread).
    playback: Mutex<VecDeque<i16>>,
    /// Client ids currently transmitting, for the speaking indicator.
    talking: Mutex<Vec<i32>>,
}

/// 20 ms at 48 kHz mono — one Opus frame, and one AudioTrack buffer.
pub const FRAME_SAMPLES: usize = 960;

/// Half a second of audio. Beyond that the UI is not draining, and buffering
/// more would only add latency when it starts again.
const MAX_QUEUED_SAMPLES: usize = FRAME_SAMPLES * 25;

impl Inner {
    pub fn set_connected(&self, value: bool) {
        self.connected.store(value, Ordering::Release);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub fn push_event(&self, event: QueuedEvent) {
        match self.events.lock() {
            Ok(mut queue) => queue.push_back(event),
            Err(poisoned) => poisoned.into_inner().push_back(event),
        }
    }

    /// Runs `f` against the snapshot under the lock. All snapshot access goes
    /// through here, so the lock discipline lives in one place.
    pub fn with_state<R>(&self, f: impl FnOnce(&mut Snapshot) -> R) -> R {
        match self.state.lock() {
            Ok(mut snapshot) => f(&mut snapshot),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    pub fn talking(&self) -> Vec<i32> {
        match self.talking.lock() {
            Ok(ids) => ids.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Records the identity the connection thread ended up using, so a shell can
    /// persist it. Called once per session, right after the identity is built.
    pub fn set_identity(&self, value: String) {
        let mut slot = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(value);
    }

    /// The identity in `counterVkey` form, or `None` before the session started.
    pub fn identity(&self) -> Option<String> {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Returns true when the speaking set changed, so the caller can bump the
    /// revision and let the UI repaint exactly once.
    pub fn set_talking(&self, ids: Vec<i32>) -> bool {
        let changed = {
            let mut current = match self.talking.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if *current == ids {
                false
            } else {
                *current = ids;
                true
            }
        };
        if changed {
            let ids = self.talking();
            self.with_state(|snapshot| {
                snapshot.set_talking(&ids);
            });
        }
        changed
    }

    // ── audio ───────────────────────────────────────────────────────────────

    pub fn push_capture(&self, samples: &[i16]) {
        let mut queue = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() + samples.len() > MAX_QUEUED_SAMPLES {
            // Drop the oldest audio: sending late audio is worse than a gap.
            let drop = (queue.len() + samples.len()).saturating_sub(MAX_QUEUED_SAMPLES);
            let drop = drop.min(queue.len());
            queue.drain(..drop);
        }
        queue.extend(samples.iter().copied());
    }

    /// Takes at most one frame; `None` when there is not enough captured audio.
    pub fn take_capture_frame(&self) -> Option<Vec<i16>> {
        let mut queue = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() < FRAME_SAMPLES {
            return None;
        }
        Some(queue.drain(..FRAME_SAMPLES).collect())
    }

    /// Drops captured audio that piled up while the mic was muted.
    pub fn clear_capture(&self) {
        self.capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn push_playback(&self, samples: &[i16]) {
        let mut queue = self.playback.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() + samples.len() > MAX_QUEUED_SAMPLES {
            let drop = (queue.len() + samples.len()).saturating_sub(MAX_QUEUED_SAMPLES);
            let drop = drop.min(queue.len());
            queue.drain(..drop);
        }
        queue.extend(samples.iter().copied());
    }

    /// Fills `out` and returns how many samples were written. Never blocks.
    pub fn read_playback(&self, out: &mut [i16]) -> usize {
        let mut queue = self.playback.lock().unwrap_or_else(|e| e.into_inner());
        let count = out.len().min(queue.len());
        for slot in out.iter_mut().take(count) {
            *slot = queue.pop_front().unwrap_or(0);
        }
        count
    }

    pub fn clear_audio(&self) {
        self.clear_capture();
        self.playback
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    fn revision(&self) -> u64 {
        self.with_state(|snapshot| snapshot.rev)
    }

    pub fn snapshot_json(&self) -> String {
        let revision = self.revision();
        if let Ok(cache) = self.cached_json.lock() {
            if cache.0 == revision {
                return cache.1.clone();
            }
        }
        let json = self.with_state(|snapshot| {
            serde_json::to_string(snapshot).unwrap_or_else(|e| {
                log::error!("Failed to serialize the snapshot: {e}");
                "{}".to_string()
            })
        });
        if let Ok(mut cache) = self.cached_json.lock() {
            *cache = (revision, json.clone());
        }
        json
    }
}

/// Everything needed to open one connection, in one value.
///
/// Bundled rather than passed as six positional `String`s: that is exactly the
/// shape in which a caller silently swaps the server password for the channel
/// password, and the resulting bug reads as "the password is wrong".
#[derive(Debug, Clone, Default)]
pub struct ConnectParams {
    pub address: String,
    /// `counterVkey` form, or empty to generate a fresh identity.
    pub identity: String,
    pub nickname: String,
    pub server_password: Option<String>,
    pub channel: Option<String>,
    pub channel_password: Option<String>,
}

impl Handle {
    /// Starts the connection thread and returns immediately.
    ///
    /// The parameters arrive as one [`ConnectParams`] value rather than six
    /// positionally-identical `String`s, so a caller cannot pass the channel
    /// password where the server password belongs.
    pub fn create(params: ConnectParams) -> Result<Handle, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib")
            .build()
            .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;

        let (commands, command_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            connected: AtomicBool::new(false),
            events: Mutex::new(VecDeque::new()),
            state: Mutex::new(Snapshot::default()),
            cached_json: Mutex::new((u64::MAX, String::new())),
            commands,
            capture: Mutex::new(VecDeque::new()),
            playback: Mutex::new(VecDeque::new()),
            talking: Mutex::new(Vec::new()),
            identity: Mutex::new(None),
        });

        // The event queue, the snapshot and the identity all outlive every
        // connection attempt, so a shell keeps reading them across a reconnect.
        // Nothing here is language-specific.
        //
        // The task is wrapped in `catch_unwind`: tsclientlib and the codec sit
        // behind a lot of `unwrap`, and one of them panicking used to abort the
        // process. Now it ends this session and reports what happened, which is
        // the difference between "the app crashes" and "this server fails".
        let task_inner = inner.clone();
        runtime.spawn(async move {
            use futures::FutureExt;

            let outcome = std::panic::AssertUnwindSafe(crate::conn::run(
                task_inner.clone(),
                command_rx,
                params,
            ))
            .catch_unwind()
            .await;

            if let Err(payload) = outcome {
                let reason = panic_message(&*payload);
                log::error!("Connection thread panicked: {reason}");
                task_inner.set_connected(false);
                task_inner.push_event(
                    QueuedEvent::new("error")
                        .str("message", format!("connection thread crashed: {reason}"))
                        .str("kind", "panic"),
                );
            }
        });

        Ok(Handle {
            inner,
            _runtime: runtime,
        })
    }

    pub fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Takes every queued event. Never blocks: the queue is locked for the drain
    /// only, not while the caller turns it into its own type.
    pub fn drain_events(&self) -> Vec<QueuedEvent> {
        let mut queue = match self.inner.events.lock() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.drain(..).collect()
    }

    pub fn snapshot_json(&self) -> String {
        self.inner.snapshot_json()
    }

    pub fn send(&self, command: Command) {
        if self.inner.commands.send(command).is_err() {
            log::warn!("Connection thread is gone; command dropped");
        }
    }
}

/// Turns a panic payload into something worth showing a user.
///
/// `panic!` carries either a `&str` or a formatted `String` depending on the
/// macro form used, and anything else (a custom `Box<dyn Any>`) is not readable
/// at all — in which case the honest answer is that we do not know.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown cause (panic payload was not a string)".to_string()
    }
}
