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
    /// The myTeamSpeak account side, once a shell has built it. Present on every
    /// session: the account is independent of the connection, so it can be
    /// logged into before the first server is joined and it survives a
    /// disconnect.
    account: Mutex<Option<Arc<crate::account::AccountEngine>>>,
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

    /// Installs the account engine. Called once, while the handle is being built.
    pub fn set_account_engine(&self, engine: Arc<crate::account::AccountEngine>) {
        *self.account.lock().unwrap_or_else(|e| e.into_inner()) = Some(engine);
    }

    /// The account engine, if one was built.
    pub fn account_engine(&self) -> Option<Arc<crate::account::AccountEngine>> {
        self.account
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The six myTeamSpeak parameters for this connection, if the account can
    /// sign. Called from the connection thread, which owns the IV.
    pub fn myts_params(&self, shared_iv: &[u8]) -> Option<crate::account::mytsid::MytsParams> {
        self.account_engine()?.myts_params(shared_iv)
    }

    /// The account report as last published, for a quick read.
    pub fn account_snapshot(&self) -> Option<crate::account::AccountReport> {
        self.account_engine()?;
        Some(self.with_state(|snapshot| snapshot.account.clone()))
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
#[derive(Clone, Default)]
pub struct ConnectParams {
    pub address: String,
    /// `counterVkey` form, or empty to generate a fresh identity.
    pub identity: String,
    pub nickname: String,
    pub server_password: Option<String>,
    pub channel: Option<String>,
    pub channel_password: Option<String>,
    /// The myTeamSpeak proof to send on `clientinit`, when the caller signed in
    /// first. `None` means the connection carries no identity, which is exactly
    /// what a client that is not signed in does.
    pub myts: Option<crate::MytsProvider>,
    /// Which signed version tuple to announce. The default (`3.6.3` + `Windows`)
    /// is resolved against the signed table at connect time.
    pub version_profile: crate::VersionChoice,
    /// Privilege key redeemed on `clientinit`, or empty.
    pub privilege_key: String,
}

impl std::fmt::Debug for ConnectParams {
    /// Hand-written: the myTeamSpeak provider is a closure, which has no `Debug`.
    /// Nothing sensitive is printed either way — the proof is computed later, per
    /// connection.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectParams")
            .field("address", &self.address)
            .field("nickname", &self.nickname)
            .field("myts", &self.myts.as_ref().map(|_| "<provider>"))
            .field("version_profile", &self.version_profile)
            .field("has_privilege_key", &!self.privilege_key.is_empty())
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// A handle with the account side only — no connection, no socket.
    ///
    /// Every shell needs this: a login screen wants to show bookmarks before the
    /// user has joined anything, and a "sync my settings" button should not
    /// require a server address at all. [`Handle::create`] always spawns a
    /// connection task, which would sit there failing on a dummy address.
    ///
    /// Commands that only make sense over a connection (`send_text`, `upload`,
    /// …) are reported as `command_error` rather than silently dropped: a caller
    /// that wired a button to one gets an answer it can show.
    pub fn account_only(config: crate::account::AccountConfig) -> Result<Handle, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib-account-only")
            .build()
            .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;

        let (commands, mut command_rx) = mpsc::unbounded_channel();
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
            account: Mutex::new(None),
        });

        match crate::account::AccountEngine::new(&inner, config) {
            Ok(engine) => inner.set_account_engine(Arc::new(engine)),
            Err(e) => return Err(format!("the account side could not be started: {e}")),
        }

        let task_inner = inner.clone();
        runtime.spawn(async move {
            // Drains the queue so the sender never sees a closed channel (which
            // would log a warning on every call) and so a connection-only
            // command produces an event instead of vanishing.
            while let Some(command) = command_rx.recv().await {
                task_inner.push_event(
                    QueuedEvent::new("command_error")
                        .str(
                            "message",
                            format!(
                                "`{}` needs a server connection; this session has none",
                                command_name(&command)
                            ),
                        )
                        .str("missing_permission", ""),
                );
            }
        });

        Ok(Handle {
            inner,
            _runtime: runtime,
        })
    }

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
            account: Mutex::new(None),
        });

        // The account side gets its own runtime and lives on the handle, not on
        // the connection: it has to work before the first join and keep working
        // after a reconnect. A failure to start it is not fatal — a client that
        // cannot log in can still talk. Paths start out empty and are set by
        // `account_config` (or `Session::set_account_config`), so no shell has to
        // know the platform default.
        match crate::account::AccountEngine::new(&inner, crate::account::AccountConfig::default()) {
            Ok(engine) => inner.set_account_engine(Arc::new(engine)),
            Err(e) => log::error!("the account side is unavailable: {e}"),
        }

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

/// A stable name for a command, for the error an account-only session reports.
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Disconnect => "disconnect",
        Command::SendText { .. } => "send_text",
        Command::Poke { .. } => "poke",
        Command::JoinChannel { .. } => "join_channel",
        Command::SetInputMuted(_) => "set_input_muted",
        Command::SetOutputMuted(_) => "set_output_muted",
        Command::SetAway { .. } => "set_away",
        Command::SetNickname(_) => "set_nickname",
        Command::ListFiles { .. } => "list_files",
        Command::Download { .. } => "download",
        Command::Upload { .. } => "upload",
        Command::SetAudioEnabled(_) => "audio_enabled",
        Command::SetMicGain(_) => "set_mic_gain",
        Command::SetUserVolume { .. } => "set_user_volume",
        Command::SetWhisperTargets { .. } => "set_whisper_targets",
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
