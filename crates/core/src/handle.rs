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
    ///
    /// `Option` only so [`Drop`] can take it: a `Runtime` cannot be dropped
    /// inside an async context, and which thread holds the last reference is not
    /// something this type controls.
    runtime: Option<Runtime>,
}

impl Drop for Handle {
    /// Shuts the runtime down off whichever thread happens to hold the last
    /// reference.
    ///
    /// Same hazard as [`crate::account::AccountEngine`]'s `Drop`, and it was
    /// solved there first: a multi-thread runtime panics when dropped from
    /// inside an async context ("Cannot drop a runtime in a context where
    /// blocking is not allowed"). The C and JNI shells drop sessions on a plain
    /// thread and never saw it, but a Rust shell that keeps a `Session` in a
    /// framework's state (Tauri, Dioxus) drops it from inside a command handler
    /// — that is, on a runtime worker. Moving the shutdown to its own thread
    /// makes it orderly regardless of who got there first.
    fn drop(&mut self) {
        // Nothing is joined: the caller must not wait for shutdown, and a
        // runtime that outlives this handle for a few milliseconds only delays
        // the exit.
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || drop(runtime));
        }
    }
}

/// How many events may wait for a shell before the oldest droppable one goes.
///
/// A shell that stops draining — minimised window, blocked UI thread, a screen
/// that has no handler for the event — used to grow this queue without bound,
/// while the audio queues right below it had a cap for exactly that reason.
///
/// The cap is not "drop the oldest": events are not interchangeable. Losing
/// `user_joined` leaves the member list wrong until the next full snapshot,
/// while losing `text_message` loses something that exists nowhere else. So the
/// queue keeps the newest `MAX_QUEUED_EVENTS` and, when it has to make room,
/// prefers to discard the oldest event whose content the snapshot can
/// reconstruct (see [`is_recoverable_from_snapshot`]).
const MAX_QUEUED_EVENTS: usize = 512;

/// Whether an event only reports a difference the snapshot already holds.
///
/// The member and channel lists live in [`Snapshot`], so an event describing a
/// change to them can be reconstructed by re-reading it. Messages, pokes, file
/// transfers, errors and account results cannot: they carry content that was
/// never in the snapshot, and dropping one is a permanent loss.
fn is_recoverable_from_snapshot(kind: &str) -> bool {
    matches!(
        kind,
        "connected"
            | "disconnected"
            | "reconnecting"
            | "user_joined"
            | "user_left"
            | "user_moved"
            | "user_renamed"
            | "user_mute_changed"
            | "user_away_changed"
            | "channel_created"
            | "channel_renamed"
            | "channel_removed"
    )
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
    /// A fresh, disconnected inner state with a command channel whose receiver
    /// the caller owns.
    ///
    /// Both session constructors build exactly this, and a test needs it too;
    /// the field list is long enough that a second copy is how the two drift.
    fn new(commands: mpsc::UnboundedSender<Command>) -> Inner {
        Inner {
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
        }
    }

    pub fn set_connected(&self, value: bool) {
        self.connected.store(value, Ordering::Release);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub fn push_event(&self, event: QueuedEvent) {
        let mut queue = match self.events.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        if queue.len() < MAX_QUEUED_EVENTS {
            queue.push_back(event);
            return;
        }

        // Full. Make room by discarding the oldest event the snapshot can
        // reconstruct; if the queue is entirely irreplaceable content, drop the
        // oldest anyway rather than grow without bound — a shell that has
        // stopped draining for this long is not going to read any of it.
        if let Some(index) = queue
            .iter()
            .position(|queued| is_recoverable_from_snapshot(&queued.kind))
        {
            queue.remove(index);
            if index == 0 {
                log::debug!("event queue full: dropped a state event the snapshot still holds");
            }
        } else {
            log::warn!(
                "event queue full of {} unrecoverable events: dropping the oldest",
                queue.len()
            );
            queue.pop_front();
        }
        queue.push_back(event);
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
    /// Whether the microphone starts muted.
    ///
    /// This has to be decided at `clientinit`, not with a later
    /// `clientupdate`: the initial declaration is what the server records, and
    /// a follow-up update of only this flag is not reliably reflected back in
    /// the client's own state. A shell that wants "join silently" must say so
    /// here.
    pub start_muted: bool,
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
        Handle::account_only_with_http(config, crate::account::http::Http::new())
    }

    /// [`Handle::account_only`] against a given HTTP client.
    ///
    /// The whole point is to reach the command surface — `exec` → dispatch →
    /// handler — from a test that stands up a recorded server, instead of calling
    /// the `account::*` free functions and skipping the handler that decides what
    /// to report. Production passes `Http::new()`; nothing else changes.
    pub fn account_only_with_http(
        config: crate::account::AccountConfig,
        http: crate::account::http::Http,
    ) -> Result<Handle, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib-account-only")
            .build()
            .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;

        let (commands, mut command_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner::new(commands));

        match crate::account::AccountEngine::with_http(&inner, config, http) {
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
            runtime: Some(runtime),
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
        let inner = Arc::new(Inner::new(commands));

        // No account side is created here.
        //
        // It used to be: every connection session started a second runtime with
        // two threads, even though most sessions never sign in. A desktop shell
        // that opens one session per server paid that per tab, and — worse —
        // each session carried its own account state, so switching servers meant
        // logging in again.
        //
        // The account belongs to the application, not to a connection. A shell
        // builds one with `Session::account_only`, signs in once, and either
        // keeps it separate (reading its snapshot and events) or hands it over
        // with `Handle::attach_account`, which is what makes a connection carry
        // the myTS proof and answer account commands. A shell that only wants to
        // talk needs neither.

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
                        .str("kind", "panic")
                        .bool("terminal", true),
                );
            }
        });

        Ok(Handle {
            inner,
            runtime: Some(runtime),
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

    /// The snapshot as a typed value, cloned out from under its lock.
    pub fn snapshot(&self) -> Snapshot {
        self.inner.with_state(|snapshot| snapshot.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn inner() -> (Arc<Inner>, mpsc::UnboundedReceiver<Command>) {
        let (commands, rx) = mpsc::unbounded_channel();
        (Arc::new(Inner::new(commands)), rx)
    }

    fn kinds(inner: &Inner) -> Vec<String> {
        let queue = inner.events.lock().unwrap_or_else(|e| e.into_inner());
        queue.iter().map(|event| event.kind.clone()).collect()
    }

    #[test]
    fn a_small_burst_is_kept_in_order() {
        let (inner, _rx) = inner();
        for index in 0..10 {
            inner.push_event(QueuedEvent::new("text_message").int("n", index));
        }
        assert_eq!(kinds(&inner).len(), 10);
    }

    #[test]
    fn a_flood_drops_state_events_before_messages() {
        let (inner, _rx) = inner();
        // One message that must survive, then enough state events to overflow.
        inner.push_event(QueuedEvent::new("text_message").str("message", "keep me"));
        for _ in 0..MAX_QUEUED_EVENTS {
            inner.push_event(QueuedEvent::new("user_moved"));
        }

        let queue = kinds(&inner);
        assert!(
            queue.len() <= MAX_QUEUED_EVENTS,
            "queue must stay bounded, got {}",
            queue.len()
        );
        assert!(
            queue.contains(&"text_message".to_string()),
            "the message is unrecoverable and must survive a flood of state events"
        );
    }

    #[test]
    fn a_flood_of_unrecoverable_events_still_stays_bounded() {
        let (inner, _rx) = inner();
        // Nothing here can be reconstructed from the snapshot, so the oldest has
        // to go — growing without bound is the worse outcome.
        for index in 0..(MAX_QUEUED_EVENTS + 50) {
            inner.push_event(QueuedEvent::new("text_message").int("n", index as i32));
        }
        let queue = kinds(&inner);
        assert_eq!(queue.len(), MAX_QUEUED_EVENTS);
    }

    #[test]
    fn draining_empties_the_queue() {
        let (inner, _rx) = inner();
        inner.push_event(QueuedEvent::new("text_message"));
        let handle = Handle {
            inner: inner.clone(),
            runtime: None,
        };
        assert_eq!(handle.drain_events().len(), 1);
        assert!(handle.drain_events().is_empty());
    }

    #[test]
    fn only_state_events_count_as_recoverable() {
        for kind in [
            "connected",
            "disconnected",
            "user_joined",
            "user_left",
            "user_moved",
            "user_renamed",
            "user_mute_changed",
            "user_away_changed",
            "channel_created",
            "channel_renamed",
            "channel_removed",
        ] {
            assert!(
                is_recoverable_from_snapshot(kind),
                "{kind} should be recoverable"
            );
        }
        for kind in [
            "text_message",
            "poked",
            "error",
            "command_error",
            "transfer_started",
            "transfer_progress",
            "transfer_done",
            "transfer_error",
            "file_list",
            "account_status",
        ] {
            assert!(
                !is_recoverable_from_snapshot(kind),
                "{kind} carries content the snapshot does not have"
            );
        }
    }
}
