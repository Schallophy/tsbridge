//! Platform-neutral TeamSpeak 3 client session.
//!
//! This crate is the whole client minus two things: audio device I/O, and the
//! language binding. It owns one connection, translates tsclientlib's property
//! level book events into semantic events, keeps a snapshot of the server as
//! JSON, buffers voice in both directions, and runs file transfers.
//!
//! Three deliberate choices, all of which exist to keep this crate binding-free:
//!
//! * **No platform types.** Nothing here mentions JNI, Android, `cfretain`, or
//!   any UI class. The shells (`tsbridge-jni`, `tsbridge-c`) add those.
//! * **Events are a value type, not callbacks.** [`QueuedEvent`] is a plain
//!   struct that serializes to a flat JSON object. Every shell pulls with
//!   [`Session::drain_events`] on its own clock; nothing in here ever calls
//!   *into* the host, so there is no re-entrancy to reason about and no thread
//!   the host must know about.
//! * **One command entry point.** [`Session::exec`] takes a name plus JSON
//!   arguments. Adding a feature is a match arm in [`command::parse`], never a
//!   new exported symbol — so the FFI surface stays the same size forever.
//!
//! The 20 ms tick is the only clock: one Opus frame in, one playback frame out.

mod audio;
pub mod command;
mod conn;
pub mod events;
mod files;
mod handle;
pub mod state;

pub use crate::events::{QueuedEvent, Value};
pub use crate::handle::{panic_message, ConnectParams, Inner, TextTarget, FRAME_SAMPLES};
pub use crate::state::{ChannelEntry, FileEntry, ServerEntry, Snapshot, UserEntry};

/// The upstream revision this library was built against.
///
/// Reported by every shell's "about"/diagnostics call. Support questions about
/// audio or protocol behaviour are unanswerable without it, because two builds a
/// few commits apart can decode the same packet differently.
pub const TS_CLIENTLIB_VERSION: &str = "ee3bc6f";

/// Version of the *shell contract*, not of the session.
///
/// Bumped when the meaning of a symbol or a parameter changes — what a shell
/// must know to call this library correctly. Additive JSON fields do not count:
/// a shell that ignores a new key is still correct. The number is defined once
/// here and re-exported by the C and JNI crates so a shell can read it from any
/// binding without a second copy, which is what makes a stale `.so` detectable
/// at startup instead of as confusing half-working behaviour.
pub const ABI_VERSION: u32 = 1;

/// How to open a session.
///
/// The passwords and the channel are kept as separate fields on purpose: the
/// server password unlocks the server, the channel password unlocks the channel
/// the client lands in, and a server may require either, both, or neither.
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// `host`, `host:port`, or `host:port?channel=…` as tsclientlib parses it.
    pub address: String,
    /// A TS3 identity (`counterVkey` or plain base64 key), or empty to generate
    /// a fresh one. Reusing it is what keeps the UID stable across launches.
    pub identity: String,
    pub nickname: String,
    pub server_password: Option<String>,
    pub channel: Option<String>,
    pub channel_password: Option<String>,
}

/// One live session. Dropping it closes the connection and stops the thread.
pub struct Session {
    handle: handle::Handle,
}

impl Session {
    /// Starts the connection thread and returns immediately. Connection
    /// progress arrives as events; only argument rejection is returned here.
    pub fn connect(config: SessionConfig) -> Result<Session, String> {
        // `SessionConfig` is the shell's own vocabulary; `ConnectParams` is the
        // connection thread's. Copying field by field here keeps the two names
        // apart — a shell that says `server_password` never has to know that the
        // loop calls it something else.
        let handle = handle::Handle::create(handle::ConnectParams {
            address: config.address,
            identity: config.identity,
            nickname: config.nickname,
            server_password: config.server_password,
            channel: config.channel,
            channel_password: config.channel_password,
        })?;
        Ok(Session { handle })
    }

    /// Whether the socket and the server handshake are up right now.
    pub fn is_connected(&self) -> bool {
        self.handle.is_connected()
    }

    /// Takes every queued event. Never blocks: the queue is locked for the
    /// drain only, not while the caller serializes it.
    pub fn drain_events(&self) -> Vec<QueuedEvent> {
        self.handle.drain_events()
    }

    /// The whole server state as JSON. An unchanged revision returns the exact
    /// same cached string, so a 50 Hz caller does not re-serialize the member
    /// list on every tick.
    pub fn snapshot_json(&self) -> String {
        self.handle.snapshot_json()
    }

    /// Runs one named command. Returns "" on success, or a user-facing error.
    pub fn exec(&self, name: &str, args_json: &str) -> String {
        match command::parse(name, args_json) {
            Ok(command) => {
                self.handle.send(command);
                String::new()
            }
            Err(e) => e,
        }
    }

    /// The identity this session is using, in TS3's `counterVkey` form. Store
    /// it and pass it back as [`SessionConfig::identity`] next time; otherwise
    /// the server sees a brand new user on every launch.
    pub fn identity_ts_str(&self) -> Option<String> {
        self.handle.inner().identity()
    }

    /// Sends a prepared request to stop, which waits for the server to close the
    /// socket rather than dropping it mid-write.
    pub fn disconnect(&self) {
        self.handle.send(handle::Command::Disconnect);
    }

    // ── voice ───────────────────────────────────────────────────────────────
    // These are the only calls that do not go through JSON: a 50 Hz stream of
    // PCM does not belong in a serializer.

    /// Queues captured PCM16 (48 kHz mono) for transmission. Returns how many
    /// samples were taken.
    pub fn audio_write(&self, samples: &[i16]) -> usize {
        self.handle.inner().push_capture(samples);
        samples.len()
    }

    /// Fills `out` with decoded PCM16 and returns how many samples are valid.
    /// Never blocks; a starved queue returns 0 and the caller repeats the last
    /// frame or plays silence.
    pub fn audio_read(&self, out: &mut [i16]) -> usize {
        self.handle.inner().read_playback(out)
    }

    /// Drops buffered audio, so the next session does not start with a second
    /// of the previous one.
    pub fn audio_reset(&self) {
        self.handle.inner().clear_audio();
    }
}

/// Compiles the platform string into the identity form TS3 expects.
///
/// Lives here, not in a shell, because every shell needs the same bytes: the
/// key is what the server hashes into the UID.
pub fn identity_to_ts_str(identity: &tsclientlib::Identity) -> String {
    format!("{}V{}", identity.counter(), identity.key().to_ts())
}
