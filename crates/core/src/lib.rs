//! Platform-neutral TeamSpeak 3 client session. TS6 compatibility is not
//! guaranteed: the protocol stack targets TS3 and nothing here is TS6-specific.
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
//!   arguments. Adding a feature is a match arm in [`command::parse`] or
//!   [`account::AccountCommand::parse`], never a new exported symbol — so the FFI
//!   surface stays the same size forever.
//!
//! The 20 ms tick is the only clock: one Opus frame in, one playback frame out.

pub mod account;
mod audio;
pub mod command;
mod conn;
pub mod events;
mod files;
mod handle;
pub mod state;
pub mod version;

pub use crate::events::{QueuedEvent, Value};
pub use crate::handle::{panic_message, ConnectParams, Inner, TextTarget, FRAME_SAMPLES};
pub use crate::state::{ChannelEntry, FileEntry, ServerEntry, Snapshot, UserEntry};
pub use crate::version::{ResolvedVersion, VersionChoice, VersionEntry};

/// Re-exported so a shell (and the tests) can build an identity from a stored
/// string in the same format [`identity_to_ts_str`] emits, without depending on
/// `tsclientlib` directly.
pub use tsclientlib::Identity;

/// Builds the six myTeamSpeak `clientinit` parameters from a connection's
/// handshake IV.
///
/// A closure rather than precomputed strings because the proof signs a
/// per-connection challenge: the IV does not exist until the handshake finishes.
/// [`Session::myts_provider`] produces one from a signed-in session.
pub type MytsProvider =
    std::sync::Arc<dyn Fn(&[u8]) -> Option<tsclientlib::MytsParams> + Send + Sync>;

/// The upstream revision this library was built against.
///
/// Reported by every shell's "about"/diagnostics call. Support questions about
/// audio or protocol behaviour are unanswerable without it, because two builds a
/// few commits apart can decode the same packet differently.
pub const TS_CLIENTLIB_VERSION: &str = "ee3bc6f";

/// Version of the *shell contract*, not of the session.
///
/// Bumped when the meaning of a symbol or a parameter changes — what a shell
/// must know to call this library correctly — and when a new exported call
/// would be missing from an older library a newer shell is pointed at.
/// Additive JSON fields do not count: a shell that ignores a new key is still
/// correct. The number is defined once here and re-exported by the C and JNI
/// crates so a shell can read it from any binding without a second copy, which
/// is what makes a stale `.so` detectable at startup instead of as confusing
/// half-working behaviour.
///
/// 2: the C and JNI shells gained account-only constructors and a connect that
/// carries the myTeamSpeak proof into `clientinit` (`tsbridge_create_account` /
/// `tsbridge_create_with_account`, and the two JNI equivalents).
/// 3: the JNI create calls take a `version` argument (the announced client
/// version profile).
/// 4: the JNI create calls take a `token` argument (a privilege key to redeem).
/// 5: the version is a `(version number, platform)` pair instead of a fixed
/// profile name. The JNI create calls take a `platform` argument after
/// `version`, and the two `nativeVersion*` calls expose the table for the
/// settings UI. `VersionProfile` is gone; the C JSON takes `version` +
/// `platform`.
pub const ABI_VERSION: u32 = 7;

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
    /// The version number + platform to announce. Resolved against the signed
    /// table at connect time to the full version text and its signature; the
    /// default (`3.6.3` + `Windows`) is what this library has always sent.
    pub version: VersionChoice,
    /// A privilege key (`token=…`) to redeem on `clientinit`, or empty.
    ///
    /// This is how a first connection gains server groups (an admin identity in
    /// particular). It is single-use: the server consumes it and later logins
    /// are authorised by the UID it granted rights to.
    pub privilege_key: String,
    /// Whether the microphone is muted from the moment the client appears on the
    /// server.
    ///
    /// Decided at `clientinit`, because that is what the server records: a
    /// later update of only the mute flag is not reflected back in our own
    /// client state, so the member list kept showing an open microphone while
    /// audio was already muted.
    pub start_muted: bool,
}

/// One live session. Dropping it closes the connection and stops the thread.
pub struct Session {
    handle: handle::Handle,
}

impl Session {
    /// A session with the account side only: no connection, no address, no
    /// socket. Login, bookmarks and backups all work through it.
    ///
    /// This exists because the account is not part of the connection: a login
    /// screen must be able to show bookmarks before the user has joined a
    /// server, and a "sync my settings" button must not need a server address at
    /// all. Commands that do need a connection are reported as `command_error`.
    pub fn account_only(config: account::AccountConfig) -> Result<Session, String> {
        Ok(Session {
            handle: handle::Handle::account_only(config)?,
        })
    }

    /// Starts the connection thread and returns immediately. Connection
    /// progress arrives as events; only argument rejection is returned here.
    pub fn connect(config: SessionConfig) -> Result<Session, String> {
        Session::connect_with_myts(config, None)
    }

    /// Like [`Session::connect`], but carries a myTeamSpeak proof from the first
    /// packet.
    ///
    /// The provider comes from [`Session::myts_provider`] on a session that is
    /// already signed in. Passing `None` is exactly `connect`.
    pub fn connect_with_myts(
        config: SessionConfig,
        myts: Option<MytsProvider>,
    ) -> Result<Session, String> {
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
            version_profile: config.version,
            privilege_key: config.privilege_key,
            start_muted: config.start_muted,
            myts,
        })?;
        Ok(Session { handle })
    }

    /// A provider for the six myTeamSpeak `clientinit` parameters, if this
    /// session is signed in with an identity.
    ///
    /// Needed because a connection has to carry the proof from the *first* packet
    /// (`clientinit`), while the login that produces it happens on the account
    /// side. A shell signs in with `account_only`, takes this, and hands it to
    /// `connect` — the official client's order is sign in, then connect.
    ///
    /// The closure captures the identity, never the session: the proof is signed
    /// per connection with the handshake IV it is given.
    pub fn myts_provider(&self) -> Option<MytsProvider> {
        let engine = self.handle.inner().account_engine()?;
        let identity = engine.identity()?;
        // The CONFIG item's badge list travels with the account, so the phone
        // does not need the official client's settings.db to show them.
        let signed_badges = engine.signed_badges().join(",");
        Some(std::sync::Arc::new(move |iv: &[u8]| {
            let params = identity.params(iv);
            Some(tsclientlib::MytsParams {
                my_teamspeak_id: params.my_teamspeak_id,
                ac_time: params.ac_time,
                user_pub_key: params.user_pub_key,
                auth_sign: params.auth_sign,
                pub_sign: params.pub_sign,
                pub_sign_cert: params.pub_sign_cert,
                signed_badges: signed_badges.clone(),
            })
        }))
    }

    /// Points the account side at the local database and backup directory.
    ///
    /// Same effect as the `account_config` command, for a Rust caller that would
    /// rather not round-trip through JSON. `None` in either field means "probe the
    /// platform default".
    pub fn set_account_config(&self, config: account::AccountConfig) {
        if let Some(engine) = self.handle.inner().account_engine() {
            engine.set_config(config);
        }
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

    /// The snapshot as a typed value.
    ///
    /// [`Session::snapshot_json`] exists because Kotlin, Swift and C can only
    /// cross a JSON string. A Rust shell linked to this crate should not have to
    /// pay for that: serialising the whole member list and parsing it back to
    /// reach a field defeats the point of the crate, and it is the one thing a
    /// JSON boundary makes worse rather than better.
    ///
    /// The clone is deliberate — the snapshot lives behind a mutex that the
    /// connection thread writes, so handing out a reference would mean holding
    /// that lock across the caller's work.
    pub fn snapshot(&self) -> Snapshot {
        self.handle.snapshot()
    }

    /// Runs one named command. Returns "" on success, or a user-facing error.
    ///
    /// Account commands are routed first and never touch the connection: a client
    /// has to be able to sync bookmarks with no server at all. Everything else is
    /// the connection thread's, which queues the work and returns immediately.
    pub fn exec(&self, name: &str, args_json: &str) -> String {
        // `account_config` only records two paths, so it stays synchronous: a
        // login in flight must not make "tell me where settings.db is" fail.
        if name == "account_config" {
            let engine = match self.handle.inner().account_engine() {
                Some(engine) => engine,
                None => return "the account side could not be started".to_string(),
            };
            return match account::parse_config(args_json) {
                Ok(config) => {
                    engine.set_config(config);
                    String::new()
                }
                Err(e) => e,
            };
        }
        if let Some(parsed) = account::AccountCommand::parse(name, args_json) {
            let command = match parsed {
                Ok(command) => command,
                Err(e) => return e,
            };
            let engine = match self.handle.inner().account_engine() {
                Some(engine) => engine,
                None => return "the account side could not be started".to_string(),
            };
            return engine.dispatch(command).err().unwrap_or_default();
        }
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
///
/// The key part is the *obfuscated* encoding, not the plain base64 DER. Both
/// parse (upstream `EccKeyPrivP256::import_str` tries plain first, then
/// obfuscated), but the obfuscated form is what the real client writes into its
/// settings database, so a string produced here can be pasted into a running
/// client's `unique_identity` and vice versa. Verified byte-for-byte against two
/// live identities: decode → re-encode reproduces the stored string exactly.
pub fn identity_to_ts_str(identity: &tsclientlib::Identity) -> String {
    format!(
        "{}V{}",
        identity.counter(),
        identity.key().to_ts_obfuscated()
    )
}
