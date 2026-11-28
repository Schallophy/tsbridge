//! C ABI over `litespeak-core`.
//!
//! The contract, and the reason it looks like this:
//!
//! * **One opaque handle.** `LiteSpeakSession *` is a boxed [`Session`]; the caller never
//!   sees a Rust type.
//! * **JSON for everything except voice.** State, events and commands all travel
//!   as strings, so adding a field never changes the ABI. Voice stays a raw
//!   sample buffer because a 50 Hz stream through a serializer is pure waste on
//!   both sides.
//! * **Every returned `char *` is owned by this library** and must be released
//!   with [`litespeak_string_free`]. That is the one rule a caller can get wrong
//!   in a way that leaks steadily; it is stated in the header too.
//! * **Every entry point catches panics.** Unwinding out of `extern "C"` is
//!   undefined behaviour, so a panicking `unwrap` deep inside the protocol stack
//!   would abort the host process instead of failing this call.
//!
//! ABI version is reported by [`litespeak_abi_version`] and must be bumped on any
//! signature change; additive JSON fields do not require a bump.

// Every `unsafe` block below states the invariant that makes it sound; the lint
// keeps the next one from arriving without it.
#![deny(clippy::undocumented_unsafe_blocks)]
// Every exported function takes raw pointers, by definition: that is what a C
// ABI is. Marking them `unsafe fn` would change nothing for the caller (a C
// caller cannot tell) while making Rust callers write `unsafe` around the whole
// call. The actual safety rule — a non-null handle must come from
// `litespeak_create` — is documented per function and in the header.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

use litespeak_core::Session;
use serde::Deserialize;

/// Bump on any change to a signature or to the meaning of a parameter.
///
/// Defined in `litespeak-core` and re-exported here, so the JNI shim reports the
/// same number without a second copy that could drift.
pub use litespeak_core::ABI_VERSION;

/// The `create` payload. Field names match every shell's own config struct, and
/// `camelCase` matches the snapshot/event JSON, so one decoder style works
/// everywhere.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    address: String,
    #[serde(default)]
    identity: String,
    /// The client version to announce, as a version number (`3.6.3`). Paired
    /// with `platform`; resolved against the signed table to the full text and
    /// signature. Absent means the standard `3.6.3` + `Windows`.
    #[serde(default)]
    version: Option<String>,
    /// The platform to announce with the version (`Windows`, `OS X`, `Linux`,
    /// `Android`, …). Absent means `Windows`.
    #[serde(default)]
    platform: Option<String>,
    /// A privilege key to redeem on first connect.
    #[serde(default)]
    token: Option<String>,
    /// Whether the microphone is muted from the first packet. Absent means
    /// "not muted", which is what a shell that says nothing expects.
    #[serde(default)]
    start_muted: Option<bool>,
    #[serde(default)]
    nickname: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    channel_password: Option<String>,
}

/// `int level, const char *target, const char *message`
type LogCallback = extern "C" fn(i32, *const c_char, *const c_char);

static LOG_CALLBACK: OnceLock<LogSink> = OnceLock::new();

struct LogSink(std::sync::RwLock<Option<LogCallback>>);

/// Forwards `log` records to whatever callback the host installed. Installed
/// once per process; `litespeak_set_log_callback` only swaps the target, so a
/// host can start logging before it has opened a session.
struct CallbackLogger;

impl log::Log for CallbackLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let Some(sink) = LOG_CALLBACK.get() else {
            return;
        };
        let target = record.target();
        let message = format!("{}", record.args());
        // A callback that panics or aborts is the host's problem; this library
        // does not catch it, because doing so would hide a real crash.
        if let Ok(guard) = sink.0.read() {
            if let Some(callback) = *guard {
                if let (Ok(target), Ok(message)) = (CString::new(target), CString::new(message)) {
                    callback(record.level() as i32, target.as_ptr(), message.as_ptr());
                }
            }
        }
    }

    fn flush(&self) {}
}

/// Runs `f`, turning a panic into `fallback` instead of letting it escape.
fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => {
            let reason = litespeak_core::panic_message(&*payload);
            log::error!("litespeak call panicked: {reason}");
            fallback
        }
    }
}

/// The opaque handle. `null` means "no session", and every other entry point
/// accepts `null` as a no-op rather than crashing.
pub type LiteSpeakSession = Session;

unsafe fn as_session<'a>(handle: *const LiteSpeakSession) -> Option<&'a Session> {
    // Safety: the pointer comes from `litespeak_create`, which never hands out
    // anything else, and the caller owns it until `litespeak_destroy`.
    if handle.is_null() {
        None
    } else {
        // Safety: `as_session` returned `Some`, so the pointer is non-null and came
        // from `litespeak_create*`; the caller owns it.
        Some(unsafe { &*handle })
    }
}

unsafe fn c_str<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    // Safety: the caller is required to pass a NUL-terminated string.
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

fn out_string(value: String) -> *mut c_char {
    // Interior NULs cannot be represented; strip them rather than truncating the
    // response, so a nickname with a stray byte does not silently lose data.
    let cleaned = value.replace('\0', "");
    CString::new(cleaned)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// ABI version of the loaded library. Compare against the version the shell was
/// built with and refuse to run on a mismatch.
#[no_mangle]
pub extern "C" fn litespeak_abi_version() -> u32 {
    ABI_VERSION
}

/// Library and protocol versions as JSON: `{"abi":2,"core":"0.1.0",…}`.
/// Meant for crash reports and support tickets, not for logic.
#[no_mangle]
pub extern "C" fn litespeak_info_json() -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        let info = serde_json::json!({
            "abi": ABI_VERSION,
            "core": env!("CARGO_PKG_VERSION"),
            "tsclientlib": litespeak_core::TS_CLIENTLIB_VERSION,
        });
        out_string(info.to_string())
    })
}

/// Parses the connection payload shared by [`litespeak_create`] and
/// [`litespeak_create_with_account`].
fn session_config(json: &str) -> Result<litespeak_core::SessionConfig, String> {
    let config: Config = serde_json::from_str(json).map_err(|e| format!("bad config: {e}"))?;
    if config.address.trim().is_empty() {
        return Err("empty address".to_string());
    }
    Ok(litespeak_core::SessionConfig {
        address: config.address,
        identity: config.identity,
        nickname: config.nickname,
        server_password: config.password.filter(|p| !p.is_empty()),
        channel: config.channel.filter(|c| !c.is_empty()),
        channel_password: config.channel_password.filter(|p| !p.is_empty()),
        version: match (config.version, config.platform) {
            (Some(version), Some(platform))
                if !version.trim().is_empty() && !platform.trim().is_empty() =>
            {
                litespeak_core::VersionChoice::new(version, platform)
            }
            _ => litespeak_core::VersionChoice::default(),
        },
        privilege_key: config.token.unwrap_or_default(),
        start_muted: config.start_muted.unwrap_or(false),
    })
}

/// Opens a session from a JSON config (see [`Config`]). Returns null if the
/// config is malformed; connection failures arrive as `error` events instead,
/// because connecting happens on the worker thread.
#[no_mangle]
pub extern "C" fn litespeak_create(config_json: *const c_char) -> *mut LiteSpeakSession {
    guard(std::ptr::null_mut(), || {
        // Safety: the header requires a NUL-terminated string here, and `c_str`
        // rejects null and only reads it for the duration of the call.
        let Some(json) = (unsafe { c_str(config_json) }) else {
            log::error!("litespeak_create called without a config");
            return std::ptr::null_mut();
        };
        let config = match session_config(json) {
            Ok(config) => config,
            Err(e) => {
                log::error!("litespeak_create: {e}");
                return std::ptr::null_mut();
            }
        };
        match Session::connect(config) {
            Ok(session) => Box::into_raw(Box::new(session)),
            Err(e) => {
                log::error!("litespeak_create failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// Opens an account-only session from a JSON config: no address, no socket.
///
/// The account side lives on the handle, so this is what lets a login screen
/// list bookmarks before a server is chosen. The config is the same object the
/// `account_config` command accepts (`legacyDb`, `backupDir`, `credentialFile`,
/// `rememberLogin`, `baselineFile`, all optional); null or empty means "no
/// paths, nothing remembered".
#[no_mangle]
pub extern "C" fn litespeak_create_account(config_json: *const c_char) -> *mut LiteSpeakSession {
    guard(std::ptr::null_mut(), || {
        // Safety: the header requires a NUL-terminated string here, and `c_str`
        // rejects null and only reads it for the duration of the call.
        let json = unsafe { c_str(config_json) }.unwrap_or("");
        let config = match litespeak_core::account::parse_config(json) {
            Ok(config) => config,
            Err(e) => {
                log::error!("litespeak_create_account: bad config: {e}");
                return std::ptr::null_mut();
            }
        };
        match litespeak_core::Session::account_only(config) {
            Ok(session) => Box::into_raw(Box::new(session)),
            Err(e) => {
                log::error!("litespeak_create_account failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// Opens a connection that carries the account's myTeamSpeak proof.
///
/// `account` may be null (then this is exactly [`litespeak_create`]) or a handle
/// from [`litespeak_create_account`]. It is only read during this call: the
/// returned connection keeps the proof it needs, so the account handle may be
/// destroyed afterwards. An account without a myTS identity also connects
/// normally — a missing badge is not a reason to refuse to join.
#[no_mangle]
pub extern "C" fn litespeak_create_with_account(
    account: *const LiteSpeakSession,
    config_json: *const c_char,
) -> *mut LiteSpeakSession {
    guard(std::ptr::null_mut(), || {
        // Safety: the header requires a NUL-terminated string here, and `c_str`
        // rejects null and only reads it for the duration of the call.
        let Some(json) = (unsafe { c_str(config_json) }) else {
            log::error!("litespeak_create_with_account called without a config");
            return std::ptr::null_mut();
        };
        let config = match session_config(json) {
            Ok(config) => config,
            Err(e) => {
                log::error!("litespeak_create_with_account: {e}");
                return std::ptr::null_mut();
            }
        };
        // The account is shared, not owned: dropping this connection must not
        // sign the user out of the next one.
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        let myts = unsafe { as_session(account) }.and_then(Session::myts_provider);
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        let attached = match unsafe { as_session(account) } {
            Some(session) => Session::connect_with_account(config, session),
            None => Session::connect_with_myts(config, myts),
        };
        match attached {
            Ok(session) => Box::into_raw(Box::new(session)),
            Err(e) => {
                log::error!("litespeak_create_with_account failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// Closes the session and frees the handle. Safe to call with null.
#[no_mangle]
pub extern "C" fn litespeak_destroy(handle: *mut LiteSpeakSession) {
    guard((), || {
        if handle.is_null() {
            return;
        }
        // Safety: `handle` came from `litespeak_create` and is not used after this.
        drop(unsafe { Box::from_raw(handle) });
    })
}

#[no_mangle]
pub extern "C" fn litespeak_is_connected(handle: *const LiteSpeakSession) -> bool {
    guard(false, || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        unsafe { as_session(handle) }.is_some_and(Session::is_connected)
    })
}

/// The whole state as JSON. Unchanged revisions return a cached string, so a
/// 50 Hz caller is cheap. `null` when `handle` is null.
#[no_mangle]
pub extern "C" fn litespeak_snapshot_json(handle: *const LiteSpeakSession) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        match unsafe { as_session(handle) } {
            Some(session) => out_string(session.snapshot_json()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Drains queued events as a JSON array (`[]` when there are none).
#[no_mangle]
pub extern "C" fn litespeak_poll_events_json(handle: *const LiteSpeakSession) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        match unsafe { as_session(handle) } {
            Some(session) => {
                let events = session.drain_events();
                match serde_json::to_string(&events) {
                    Ok(json) => out_string(json),
                    Err(e) => {
                        log::error!("could not serialize events: {e}");
                        out_string("[]".to_string())
                    }
                }
            }
            None => out_string("[]".to_string()),
        }
    })
}

/// Runs one named command. Returns "" on success, or the error text.
#[no_mangle]
pub extern "C" fn litespeak_exec(
    handle: *const LiteSpeakSession,
    name: *const c_char,
    args_json: *const c_char,
) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        // Safety: the header requires a NUL-terminated string here, and `c_str`
        // rejects null and only reads it for the duration of the call.
        let Some(name) = (unsafe { c_str(name) }) else {
            return out_string("missing command name".to_string());
        };
        // Safety: the header requires a NUL-terminated string here, and `c_str`
        // rejects null and only reads it for the duration of the call.
        let args = unsafe { c_str(args_json) }.unwrap_or("");
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        match unsafe { as_session(handle) } {
            Some(session) => out_string(session.exec(name, args)),
            None => out_string("not connected".to_string()),
        }
    })
}

/// The identity in TS3 `counterVkey` form, for the shell to persist. `null`
/// until the session has started. Pass it back as `"identity"` in the next
/// config, or the server sees a new UID every launch.
#[no_mangle]
pub extern "C" fn litespeak_identity(handle: *const LiteSpeakSession) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        match unsafe { as_session(handle) } {
            Some(session) => match session.identity_ts_str() {
                Some(identity) => out_string(identity),
                None => std::ptr::null_mut(),
            },
            None => std::ptr::null_mut(),
        }
    })
}

/// Asks the session to stop. Waits for the server to close the socket rather
/// than dropping it mid-write, so the client does not linger as "online".
#[no_mangle]
pub extern "C" fn litespeak_disconnect(handle: *mut LiteSpeakSession) {
    guard((), || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        if let Some(session) = unsafe { as_session(handle) } {
            session.disconnect();
        }
    })
}

// ── voice ───────────────────────────────────────────────────────────────────
// Raw samples, because JSON at 50 Hz is a waste. Frames are 960 samples
// (20 ms at 48 kHz mono); a caller that sends other sizes still works, it just
// gets buffered or split.

/// Queues `len` captured PCM16 samples for transmission. Returns how many were
/// taken (0 when the session is null or the buffer is null).
#[no_mangle]
pub extern "C" fn litespeak_audio_write(
    handle: *mut LiteSpeakSession,
    samples: *const i16,
    len: usize,
) -> usize {
    guard(0, || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        let Some(session) = (unsafe { as_session(handle) }) else {
            return 0;
        };
        if samples.is_null() || len == 0 {
            return 0;
        }
        // Safety: the caller passes `len` readable samples, as the header says.
        let slice = unsafe { std::slice::from_raw_parts(samples, len) };
        session.audio_write(slice)
    })
}

/// Fills `out` with at most `len` decoded PCM16 samples and returns the count.
/// Starved queues return 0 rather than blocking.
#[no_mangle]
pub extern "C" fn litespeak_audio_read(
    handle: *mut LiteSpeakSession,
    out: *mut i16,
    len: usize,
) -> usize {
    guard(0, || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        let Some(session) = (unsafe { as_session(handle) }) else {
            return 0;
        };
        if out.is_null() || len == 0 {
            return 0;
        }
        // Safety: the caller passes `len` writable samples, as the header says.
        let buffer = unsafe { std::slice::from_raw_parts_mut(out, len) };
        session.audio_read(buffer)
    })
}

/// Drops buffered audio so the next session does not start with the previous
/// one's tail.
#[no_mangle]
pub extern "C" fn litespeak_audio_reset(handle: *mut LiteSpeakSession) {
    guard((), || {
        // Safety: `handle` is 0 or a pointer from `litespeak_create*` that the caller
        // still owns; `as_session` rejects null before dereferencing.
        if let Some(session) = unsafe { as_session(handle) } {
            session.audio_reset();
        }
    })
}

// ── plumbing ────────────────────────────────────────────────────────────────

/// Releases a string returned by this library. Passing null is allowed.
#[no_mangle]
pub extern "C" fn litespeak_string_free(value: *mut c_char) {
    guard((), || {
        if value.is_null() {
            return;
        }
        // Safety: every `char *` handed out here came from `CString::into_raw`.
        drop(unsafe { CString::from_raw(value) });
    })
}

/// Installs (or swaps) the log sink. Call before `litespeak_create` to see the
/// connection log. Idempotent: the `log` logger is registered once per process.
#[no_mangle]
pub extern "C" fn litespeak_set_log_callback(callback: Option<LogCallback>) {
    let sink = LOG_CALLBACK.get_or_init(|| {
        // If another library already installed a logger, this fails; that is
        // fine — the host already has logging, and the callback stays unused.
        let _ = log::set_logger(&CallbackLogger);
        log::set_max_level(log::LevelFilter::Debug);
        LogSink(std::sync::RwLock::new(None))
    });
    if let Ok(mut slot) = sink.0.write() {
        *slot = callback;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_config_without_panicking() {
        let json = CString::new("{\"nickname\":\"x\"}").unwrap();
        let handle = litespeak_create(json.as_ptr());
        assert!(handle.is_null());
    }

    #[test]
    fn account_handle_opens_without_an_address() {
        let json = CString::new("{}").unwrap();
        let handle = litespeak_create_account(json.as_ptr());
        assert!(!handle.is_null());

        let raw = litespeak_snapshot_json(handle);
        assert!(!raw.is_null());
        // Safety: `raw` is the string this library just returned, so it is a
        // NUL-terminated allocation that has not been freed yet.
        let snapshot = String::from_utf8_lossy(unsafe { std::ffi::CStr::from_ptr(raw) }.to_bytes())
            .into_owned();
        litespeak_string_free(raw);
        // The account object is present even though no server exists.
        assert!(snapshot.contains("\"account\""), "{snapshot}");

        litespeak_destroy(handle);
    }

    #[test]
    fn account_creator_rejects_bad_json() {
        let json = CString::new("{not json").unwrap();
        assert!(litespeak_create_account(json.as_ptr()).is_null());
    }

    #[test]
    fn connect_with_account_still_validates_the_connection_config() {
        let json = CString::new("{\"nickname\":\"x\"}").unwrap();
        assert!(litespeak_create_with_account(std::ptr::null(), json.as_ptr()).is_null());
    }

    #[test]
    fn null_handle_is_a_noop_everywhere() {
        assert!(!litespeak_is_connected(std::ptr::null()));
        assert!(litespeak_snapshot_json(std::ptr::null()).is_null());
        assert!(litespeak_identity(std::ptr::null()).is_null());
        litespeak_disconnect(std::ptr::null_mut());
        litespeak_destroy(std::ptr::null_mut());
        assert_eq!(
            litespeak_audio_write(std::ptr::null_mut(), [0i16; 4].as_ptr(), 4),
            0
        );
    }

    #[test]
    fn abi_version_is_reported() {
        assert_eq!(litespeak_abi_version(), ABI_VERSION);
    }
}
