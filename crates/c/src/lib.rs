//! C ABI over `tsbridge-core`.
//!
//! The contract, and the reason it looks like this:
//!
//! * **One opaque handle.** `TsBridge *` is a boxed [`Session`]; the caller never
//!   sees a Rust type.
//! * **JSON for everything except voice.** State, events and commands all travel
//!   as strings, so adding a field never changes the ABI. Voice stays a raw
//!   sample buffer because a 50 Hz stream through a serializer is pure waste on
//!   both sides.
//! * **Every returned `char *` is owned by this library** and must be released
//!   with [`tsbridge_string_free`]. That is the one rule a caller can get wrong
//!   in a way that leaks steadily; it is stated in the header too.
//! * **Every entry point catches panics.** Unwinding out of `extern "C"` is
//!   undefined behaviour, so a panicking `unwrap` deep inside the protocol stack
//!   would abort the host process instead of failing this call.
//!
//! ABI version is reported by [`tsbridge_abi_version`] and must be bumped on any
//! signature change; additive JSON fields do not require a bump.

// Every exported function takes raw pointers, by definition: that is what a C
// ABI is. Marking them `unsafe fn` would change nothing for the caller (a C
// caller cannot tell) while making Rust callers write `unsafe` around the whole
// call. The actual safety rule — a non-null handle must come from
// `tsbridge_create` — is documented per function and in the header.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

use serde::Deserialize;
use tsbridge_core::Session;

/// Bump on any change to a signature or to the meaning of a parameter.
///
/// Defined in `tsbridge-core` and re-exported here, so the JNI shim reports the
/// same number without a second copy that could drift.
pub use tsbridge_core::ABI_VERSION;

/// The `create` payload. Field names match every shell's own config struct, and
/// `camelCase` matches the snapshot/event JSON, so one decoder style works
/// everywhere.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    address: String,
    #[serde(default)]
    identity: String,
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
/// once per process; `tsbridge_set_log_callback` only swaps the target, so a
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
            let reason = tsbridge_core::panic_message(&*payload);
            log::error!("tsbridge call panicked: {reason}");
            fallback
        }
    }
}

/// The opaque handle. `null` means "no session", and every other entry point
/// accepts `null` as a no-op rather than crashing.
pub type TsBridge = Session;

unsafe fn as_session<'a>(handle: *const TsBridge) -> Option<&'a Session> {
    // Safety: the pointer comes from `tsbridge_create`, which never hands out
    // anything else, and the caller owns it until `tsbridge_destroy`.
    if handle.is_null() {
        None
    } else {
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
pub extern "C" fn tsbridge_abi_version() -> u32 {
    ABI_VERSION
}

/// Library and protocol versions as JSON: `{"abi":2,"core":"0.1.0",…}`.
/// Meant for crash reports and support tickets, not for logic.
#[no_mangle]
pub extern "C" fn tsbridge_info_json() -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        let info = serde_json::json!({
            "abi": ABI_VERSION,
            "core": env!("CARGO_PKG_VERSION"),
            "tsclientlib": tsbridge_core::TS_CLIENTLIB_VERSION,
        });
        out_string(info.to_string())
    })
}

/// Opens a session from a JSON config (see [`Config`]). Returns null if the
/// config is malformed; connection failures arrive as `error` events instead,
/// because connecting happens on the worker thread.
#[no_mangle]
pub extern "C" fn tsbridge_create(config_json: *const c_char) -> *mut TsBridge {
    guard(std::ptr::null_mut(), || {
        let Some(json) = (unsafe { c_str(config_json) }) else {
            log::error!("tsbridge_create called without a config");
            return std::ptr::null_mut();
        };
        let config: Config = match serde_json::from_str(json) {
            Ok(config) => config,
            Err(e) => {
                log::error!("tsbridge_create: bad config: {e}");
                return std::ptr::null_mut();
            }
        };
        if config.address.trim().is_empty() {
            log::error!("tsbridge_create: empty address");
            return std::ptr::null_mut();
        }
        let session = tsbridge_core::SessionConfig {
            address: config.address,
            identity: config.identity,
            nickname: config.nickname,
            server_password: config.password.filter(|p| !p.is_empty()),
            channel: config.channel.filter(|c| !c.is_empty()),
            channel_password: config.channel_password.filter(|p| !p.is_empty()),
        };
        match Session::connect(session) {
            Ok(session) => Box::into_raw(Box::new(session)),
            Err(e) => {
                log::error!("tsbridge_create failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// Closes the session and frees the handle. Safe to call with null.
#[no_mangle]
pub extern "C" fn tsbridge_destroy(handle: *mut TsBridge) {
    guard((), || {
        if handle.is_null() {
            return;
        }
        // Safety: `handle` came from `tsbridge_create` and is not used after this.
        drop(unsafe { Box::from_raw(handle) });
    })
}

#[no_mangle]
pub extern "C" fn tsbridge_is_connected(handle: *const TsBridge) -> bool {
    guard(false, || {
        unsafe { as_session(handle) }.is_some_and(Session::is_connected)
    })
}

/// The whole state as JSON. Unchanged revisions return a cached string, so a
/// 50 Hz caller is cheap. `null` when `handle` is null.
#[no_mangle]
pub extern "C" fn tsbridge_snapshot_json(handle: *const TsBridge) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        match unsafe { as_session(handle) } {
            Some(session) => out_string(session.snapshot_json()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Drains queued events as a JSON array (`[]` when there are none).
#[no_mangle]
pub extern "C" fn tsbridge_poll_events_json(handle: *const TsBridge) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
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
pub extern "C" fn tsbridge_exec(
    handle: *const TsBridge,
    name: *const c_char,
    args_json: *const c_char,
) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        let Some(name) = (unsafe { c_str(name) }) else {
            return out_string("missing command name".to_string());
        };
        let args = unsafe { c_str(args_json) }.unwrap_or("");
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
pub extern "C" fn tsbridge_identity(handle: *const TsBridge) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
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
pub extern "C" fn tsbridge_disconnect(handle: *mut TsBridge) {
    guard((), || {
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
pub extern "C" fn tsbridge_audio_write(
    handle: *mut TsBridge,
    samples: *const i16,
    len: usize,
) -> usize {
    guard(0, || {
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
pub extern "C" fn tsbridge_audio_read(handle: *mut TsBridge, out: *mut i16, len: usize) -> usize {
    guard(0, || {
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
pub extern "C" fn tsbridge_audio_reset(handle: *mut TsBridge) {
    guard((), || {
        if let Some(session) = unsafe { as_session(handle) } {
            session.audio_reset();
        }
    })
}

// ── plumbing ────────────────────────────────────────────────────────────────

/// Releases a string returned by this library. Passing null is allowed.
#[no_mangle]
pub extern "C" fn tsbridge_string_free(value: *mut c_char) {
    guard((), || {
        if value.is_null() {
            return;
        }
        // Safety: every `char *` handed out here came from `CString::into_raw`.
        drop(unsafe { CString::from_raw(value) });
    })
}

/// Installs (or swaps) the log sink. Call before `tsbridge_create` to see the
/// connection log. Idempotent: the `log` logger is registered once per process.
#[no_mangle]
pub extern "C" fn tsbridge_set_log_callback(callback: Option<LogCallback>) {
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
        let handle = tsbridge_create(json.as_ptr());
        assert!(handle.is_null());
    }

    #[test]
    fn null_handle_is_a_noop_everywhere() {
        assert!(!tsbridge_is_connected(std::ptr::null()));
        assert!(tsbridge_snapshot_json(std::ptr::null()).is_null());
        assert!(tsbridge_identity(std::ptr::null()).is_null());
        tsbridge_disconnect(std::ptr::null_mut());
        tsbridge_destroy(std::ptr::null_mut());
        assert_eq!(
            tsbridge_audio_write(std::ptr::null_mut(), [0i16; 4].as_ptr(), 4),
            0
        );
    }

    #[test]
    fn abi_version_is_reported() {
        assert_eq!(tsbridge_abi_version(), ABI_VERSION);
    }
}
