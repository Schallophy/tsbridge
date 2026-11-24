//! JNI shim over `tsbridge-core`.
//!
//! This crate exists only to turn the platform-neutral core into the symbols
//! Android's `dev.tsdroid.core.Native` expects. Anything Android-specific
//! lives here and nowhere else:
//!
//! * `JNI_OnLoad` — installs `android_logger`, the panic hook, and the
//!   `ndk-context` handle that `hickory-resolver` needs for DNS.
//! * The `HashMap[]` conversion of events — Java reads plain JDK types, so this
//!   crate never has to ship a class.
//!
//! The core itself has no idea Java exists, which is what lets the same session
//! logic compile into a `.dylib` for macOS and a `.dll` for Windows.
//!
//! Every exported function is wrapped in [`guard`]: unwinding into Java is
//! undefined behaviour, and before this wrapper existed one panicking `unwrap`
//! deep in the protocol stack killed the process with a SIGABRT naming no cause.

use jni::objects::{JClass, JObject, JShortArray, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jobjectArray, jstring};
use jni::JNIEnv;
use jni::JavaVM;

use tsbridge_core::{Session, Value};

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _class: JClass) -> jint {
    init_logging();

    // The hook fires before unwinding starts, which is the only place the source
    // location is still available: the payload alone rarely says which call
    // panicked, and `panic = "abort"` used to lose it entirely.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        log::error!(
            "RUST PANIC at {location}: {}",
            tsbridge_core::panic_message(info.payload())
        );
    }));

    init_android_context(&vm);

    jni::sys::JNI_VERSION_1_6
}

#[cfg(target_os = "android")]
fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("tslib"),
    );
}

#[cfg(not(target_os = "android"))]
fn init_logging() {
    // Building this crate for a non-Android target is only done to type-check it.
    // Without a logger installed, `log::info!` calls are dropped, which is fine.
}

/// Hands the JVM and the application object to `ndk-context`.
///
/// `hickory-resolver` asks the system `ConnectivityManager` for nameservers, and
/// reaches it through `ndk_context`. Skipping this makes every name lookup panic
/// with "android context was not initialized", one line after a successful
/// connect — which reads as "it connects, then dies".
#[cfg(target_os = "android")]
fn init_android_context(vm: &JavaVM) {
    let result = (|| -> jni::errors::Result<()> {
        let mut env = vm.get_env()?;
        let thread_class = env.find_class("android/app/ActivityThread")?;
        let application = env.call_static_method(
            thread_class,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )?;
        let application = application.l()?;
        if application.is_null() {
            log::error!("ActivityThread.currentApplication() returned null; DNS will not resolve");
            return Ok(());
        }
        // Before any HTTPS: reqwest's default verifier on Android is the system
        // TrustManager, reached through this crate, and it panics on first use
        // unless the JVM context was handed over. The account login is the first
        // HTTPS call this library makes, so missing this killed the login task
        // before it could clear `busy` — the UI stayed on "signing in".
        init_tls_verifier(&mut env, &application);
        let global = env.new_global_ref(application)?;
        let raw = global.as_obj().as_raw();
        unsafe {
            ndk_context::initialize_android_context(
                vm.get_java_vm_pointer() as *mut std::ffi::c_void,
                raw as *mut std::ffi::c_void,
            );
        }
        // Leaked on purpose: `ndk_context` keeps the raw pointer, and dropping
        // the `GlobalRef` here would leave it dangling.
        std::mem::forget(global);
        log::info!("Android context handed to ndk-context; DNS can use the system resolver");
        Ok(())
    })();

    if let Err(e) = result {
        log::error!("Failed to initialize the Android context: {e}");
    }
}

#[cfg(not(target_os = "android"))]
fn init_android_context(_vm: &JavaVM) {}

/// Gives `rustls-platform-verifier` the JVM and application context it needs.
///
/// Two `jni` versions meet here: this shim is on 0.21 (its exported signatures
/// are the app's ABI) and the verifier on 0.22. Both wrappers describe the same
/// `JNIEnv` pointer, so the bridge is the raw pointer plus the verifier's own
/// `EnvUnowned` wrapper; nothing is re-created or attached twice.
#[cfg(target_os = "android")]
fn init_tls_verifier(env: &mut JNIEnv, application: &JObject) {
    use std::cell::Cell;

    let raw_env = env.get_native_interface();
    let raw_context = application.as_raw();
    let initialized = Cell::new(false);
    // Safety: both pointers come from the live JNI call one frame up, and the
    // closure runs and returns before this frame is popped. `EnvUnowned` does
    // not own or detach the thread.
    unsafe {
        let mut unowned = jni022::EnvUnowned::from_raw(raw_env.cast());
        unowned
            .with_env(|env| {
                let context = jni022::objects::JObject::from_raw(env, raw_context.cast());
                let result = rustls_platform_verifier::android::init_with_env(env, context);
                if result.is_ok() {
                    initialized.set(true);
                }
                result
            })
            // Logs and returns () on error or panic, so one broken TLS
            // initialisation cannot take the whole app down at load time.
            .resolve::<jni022::errors::LogErrorAndDefault>();
    }
    if initialized.get() {
        log::info!("rustls-platform-verifier initialized with the Android TrustManager");
    }
}

/// Runs `f`, turning a panic into `fallback` instead of letting it escape.
fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => {
            log::error!(
                "JNI call panicked: {}",
                tsbridge_core::panic_message(&*payload)
            );
            fallback
        }
    }
}

/// Borrows the handle behind a `jlong`.
///
/// Safety: `ptr` must be either 0 or a value returned by [`nativeCreate`] that
/// has not been passed to [`nativeDestroy`].
unsafe fn session<'a>(ptr: jlong) -> Option<&'a Session> {
    if ptr == 0 {
        None
    } else {
        Some(unsafe { &*(ptr as *const Session) })
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    // The one export that cannot fail: it reads a constant, and a shell calls it
    // before it trusts anything else. No `guard` needed, and no logging.
    tsbridge_core::ABI_VERSION as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    address: JString,
    identity_ini: JString,
    nickname: JString,
    server_password: JString,
    channel: JString,
    channel_password: JString,
    version: JString,
    token: JString,
) -> jlong {
    guard(0, || {
        let Some(address) = read_string(&mut env, &address) else {
            log::error!("nativeCreate called without an address");
            return 0;
        };
        let config = tsbridge_core::SessionConfig {
            address,
            identity: read_string(&mut env, &identity_ini).unwrap_or_default(),
            nickname: read_string(&mut env, &nickname).unwrap_or_default(),
            server_password: read_string(&mut env, &server_password),
            channel: read_string(&mut env, &channel),
            channel_password: read_string(&mut env, &channel_password),
            version: tsbridge_core::VersionProfile::parse(
                &read_string(&mut env, &version).unwrap_or_default(),
            ),
            privilege_key: read_string(&mut env, &token).unwrap_or_default(),
        };
        match Session::connect(config) {
            Ok(session) => Box::into_raw(Box::new(session)) as jlong,
            Err(e) => {
                log::error!("nativeCreate failed: {e}");
                0
            }
        }
    })
}

/// Creates an account-only session: no address, no socket.
///
/// The account side lives on the handle, not on the connection, so a login
/// screen has to be able to exist before anything is joined. The three paths
/// are where the library may write: the remembered login, the sync baseline and
/// pre-write backups. Empty means "store nothing there", which is what a shell
/// that has not decided yet should pass.
///
/// `remember_login` is always on: Android's private app directory is the only
/// place this file can go, and a login the next launch cannot reuse is the
/// behaviour users report as "it logged me out".
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeCreateAccount(
    mut env: JNIEnv,
    _class: JClass,
    credential_file: JString,
    baseline_file: JString,
    backup_dir: JString,
) -> jlong {
    guard(0, || {
        let path = |env: &mut JNIEnv, value: &JString| -> Option<std::path::PathBuf> {
            read_string(env, value)
                .filter(|text| !text.trim().is_empty())
                .map(std::path::PathBuf::from)
        };
        let config = tsbridge_core::account::AccountConfig {
            // Never probed: importing another client's settings.db is only ever
            // an explicit user action, and Android has no such file to read.
            legacy_db: None,
            backup_dir: path(&mut env, &backup_dir),
            credential_file: path(&mut env, &credential_file),
            remember_login: true,
            baseline_file: path(&mut env, &baseline_file),
        };
        match Session::account_only(config) {
            Ok(session) => Box::into_raw(Box::new(session)) as jlong,
            Err(e) => {
                log::error!("nativeCreateAccount failed: {e}");
                0
            }
        }
    })
}

/// Connects, carrying the signed-in account's myTeamSpeak proof.
///
/// The proof is signed per connection over the server's handshake IV, so it has
/// to come from the live account session rather than from a cached string. A
/// zero `account_ptr`, or one whose account has no myTS identity, connects
/// exactly like `nativeCreate` — "no badge" is not a reason to refuse to join.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeCreateWithAccount(
    mut env: JNIEnv,
    _class: JClass,
    account_ptr: jlong,
    address: JString,
    identity_ini: JString,
    nickname: JString,
    server_password: JString,
    channel: JString,
    channel_password: JString,
    version: JString,
    token: JString,
) -> jlong {
    guard(0, || {
        let Some(address) = read_string(&mut env, &address) else {
            log::error!("nativeCreateWithAccount called without an address");
            return 0;
        };
        let config = tsbridge_core::SessionConfig {
            address,
            identity: read_string(&mut env, &identity_ini).unwrap_or_default(),
            nickname: read_string(&mut env, &nickname).unwrap_or_default(),
            server_password: read_string(&mut env, &server_password),
            channel: read_string(&mut env, &channel),
            channel_password: read_string(&mut env, &channel_password),
            version: tsbridge_core::VersionProfile::parse(
                &read_string(&mut env, &version).unwrap_or_default(),
            ),
            privilege_key: read_string(&mut env, &token).unwrap_or_default(),
        };
        let myts = unsafe { session(account_ptr) }.and_then(Session::myts_provider);
        match Session::connect_with_myts(config, myts) {
            Ok(session) => Box::into_raw(Box::new(session)) as jlong,
            Err(e) => {
                log::error!("nativeCreateWithAccount failed: {e}");
                0
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    guard((), || {
        if ptr == 0 {
            return;
        }
        // Dropping the handle closes the command channel, which ends the
        // connection thread, which drops the socket.
        drop(unsafe { Box::from_raw(ptr as *mut Session) });
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeIsConnected(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jboolean {
    guard(false as jboolean, || {
        unsafe { session(ptr) }.is_some_and(Session::is_connected) as jboolean
    })
}

/// Drains queued events. The caller polls this on its 20 ms tick.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativePoll(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jobjectArray {
    guard(std::ptr::null_mut(), || {
        let Some(session) = (unsafe { session(ptr) }) else {
            return std::ptr::null_mut();
        };
        match to_java_array(&mut env, session.drain_events()) {
            Ok(array) => array,
            Err(e) => {
                log::error!("nativePoll failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeSnapshot(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let Some(session) = (unsafe { session(ptr) }) else {
            return std::ptr::null_mut();
        };
        match env.new_string(session.snapshot_json()) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                log::error!("nativeSnapshot failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// `nativeExec(command, argsJson)` — returns "" on success, or the error text.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeExec(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    name: JString,
    args: JString,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let message = match read_string(&mut env, &name) {
            Some(name) => {
                let args = read_string(&mut env, &args).unwrap_or_default();
                match unsafe { session(ptr) } {
                    Some(session) => session.exec(&name, &args),
                    None => "not connected".to_string(),
                }
            }
            None => "missing command name".to_string(),
        };

        match env.new_string(message) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                log::error!("nativeExec could not return its result: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    guard((), || {
        if let Some(session) = unsafe { session(ptr) } {
            session.disconnect();
        }
    })
}

/// The identity in TS3 `counterVkey` form, or null before the session started.
/// The Kotlin side stores this so the UID survives an app restart.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeIdentity(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let Some(identity) = (unsafe { session(ptr) }).and_then(Session::identity_ts_str) else {
            return std::ptr::null_mut();
        };
        match env.new_string(identity) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                log::error!("nativeIdentity failed: {e}");
                std::ptr::null_mut()
            }
        }
    })
}

/// Queues captured PCM16 for transmission. Returns how many samples were taken.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeAudioWrite(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    samples: JShortArray,
) -> jint {
    guard(0, || {
        let Some(session) = (unsafe { session(ptr) }) else {
            return 0;
        };
        let length = env.get_array_length(&samples).unwrap_or(0) as usize;
        if length == 0 {
            return 0;
        }
        let mut buffer = vec![0i16; length];
        if env
            .get_short_array_region(&samples, 0, &mut buffer)
            .is_err()
        {
            return 0;
        }
        let written = session.audio_write(&buffer);
        written as jint
    })
}

/// Fills the given array with decoded PCM16. Returns the sample count; the
/// caller plays `out[0 until count]`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeAudioRead(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    out: JShortArray,
) -> jint {
    guard(0, || {
        let Some(session) = (unsafe { session(ptr) }) else {
            return 0;
        };
        let length = env.get_array_length(&out).unwrap_or(0) as usize;
        if length == 0 {
            return 0;
        }
        let mut buffer = vec![0i16; length];
        let written = session.audio_read(&mut buffer);
        if written == 0 {
            return 0;
        }
        if env
            .set_short_array_region(&out, 0, &buffer[..written])
            .is_err()
        {
            return 0;
        }
        written as jint
    })
}

/// Drops buffered audio so the next session does not start with a second of the
/// previous one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_tsdroid_core_Native_nativeAudioReset(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    guard((), || {
        if let Some(session) = unsafe { session(ptr) } {
            session.audio_reset();
        }
    })
}

/// Builds the `HashMap[]` the Kotlin side reads.
///
/// Deliberately plain JDK types (`HashMap`, `String`, `Integer`, `Long`,
/// `Boolean`): the library never has to ship or know a UI class, so a renamed
/// data class cannot desynchronize the two sides at runtime.
fn to_java_array(
    env: &mut JNIEnv,
    events: Vec<tsbridge_core::QueuedEvent>,
) -> jni::errors::Result<jobjectArray> {
    let map_class = env.find_class("java/util/HashMap")?;
    let array = env.new_object_array(events.len() as i32, &map_class, JObject::null())?;

    for (index, event) in events.into_iter().enumerate() {
        let map = env.new_object(&map_class, "()V", &[])?;
        put(env, &map, "type", Value::Str(event.kind))?;
        for (key, value) in event.data {
            put(env, &map, &key, value)?;
        }
        env.set_object_array_element(&array, index as i32, &map)?;
    }

    Ok(array.into_raw())
}

fn put(env: &mut JNIEnv, map: &JObject, key: &str, value: Value) -> jni::errors::Result<()> {
    let key = env.new_string(key)?;
    // `JObject` from every arm: `JString` converts, `new_object` already returns
    // one. Matching on the value first keeps the shapes explicit rather than
    // relying on a blanket `Into` that also converts `JObject` to itself.
    let value: JObject = match value {
        Value::Str(text) => env.new_string(text)?.into(),
        Value::Int(number) => {
            env.new_object("java/lang/Integer", "(I)V", &[JValue::Int(number)])?
        }
        Value::Long(number) => env.new_object("java/lang/Long", "(J)V", &[JValue::Long(number)])?,
        Value::Bool(flag) => {
            env.new_object("java/lang/Boolean", "(Z)V", &[JValue::Bool(flag as u8)])?
        }
    };
    env.call_method(
        map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[(&key).into(), (&value).into()],
    )?;
    Ok(())
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    if value.is_null() {
        return None;
    }
    match env.get_string(value) {
        Ok(s) => Some(s.into()),
        Err(e) => {
            log::error!("Failed to read a Java string: {e}");
            None
        }
    }
}
