# LiteSpeak

A lightweight TeamSpeak 3 client: an Android shell and a platform-neutral core
in one checkout.

The core — protocol, connection, state, voice codec and file transfers — has no
UI and no platform dependency, so the same session logic builds as one
`.so`/`.dylib`/`.dll` per platform. `shells/android` is the first shell.

**Target: TeamSpeak 3.** TS6 is not a supported target. What has been checked:
connecting, the state and the myTeamSpeak ID proof were exercised against an
official `teamspeak6-server` 6.0.0-beta14, and both worked — the server
negotiates the same 64-byte handshake IV as TS3 and accepts the proof
(docs/myteamspeak.md records the client field and the corrupted-proof control
that proves it is verified). Nothing here is TS6-specific, no registry test runs
against a TS6 server, and TS6 may change after any release, so this is a
measurement rather than a promise.

One `.so` / `.dylib` / `.dll` per platform containing everything — the protocol
stack (`tsclientlib`), the Opus codec, and this project's own session logic.
Nothing else needs to be installed on the target machine.

```
Android ── liblitespeak_jni.so ──┐
macOS   ── liblitespeak.dylib ──┼── crates/core ── tsclientlib + Opus
Windows ── litespeak.dll      ──┤
Linux   ── liblitespeak.so    ──┘
```

## Layout

| Path | What it is |
|---|---|
| `shells/android` | The Android client: Compose UI in Kotlin over the JNI shim, plus the Gradle tasks that compile the core for arm64. |
| `crates/core` | Platform-neutral session: connection loop, snapshot, events, Opus, file transfers. Zero FFI, zero platform types. |
| `crates/c` | The C ABI. `cdylib` + `staticlib`, one opaque handle, JSON everywhere except audio. |
| `crates/jni` | The Android shim. `JNI_OnLoad`, `android_logger`, `ndk-context` for DNS, `HashMap[]` events. |
| `crates/cli` | Smoke binary that links the core directly, with no FFI in between. |
| `crates/account-demo` | Local web page for trying the account side by hand: log in, read bookmarks, back up. Links the core exactly as a shell does. |
| `vendor/tsclientlib` | Upstream `tsclientlib`/`tsproto`, vendored so the handshake IV can be made variable — see [its VENDORING.md](vendor/tsclientlib/VENDORING.md). Four marked hunks; the rest is upstream verbatim. |
| `include/litespeak.h` | The C contract, with the JSON shapes documented inline. |
| `swift/` | SwiftPM package that wraps the dylib for SwiftUI. |
| `docs/events.md` | Event names and fields — the cross-language contract. |
| `docs/identity.md` | The `counterVkey` identity string: format, obfuscation, DER, UID, golden value. |
| `docs/myteamspeak.md` | myTeamSpeak account side: key chain, sync items and what may be written. |
| `docs/testing.md` | How this is tested, and the traps that made passing tests verify nothing. |
| `tools/` | Build and smoke-test scripts, and `live-server-clean.py` for the live-test server. |

## Design in one paragraph

The core exposes exactly one command entry point (`exec(name, args_json)`) and
two pull-based reads (`snapshot_json`, `poll_events_json`). Adding a feature
costs a match arm in `command.rs`, not a new exported symbol — so the ABI does
not grow, and a shell built last year still works. Events are pulled on the
shell's own 20 ms clock instead of pushed from a callback, because a callback
means the core has to re-enter the host's language on its own thread, which is
where cross-language clients usually break.

Two things deliberately stay outside the core:

* **Audio device I/O.** Echo cancellation, noise suppression and device routing
  are per-platform APIs. The core only sees PCM16 in and PCM16 out (`write`,
  `read`, `reset`), so each shell brings its own quality.
* **Identity storage.** The core hands out the identity string; the shell
  decides whether it goes in Keychain, DPAPI, or a file. `litespeak_identity`
  returns "the key this session is using", so a fresh identity is persisted on
  the first connect and reused afterwards. The format is pinned in
  [docs/identity.md](docs/identity.md) — emit the obfuscated key, not the plain
  DER one, or the string will not survive a round trip through the official
  client.

The myTeamSpeak account side is **inside** the core: login, the key chain, and
the synchronisation items (bookmarks, identities, addons, config). It lives on
its own session — `Session::account_only` — not on a connection, so it works
before the first join, keeps working when a server connection comes and goes, and
can back several connections in turn. Its commands are the `account_*` /
`sync_*` entries in `include/litespeak.h`. Results arrive in `snapshot.account`
and in one `account_status` event per command. The contract —
the item cipher, and why a write is backed up and re-read — is
[docs/myteamspeak.md](docs/myteamspeak.md). Four things about it are worth
knowing before writing a shell:

* **It is a standalone client.** Sign in with an email and password; the item
  key is the account key that comes back in the login response. Nothing is read
  from an installed TeamSpeak client unless the caller explicitly asks for a
  one-time `fromTs3Client` login migration.
* **Nothing blocks.** A command is accepted, not executed: the call returns
  immediately and the answer arrives later through the snapshot and the event.
* **Every write is preceded by a backup file and followed by a byte comparison.**
  The reply's `300 IN_SYNC` is not treated as proof; the stored blob is.
* **A server accepts the myTeamSpeak ID.** The account's Ed25519 key comes out of
  the item envelope, and the six `clientinit` parameters are signed over the
  connection's own challenge. A local 3.13.9 server logs
  `client connected … using a myTeamSpeak ID`; one flipped byte in `authSign`
  makes it log `rejecting myteamspeakid: invalid signature` instead, so the proof
  is really verified. Sign in first, then connect with
  `Session::connect_with_myts` — the parameters have to ride on `clientinit`,
  which is why the protocol stack is vendored.
* **An expired session is replaced, not reported.** Every read path notices
  `102 SESSION_EXPIRED`, signs in again with the credential hash the last login
  already accepted, and repeats once. A refused credential comes back as an
  error rather than a loop. `tests/replay_contract.rs` drives this against a
  recorded `127.0.0.1` server, so the whole login → read → decrypt → write path
  is testable with no account and no network.

## Build

```sh
cargo build --release                 # host platform: liblitespeak.{so,dylib} / litespeak.dll
cargo test --workspace                # ABI tests, event contract test
cargo run -p litespeak-cli -- host 20  # connect with no FFI, print events + snapshots

cd shells/android
./gradlew :app:assembleDebug          # debug APK; compiles the JNI library with cargo-ndk
./gradlew :app:testDebugUnitTest      # JVM tests; no NDK, no device
```

`release` is the shipping profile (fat LTO). For a local optimised build use
`cargo build --profile local` — thin LTO, sixteen codegen units — and for the
Android debug APK litespeak uses `android-dev`, which is a debug build with
`opt-level = 1` and no LTO. `dev` and `test` keep line tables only and strip
debug info from dependencies, because full DWARF is what made `target/` tens of
gigabytes.

The account side has a local page for trying it by hand, which links the core
exactly the way a shell does:

```sh
cargo run -p litespeak-account-demo              # http://127.0.0.1:8787
cargo run -p litespeak-account-demo -- --port 9000 --legacy-db "C:\...\TS3Client\settings.db"
```

It is loopback-only, origin-checked, and read-only: login, refresh, backup and
logout. The password travels over `127.0.0.1` and is never logged. Creating or
deleting items is implemented in the library and covered by tests, but the page
deliberately does not expose it — leaving that button open on a real account is
how a test ends with somebody's bookmarks gone.

`audiopus` compiles Opus from C source, so a C toolchain is required (CMake or
`cc`). On Windows the CMake it finds must be on `PATH` — the Visual Studio
toolchain alone is not enough — and with CMake 4.x set
`CMAKE_POLICY_VERSION_MINIMUM=3.5`, because Opus's `CMakeLists.txt` still
declares a pre-3.5 minimum. Neither is a source change; it is Opus's own build
file being old.

Platform packaging:

```sh
./tools/build-android.ps1              # arm64 .so into out/android/
./tools/build-linux.sh                # x86_64 + aarch64, soname liblitespeak.so.1
./tools/build-macos.sh                # universal dylib -> Vendor/litespeak.xcframework
./tools/smoke.ps1 [-Release]          # C ABI smoke test (Windows, MSVC)
```

The smoke test compiles `tools/smoke.c` and runs it against `target\debug`
(or `target\release` with `-Release`). It checks the calls a shell makes before
it has a server — version, info, NULL-handle behaviour, malformed config — and
never connects, because a test that needs a server is not a smoke test.

Also note that a `cargo build` needs `cmake` on `PATH` for Windows release builds
of Opus; with CMake 4.x the `CMAKE_POLICY_VERSION_MINIMUM=3.5` above is required
too. Neither is a source change: it is Opus's own `CMakeLists.txt` being old.

The Linux `.so` exports only the C ABI (a version script in `crates/c/build.rs`
hides everything else) and carries `soname liblitespeak.so.1`, so a binary linked
against it keeps working across patch releases. Windows has no linker version
script, so its export table can be a superset of the header; nothing links to
those extra names.

Android is the exception to "one library": `cargo ndk` produces
`liblitespeak_jni.so`, the same core behind a JNI shim, because the app reaches it
through `System.loadLibrary`.

## CI

Six jobs, because the things that break here break in different places:

| job | what it proves |
|---|---|
| `lint` | `cargo fmt --check` and `cargo clippy --all-targets` clean under `-D warnings` |
| `test` | `cargo test --workspace --all-targets` on ubuntu, macOS **and** Windows; that is the only cross-platform compile check |
| `c-abi` | the shared library builds, the C smoke test links and runs against it, and the exported symbols equal `include/litespeak.h` (Linux; the Windows export table is a documented superset) |
| `android` | the arm64 JNI `.so` cross-compiles and its exported functions equal what `crates/jni` declares |
| `android-unit` | the JVM tests: the event table, the ABI number and the JNI symbol names against this checkout, plus the licence texts |
| `android-apk` | `assembleDebug` compiles the core with cargo-ndk and the packaged `.so` is byte-identical to what Gradle built |

`rust-toolchain.toml` pins the compiler (`1.97.1`), so a green CI run and a
working laptop mean the same toolchain judged the code. There is no job that
publishes an XCFramework: `tools/build-macos.sh` runs locally, and a CI artifact
would need a release process nothing consumes yet.

## Use from C

```c
#include "litespeak.h"

LiteSpeakSession *h = litespeak_create("{\"address\":\"ts.example.com\",\"nickname\":\"ann\"}");
for (;;) {
    char *events = litespeak_poll_events_json(h);   /* always owns a string */
    puts(events);
    litespeak_string_free(events);
}
```

Every returned `char *` belongs to the library and is released with
`litespeak_string_free`; `free()` would be a heap mismatch. The complete
signature list is in `include/litespeak.h`, which is the ABI — `LITESPEAK_ABI_VERSION`
is checked at startup by every well-behaved shell.

## Use from Swift

The Swift package is only meaningful after `tools/build-macos.sh` has produced
`swift/Vendor/litespeak.xcframework` (it is a build artifact, not checked in).

```swift
import LiteSpeak

let session = try Bridge(config: BridgeConfig(address: "ts.example.com", nickname: "ann"))
for event in session.pollEvents() { print(event) }
```

`Bridge` owns the handle and frees it in `deinit`; it is the only place a
returned C string is touched, so a 50 Hz poll loop cannot leak. The raw C API is
also importable (`import litespeak`) if a caller would rather do it by hand.

## Android

`shells/android` compiles the core itself: `app:buildCoreJniDebug` runs
`cargo ndk -t arm64-v8a -o ... build --profile android-dev -p litespeak-jni`,
and `buildCoreJniRelease` uses the shipping `release` profile. No `.so` is
checked in anywhere, so the library and the sources in this commit cannot drift.

```sh
cd shells/android
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # JVM tests, no NDK needed
```

`tools/build-android.ps1` still exists for building the JNI library outside
Gradle; its output lands in `out/android/` and nothing consumes it.

The JNI symbol names are the ones Kotlin already declares
(`Java_dev_litespeak_core_Native_*`), so an ordinary core change needs no Kotlin
edits. The exception is an ABI bump: Kotlin hard-codes `Native.EXPECTED_ABI` and
compares it with `nativeAbiVersion()` at startup, which is what turns a stale
`.so` into a message instead of confusing half-working behaviour. litespeak's
`NativeAbiTest` reads `LITESPEAK_ABI_VERSION` out of this repository's header and
fails the build if the two numbers disagree, so the bump cannot be forgotten in
only one place.

The one piece of Android state the core does not own is the identity file:
Kotlin reads `identity.ini`, passes it as `identity` and writes back whatever
`litespeak_identity` reports. That is deliberate — the core never touches the
filesystem for user data.

## License

MIT OR Apache-2.0. Third-party components and their attribution are in
[NOTICE](NOTICE). `tsclientlib` is Apache-2.0 OR MIT and is statically linked
into every artifact, so the notice has to ship with the binary too.
