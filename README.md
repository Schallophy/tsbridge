# tsbridge

The TeamSpeak 3/6 client core as a standalone library: protocol, connection,
state, voice codec and file transfers, with no UI and no platform dependency.

One `.so` / `.dylib` / `.dll` per platform containing everything — the protocol
stack (`tsclientlib`), the Opus codec, and this project's own session logic.
Nothing else needs to be installed on the target machine.

```
Android ── libtsbridge_jni.so ──┐
macOS   ── libtsbridge.dylib ──┼── crates/core ── tsclientlib + Opus
Windows ── tsbridge.dll      ──┤
Linux   ── libtsbridge.so    ──┘
```

## Layout

| Path | What it is |
|---|---|
| `crates/core` | Platform-neutral session: connection loop, snapshot, events, Opus, file transfers. Zero FFI, zero platform types. |
| `crates/c` | The C ABI. `cdylib` + `staticlib`, one opaque handle, JSON everywhere except audio. |
| `crates/jni` | The Android shim. `JNI_OnLoad`, `android_logger`, `ndk-context` for DNS, `HashMap[]` events. |
| `crates/cli` | Smoke binary that links the core directly, with no FFI in between. |
| `include/tsbridge.h` | The C contract, with the JSON shapes documented inline. |
| `swift/` | SwiftPM package that wraps the dylib for SwiftUI. |
| `docs/events.md` | Event names and fields — the cross-language contract. |
| `tools/` | Build and smoke-test scripts. |

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
  decides whether it goes in Keychain, DPAPI, or a file. `tsbridge_identity`
  returns "the key this session is using", so a fresh identity is persisted on
  the first connect and reused afterwards.

## Build

```sh
cargo build --release                 # host platform: libtsbridge.{so,dylib} / tsbridge.dll
cargo test --workspace                # ABI tests, event contract test
cargo run -p tsbridge-cli -- host 20  # connect with no FFI, print events + snapshots
```

`audiopus` compiles Opus from C source, so a C toolchain is required (CMake or
`cc`). On Windows the CMake it finds must be on `PATH` — the Visual Studio
toolchain alone is not enough — and with CMake 4.x set
`CMAKE_POLICY_VERSION_MINIMUM=3.5`, because Opus's `CMakeLists.txt` still
declares a pre-3.5 minimum. Neither is a source change; it is Opus's own build
file being old.

Platform packaging:

```sh
./tools/build-android.ps1              # arm64 .so into out/android/
./tools/build-linux.sh                # x86_64 + aarch64, soname libtsbridge.so.1
./tools/build-macos.sh                # universal dylib -> Vendor/tsbridge.xcframework
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
hides everything else) and carries `soname libtsbridge.so.1`, so a binary linked
against it keeps working across patch releases. On Windows the export table is a
superset: `aws-lc` marks nine `jent_*` helpers `dllexport` and a `.def` cannot
override that. Nothing links to those by name.

Android is the exception to "one library": `cargo ndk` produces
`libtsbridge_jni.so`, the same core behind a JNI shim, because the app reaches it
through `System.loadLibrary`.

## Use from C

```c
#include "tsbridge.h"

TsBridge *h = tsbridge_create("{\"address\":\"ts.example.com\",\"nickname\":\"ann\"}");
for (;;) {
    char *events = tsbridge_poll_events_json(h);   /* always owns a string */
    puts(events);
    tsbridge_string_free(events);
}
```

Every returned `char *` belongs to the library and is released with
`tsbridge_string_free`; `free()` would be a heap mismatch. The complete
signature list is in `include/tsbridge.h`, which is the ABI — `TSBRIDGE_ABI_VERSION`
is checked at startup by every well-behaved shell.

## Use from Swift

The Swift package is only meaningful after `tools/build-macos.sh` has produced
`swift/Vendor/tsbridge.xcframework` (it is a build artifact, not checked in).

```swift
import TSBridge

let session = try Bridge(config: BridgeConfig(address: "ts.example.com", nickname: "ann"))
for event in session.pollEvents() { print(event) }
```

`Bridge` owns the handle and frees it in `deinit`; it is the only place a
returned C string is touched, so a 50 Hz poll loop cannot leak. The raw C API is
also importable (`import tsbridge`) if a caller would rather do it by hand.

## Android

tsdroid consumes this repository as a git submodule and compiles it itself: its
`app:buildTsbridgeJni` task runs `cargo ndk -t arm64-v8a -o ... build --release
-p tsbridge-jni`, so no `.so` is checked in anywhere. That keeps the library and
the sources in lockstep — bumping the core is a one-line gitlink change with its
own commit, rather than a hand-copied binary nobody can trace back.

Updating the app therefore does *not* involve this checkout's `tools/` scripts:

```sh
cd third_party/tsbridge && git checkout <commit> && cd ../..
git add third_party/tsbridge && git commit -m "tsbridge: bump core"
```

`tools/build-android.ps1` still exists for working on the core outside Gradle;
its output lands in `out/android/` and nothing consumes it.

The JNI symbol names are the ones Kotlin already declares
(`Java_dev_tsdroid_core_Native_*`), so the Android side needs no Kotlin changes
when the core is updated.

The one piece of Android state the core does not own is the identity file:
Kotlin reads `identity.ini`, passes it as `identity` and writes back whatever
`tsbridge_identity` reports. That is deliberate — the core never touches the
filesystem for user data.

## License

MIT OR Apache-2.0. Third-party components and their attribution are in
[NOTICE](NOTICE). `tsclientlib` is Apache-2.0 OR MIT and is statically linked
into every artifact, so the notice has to ship with the binary too.
