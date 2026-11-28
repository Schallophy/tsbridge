# LiteSpeak — Android shell

A TeamSpeak 3 client for Android: a Compose UI in Kotlin over the shared core in
this repository.

The protocol, connection, state, voice codec and file transfers live in
`crates/core` at the repository root and build as one self-contained library per
platform. This module is the Android consumer: `liblitespeak_jni.so` plus the
Compose UI on top. The same core also builds for macOS, Windows and Linux, so
another shell does not have to re-derive anything.

## What it does

| | |
|---|---|
| **Connection** | connect by address, optional channel + password, saved server list |
| **Channels** | full tree with nesting, lock icon, member counts, join (with password) |
| **Members** | live list per channel, mute state (button and switched-off device), away state, speaking indicator |
| **Chat** | channel / server / private messages, unread badges, own messages right-aligned |
| **Pokes** | send and receive, shown inline as an amber system line |
| **Status** | away + away message, mic mute, speaker mute — all server-visible |
| **Voice** | Opus 24 kbps mono both ways, 20 ms frames, jitter buffer + PLC |
| **Files** | browse a channel, download, upload, live transfer progress |
| **Audio** | noise suppression, echo cancellation, mic gain, speaker boost, optional Bluetooth mic |
| **Volume** | per-user playback volume, 0–200%, keyed by UID so it survives a reconnect |
| **Whisper** | member, channel and group targets from the header picker (groups use the all-channels form) |
| **Settings** | channel editor (codec, quality, limits, flags) on long-press; server editor from the header gear |
| **Permissions** | channel, server-group, channel-group, client and channel-client permission editors |
| **Identity** | the session's key is written to `identity.ini`, so the UID survives a restart |
| **Account** | myTeamSpeak login (password + optional OTP), remembered login, cloud bookmarks that fill the connect form (passwords read on demand), backup, logout; the myTS ID is announced on connect |

The channel codec list is Opus Voice and Opus Music only. TeamSpeak Server
3.11.0 migrated channels using the deprecated Speex/CELT codecs to Opus and
removed them from channel creation/editing; 3.13.9 rejects them. Carrying those
codecs would be a setting the official server no longer accepts.

The account side runs on its own native handle, so signing in, reading bookmarks
and backing them up work before any server is joined. The same handle is handed
to the connection, where the core signs the per-connection myTeamSpeak proof
(`clientinit`). The remembered login and sync baseline live in the app's private
`files/account/` directory; logging out deletes the credential, and that whole
directory is excluded from Android auto-backup and device transfer.

Bookmark passwords are presence-only in the normal polled snapshot. After a
login or refresh the account client reads the list once with `revealSecrets`,
keeps the values in its own memory cache, and immediately re-lists without the
flag; a bookmark click is then a synchronous lookup, and the secret never stays
in the state the UI polls.

## Layout

```
litespeak/
├── app/src/main/kotlin/io/github/schallophy/litespeak/
│   ├── core/Native.kt          the external functions
│   ├── core/NativeClient.kt    handle ownership, 20 ms poll, command wrappers
│   ├── core/AccountClient.kt   the account-only handle, its poll and commands
│   ├── core/AudioBridge.kt     AudioRecord/AudioTrack, AEC, SCO routing, playback gain
│   ├── model/                  snapshot, events, chat and account types (the contract)
│   ├── data/                   saved servers, identity file, local settings
│   ├── SessionViewModel.kt     session state machine, owns both handles
│   └── ui/                     connect, session (3 tabs), settings, account
├── app/libs/                   the Java half of rustls-platform-verifier (see below)
├── iconpack/                   dark.ts3_iconpack, the upstream release asset
└── tools/                      svg2vector.py, per-icon overrides, icon converter inputs
```

`app/libs/rustls-platform-verifier-<version>.aar` is the Android TrustManager
component the account client verifies TLS through. Its version is read from the core's
`Cargo.lock` at build time, so it cannot drift from the Rust half linked into
`liblitespeak_jni.so`; `JNI_OnLoad` initializes it before the account's first
HTTPS request. The AAR is vendored rather than fetched so a build does not
depend on GitHub's raw Maven branch.

The native library is not checked in. `app/buildCoreJniDebug` and
`app/buildCoreJniRelease` compile the core at the repository root (`../..`) with
`cargo ndk` into `app/build/generated/coreJniLibs/{debug,release}` and Android
packages the matching one from there, so the `.so` always matches the sources in
this commit — there is no separate binary that could be from another checkout. The debug
variant uses the core's `android-dev` profile (no LTO), so a core edit does not
pay the release link; the release variant keeps the shipping profile.

Because of that, building an APK needs a Rust toolchain with `cargo-ndk`, the
Android NDK and CMake; there is no submodule to initialise.

The Rust sources live at the repository root: `crates/core` (platform-neutral)
and `crates/jni` (the Android shim).

### The icons

`iconpack/dark.ts3_iconpack` is the upstream release artifact (v1.0.1), committed
verbatim; `iconpack/README.md` records its sha256 and URL. The build converts it
— `:app:buildIconpackDebug` / `Release` — into
`build/generated/res/buildIconpack<variant>/drawable/icon_*.xml`. The only file
under `app/src/main/res/drawable` is the Logout glyph the notification action
needs: actions take a Drawable where Compose takes an ImageVector, so the same
Material path appears once as XML. The whole pack ships, not just the
marks in use: a client that shows a channel, a group or a permission mark should
draw the same picture the desktop client draws.

`tools/svg2vector.py` is the converter. It refuses what it cannot express
exactly — a radial gradient, a rounded rect, a stroked path — rather than
shipping an approximation. `ban_list`'s rotated `<rect>` is mapped corner by
corner. `moderated` is the one icon not taken straight from the pack: its "M" is
a `<text>` run in a macOS-only font, so the outlined paths live in
`tools/iconpack-overrides/moderated.svg` and are converted from there.

Every resource is named `icon_` plus the pack's own name. The prefix is uniform
so a drawable in the tree is recognisably from the pack, and it is what makes
the pack's name survive Android's rules without being rewritten: `3d_sound`
starts with a digit and `addon-collection` has a hyphen, which becomes an
underscore — all a resource name allows.

### Badges

`badges/` holds the myTeamSpeak badge artwork as one SVG per badge UUID, fetched
from `https://badges-content.teamspeak.com/list` by `tools/fetch-badges.py`.
`tools/badges.py` converts them at build time into VectorDrawables named
`badge_<uuid>`, so a member row resolves a badge by the id it already carries.
The art belongs to TeamSpeak; `badges/README.md` records the source. A badge
whose SVG the converter cannot express exactly is skipped, not approximated.

Only the client's own badges are known: `client_signed_badges` for other
clients arrives in `cliententerview`, which the bookkeeping layer drops before
this project sees it.

The fills are baked into the paths (`#a9aaac` grey, `#7289da` blue, `#c90709`
red), so `Icon(tint = ...)`-style recolouring does nothing useful — the
microphone, the speaker and the connect header all put them on one fixed dark
plate (`IconPlate`) instead. That is also why the bottom navigation still uses
Material icons: it signals the selected tab by tinting, which these cannot do.

Which status mark applies is decided once, in `components/Common.kt`
(`inputStatusIcon` / `outputStatusIcon`): switched-off device first, mute
button second. Every screen uses those two functions, so the member row, the
user sheet and the self-view cannot disagree about the same person.

## The native contract

Fourteen functions, and the count is fixed. The JNI symbol names are
`Java_io_github_schallophy_litespeak_core_Native_<name>`, so this package path must not be renamed
casually — `crates/jni` in litespeak hard-codes it:

| function | purpose |
|---|---|
| `nativeCreate` / `nativeDestroy` | session lifecycle, opaque handle |
| `nativeCreateAccount` | an account-only handle: no address, no socket |
| `nativeCreateWithAccount` | connect while carrying the account's myTS proof |
| `nativeIsConnected` | connection state |
| `nativePoll` | drain events as `HashMap[]` |
| `nativeSnapshot` | whole state as one JSON string |
| `nativeExec` | **every** command: name + JSON args |
| `nativeIdentity` | the identity to persist, so the UID is stable |
| `nativeAudioWrite` / `nativeAudioRead` / `nativeAudioReset` | the 50 Hz PCM stream |
| `nativeAbiVersion` | checked once at load; a stale `.so` fails with a message |
| `nativeDisconnect` | close the connection |

Events and state cross the boundary as plain JDK types and JSON, so the native
library never references an app class and does not need rebuilding when the UI's
data classes change. Adding a feature means adding a match arm in litespeak's
`command.rs` (or `account/mod.rs`) and a caller in the Kotlin client — only a new
*kind* of handle needs a new symbol, which is why the account side added two.

Event names and field keys are the real API: litespeak's `docs/events.md` and
`model/ServerEvent.kt` must change together. `litespeak` has a test that fails when
an emitted event is not in that document.

## Building

**Prerequisites** (once): JDK 17, Android SDK with platform 35 + build-tools 36,
Rust, `cargo install cargo-ndk`, the NDK (27.x), CMake and Ninja — the last two
because Opus is compiled from C source. On Windows `cmake` must be on `PATH`; the
build task prepends `C:\Program Files\CMake\bin` if it is not.

```bash
git clone https://github.com/Schallophy/litespeak.git
cd shells/android
./gradlew :app:assembleDebug
```

`assembleDebug` runs `:app:buildCoreJniDebug`, which compiles the core at the
repository root (`../..`) with `cargo ndk` (profile `android-dev`) and drops
`liblitespeak_jni.so` into `app/build/generated/coreJniLibs/debug`.
`assembleRelease` uses `buildCoreJniRelease` and
`app/build/generated/coreJniLibs/release`. Nothing under `app/src/main/jniLibs`
is used or tracked.

**Native library alone**, for working on the core without Gradle:

```powershell
cd ../..
./tools/build-android.ps1      # -> out/android/arm64-v8a/liblitespeak_jni.so
```

Gradle compiles the core itself, so a hand-built `.so` is only an artifact to
inspect; there is no "install into the app" step.

Both paths share the root `target/`, so the first build pays the cold cost and
later ones are incremental — and when nothing under the core changed, the
variant's Gradle task is a cache hit and cargo does not run at all. `buildCoreJniDebug` and
`buildCoreJniRelease` have separate keys because they build different
profiles; switching between `assembleDebug` and `assembleRelease` is not one
cache entry overwriting the other.

License texts for the statically linked third-party code (tsclientlib, Opus,
ureq, rustls/ring) are copied from the root `NOTICE` into
`app/src/main/assets/licenses/` and ship inside the APK — the Apache-2.0 notice
obligation applies to the binary, not just the source tree. Refresh them
whenever the root `NOTICE` changes. `android-unit` in the root CI compares the
two byte for byte.

## Tests

`./gradlew :app:testDebugUnitTest` runs on the JVM — no emulator, no device, no
native library. Four suites, all pinning contracts that used to fail silently:

| suite | what it pins |
|---|---|
| `core/NativeAbiTest` | `Native.EXPECTED_ABI` against `LITESPEAK_ABI_VERSION` in the core's header |
| `model/ServerEventTest` | every `ServerEvent` `type` and field key against `docs/events.md` |
| `core/NativeSymbolsTest` | every `external fun` in `Native.kt` against the `Java_io_github_schallophy_litespeak_core_Native_*` symbols `crates/jni` exports |
| `model/AccountStateTest` | the `snapshot.account` shape: bookmark fields, folder nesting, `host:port` |
| `ui/components/StatusIconTest` | the icon precedence in `inputStatusIcon` / `outputStatusIcon`: switched-off device first, mute button second |

The first two cannot pass on one side alone: litespeak's `event_contract.rs`
proves the Rust and the docs agree, and `ServerEventTest` proves the docs and
Kotlin agree, so a rename in the core fails this build without the table being
copied twice. `StatusIconTest` is the third leg of the same idea — one precedence,
three screens, so a change in `components/Common.kt` cannot silently desync the
member list from the self-view.

## CI

Two jobs in the repository's `.github/workflows/ci.yml`, both `ubuntu-latest`:

| job | what it proves |
|---|---|
| `android-unit` | `:app:testDebugUnitTest` on a bare JVM, plus a byte-for-byte check that `assets/licenses/*` matches the root copies. No `.so` exists on that runner, so a test that reached into the native library would fail instead of passing on a leftover binary. |
| `android-apk` | `assembleDebug` with `cargo ndk` and NDK r27c, then compares the `.so` packaged in the APK against the stripped artifact Gradle derived from `buildCoreJniDebug` |

Both jobs cache what they can. Gradle User Home — the distribution, the
dependencies and the local build cache — is restored by setup-gradle, and each
`buildCoreJni*` variant is a `@CacheableTask`, so a push that does not change
the core restores the compiled `.so` instead of rebuilding it. A cold run
is what happens when the core or a lockfile changes.

There is no emulator job: there are no instrumentation tests to run, and a
booted emulator would cost minutes per run to prove nothing the JVM suite does
not already pin. `build.gradle.kts` prefers `ANDROID_NDK_HOME` over "newest NDK
in the SDK", so CI and a local build never compile against different sysroots.

## Known gaps

* Release builds are signed with the debug key: no `release.keystore` in the repo.
* No foreground service, so a long call can be killed when the app is backgrounded.
* Only `arm64-v8a` is shipped.
* The unit tests read the core from disk (docs and header), so they run on a
  plain JVM checkout with no NDK and no `.so`.
