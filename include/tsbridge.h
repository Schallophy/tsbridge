/*
 * tsbridge - C ABI for the TeamSpeak 3 client core.
 *
 * TS6 is not a supported target: the core targets TS3 and its test suite runs
 * against TS3 only. It was checked by hand against an official TS6 server
 * (6.0.0-beta14) — connecting, the state, and the myTeamSpeak ID proof all
 * worked there — but nothing here is TS6-specific and a TS6 release may change
 * any of it.
 *
 * Link with libtsbridge.so / libtsbridge.dylib / tsbridge.dll, or load it at
 * runtime. One shared library contains the protocol stack, the Opus codec, and
 * the session logic; nothing else has to be installed.
 *
 * NOTE: this header is ASCII on purpose. MSVC warns C4819 on any non-ASCII byte
 * inside a header read as the system code page, and the warning then appears in
 * every translation unit that includes it.
 *
 * -- The contract ------------------------------------------------------------
 *
 * Everything except audio crosses the boundary as JSON. That is the whole point:
 * adding a field to a snapshot or an event never changes this header, so a
 * shell built against an older ABI keeps working against a newer library. A
 * change to a *signature* requires bumping TSBRIDGE_ABI_VERSION, and so does a
 * new exported call that a newer shell would expect to find; the shell should
 * refuse to run on a mismatch.
 *
 * Every `char *` returned here is allocated by the library and must be released
 * with tsbridge_string_free(). Freeing it with `free()` is a heap mismatch;
 * leaking it is a steady leak at 50 Hz.
 *
 * Handles are not thread-safe for destroy: call tsbridge_destroy from one
 * thread after every other call on that handle has returned. The snapshot,
 * event drain and audio calls may be made from different threads concurrently.
 */

#ifndef TSBRIDGE_H
#define TSBRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  define TSBRIDGE_CALL __cdecl
#else
#  define TSBRIDGE_CALL
#endif

/** Opaque session handle. Never dereference it. */
typedef struct TsBridge TsBridge;

/**
 * ABI version of this header. Compare with tsbridge_abi_version() at startup.
 * Bumped only on incompatible signature or semantics changes; additive JSON
 * fields do not bump it.
 */
#define TSBRIDGE_ABI_VERSION 7

/** Log severity, matching Rust's `log` crate: 1=error 2=warn 3=info 4=debug 5=trace. */
typedef void (TSBRIDGE_CALL *TsBridgeLogCallback)(
    int level,
    const char *target,
    const char *message);

/* -- lifecycle ------------------------------------------------------------ */

uint32_t TSBRIDGE_CALL tsbridge_abi_version(void);

/**
 * Library and protocol versions as JSON.
 * `{"abi":5,"core":"0.1.0","tsclientlib":"ee3bc6f"}` - for crash reports.
 */
char *TSBRIDGE_CALL tsbridge_info_json(void);

/**
 * Opens a session from a JSON config and returns immediately; the actual
 * connect happens on a worker thread and reports progress as events.
 *
 * ```json
 * { "address": "ts.example.com:9987",
 *   "identity": "0V...",          // omit for a fresh identity
 *   "nickname": "ann",
 *   "password": "server-secret",  // unlocks the server
 *   "channel": "Lobby",           // where to land
 *   "channelPassword": "...",     // unlocks that channel
 *   "token": "…",                 // privilege key, redeemed once
 *   "version": "3.6.3",           // version number
 *   "platform": "Windows" }       // Windows | OS X | macOS | Linux | Android | iOS
 * ```
 *
 * `version` + `platform` pick which signed client version is announced. The
 * server compares the announced text with its signature byte for byte, so the
 * pair must name an entry of the TeamSpeak-published version table; the core
 * resolves the pair to the full version text (with its `[Build: …]` suffix) and
 * the signature. Absent means `3.6.3` + `Windows`, the standard tuple. A pair
 * that does not resolve falls back to the standard one rather than refusing to
 * connect.
 *
 * `token` is a privilege key (`ServerAdmin privilege key created … token=…` from
 * the server's own output), sent on `clientinit`. It is single-use and grants
 * the groups it names to **this UID**, which is why an admin identity is lost
 * when the identity changes afterwards.
 *
 * `password` and `channelPassword` are different secrets: a server may require
 * either, both, or neither.
 *
 * A nickname that is already in use is retried with a numeric suffix (`ann1`,
 * `ann2`, … up to 20 attempts) by the core, so every shell behaves the same.
 *
 * Returns NULL if the JSON is malformed or `address` is empty.
 */
TsBridge *TSBRIDGE_CALL tsbridge_create(const char *config_json);

/**
 * Opens an account-only session: no address, no socket, no connection thread.
 *
 * The account side lives on the handle, not on the connection, so this is what
 * lets a login screen list bookmarks before a server has been chosen — and what
 * lets a shell sign in first and connect second. Account commands
 * (`account_login`, `sync_list`, …) run through tsbridge_exec and report
 * through `snapshot.account` plus `account_status` events, exactly as they do
 * on a connected session.
 *
 * `config_json` is the same object the `account_config` command accepts:
 *
 * ```json
 * { "legacyDb": "/path/settings.db",   // only for fromTs3Client migration
 *   "backupDir": "/path/backups",       // where pre-write backups land
 *   "credentialFile": "/path/login.json", // enables "stay signed in"
 *   "rememberLogin": true,               // default true
 *   "baselineFile": "/path/sync.json" }  // for sync_merge attribution
 * ```
 *
 * Every field is optional; NULL or "" means "no paths, nothing remembered".
 * Nothing is probed: the library never goes looking for another client's files.
 *
 * Returns NULL only when the account engine could not start.
 */
TsBridge *TSBRIDGE_CALL tsbridge_create_account(const char *config_json);

/**
 * Opens a connection that carries the account's myTeamSpeak proof.
 *
 * `account` is a handle from tsbridge_create_account, or NULL to connect
 * exactly like tsbridge_create. The proof is signed per connection over the
 * server's handshake IV, so it has to come from a live account session: pass a
 * handle that is still open. It is only read during this call — the returned
 * connection keeps what it needs, and the account handle may be destroyed
 * afterwards if the shell no longer needs to manage the account.
 *
 * An account without a myTS identity (or one still signing in) connects
 * normally; a missing badge is not a reason to refuse to join.
 *
 * Returns NULL if the JSON is malformed or `address` is empty.
 */
TsBridge *TSBRIDGE_CALL tsbridge_create_with_account(
    const TsBridge *account,
    const char *config_json);

/**
 * Closes the socket and frees the handle. NULL is allowed.
 * Waits for the worker thread to finish a clean disconnect; call it off the UI
 * thread if the session is still connected.
 */
void TSBRIDGE_CALL tsbridge_destroy(TsBridge *handle);

/** Whether the handshake has completed right now. */
bool TSBRIDGE_CALL tsbridge_is_connected(const TsBridge *handle);

/* -- state ---------------------------------------------------------------- */

/**
 * The entire server state as JSON: channels, members, files, your own client.
 * An unchanged revision returns the identical cached string, so calling this at
 * 50 Hz is cheap. Returns NULL for a NULL handle.
 */
char *TSBRIDGE_CALL tsbridge_snapshot_json(const TsBridge *handle);

/**
 * Drains queued semantic events as a JSON array, e.g.
 * `[{"type":"user_joined","client_id":7,"nickname":"ann"}]`.
 * Returns `[]` when there is nothing new, never NULL for a valid handle.
 *
 * The event names and their fields are a cross-language contract; see
 * docs/events.md. Unknown types must be preserved by the consumer, not dropped.
 */
char *TSBRIDGE_CALL tsbridge_poll_events_json(const TsBridge *handle);

/* -- commands ------------------------------------------------------------- */

/**
 * Runs one named command. Returns "" on success, or a user-facing error string.
 *
 * Available names and their JSON arguments:
 *   disconnect                                  -
 *   send_text          {"target":"server"|"channel"|"client","clientId":n,"message":"..."}
 *   poke               {"clientId":n,"message":"..."}
 *   join_channel       {"channelId":n,"password":"..."}
 *   set_input_muted    {"muted":bool}
 *   set_output_muted   {"muted":bool}
 *   set_away           {"away":bool,"message":"..."}
 *   set_nickname       {"nickname":"..."}
 *   list_files         {"channelId":n,"path":"/","password":"..."}
 *   download           {"channelId":n,"path":"remote","local":"/abs/path","password":"..."}
 *   upload             {"channelId":n,"path":"remote","local":"/abs/path","overwrite":bool}
 *   audio_enabled      {"enabled":bool}
 *   set_mic_gain       {"gain":1.0}              linear, clamped 0.2–4.0
 *   set_user_volume    {"clientId":n,"volume":1.0}  linear, clamped 0.0–2.0
 *   set_whisper_targets {"clients":[n],"channels":[n],
 *                        "groups":[{"type":"server_group"|"channel_group"|
 *                                          "channel_commander"|"all_clients",
 *                                   "target":"all_channels"|"current_channel"|
 *                                           "parent_channel"|"all_parent_channel"|
 *                                           "channel_family"|"complete_channel_family"|
 *                                           "subchannels",
 *                                   "id":n}]}
 *                      Empty targets restore ordinary channel talk. Client and
 *                      channel lists share one packet; each group is resolved by
 *                      the server and gets its own, so late joiners are covered.
 *
 * Account commands (myTeamSpeak). They run on the library's own worker and
 * report through `snapshot.account` plus one `account_status` event, so `exec`
 * returns "" as soon as the command is accepted rather than when it is done.
 * None of them need a server connection: open an account-only handle with
 * tsbridge_create_account to use them before anything is joined, or run them on
 * a connected handle (which has the account side with no paths configured).
 *   account_config     {"legacyDb":"/abs/path","backupDir":"/abs/path",
 *                       "credentialFile":"/abs/path","rememberLogin":bool,
 *                       "baselineFile":"/abs/path"}
 *                      legacyDb is an installed client's settings.db, used only
 *                      by fromTs3Client to import a login. Optional; never probed.
 *                      credentialFile enables "stay signed in": a successful
 *                      login writes the accepted credential hash, the account
 *                      key, the session token and the myTS identity there (never
 *                      the password), a bare {"":""} login reads it, and
 *                      account_logout deletes it. Absent means nothing is
 *                      written at all. baselineFile is where a sync baseline
 *                      goes: what both sides last agreed on, stored as per-field
 *                      digests (never content) plus the server cursors. Absent
 *                      means sync_merge cannot attribute a change to one side.
 *   account_login      {"email":"...","password":"...","otp":"...","recoveryKey":"..."}
 *                      or {"fromTs3Client":true} to import the stored login
 *                      or {} to sign in with the remembered credential
 *                      A login also fills `snapshot.account.items`.
 *   account_resume     -     restores the remembered account with no network
 *                      login: the session, account key and myTS identity come
 *                      from credentialFile, so the second launch is instant and
 *                      starts offline. A session the server retired is renewed by
 *                      the next read/identity_pick. Only a file written before
 *                      sessions were stored falls back to one account_login.
 *   account_logout     -     also deletes credentialFile
 *   account_refresh    {"revealSecrets":bool}   re-reads /me and the item list
 *   sync_list          {"revealSecrets":bool}   bookmark passwords are presence
 *                      only unless this is true; they never reach a default render
 *   sync_backup        -     writes a backup file, no server write
 *   sync_bookmark_create  {"name":"...","address":"...","port":n,"nickname":"..."}
 *   sync_bookmark_edit    {"uuid":"...","name":"...","address":"...","port":n,"nickname":"..."}
 *                      Keeps the item's uuid, password, placement and profile;
 *                      only the four user-visible fields change.
 *   sync_bookmark_move    {"uuid":"...","after":"<sibling uuid>"|""}
 *                      `after` is the sibling to follow, empty for "first".
 *                      Writes only the items whose link actually changed.
 *   sync_addon_enabled {"uuid":"...","enabled":bool}   any ADD_ON item
 *   sync_delete        {"uuid":"...","class":"BOOKMARK"|...}
 *   sync_restore       {"file":"/abs/path/backup.json"}   one item per request
 *   The myTeamSpeak ID is not a command: a login that recovers it fills
 *   snapshot.account.mytsId (base64, 33 B) and mytsPublicKey (base64, 32 B), and
 *   Account exposes mytsParams(sharedIV) for the six clientinit parameters. The
 *   private scalar never leaves the library. To announce it on a connection,
 *   pass the signed-in account handle to tsbridge_create_with_account.
 *   identity_pick      {"address":"ts.example.com"}
 *                      Answers "which identity does this server know me by",
 *                      from the account itself: a bookmark for that address
 *                      names the IDENTITY item the official client used, and
 *                      failing that a single marked default, failing that the
 *                      only identity. Fills `snapshot.account.pickedIdentity`
 *                      (`value`/`name`/`nickname`) or `{}` when the account is
 *                      ambiguous. Read-only, safe before every connect. Call it
 *                      after login with the address about to be joined, then
 *                      pass `value` as the connection's `identity`.
 *   identity_import    {"identity":"42V...","uuid":"..."}
 *                      Copies that identity into the account's IDENTITY item so
 *                      a fresh install keeps the UID its server groups are bound
 *                      to. `uuid` picks a specific item; absent means the
 *                      default (or the only) one. Validates the string first and
 *                      writes nothing when it is already there. Readable strings
 *                      also appear in `snapshot.account.identities`.
 *   sync_merge         {"local":"/abs/path/backup.json",
 *                       "baseline":"/abs/path/sync.json","record":bool}
 *                      Compares that backup against the account and fills
 *                      snapshot.account.merge with per-item, per-field actions:
 *                      inSync / push / pull / merge / conflict. READ-ONLY unless
 *                      "record" is true, which rewrites the baseline with only
 *                      the items both sides already hold identically. A conflict
 *                      is reported, never resolved: choosing a side is the user's
 *                      decision.
 */
char *TSBRIDGE_CALL tsbridge_exec(
    TsBridge *handle,
    const char *name,
    const char *args_json);

/**
 * Sends a clean disconnect (the server is told why) but keeps the handle
 * readable so the shell can show "disconnected". Follow with tsbridge_destroy.
 */
void TSBRIDGE_CALL tsbridge_disconnect(TsBridge *handle);

/* -- identity ------------------------------------------------------------- */

/**
 * The identity in TS3 `counterVkey` form, for the shell to store wherever it
 * keeps secrets (Keychain, DPAPI, a file). NULL before the worker thread has
 * built one.
 *
 * Persist it and pass it back as `"identity"` in the next config. Without this
 * the server sees a brand-new user - a new UID - on every launch.
 */
char *TSBRIDGE_CALL tsbridge_identity(const TsBridge *handle);

/* -- voice ---------------------------------------------------------------- */

/**
 * Queues captured PCM16, 48 kHz mono, for transmission. A frame is 960 samples
 * (20 ms); other sizes are buffered and split. Returns how many were taken.
 *
 * Capture itself belongs to the shell: that is where echo cancellation, noise
 * suppression and device routing live, and none of it is portable.
 */
size_t TSBRIDGE_CALL tsbridge_audio_write(
    TsBridge *handle,
    const int16_t *samples,
    size_t count);

/**
 * Fills `out` with at most `count` decoded PCM16 samples and returns how many
 * are valid. Never blocks: a starved queue returns 0 and the shell repeats the
 * previous frame or plays silence.
 */
size_t TSBRIDGE_CALL tsbridge_audio_read(
    TsBridge *handle,
    int16_t *out,
    size_t count);

/** Drops buffered audio so the next call does not start with stale samples. */
void TSBRIDGE_CALL tsbridge_audio_reset(TsBridge *handle);

/* -- plumbing ------------------------------------------------------------- */

/** Releases a string returned by this library. NULL is allowed. */
void TSBRIDGE_CALL tsbridge_string_free(char *value);

/**
 * Installs the log sink. Call before tsbridge_create to capture connection
 * logs. Passing NULL removes it. Only one sink per process exists; a second
 * call replaces the callback rather than adding another.
 */
void TSBRIDGE_CALL tsbridge_set_log_callback(TsBridgeLogCallback callback);

#ifdef __cplusplus
}
#endif

#endif /* TSBRIDGE_H */
