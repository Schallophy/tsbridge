/*
 * tsbridge - C ABI for the TeamSpeak 3 client core.
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
 * shell built against ABI 1 keeps working against a newer library. Only a
 * change to a *signature* requires bumping TSBRIDGE_ABI_VERSION, and the shell
 * should refuse to run on a mismatch.
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
#define TSBRIDGE_ABI_VERSION 1

/** Log severity, matching Rust's `log` crate: 1=error 2=warn 3=info 4=debug 5=trace. */
typedef void (TSBRIDGE_CALL *TsBridgeLogCallback)(
    int level,
    const char *target,
    const char *message);

/* -- lifecycle ------------------------------------------------------------ */

uint32_t TSBRIDGE_CALL tsbridge_abi_version(void);

/**
 * Library and protocol versions as JSON.
 * `{"abi":1,"core":"0.1.0","tsclientlib":"ee3bc6f"}` - for crash reports.
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
 *   "channelPassword": "..." }    // unlocks that channel
 * ```
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
