# Wire format

The library speaks JSON in both directions. This file is the contract: the type
strings and field names below are shared by Kotlin, Swift and any C caller, so
renaming one silently breaks a feature in exactly one client. Change the code in
`crates/core` and this file in the same commit.

Values are limited to `string`, `integer`, `boolean` (and `null` where noted) —
the set every target language can read out of a decoded object without a schema.

## Snapshot — `tsbridge_snapshot_json`

One object describing the whole server right now. It carries a `rev` counter that
is bumped only when something a UI would render changed; an unchanged revision
returns the identical cached string, so calling this at 50 Hz is cheap.

```json
{
  "rev": 42,
  "connected": true,
  "ownClientId": 5,
  "ownChannelId": 12,
  "nickname": "ann",
  "inputMuted": false,
  "outputMuted": false,
  "inputHardwareEnabled": true,
  "outputHardwareEnabled": true,
  "away": false,
  "awayMessage": "",
  "server": {
    "name": "Example", "version": "6.0.0", "platform": "Linux",
    "clientsOnline": 8, "maxClients": 32, "welcomeMessage": "…"
  },
  "users": [
    { "id": 5, "uid": "abc=", "nickname": "ann", "channelId": 12,
      "inputMuted": false, "outputMuted": false,
      "inputHardwareEnabled": true, "outputHardwareEnabled": true,
      "clientType": 0,
      "away": false, "awayMessage": "", "description": "", "talking": false }
  ],
  "channels": [
    { "id": 12, "parentId": 0, "name": "Lobby", "order": 0,
      "hasPassword": false, "isDefault": false, "topic": "",
      "maxClients": -1 }
  ],
  "files": [
    { "channelId": 12, "path": "/", "name": "notes.txt", "size": 1024,
      "isFile": true, "dateTime": 1700000000 }
  ]
}
```

* `ownClientId` / `ownChannelId` are `null` before the handshake completes.
* `clientType` is `0` for a normal voice client and `1` for a server query
  connection — server queries are not people and should not be listed.
* `order` on a channel is the server's linked-list position, not a sort
  index: it is the id of the sibling this channel comes after, and `0` means
  "first". Walk the chain (starting from `0`) within each parent; sorting by
  the raw value puts never-reordered servers right and reordered ones wrong.
* `maxClients` on a channel: `-1` unlimited, `-2` inherited, otherwise a limit.
* `inputHardwareEnabled` / `outputHardwareEnabled` are about the *capture
  device*, not the mute button: TeamSpeak lets a client switch its microphone
  off in its own settings (`client_input_hardware=0`), which the server reports
  separately from `inputMuted`. A client with the microphone disabled sends no
  audio while `inputMuted` stays `false`, so a UI that only looks at
  `inputMuted` draws an open microphone and leaves the user wondering why no
  voice arrives. Both flags being absent (older library versions) must be treated
  as `true`.

## Events — `tsbridge_poll_events_json`

An array of flat objects, each with a `type` key. Empty array when nothing
happened. Draining is destructive: the queue is emptied by the call, so an event
read once is gone.

Unknown types **must** be preserved by the consumer (render as raw, log it,
ignore it) rather than dropped: a newer library may emit an event an older shell
has no case for, and silently discarding it is how a shipped feature goes quiet.

| `type` | fields |
|---|---|
| `connected` | `client_id` int, `server_name` str, `server_version` str |
| `disconnected` | — |
| `reconnecting` | — |
| `error` | `message` str, `kind` str (`connect` · `identity` · `panic` · `poll`…) |
| `command_error` | `message` str, `missing_permission` str (empty when it is not a permission problem), `command_id` int (absent for errors detected locally) |
| `user_joined` | `client_id` int, `nickname` str, `uid` str, `channel_id` int64 |
| `user_left` | `client_id` int, `nickname` str |
| `user_moved` | `client_id` int, `nickname` str, `channel_id` int64, `old_channel_id` int64 |
| `user_renamed` | `client_id` int, `nickname` str, `old_nickname` str |
| `user_mute_changed` | `client_id` int, `nickname` str, `input_muted` bool, `output_muted` bool, `input_hardware_enabled` bool, `output_hardware_enabled` bool, `scope` str (`input` · `output`) |
| `user_away_changed` | `client_id` int, `nickname` str, `away` bool, `away_message` str |
| `channel_created` | `channel_id` int64, `parent_id` int64, `name` str |
| `channel_renamed` | `channel_id` int64, `name` str, `old_name` str |
| `channel_removed` | `channel_id` int64 |
| `text_message` | `target` str (`server` · `channel` · `client`), `from_id` int, `from_name` str, `from_uid` str, `message` str, `to_id` int, `timestamp` int64 (unix seconds, 0 when unknown) |
| `poked` | `from_id` int, `from_name` str, `message` str |
| `file_list` | `channel_id` int64, `count` int |
| `transfer_started` | `name` str, `direction` str (`upload` · `download`), `total` int64 |
| `transfer_progress` | `name` str, `direction` str, `done` int64, `total` int64 |
| `transfer_done` | `name` str, `direction` str, `local` str, `total` int64 |
| `transfer_error` | `name` str, `message` str |

`crates/core/tests/event_contract.rs` has a test that pins this list in both
directions: it fails if a name is emitted but undocumented, and also if a row
here has no emitter (a contract that promises something that never happens).
That is the cheapest possible guard against a silent rename.

## Commands — `tsbridge_exec(name, args_json)`

See `include/tsbridge.h` for the table of names and their arguments. Every
command returns `""` on success or a user-facing error string. Errors are
returned rather than thrown: a rejected poke must not take the session down.

## Audio

Not JSON. `tsbridge_audio_write` / `tsbridge_audio_read` move raw PCM16 at
48 kHz mono; one frame is 960 samples (20 ms). Anything larger is buffered and
split, anything smaller is accumulated. `tsbridge_audio_read` never blocks — a
starved queue returns 0, and the shell repeats its previous frame or plays
silence.

Capture and playback devices belong to the shell, because echo cancellation,
noise suppression and Bluetooth routing are platform APIs. The core only sees
samples.
