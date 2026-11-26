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
  "identityReady": true,
  "ownClientId": 5,
  "ownChannelId": 12,
  "nickname": "ann",
  "inputMuted": false,
  "outputMuted": false,
  "inputHardwareEnabled": true,
  "outputHardwareEnabled": true,
  "away": false,
  "awayMessage": "",
  "ownTalking": false,
  "server": {
    "name": "Example", "version": "6.0.0", "platform": "Linux",
    "clientsOnline": 8, "maxClients": 32, "welcomeMessage": "…"
  },
  "users": [
    { "id": 5, "uid": "abc=", "nickname": "ann", "channelId": 12,
      "inputMuted": false, "outputMuted": false,
      "inputHardwareEnabled": true, "outputHardwareEnabled": true,
      "clientType": 0,
      "away": false, "awayMessage": "", "description": "", "talking": false,
      "serverGroups": [7], "badges": "" }
  ],
  "channels": [
    { "id": 12, "parentId": 0, "name": "Lobby", "order": 0,
      "hasPassword": false, "isDefault": false, "topic": "",
      "maxClients": -1, "permissionHints": 0 }
  ],
  "channelTree": [
    { "id": 12, "depth": 0 }
  ],
  "serverGroups": [
    { "id": 6, "name": "Normal" }
  ],
  "ownServerGroups": [
    { "id": 6, "name": "Server Admin" }
  ],
  "channelGroups": [
    { "id": 8, "name": "Channel Admin" }
  ],
  "files": [
    { "channelId": 12, "path": "/", "name": "notes.txt", "size": 1024,
      "isFile": true, "dateTime": 1700000000 }
  ],
  "account": {
    "loggedIn": false, "email": "", "username": "", "uuid": "",
    "unwrappedWith": "", "keyBytes": 0, "busy": false,
    "command": "", "lastError": "", "lastBackup": "", "progress": "",
    "status": 0, "statusName": "", "globalVersion": "",
    "itemCount": 0, "items": [],
    "hierarchy": { "entries": [], "unplaced": [], "folders": 0, "roots": 0 },
    "merge": {},
    "mytsId": "", "mytsPublicKey": "",
    "profile": {}
  }
}
```

* `account` is always present, even when nobody is signed in and no server is
  joined: the account side has its own worker and its own lifetime, so a shell
  renders `loggedIn` instead of testing for `null`. `command` is the last
  accepted command name (`account_login`, `sync_list`, …) and `lastError` is
  empty when that command succeeded. `progress` is the in-flight text of a
  multi-step command (`3/25 items restored`) and empty otherwise — it is not an
  error, so it must not be painted like one. `keyBytes` is the *length* of the
  unwrapped account key, never the key: a snapshot ends up in logs.
* `account.items` is one object per server item — `uuid`, `class`, `classId`,
  `itemVersion`, `bytes`, `capability` (`plaintext` · `encrypted` · `locked` ·
  `empty`), `writable` (whether this session can rewrite it), `plaintextBytes`
  when the content was read, `parent` and `sortOrder` (always present, empty for
  "top level"), `folder` for an `ITEM_FOLDER`, and `bookmark` for a bookmark
  whose content is readable. There is deliberately no length ceiling: the item
  cipher is a stream cipher over the whole item. See `docs/myteamspeak.md` for
  what each tier permits and why `locked` exists.
* `account.hierarchy` is the same items as a tree, for an importer or a UI that
  draws indentation: `entries` is one flat **pre-order** list of
  `{uuid, parent, depth, name, folderFor, isFolder}`, and `unplaced` names the
  items that could not be placed. `sortOrder` is a **link to the previous
  sibling, not a rank** — the first item of a list carries an empty string — so
  the order can only be recovered by following the links; that is what this list
  has already done. An item whose `parent` is not a folder in this state, and a
  `locked` item whose placement cannot be read, appear in `unplaced` and are
  kept in `items`, because a row that silently disappeared is worse than one
  that is reported.
* A bookmark object reports `hasServerPassword` / `hasChannelPassword` always, and
  the password **values** only when the command that read the list asked for them
  (`sync_list {"revealSecrets": true}`). The same rule applies to the account key
  (`keyBytes`, never `key`): a snapshot is read at 50 Hz and may reach a log or a
  crash report, so a secret is opt-in and the default render is presence only.
* `account.mytsId` / `account.mytsPublicKey` are the myTeamSpeak ID (33 B,
  base64) and the Ed25519 public key (32 B, base64) that this login recovered.
  Empty means the account has no myTS identity, or its wrapped private key could
  not be opened — a shell shows that as "name and badge are not announced" rather
  than as an error. The **private scalar never appears in a snapshot**: it lives
  inside `Account` and is only used to answer `mytsParams(sharedIV)`, because the
  signature embeds a per-connection challenge.
* `account.merge` is the last `sync_merge` report and `{}` until one runs. It is
  `{hasBaseline, cursorsMatch, inSync, push, pull, merge, conflict, conflicts,
  items}`, where each item is `{uuid, class, classId, action, writesServer,
  writesLocal, merged, fields}` and each field is `{key, label, local, server,
  conflict}` with the four changes `unchanged` · `added` · `modified` ·
  `removed`. A **conflict is not an error**: the command succeeds and says how
  many there are, because choosing a side is the user's decision, and a shell that
  painted it as a failure would hide the report. Nothing is applied by
  `sync_merge` except, when `record` is set, the local baseline file.
* `account_loggedOut` is not a separate field: `loggedIn` is `false` and the
  identity fields are empty. Signing out also deletes any remembered credential
  file, so "sign out" is not undone by the next launch.

* `ownClientId` / `ownChannelId` are `null` before the handshake completes.
* `ownTalking` is computed by the core from the capture path (gain applied,
  then the voice gate: -45 dBFS to open, 3 dB hysteresis, 400 ms hangover,
  300 ms of pre-speech audio kept so onsets are not clipped). The server never reports our own voice, so this
  is the only speaking signal that covers this client; do not derive it from a
  shell-side level meter.
* `identityReady` turns `true` once `tsbridge_identity` returns a value. The
  key itself is deliberately not in the snapshot — snapshots end up in logs.
  Shells read the identity once after seeing the flag instead of polling for it.
* `clientType` is `0` for a normal voice client and `1` for a server query
  connection — server queries are not people and should not be listed.
* `channelTree` is the display order: `id` indexes `channels` and `depth` is 0
  for a root, growing with nesting. Channels whose parent is missing are shown
  as roots. Render this list as given; do not re-sort `channels`.
* `serverGroups` / `channelGroups` are requested once per connection and sorted
  by name. They stay empty when the account may not list them.
* `ownServerGroups` is those two lists joined for this client: the groups it
  actually holds, by name. Server rights are bound to the UID and to these
  memberships, so this is the field that answers "am I an admin here";
  `users[].serverGroups` carries the raw ids for everyone else.
* `users[].badges` is the server's raw `client_badges` (e.g. `overwolf=0`),
  empty when it reported none — which is also what a client that sent no
  myTeamSpeak proof gets.
* `files` is sorted by the core: directories first, then case-insensitive name.
  Render the list as given.
* `permissionHints` on a channel is `0` until a `list_files` request for it has
  been answered, then a mask: `1` join, `64` upload, `128` download, `256`
  delete, `512` rename, `1024` browse, `2048` create directory. Hide the
  buttons whose bit is absent; the server still enforces the real check.
* `order` on a channel is the server's linked-list position, not a sort
  index: it is the id of the sibling this channel comes after, and `0` means
  "first". Kept for callers that build their own view; `channelTree` already
  applies it.
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
| `error` | `message` str, `kind` str (`connect` · `identity` · `panic` · `poll`…), `terminal` bool (true when this session is over and no further command will be handled) |
| `command_error` | `message` str, `missing_permission` str (empty when it is not a permission problem), `command_id` int (absent for errors detected locally) |
| `user_joined` | `client_id` int, `nickname` str, `uid` str, `channel_id` int64 |
| `user_left` | `client_id` int, `nickname` str |
| `user_moved` | `client_id` int, `nickname` str, `channel_id` int64, `old_channel_id` int64 |
| `user_renamed` | `client_id` int, `nickname` str, `old_nickname` str |
| `user_mute_changed` | `client_id` int, `nickname` str, `input_muted` bool, `output_muted` bool, `input_hardware_enabled` bool, `output_hardware_enabled` bool, `scope` str (`input` · `output`) |
| `user_priority_speaker_changed` | `client_id` int, `nickname` str, `priority_speaker` bool |
| `user_unread_messages_changed` | `client_id` int, `nickname` str, `unread_messages` int64 |
| `user_away_changed` | `client_id` int, `nickname` str, `away` bool, `away_message` str |
| `server_query_login_password` | `password` str |
| `chat_composing` | `client_id` int, `uid` str |
| `file_list_finished` | `channel_id` int64, `path` str |
| `missing_permission` | `permission_id` int64, `value` int |
| `channel_changed` | `channel_id` int64 |
| `channel_password_changed` | `channel_id` int64 |
| `plugin_command` | `name` str, `data` str, `invoker_id` int, `invoker_name` str, `invoker_uid` str |
| `channel_created_id` | `channel_id` int64 |
| `server_group_created` | `group_id` int64 |
| `channel_created` | `channel_id` int64, `parent_id` int64, `name` str |
| `channel_renamed` | `channel_id` int64, `name` str, `old_name` str |
| `channel_removed` | `channel_id` int64 |
| `text_message` | `target` str (`server` · `channel` · `client`), `from_id` int, `from_name` str, `from_uid` str, `message` str, `to_id` int, `from_self` bool, `timestamp` int64 (unix seconds, 0 when unknown), `timestamp_ms` int64 (unix milliseconds, 0 when unknown) |
| `poked` | `from_id` int, `from_name` str, `message` str |
| `file_list` | `channel_id` int64, `count` int |
| `transfer_started` | `name` str, `direction` str (`upload` · `download`), `total` int64 |
| `transfer_progress` | `name` str, `direction` str, `done` int64, `total` int64 |
| `transfer_done` | `name` str, `direction` str, `local` str, `total` int64 |
| `transfer_error` | `name` str, `message` str |
| `icon_ready` | `icon_id` int64, `path` str, `format` str, `size` int64 |
| `icon_failed` | `icon_id` int64, `message` str |
| `ban_listed` | `ban_id` int64, `ip` str, `name` str, `uid` str, `last_nickname` str, `created` int64, `duration` int64, `invoker_name` str, `reason` str |
| `ban_list_done` | — |
| `complaint_listed` | `target_db_id` int64, `target_name` str, `from_db_id` int64, `from_name` str, `message` str, `timestamp` int64 |
| `complaint_list_done` | — |
| `offline_message_listed` | `message_id` int64, `uid` str, `subject` str, `timestamp` int64, `read` bool |
| `offline_message_list_done` | — |
| `offline_message` | `message_id` int64, `uid` str, `subject` str, `message` str, `timestamp` int64 |
| `client_permission` | `client_db_id` int64, `name` str, `value` int, `negated` bool, `skip` bool |
| `client_permission_list_done` | — |
| `channel_permission` | `channel_id` int64, `name` str, `value` int, `negated` bool, `skip` bool |
| `channel_permission_list_done` | — |
| `temp_password_listed` | `nickname` str, `uid` str, `description` str, `password` str, `start` int64, `end` int64, `channel_id` int64 |
| `temp_password_list_done` | — |
| `client_db_entry` | `client_db_id` int64, `uid` str, `nickname` str, `created` int64, `last_connected` int64, `connections` int64, `description` str |
| `client_db_list_done` | — |
| `client_db_info` | `client_db_id` int64, `uid` str, `nickname` str, `client_id` int, `channel_id` int64, `description` str, `avatar_hash` str, `icon_id` int64, `created` int64 |
| `client_db_found` | `client_db_id` int64, `uid` str, `nickname` str, `last_connected` int64, `connections` int64 |
| `client_db_find_done` | — |
| `recording_started` | `path` str |
| `recording_stopped` | `path` str, `frames` int64, `seconds` int64, `failed` bool, `reason` str (only when `failed`) |
| `server_group_client` | `group_id` int64, `client_db_id` int64, `nickname` str, `uid` str |
| `server_group_client_list_done` | — |
| `group_permission` | `group_kind` str, `group_id` int64, `name` str, `value` int, `negated` bool, `skip` bool |
| `group_permission_list_done` | `group_kind` str |
| `channel_group_client` | `channel_id` int64, `client_db_id` int64, `group_id` int64 |
| `channel_group_client_list_done` | — |
| `channel_client_permission` | `channel_id` int64, `client_db_id` int64, `name` str, `value` int, `negated` bool, `skip` bool |
| `channel_client_permission_list_done` | — |
| `client_server_group` | `client_db_id` int64, `group_id` int64, `name` str |
| `client_server_group_list_done` | — |
| `client_id_resolved` | `uid` str, `client_id` int, `nickname` str |
| `client_id_resolved_done` | — |
| `client_name_resolved` | `uid` str, `client_db_id` int64, `nickname` str |
| `client_name_resolved_done` | — |
| `client_uid_resolved` | `uid` str, `client_id` int, `nickname` str |
| `client_uid_resolved_done` | — |
| `client_connection_info` | `client_id` int, `ping` int64, `ping_deviation` int64, `connected_time` int64, `ip` str, `port` int, `packets_sent` int64, `bytes_sent` int64, `packets_received` int64, `bytes_received` int64, `packet_loss` int |
| `server_connection_info` | `packets_sent` int64, `bytes_sent` int64, `packets_received` int64, `bytes_received` int64, `filetransfer_bytes_sent` int64, `filetransfer_bytes_received` int64, `connected_time` int64, `ping` int64, `packet_loss` int |
| `file_info` | `channel_id` int64, `path` str, `name` str, `size` int64, `date_time` int64 |
| `perm_found` | `scope` str, `id1` int64, `id2` int64, `permission_id` int64 |
| `perm_find_done` | — |
| `perm_listed` | `group_id_end` int64, `permission_id` int64, `name` str, `description` str |
| `perm_list_done` | — |
| `log_line` | `offset` int64, `file_size` int64, `line` str |
| `token_created` | `token` str |
| `token_listed` | `token` str, `token_kind` str, `group_id` int64, `channel_id` int64, `created` int64, `description` str |
| `token_list_done` | — |
| `token_used` | `token` str, `custom_set` str, `group_id` str, `channel_id` str, `client_id` int, `client_db_id` int64, `uid` str |
| `client_info` | `client_db_id` int64, `uid` str, `nickname` str, `channel_id` int64, `platform` str, `version` str, `version_sign` str, `login_name` str, `ip` str, `country` str, `description` str, `avatar_hash` str, `icon_id` int64, `badges` str, `idle_time` int64, `connected_time` int64, `packets_sent` int64, `packets_received` int64, `bytes_sent` int64, `bytes_received` int64, `filetransfer_bytes_sent` int64, `filetransfer_bytes_received` int64, `client_type` int, `recording` bool, `away` bool, `away_message` str, `talk_power` int, `channel_group_id` int64 |
| `channel_info` | `parent_id` int64, `name` str, `topic` str, `description` str, `has_password` bool, `codec` str, `codec_quality` int, `max_clients` int, `max_family_clients` int, `order` int64, `is_permanent` bool, `is_default` bool, `needed_talk_power` int, `forced_silence` bool, `icon_id` int64, `delete_delay` int64 |
| `channel_found` | `channel_id` int64, `name` str |
| `channel_find_done` | — |
| `client_listed` | `client_id` int, `channel_id` int64, `client_db_id` int64, `nickname` str, `uid` str, `client_type` int, `away` bool, `away_message` str, `talking` bool, `input_muted` bool, `output_muted` bool, `recording` bool, `talk_power` int, `channel_group_id` int64, `platform` str, `version` str, `country` str |
| `client_list_done` | — |
| `virtual_server_listed` | `server_id` int64, `port` int, `status` str, `clients_online` int, `query_clients_online` int, `max_clients` int, `uptime` int64, `autostart` bool, `machine_id` str, `name` str, `uid` str |
| `virtual_server_list_done` | — |
| `channel_edited` | `channel_id` int64, `description` str |
| `client_db_id_resolved` | `uid` str, `client_db_id` int64 |
| `client_db_id_resolved_done` | — |
| `client_found` | `client_id` int, `nickname` str |
| `client_find_done` | — |
| `perm_value` | `permission_id` int64, `name` str, `value` int |
| `server_info` | `uid` str, `name` str, `welcome_message` str, `platform` str, `version` str, `max_clients` int, `clients_online` int, `channels_online` int64, `created` int64, `uptime` int64, `port` int, `has_password` bool, `autostart` bool, `weblist_enabled` bool, `ask_for_privilegekey` bool, `hostmessage` str, `hostmessage_mode` int, `hostbanner_url` str, `hostbanner_gfx_url` str, `hostbutton_tooltip` str, `hostbutton_url` str, `hostbutton_gfx_url` str, `machine_id` str, `nickname` str, `phonetic_name` str, `icon_id` int64, `reserved_slots` int, `download_quota` int64, `upload_quota` int64, `bytes_downloaded_month` int64, `bytes_uploaded_month` int64, `bytes_downloaded_total` int64, `bytes_uploaded_total` int64, `packet_loss` int, `ping` int64, `query_clients_online` int64, `connection_count_total` int64, `query_count_total` int64, `needed_identity_security_level` int, `priority_speaker_dimm_modificator` int, `status` str, `default_server_group` int64, `default_channel_group` int64, `default_channel_admin_group` int64, `max_download_bandwidth_total` int64, `max_upload_bandwidth_total` int64, `temp_channel_default_delete_delay` int64, `log_client` bool, `log_query` bool, `log_channel` bool, `log_permissions` bool, `log_server` bool, `log_filetransfer` bool |
| `server_snapshot` | `snapshot` str, `size` int64 |
| `custom_entry` | `client_db_id` int64, `ident` str, `value` str |
| `custom_info_done` | — |
| `custom_search_done` | — |
| `who_am_i` | `client_id` int, `channel_id` int64, `nickname` str, `client_db_id` int64, `login_name` str, `uid` str, `server_id` int64, `origin_server_id` int64, `server_uid` str, `port` int, `server_status` str |
| `chat_closed` | `client_id` int, `uid` str |
| `filetransfer` | `client_id` int, `path` str, `name` str, `size` int64, `size_done` int64, `server_id` int, `client_id_transfer` int, `sender` str, `status` int, `speed` int, `runtime` int64 |
| `filetransfer_list_done` | — |
| `account_status` | `command` str, `ok` bool, `message` str |

The account side is independent of the connection, so `account_status` arrives
whether or not the session is joined to a server. It fires exactly once per
command, after the command's own report has been published to the snapshot: a
shell that only watches events still sees the final state, and one that only
reads the snapshot needs no event for the result. `command` is the name that was
accepted (`account_login`, `sync_list`, …), `ok` says whether it finished, and
`message` is the same sentence a shell would show. A command that is *rejected*
before it starts (one is already running, or the arguments are wrong) returns an
error string from `exec` and emits no event — there is nothing to report on.

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

### 3D sound

`set_user_position` places one client in the field: `angle` is a compass bearing
in degrees (0 ahead, 90 right, 180 behind, 270 left) and `distance` is in
whatever unit the shell draws, because only the ratio to the full-volume radius
matters. `{"clientId":1}` with no angle and distance clears the position;
`clear_positions` clears every one.

Panning is constant-power: a source crossing in front of the listener keeps its
loudness instead of dipping in the middle. Distance attenuates linearly between
1× and 8× the full-volume radius and is silent beyond that. A client with no
position is mixed centred and unattenuated, so 3D being off is the same as the
position map being empty — there is no separate switch to fall out of sync.

The positions are also in the snapshot (`users[].position`), which is what a
shell draws its spatial view from. They survive a client update: a position is
something the shell set, not something the server sends.

### Recording

`record_start` takes a path and writes what the phone **hears** — the playback
mix — to a 48 kHz mono 16-bit PCM WAV. The microphone is not what is recorded:
any screen recorder already has it, and a recording of only yourself says
nothing about the conversation. `record_stop` patches the header (the length is
not known before that) and reports the frame count.

The file is written incrementally, one frame per tick, so a long call does not
sit in memory. A write error — a full disk — ends the recording with
`recording_stopped { failed: true, reason }` instead of failing every tick: a
full disk must not stop the voice.

`snapshot.recording` carries `active`, `path` and `seconds` so a shell can draw
a timer without keeping its own clock.
