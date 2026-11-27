# Vendored: tsclientlib

Upstream: <https://github.com/ReSpeak/tsclientlib> at
`ee3bc6f45a7137db7793ba5593a321df400d53e5` (master, 2026-07-22). Copied here in
upstream's own workspace layout, with upstream's licenses.

## Why it is in the tree

Three things the myTeamSpeak ID proof needs are not reachable from outside:

1. **The connection's shared IV.** Upstream gates `get_tsproto_client()` behind
   its `unstable` feature; that is the only way to read the value the proof is
   signed over.
2. **That IV's length.** The IV is `alpha ‖ beta`, and `beta` is whatever the
   server negotiates: 10 bytes on the AES-128/SHA-256 handshake, 54 on the
   other. Upstream hardcodes 54 everywhere (`compute_iv_mac`,
   `ConnectedParams`, the `beta` parse), so on a 10-byte server the IV is 20
   bytes and the proof can never match.
3. **The parameters have to ride on `clientinit`.** The proof signs
   `SHA256("30 08" ‖ generation ‖ IV) ‖ "MyTeamSpeakID"`. `clientinit` is the first
   command packet, so its generation is zero — which is what the official
   client, ts3java and huixiang all rely on. Sending the six on
   `updatemytsid` after the connection is up signs a challenge whose counter
   has already advanced, and the server refuses it with
   `invalid signature`. `clientinit` is built inside this crate, so a provider
   hook is the only way in from outside.

A git dependency cannot be edited; a fork would be a second repository to keep in
step. A path dependency is the only form where a fix sits next to its reason.

## What was changed, and where

Every edit is marked `Local change (tsbridge)` in the source.

| file | change |
|---|---|
| `tsproto/src/connection.rs` | `ConnectedParams::shared_iv` and its constructor take the negotiated length instead of `[u8; 64]` |
| `tsproto/src/algorithms.rs` | `compute_iv_mac` takes `beta: &[u8]` and returns `Vec<u8>`; `create_key_nonce`, `encrypt` and `decrypt` take `&[u8]` |
| `tsproto/src/client.rs` | the `beta` parse accepts 10 or 54 instead of only 54 |
| `utils/tsproto-structs/declarations/Messages.toml` | `ClientInit` gains six attributes and six `Field` entries (`myTeamspeakId`, `acTime`, `userPubKey`, `authSign`, `pubSign`, `pubSignCert`), so the generated struct carries them |
| `utils/ts-bookkeeping/build/MessageDeclarations.tt` | `InMessage::new_response` parses a reply that arrived with no command name, as a type the caller names |
| `utils/tsproto-structs/declarations/Messages.toml` | `ClientFind`, `PermGet`, `ServerInfoResponse` and `ServerSnapshotCreateResponse` gain declarations; `ServerInfo` was declared with no attributes, so its reply parsed to an empty struct |
| `tsclientlib/src/lib.rs` | `Connection::send_expecting` records the reply type against the `return_code` it writes, and the receive path parses a nameless packet only when a matching request is outstanding |
| `tsclientlib/src/lib.rs` | `ConnectOptions` gains a `MytsProvider` (an `Arc` of `Fn(&[u8]) -> Option<MytsParams>`) called with the IV while `clientinit` is assembled; `MytsParams` and its hand-written `Debug` live here, including `signed_badges` (the account's `CONFIG` badge UUIDs) which fills `client_signed_badges`. It also gains `version_text`/`platform_text` test hooks (unused in production) and `default_token`, which fills the `client_default_token` field upstream hardcoded to `""` |

The nameless-reply change is not about myTeamSpeak, but it is the same kind of
gap: upstream's generator only emits parse arms for messages that carry a
`notify` name, so every `response=true, notify=None` reply is dropped. That
covers `clientdbinfo`, `clientinfo`, `channelinfo`, `whoami`, `serverlist`,
`clientlist`, `channelfind`, `serverinfo` and a few more — a whole class of
commands a client cannot use. The fix is deliberately narrow: a nameless packet
is only accepted when a request recorded its `return_code`, so an unsolicited
one is still a parse error and nothing that used to be rejected is now accepted
by accident.

Not every such reply carries its `return_code` in the same place. `serverinfo`
puts the code in the separate `error id=0 msg=ok return_code=N` packet that
follows, and `serversnapshotcreate` sends a named body (`serversnapshot
version=3 data=…`) with no code at all. Matching only on a code found in the
body therefore never found either reply, and both timed out with the request
still outstanding. `parse_nameless` now falls back to the single outstanding
request when the body carries no code: the server answers in order, so with one
request waiting there is nothing else the packet could be. Two requests waiting
is still ambiguous and still rejected, which keeps an unsolicited packet a parse
error.

`serversnapshotdeploy` was listed in this table's client section, and it is not
a client command: a client connection is answered `invalid client type`, while the
same snapshot body deploys fine over ServerQuery. The line is commented out with
that reason next to it. A wrapper built from it was removed from
`crates/core/src` — it could never have worked, and the refusal only became
visible once refused writes started being reported.

The raw-body rule still applies to the query transport and is worth keeping: the
snapshot is the argument list the server itself produced, so wrapping it as
`virtualserver_snapshot=…` adds an `=` the server rejects, and escaping it double-escapes the
`\s` and `\p` it already contains. py-ts3 shipped that bug and documented it
(issue #49). It is not a client concern any more, but a query client would need
exactly that form.

The other `# TODO` entries in that section were probed on 3.13.9 and *are* client
commands: `permreset`, `servercreate`, `serverdelete`, `serverstart`, `serverstop`
and `serverprocessstop` each answer a permission refusal, not a transport one. The
`# TODO` marks upstream's uncertainty about the field sets, not about the transport,
and only `serversnapshotdeploy` turned out to be in the wrong section.

`ChannelPermList` was declared with `permid` required and no `permsid?`, unlike
the other four permission lists. That is why `channelpermissionlist` could never
return permission names: the field to carry them did not exist. It now matches
its siblings.

`instanceedit` and `clientdbedit` were both declared `attributes=[]`/`[cldbid]`
with a `TODO PROPERTIES` comment, which made the commands send a bare name that
the server accepts and ignores. The property sets come from py-ts3, whose
examples are `instanceedit serverinstance_filetransfer_port=1337` and
`clientdbedit cldbid=56 client_description=…`, and from the `instanceinfo` reply
which lists every `serverinstance_*` field. They are declared as optional
attributes here, since both commands send only the properties the caller sets.

`custominfo` and `customsearch` are the same gap from the other side. Both
requests are declared with a `notify` name, but neither reply carries a command
word on the wire, so neither had a parse arm — which is why the commands were
removed once. `CustomInfoResponse` and `CustomSearchResponse` declare the reply
body (`cldbid`, `ident`, `value`) so the nameless routing can reach them.

Four replies had no usable declaration at all: `ClientFind` did not exist,
`ServerInfo` existed with `attributes=[]`, and `permget` and
`serversnapshotcreate` had request entries but no reply types. The declarations
added here use the field sets the protocol comments in the same file document,
so a future upstream that fills them in should be compared against these rather
than assumed equivalent — the names are what the wire carries, and a wrong one
fails to parse rather than failing quietly.

`ServerSnapshotCreateResponse` was first declared with a single `snapshot` field.
That name never appears on the wire: the documented reply is `version=3 data=…`,
plus `salt=` when the snapshot is password protected. The declaration now says
`version`, `salt?`, `data`, and `crates/core/src/conn.rs` renames `data` to
`snapshot` only in the event it emits, so the UI contract is unchanged.

`InitServer` declared `virtualserver_filebase` as required. Neither 3.11 nor
3.13.9 sends it in `initserver` — it belongs to `serverinfo`, which is where the
field is documented — so the handshake reply failed to parse and the connection
died with `InitserverTimeout`, which looks exactly like a network problem. It is
now optional, so a server that does send it still gets the value. The general
form of this mistake is now checked offline: `crates/core/tests/
handshake_contract.rs` parses a captured `initserver` body from each version and
asserts every attribute declared required appears in it.

Nothing else was touched, so a future rebase onto a newer upstream is a small
merge rather than a rewrite. `Cargo.toml` of `tsclientlib` itself is unchanged:
the `unstable` feature is enabled from our root `Cargo.toml`.

## Evidence that it works

A local TeamSpeak 3.13.9 server, official binary, Linux and Windows builds:

```text
client connected 'probe'(id:69) using a myTeamSpeak ID from 127.0.0.1
```

The control run — the same path with one byte of `authSign` flipped — produces
`rejecting myteamspeakid: invalid signature`, so the server verifies rather than
ignores the proof.

## Re-vendoring

```sh
SRC=$(ls -d ~/.cargo/git/checkouts/tsclientlib-*/<rev>)
rm -rf vendor/tsclientlib
cp -r "$SRC"/{tsclientlib,tsproto,utils,Cargo.toml,LICENSE-APACHE,LICENSE-MIT,README.md} vendor/tsclientlib/
```

Then re-apply the changes above (all marked `Local change (tsbridge)` in the
source). `tools/fmt.sh` deliberately formats only our own crates: upstream uses
hard tabs and compressed parameters, and rewriting its style would make every
future rebase conflict in every file.
