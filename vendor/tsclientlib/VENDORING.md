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
| `tsclientlib/src/lib.rs` | `ConnectOptions` gains a `MytsProvider` (an `Arc` of `Fn(&[u8]) -> Option<MytsParams>`) called with the IV while `clientinit` is assembled; `MytsParams` and its hand-written `Debug` live here, including `signed_badges` (the account's `CONFIG` badge UUIDs) which fills `client_signed_badges`. It also gains `version_text`/`platform_text` test hooks (unused in production) and `default_token`, which fills the `client_default_token` field upstream hardcoded to `""` |

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
