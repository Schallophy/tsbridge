# myTeamSpeak account side

The account-side findings that matter to a client: the login key chain, and the
synchronisation items (bookmarks, identities, addons, config) that a client is
expected to keep in step with the server. This is a contract summary; the
implementation is `crates/core/src/account/`, and the reference it was ported
from is `research/myts-login` (`myts-login.mjs`, `myts-crypto.mjs`,
`myts-sync.mjs`).

Everything below is implemented. The account side lives on the handle rather than
on the connection, so it works before the first join and keeps working when a
server connection comes and goes; commands are listed in `include/tsbridge.h` and
results arrive in `snapshot.account` plus one `account_status` event per command.

**This is a standalone client.** It signs in with an email and password of its
own, and the item key comes out of the login response. The one thing it ever uses
an official client's `settings.db` for is an optional `fromTs3Client` *migration*
of an existing login — never for item content, and never by probing for the file.

## Two secrets, not one

| | what it is | where it comes from |
|---|---|---|
| TS3 identity | P-256 private key + hash-cash counter → server-visible UID | generated locally, see [identity.md](identity.md) |
| myTeamSpeak account key | 32 B AES key | unwrapped from the login response |

They are unrelated. The account key does **not** contain the identity private
key, and knowing one tells you nothing about the other.

## Login key chain

The login response carries the account key already wrapped:

```
login response `key` (sjcl blob: ver=2 | tag16 | nonce12 | ct)
        │
        └── AES-256-GCM unwrap with the wrapper ──► account key (32 B)
```

The wrapper is the only question, and there are two ways to have one:

| wrapper | when it exists | measured? |
|---|---|---|
| `PBKDF2-HMAC-SHA512(password, lower(email) + "ts3Encryption" + password, 10 000, 256)` | whenever the user typed a password | **source** (see below) |
| `settings.db` `Account.field5` (32 B) | an installed client has already signed in | yes, live |

* `field5` is the **wrapper**, not the account key. The two are different values;
  treating them as one is a mistake the research initially made and then fixed.
* The sjcl blob puts the GCM **tag before** the nonce, and tags are not
  interchangeable with a plain `ciphertext||tag` layout: the decrypt input has to
  be reassembled as `ct || tag`.
* Re-wrapping (change password / email) is: unwrap with the old AES key, wrap
  with the new one. That is all `generateKey` does.
* The login credential hash is PBKDF2-HMAC-SHA512 over
  `lower(email) + "ts3Login" + password`, 10 000 iterations, 384 bits. A
  remembered login can therefore be reused without the plaintext password.

**Where the password sits in the wrapper derivation matters, and the web helper
reads backwards.** The sibling helper `hashedPassword(p, N)` puts the password
first and the email in the salt; `hashedEncriptionPassword(p, N)` *names* its
parameters the same way but computes `PBKDF2(secret = N, salt = p + …)`. Following
the parameter names therefore puts the email in the KDF secret, which is a
different 32 bytes.

The open-source `ts3java` client settles it: for `accountKey` it derives

```
salt = ascii_lower(email) + "ts3Encryption" + password
key  = PBKDF2-HMAC-SHA512(secret = password, salt, 10 000, 32)
```

— the **password is the KDF secret**, the email is in the salt, lower-cased.
Lowercasing is ASCII-only and bytewise, so a non-ASCII address is not case-folded
the way Unicode rules would.

`ts3java` also implements the item cipher as a **16-byte little-endian counter**
that carries across the whole header, which is the rule this library uses. The
32-bit-word reading passes the live items too (no live header is close enough to
`0xff` for a multi-block item to cross the carry), so the width was settled by the
source, not by the data — and the fixed vector in `tests/account_contract.rs` uses
a header that wraps on the second block so the distinction cannot regress.

*Verification rule:* the GCM tag check is the only witness. Never trust a decrypted
result that has not passed it, and keep `field5` as a fallback for a migrated
login. The library tries a short ordered list (canonical first) rather than one
guess, so a login does not fail because of an argument-order assumption.

## Token / session

`push_token` is a PS512 JWT whose payload is the client session id as 16 raw
bytes (not UTF-8, not a uuid string). Comparing it against the *web* session id
gives a false negative; compare it against `Account_Data.field50`.

## Sync items

`SynchronizationService` has exactly two methods and they are easy to confuse:

| method | semantics |
|---|---|
| `requestServerItems` | pure read |
| `synchronizeItems` | **upsert — a write** |

They share the same request/reply messages and the reply carries a `SyncStatus`
in both cases. Identical schema does **not** mean identical semantics. This is
the single most expensive lesson in the research: treating the second one as a
diff query emptied every item blob on a real account.

### Write shape (verified field by field)

```
class.version          = the server's *current* value (missing → whole request 103)
detail                 = item_uuid + item_version + item_blob   (both, always)
globalversion          = required; the stored value is replaced by the server, never honoured
item_delte_on_server   must not appear in the same detail as item_version
one detail per request is the reliable form
```

Consequences worth internalising:

* **version without blob = erase the content.** Not a no-op.
* an unknown `uuid` in a detail **creates** an item.
* `globalversion` cannot be rolled back: any write changes it, and sending the
  old one is ignored.
* delete is a separate request: `uuid` + `item_delte_on_server=1`, no version.

Back up before every write. `status=300` on the reply means accepted; the reply
is only 41 bytes.

### Read shape: cursors make it incremental

The same request type is also a **delta query**, and that is what a client with
any local state should use:

| request | reply |
|---|---|
| no class cursors | every class whole — 25 items, 8862 B |
| every cursor current | no class messages at all — 59 B |
| one class's cursor stale | that class whole (8 items), others omitted — 3768 B |
| `globalversion` stale, classes current | nothing; it does not force a refresh |

Measured read-only against the reference account. Two consequences:

* **A class absent from the reply means "unchanged", not "empty".** Folding a
  delta in must replace only the classes it names; treating an omission as a
  deletion wipes the account.
* **A class that appears must replace that class wholesale.** The server sends
  its complete current contents, so keeping the old items alongside resurrects
  anything deleted elsewhere.

The cursor is the **class** version, not a per-item one: a class moves as a
whole and the server never sends partial class contents.

### Item shape: `manipulated` and `last_known_version`

`Item_Data` field 4 is `Manipulation_Flag`, field 5 is `last_known_version`. A
new item and an edited item are not the same shape, and copying a template's
values into a new item produces an item that lies about its history:

| state | f4 | f5 |
|---|---|---|
| created, never uploaded | `ITEM_ADDED(0)` | `ffffffff-…-ffffffff` (all-ones) |
| uploaded as a change | `ITEM_NOT_MANIPULATED(3)` | the version it replaced |
| as stored by the server | `3` (9 of 12 wrapped items), occasionally `0`/`1`/absent | usually a real uuid |

The all-ones value is taken from the official client's own rows that it created
on this machine and never uploaded (`03d4b1c0`, `19a2b805`), which are the only
ground truth for "a new item" — they carry `f4 = 0` and exactly that string.

Note what the official client writes on a *change*: `manipulated = 3`, not
`ITEM_CHANGED(1)`. It uploads committed state and lets the cursors carry the
change. An implementation that invents `1` is producing a blob no client of
theirs ever writes.

### What can be rewritten, and with what

The deciding factor is whether a blob carries an envelope, and whether this
session holds the account key. There is no third state:

| tier | shape | capability |
|---|---|---|
| `plaintext` | blob *is* the bare `Item_Data` | rewrite anything, any length, no key needed |
| `encrypted` | `header16 \|\| ct \|\| sha512(plaintext)` | rewrite anything, any length, with the account key |
| `locked` | encrypted, and this session has no usable account key | read/rewrite refused until a working login |

In the reference account: 13 `plaintext` (all ADD_ON), 12 `encrypted`
(8 bookmarks, 2 identities, 1 hotkey profile, 1 config), 0 locked.

Neither writable tier has a length ceiling — there is no length ceiling at all.
The item cipher is a stream cipher over the whole item, so `plaintext` and
`encrypted` items take any content of any size; only `locked` items are limited,
and only because this session lacks the key.

**The item key is the account key.** That is the finding that makes a standalone
client possible: nothing needs to be recovered from the official client's
database. The cipher is

```
blob       = header16 || ct || sha512(plaintext)
plaintext  = AES-256-CTR(accountKey, header)(ct)
```

with the counter being the **whole 16-byte header read little-endian**, incremented
per 16-byte block with the carry rippling upward. The account key is the 32 B that
comes back in the login response as `key`, once its sjcl wrapper is removed.

Verification, not inspection: the trailing `sha512` is a check over the
plaintext, so a wrong key or a wrong counter rule fails it. At the time of writing
`research/myts-login/explore/itemcipher_check.mjs` passes 16/16 — 12/12 wrapped
items decrypt with the trailer verifying, 12/12 re-encrypt byte-identically,
lengths from 1 B to 5 kB round-trip, and a key corrupted in one byte verifies
0/12.

The counter **width** is not observable from these items alone: a 32-bit word-0
counter and a 128-bit little-endian one agree until a carry leaves byte 3, and no
live header is close enough to `0xff` for a multi-block item to cross that. The
128-bit rule comes from the open-source `ts3java` client, which implements the
increment byte-by-byte across all 16 bytes
(`explore/itemcipher_counter_width.mjs` shows both rules pass 12/12 on the live
data, and that the fixed test vector distinguishes them).

### What this replaced, and why the earlier answer was wrong

The research first concluded the item key was unrecoverable, and built a
three-tier model around that belief: `plaintext`, `keystream` (recover the
keystream by XORing the official client's local row against the server blob),
and `opaque` (replay or delete only). A new bookmark was capped by the longest
same-class keystream (367 B of plaintext).

The key was in hand the whole time. The sweep that "proved" otherwise used
node's `aes-256-ctr`, which is a **128-bit big-endian** counter; the real cipher
increments a **little-endian** one. Block 0 is identical either way, so the search
appeared to be testing the right key and failing after the first block — 130 152
PBKDF2 attempts, all discarded.

That model is gone from the code: `Capability` is now `plaintext` / `encrypted` /
`locked` / `empty`, there is no keystream recovery, no donor, and no length
ceilings. The old `keystream` and `opaque` wording survives only in this section
as a record of what was believed and why.

### Operational limits worth knowing before writing anything

* **A new item needs a template, not a donor.** Every field this code does not
  know how to fill (profile references, flags, defaults) comes from an existing
  item of the same class, so the result has the shape the real client writes.
  Any readable item of the class will do; length is no longer a constraint.
* **`plaintext` items still carry an envelope-free `Item_Data`, and its `f4`
  field is not guaranteed to match any local copy.** In the reference account the
  server had `ITEM_ADDED(0)` for all 13 addons while the local rows had
  `ITEM_NOT_MANIPULATED(3)` for 11 of them. Rewriting an addon must preserve the
  *server's* value, not a stale local one, or the item's meaning changes. This is
  why an add-on edit reads the item from the server rather than from any cache.
* **A header must not be reused for different content.** It is the counter base;
  two plaintexts under one header leak their XOR to anyone holding both blobs.
  `ItemCipher::seal` mints a fresh random 16-byte header every time.

## Envelope, if anyone speaks this transport directly

```
POST <basePath>
Content-Type: application/ts3cloud
User-Agent: cpp-httplib/0.11.1

body = [varint byte-length of method name][method name UTF-8][payload protobuf]
```

It is **not** gRPC, despite the shape. A wrong length prefix is a bare 500; an
unknown name is a 200 carrying `status=100`. Replies are labelled
`application/json` but the bytes are protobuf.

Service → path: `/user`, `/session` (+ `/authentication` for login/token
methods), `/synchronization`, `/tschat`, `/addon`, `/integration`,
`/messenger`.

## How the implementation behaves

Decision points a shell has to rely on, and the reason each is the way it is:

* **Nothing blocks the caller.** Every command starts a task on the account's own
  runtime and returns as soon as it is accepted. The result arrives in
  `snapshot.account` and in one `account_status` event. A 25-second HTTP call
  inside `exec` would freeze a UI thread on a phone.
* **One command at a time.** A second command while one is running is rejected
  with the name of the running one. Two overlapping login/write sequences would
  race each other's `globalversion`, and the loser's write would be accepted with
  the wrong state.
* **A failed login keeps the previous one.** A re-login that comes back wrong must
  not silently sign a user out of a session that still works.
* **The session is re-proved before success is reported.** `/client/login` can
  answer 200 with a session that is already dead; `/me` is called before the login
  is reported, so "logged in" means "the session was just used".
* **Wrapper candidates, in order.** A plaintext password yields a short ordered
  list (canonical `ts3Encryption` shape first, the web helper's argument order
  after it as a fallback); a `fromTs3Client` migration adds the wrapper stored in
  an installed client's `settings.db` **last**, so a password-derived wrapper is
  credited when it is the one that worked. The GCM tag decides every candidate;
  a failure discards it, it does not fail the login. A normal login never touches
  another application's database, and an unwrappable key is a warning rather than
  an error because reads need only the session.
* **Every write is backed up, then verified.** The backup is taken before the
  request and the item is re-read afterwards and compared byte for byte. `300`
  alone is not reported as success: "the server said yes" and "the stored bytes
  are what was meant" are different claims, and only the second one is useful.
* **A rejected or mismatched write is an error, never a warning.** The report
  says what happened and names the backup to replay.
* **Restore is one item per request.** Batching is how a single collision becomes
  "some of it was applied and nobody knows which".
* **A login can be remembered without keeping the password.** A shell that names
  a `credentialFile` gets "stay signed in": the login writes the credential hash
  the server just accepted plus the account key, never the plaintext. A bare
  `account_login` (no email, no password) then signs in from that file, and
  `account_logout` deletes it. The key is stored because a hash login cannot
  derive a wrapper — without it the second launch would read the item list with
  every item `locked`. The path is opt-in: a session that was not given one writes
  nothing.
* **`settings.db` is optional, and only read.** The only thing it is used for is
  importing a login from an installed client; item content never comes from it.
  The reader parses the file's bytes itself (no C SQLite, no `rusqlite`) and has no
  write path at all, so "the other client's database is untouched" is structural
  rather than a habit. Nothing probes for the file: a client that never imports
  never opens one.
* **A login is also a read.** The command finishes with the item list filled in,
  so a shell shows bookmarks immediately instead of a blank pane until it asks
  again. A failure of that read is reported *with* the login's success — the
  session is valid either way.
* **An expired session is replaced, not reported.** The server answers a dead
  session with `status=102 SESSION_EXPIRED` and no items. Every read path —
  `sync_list`, `account_refresh`, a backup, a write's cursor check and its
  verification — goes through one helper that sees that code, signs in again with
  the credential hash the previous login already accepted, and repeats the read.
  The user never sees "session expired". A write does the same once, re-sending
  the same payload on the new session; `102` is a refusal, so the first attempt
  changed nothing and the retry cannot double-apply. **One retry, never a loop**:
  a credential the server refuses (password changed, 2FA now required) comes back
  as that error. The renewal carries the account key over, because a hash login
  cannot derive a wrapper and every item would otherwise turn `locked`.
* **Two user agents, deliberately.** The REST surface (`www.myteamspeak.com/api`)
  and the protobuf surface (`clientapi.myteamspeak.com`) sit behind different
  edges. The cloud call must claim `cpp-httplib/0.11.1`; sending that string to
  the REST surface gets an edge error instead of a login reply. The agent belongs
  to the request, not to the client, and copying one to the other is a login that
  mysteriously answers 503.

## Announcing the myTeamSpeak ID to a server

When a bookmark has "Enable myTeamSpeak features" on — `send_mytsid_on_server`
(f22), **true by default** — the official client sends six extra `clientinit`
parameters, and the server then shows the account's name, badge and myTS ID:

| parameter | value | source |
|---|---|---|
| `myTeamspeakId` | base64 of the 33-byte ID (`01 20 …`) | login `mytsIdData.myTeamspeakId` |
| `acTime` | the creation time, halves swapped, in decimal | `accountCreationTime` |
| `userPubKey` | base64, 32 B | `userPublicKey` |
| `pubSign` | base64, 64 B | first half of `publicSignature` |
| `pubSignCert` | base64, 112 B | second half of `publicSignature` (176 B total) |
| `authSign` | base64, 64 B **R ‖ S** | computed per connection, below |

`acTime` is not the number you read: `1790376353` goes out as
`11671560475690139648`, because the wire form is the little-endian byte layout
read back as a big-endian u64. `sync::ac_time` is that swap.

### Where the signing key comes from

`authSign` needs the account's **Ed25519 private key**, and that arrives in the
login reply as `mytsIdData.userPrivateKey.encryptedUserPrivateKey` — in the
**item envelope**, not a bespoke wrap:

```text
blob   = header16 ‖ ciphertext32 ‖ sha512(scalar)64
scalar = AES-256-CTR(accountKey, header)(ciphertext)
```

That is `ItemCipher::open` unchanged, and the trailing digest is what proves the
key was right. The scalar is **raw** — reduced mod L, already the private key —
so a seed-based signer cannot be used: `ed25519-dalek`'s `SigningKey` would hash
and clamp it again and sign with a different key.

Why this matters concretely: with the plaintext password, `accountKey` opens the
blob, the payload reproduces `userPublicKey` through `scalar · B`, and the
account's `authSign` verifies. That is measured, not inferred
(`explore/password_unwrap_userkey.mjs`). Before the password arrived, the same
blob was attacked with ~780 layouts and refused, so the path is now pinned from
both ends.

### What is signed

```text
C  = SHA256("30 08 00 00 00 00" ‖ sharedIV)     server direction, type 8, gen 0
M  = C ‖ "MyTeamSpeakID"                       45 bytes, no NUL terminator
sig= R ‖ S,  standard Ed25519 equation          S·B = R + k·A
   r = SHA512(a ‖ M) mod L                      deterministic, seeded by the scalar
   R = r·B,  k = SHA512(R ‖ A ‖ M) mod L,  S = r + k·a
```

`sharedIV` is the 64-byte value the handshake mixes in
(`SHA512(ecdh point) XOR alpha‖beta`), so the signature is **per connection** and
cannot be cached or replayed. `MytsIdentity::params(&shared_iv)` is the entry
point; a shell calls it once the connection's IV is known.

The nonce rule is the one thing that differs from RFC 8032: `r` is seeded by the
raw scalar rather than by a 32-byte seed. The signature still satisfies the
standard verification equation, which is what a server checks —
`mytsid::verify_signature` computes exactly that, and the tests assert a
generated signature passes it and a single flipped bit fails.

### Limits

* **The identity is not remembered.** It lives inside `Account` in memory and is
  carried across a session renewal, but it is not written to the credential
  file: that file already holds a credential, and a second copy of a private key
  is not something to add to it.
* **A login that could not open the blob simply has no ID.** `account.mytsId` is
  empty and `mytsParams` returns `None`. That is reported, not fatal: everything
  else about the account still works, and a server just sees an ordinary client.
* **It is accepted, and the earlier failures were a timing bug rather than a
  crypto one.** A local TeamSpeak 3.13.9 server's own log says:

  ```text
  VirtualServerBase | client connected 'probe'(id:69) using a myTeamSpeak ID from 127.0.0.1
  ```

  and the client's `client_myteamspeak_id` is populated when queried. The
  control run — the same path with one byte of `authSign` flipped — gets
  `rejecting myteamspeakid: invalid signature`, so the server really does verify
  the proof; it is not merely ignoring it.

  What was wrong: the six parameters were being sent on `updatemytsid`, after the
  connection was up. The proof signs
  `SHA256("30 08" ‖ generation ‖ IV) ‖ "MyTeamSpeakID"`, and the generation
  counter has already advanced by then, so it signed a challenge the server
  never computes. Every reference client — the official 3.6.2 client, ts3java,
  and huixiang — sends the six on **`clientinit`**, the first command packet,
  where the generation is provably zero.

  That is why the signature verified offline the whole time: the algorithm was
  right, and only the counter in the message was stale. The fix is in the
  vendored `tsclientlib` (see `vendor/tsclientlib/VENDORING.md`): `ConnectOptions`
  takes a provider that is called with the connection's IV while `clientinit` is
  assembled.

  Order matters for a shell: sign in first, then connect, carrying the proof —
  `Session::myts_provider()` from a signed-in session, passed to
  `Session::connect_with_myts`. That is the official client's order too.

  A proof that is not recovered (locked account, no myTeamSpeak ID) simply
  leaves `clientinit` as upstream sends it: an ordinary client, no badge.

### What each server version actually negotiates

Measured, not assumed: a probe connects with this stack and reads the IV the
server hands out (`tools/probe-iv.sh`). The IV is `alpha ‖ beta`, so **64 bytes
means `beta` 54** and 20 means `beta` 10.

| server | IV | `beta` | note |
|---|---|---|---|
| 3.13.9 | 64 B | 54 | the tested path; the myTeamSpeak proof is accepted |
| 3.13.8 | 64 B | 54 | same |
| 3.13.7 | 64 B | 54 | same |
| 3.13.0, 3.12.0, 3.11.0 | — | — | **could not be measured**: their bundled default license has expired ("The default license has expired. Please use the latest server version"), so they refuse to start at all. Their binaries do carry `initivexpand2`, `beta`, `clientinitiv` and the `encryption_ciphers` fields, so they speak the same handshake; the mode itself is unverified. |
| **TS6 6.0.0-beta14** | 64 B | 54 | same mode as TS3, and the proof is accepted (see below) |

So across the versions that could be run — **including TeamSpeak 6** — the mode
is **uniform**: every one of them negotiates the 64-byte IV.

### TeamSpeak 6

A TeamSpeak 6 server (official `teamspeak6-server` 6.0.0-beta14) accepts this
client's proof too. It does not print the TS3-style `using a myTeamSpeak ID`
line, so the evidence is the client field plus a control run:

| run | `client_myteamspeak_id` |
|---|---|
| valid `authSign` | `Af26KB769vdVm93FU+0scgpugGgCMoltCo/vkghPJ2WW` (the account's ID) |
| one byte of `authSign` flipped | empty |

That is a real check, not a coincidence: a corrupted proof is dropped, a valid
one is stored and would be announced to other clients. The handshake is
therefore the same on both products — the "TS6 uses something different" idea
that motivated the 20-byte work does not hold for beta14. The variable-length
support stays as an insurance policy, not because TS6 needs it.

Worth knowing when testing TS6: it negotiates the same 64-byte IV, it runs a
dedicated `mytsid_io` thread for this feature, and its server query listens on
HTTP (10080) by default rather than TCP 10011 — `--query-http-enable` plus an
API key, or `clientinfo` to read the field back.

Nothing in the code depends on the mode being 64 bytes, which is the point of the
vendor change: the 20-byte path is implemented so a server that chooses the other
mode still works, rather than failing later with a signature that cannot match.

### Which server variations the proof survives

The signature is built from two server-chosen values: the **IV** (length and
contents) and the **generation** in the challenge prefix. Both are listed here
with what actually happens, so a failure can be attributed instead of guessed at.

| variation | what we do | evidence |
|---|---|---|
| **64-byte IV** (`beta` 54) | the tested path | accepted by a local 3.13.9: `client connected … using a myTeamSpeak ID` |
| **20-byte IV** (`beta` 10) | supported: the vendor change accepts 10 or 54, and `challenge` takes `&[u8]` | pinned by `the_challenge_follows_the_negotiated_iv_length`; **never seen live** — 3.13.9 negotiates 54 |
| any other IV length | rejected at the handshake, before a proof is built | `beta` is validated as 10 or 54 |
| **generation ≠ 0** | impossible on this path: the proof rides on `clientinit`, the first command packet | that is why the earlier `updatemytsid` attempt failed |
| **different packet type / direction** | not configurable; the prefix is fixed `30 08` | official client, ts3java and huixiang all send it there |

Two variations are outside this client's reach entirely:

* **A negotiated cipher suite other than EAX/AES-128.** TS6's control channel
  advertises suites (`virtualserver_encryption_ciphers`,
  `client_encryption_ciphers`) and ts3java notes a SHA-512 mode with a 32-byte
  key and 32-byte nonce, which would make the challenge 77 bytes instead of 45.
  `tsclientlib` has exactly one code path (`Eax<Aes128>`, `U16` key/nonce), so on
  such a server the *connection itself* would not come up — not the proof. That
  is a protocol-stack limitation, not a signature one, and it is why the upstream
  README says TS6 is unsupported.
* **A server that does not verify proofs at all.** Then nothing is sent that the
  server reads, which is indistinguishable from success; the badge simply does
  not appear.

If a server ever rejects a proof, the log line names the reason
(`data is invalid` / `invalid signature` / `invalid public signature` /
`certificate error …` / `revoke list out of date`), and the first two are
distinguishable: the corrupted-`authSign` control run produces
`invalid signature`, which is the only one this code can cause.

## Where an item sits

Two `Item_Data` fields give the account its shape, and both are easy to
misread:

| field | what it is | live values |
|---|---|---|
| `parent` (f7) | the `ITEM_FOLDER` this item is in, empty at the top level | present, length 0, for all 25 |
| `sort_order` (f8) | **the uuid of the sibling before this one**, empty for the first | present, length 0, for the plaintext rows |

`sort_order` is a **link, not a rank**. The reference account's eight bookmarks
chain like this:

```text
localhost      sort_order = ""
Schallophy's   sort_order = fcfe1a38…   (localhost)
Daiso          sort_order = 973984d8…   (Schallophy's)
Woops'         sort_order = cad3333c…   (Daiso)
```

Reading it as a number, or sorting the list by it, reorders the user's bookmarks.
The order is only recoverable by following the links, which is what
`sync::order_by_sort_order` does — including on a **cycle** (it stops rather
than loops), on a **link to an item outside the list** (that item becomes a chain
head rather than being dropped), and on **leftovers** (anything the walk did not
reach is appended, because losing a bookmark is worse than showing it last).

**Folders are class 6, and their payload is field 22**:

```proto
message Item_Folder {
  string folder_name = 1;
  Item_Class folder_type = 2;   // the class this folder groups
}
```

Nothing here nests folders: a folder of folders is another folder whose
`parent` points at the first. A folder's `folder_type` is kept even when it
names a class this build does not know — the number is reported rather than
guessed at, which is the only sane way to meet a TS6 class 8 (see the limits
below).

`sync::hierarchy` turns `parent` + `sort_order` into a pre-order list with a
depth per node. `snapshot.account.hierarchy` is that list, so an importer does
not have to rebuild the tree and a UI does not have to guess at indentation. An
item whose content cannot be read (a `locked` blob) has no readable `parent`,
so it goes into `unplaced` instead of being quietly put at the top level — a
flattened import is the failure this exists to prevent.

## Comparing a local copy against the account

`sync_merge` answers the question item 4's cursor check cannot: *whose* change is
this? It is a **three-way compare** — the last agreement, the local copy, the
server — and it **reports**, never applies. A client that picked a side on its own
is how another machine's edit disappears, which is the failure this exists to
prevent.

The third input is a **baseline** (`baselineFile`, default
`%LOCALAPPDATA%\tsbridge\myteamspeak-sync.json`). Two rules make it work:

* **Digests, never content.** Per item, one `sha256` per field. A baseline that
  stored plaintext would be a second copy of every bookmark password in a file
  nobody thinks of as sensitive; a digest can say "field 7 changed" and nothing
  else.
* **Only the stable projection.** `sync_version_uuid` (f3), `manipulated` (f4),
  `last_known_version` (f5) and `timestamp` (f9) are revision bookkeeping: the
  server rewrites them on every store even when nobody edited anything. They are
  excluded, or every write by any client would report a conflict.

The compare produces, per item, one of five actions:

| action | when | who acts |
|---|---|---|
| `inSync` | both sides hold the same bytes | nobody |
| `push` | only the local side differs | the local copy goes to the server |
| `pull` | only the server differs | the server's copy comes back |
| `merge` | both differ, on *different* fields | the union is built, see below |
| `conflict` | both differ, on the *same* field | a human decides |

Each differing field is named with a label (`name`, `address`, `port`, …) so a
UI does not have to show `bookmark.2`. Agreement is a **value** comparison, not a
"both changed" one: two machines making the same edit is `inSync`, and one side
moving while the other already had that value is also `inSync`.

A `merge` is built from bytes, not from digests: the local plaintext is the base,
and every field only the *server* changed is copied in by `set_raw_field` — the
other side's encoded bytes, so a field this code has no label for still round-trips
exactly. A `conflict` never produces a merged message.

**What is recorded is what both sides already agree on.** A locally-added
bookmark is `push`, not agreement: recording it would make the next compare read
"the server removed it" and propose deleting the very thing waiting to be
uploaded. That is the one failure this rule prevents, and it is why the baseline is
narrower than "the current server state".

The baseline also stores the **cursors** (`globalversion` + per-class) that were
current when it was recorded. They are used for one thing only — answering "did
anything move while we were away" without inspecting items. They are deliberately
**not** used to ask for a partial read: a baseline holds digests rather than items,
so a reply that omitted a class would have to be read as *that class was deleted*,
which is the misreading `SyncState::apply` exists to prevent.

## Testing without an account

`tests/replay_contract.rs` stands up a `127.0.0.1` server and drives the real
login, read, decrypt and write paths over it — the part that pure-function tests
cannot reach. The server is a *reconstruction* in the sense `ts3java`'s harness
uses: the reply is rebuilt to the capture's shape (eight classes, 25 items,
8/2/1/13/1, three classes present but empty, 13 plaintext and 12 sealed), but
every uuid, version and string is synthesised and re-sealed under a throwaway
key, so no captured account data is in the repository. It also models a session
that expires on demand, which is how the transparent re-login is tested instead
of waited for.

Two properties make this safe to keep in CI:

* **Plain HTTP is refused unless a test opts in.** `Endpoints` defaults to
  `allow_plain_http: false`, and every REST and cloud call checks it before
  sending: a session id and a credential hash are bearer credentials, and "the
  base URL happened to start with http" is not a reason to hand them to the
  network. The recorder sets the flag explicitly, so the exception is visible in
  the one place it exists.
* **The credential is not reachable from outside the module.** `Account` keeps
  the credential hash it was created with, in memory only, behind a private field;
  the only accessor is `can_renew()`. `Debug` for `Account` and for the
  credential type prints `<redacted>` in place of both the session and the hash,
  because a stray `{:?}` in a log is exactly how a bearer token escapes.

## Known limits

These are behaviours, not bugs to be fixed later by guessing:

* **The password-only wrapper is sourced, not measured on this account.** The
  derivation follows the open-source `ts3java` client, which is verified code for
  this exact protocol; the reference account here has never been logged in with a
  plaintext password, so the value has not been observed unwrapping `key` on *this*
  account. The candidate list makes a wrong assumption recoverable rather than
  fatal, and a `fromTs3Client` migration remains the guaranteed route. If a login
  reports `locked` items, the event carries the reason and the login itself still
  succeeded.
* **A remembered login is a credential file, with the same trust as `settings.db`.**
  Whoever reads it can act as the account until the password changes. On Unix it
  is written `0600`; on Windows the protection is the per-user directory
  (`%LOCALAPPDATA%\tsbridge\account.json`), because a fixed ACL would need a
  dependency this crate does not carry. A shell that would rather not keep one
  simply leaves `credentialFile` unset.
* **A write checks the cursors before sending.** `synchronizeItems` accepts a
  stale `globalversion` and overwrites, so a write built from an older snapshot
  would silently replace another client's change. `execute_write` re-reads and
  compares first, and refuses with "the account changed since this was read;
  read again and retry". This is a window, not a lock: two clients can still race
  between the check and the request, and the server offers no way to close that.
* **There is no captured vector for a non-empty folder or a real `parent`.**
  The reference account's class 6 came back present but empty, and every `parent`
  and `sort_order` on its 25 items was a zero-length string. The bytes the tests
  pin are therefore *constructed from the schema*
  (`harvest/proto/schema-full.proto`: `Item_Folder` at 22, `parent` at 7,
  `sort_order` at 8), not captured — the same standing as the class-8/TS6 rows.
  What *is* captured is the chain: the eight bookmarks' `sort_order` values are
  the ones the local database holds, so the link-not-rank rule and the cycle
  handling are pinned against real data.
* **The myTS identity signing key is not locally derivable.** `authSign` needs
  the Ed25519 key in `mytsIdData.userPrivateKey.encryptedUserPrivateKey` (112 B).
  With the plaintext password in hand it was attacked with 779 layouts across
  every key this account derives — GCM, CTR, CBC, the protocol's own
  `header16‖ct‖sha512` envelope, and every blob the client's `settings.db` holds —
  and none opens to a seed that reproduces the published `userPublicKey`
  (`explore/GOAL8_STATUS.md`). So the wrapper is not a password derivation. Signing
  needs either a captured `clientinit` from a real client (to verify the algorithm
  against real bytes) or publishing a fresh public key with
  `setNewUserPublicKey`, which is a **write** to the account and invalidates the
  current signing identity.
* **A renewal is only as good as the credential.** `Account::can_renew` is false
  only for an account with no credential (a session supplied from somewhere else).
  A remembered credential also ages: it is the hash of the password at the time of
  the last password login, so after a password change every renewal fails with
  "the server rejected the login". That is a real limit, not an oversight — the
  client cannot invent a new credential — and the fix is one `account_login` with
  the new password.
* **No long-lived connection is involved.** The login is a bearer token: no
  heartbeat, no refresh timer, no socket. A session used 52 minutes after login,
  with nothing happening in between, still answers `/me` with 200. "Survives a
  reconnect" in this document means a TeamSpeak *server* connection coming and
  going underneath an account that never noticed.

