# Identity strings

`tsbridge_identity` returns one string, and that string is what a shell stores
and hands back as `identity` on the next connect. This file is the contract for
that string: what it must look like, why, and what the tests pin.

Code: `crates/core/src/lib.rs::identity_to_ts_str`. Tests:
`crates/core/tests/identity_contract.rs`.

## The format

```
<counter>V<key>
```

`counter` is a decimal integer, `V` is a literal uppercase V, and `key` is the
obfuscated encoding of the private key. Two encodings of the key both parse
upstream, but only one is *ours* to emit:

| key part | what it is | who writes it |
|---|---|---|
| plain | `base64(tomcrypt DER)` | `tsproto`'s `to_ts()`; readable, not what a real client stores |
| **obfuscated** | XOR-obfuscated then base64 | **the official TeamSpeak client's `settings.db`, and us** |

`identity_to_ts_str` emits the obfuscated form. That is not cosmetic:

* A user migrating from the official client can paste its stored string in
  verbatim, and `new_from_str` accepts it.
* A string we report can be pasted back into that client without it deciding
  the identity is corrupt.
* Two live identities were decoded and re-encoded byte-for-byte during the
  myTeamSpeak research; the encoder here reproduces the stored strings exactly
  (`research/myts-login/explore/identity_doc_check.mjs`: 2/2 exact, and a
  tampered inner key no longer re-encodes to the stored string).

Upstream `import_str` tries plain base64 first, then obfuscated, so a shell that
already persisted the plain form from an older build keeps working. That
backwards compatibility is tested explicitly — do not break it.

## Parsing: do not split on the first `V`

The key part is base64, and base64's alphabet **contains `V`**. Splitting on
`strchr(.., 'V')` or `indexOf("V")` cuts the key in half and yields a garbage
counter. Anchor the prefix instead:

```js
/^(\d+)V/
```

The research implementation hit exactly this bug (`myts-identity.mjs`); it
silently produced wrong levels until the regex anchor replaced the split.

## What the obfuscation is

```text
out = bytes(key_text)
for i in 0..min(len,100):  out[i] ^= OBFUSCATION[i]        // 128-byte constant
tail = out[20:]
n    = index of NUL in tail, or tail.len
hash = sha1(out[20:20+n])
for i in 0..20:            out[i] ^= hash[i]
return base64(out)
```

Decoding is the same two XOR steps in the other order. The constant is
`b9dfaa7b…a0983e6e` (128 ASCII bytes, kept as `*b"..."` upstream). It is not a
secret — it ships inside `tsproto` and the client — it only stops casual
copy-paste of a private key.

## The DER inside

The plain form is a tomcrypt key blob, not a PKCS#8 or SPKI structure:

```text
30 <len>
  03 02 07 80        BIT STRING, 7 unused bits, 0x80 = private key present
  02 01 20           INTEGER 32
  02 <n> <X>         INTEGER X
  02 <n> <Y>         INTEGER Y
  02 <n> <priv>      INTEGER priv
```

The **public** form differs in one byte: `03 02 07 00`, no "private key
present" bit. Write `0x80` where the public encoder wants `0x00` and the UID
changes, which the server sees as a different user. Both encoders live in
`myts-identity.mjs::buildTomcryptDer` / `buildPublicTomcryptDer` and were checked
against `tsproto-types`' own output.

Note also that INTEGERs get a `0x00` prefix when the top bit is set (DER sign
padding) — a naive fixed-width writer produces a key the client will reject.

## UID

```text
uid = base64( sha1( ascii(to_ts(public_key)) ) )
```

Hash the **ASCII text** of the public tomcrypt blob, not its bytes, and not the
private key. `tsproto`'s `EccKeyPubP256::get_uid` does exactly this; getting it
wrong yields a UID the server has never seen.

## The counter, and the golden value

`counter` is a hash-cash level: the client scans offsets until the SHA-1 level
of the public key reaches 8. Inputs without a counter therefore get one
computed for them, deterministically.

The test fixture is `tsproto-types`' public `TEST_PRIV_KEY`, and
`upgrade_level(8)` picks **354** for it. Pinning that number turns any change in
the hash-cash algorithm into a test failure instead of a silent identity change.

```text
identity_to_ts_str(fixture) ==
354VOfydZwzLwCCWm3smUImF+mI+6W1fV1lhW1UpASZABXEQe1h0XnoPAA8ZEABhJXoDSF4Id2FYdj82Un0GfFZ5X1Nce18DCUoFDCFJBlcSCgN6AmNCT0AGVlYBcUUBLGMBLGRFcC81MENJQThNNW5tREJubURNL2daLy80QUFBQUFBQUFBQUFBQUFBQUFBQUFaUnpPSQ==
```

The fixture's DER was independently confirmed to round-trip through the
canonical re-encoder, and `x/y == pub`, so the golden value is not circular.

## Three tests, and what each protects

| test | fails when |
|---|---|
| `identity_string_uses_the_obfuscated_form` | someone switches back to plain output, or the hash-cash counter drifts |
| `identity_string_survives_a_round_trip` | emitting changes the key/UID/counter, i.e. storage would drift across launches |
| `plain_der_input_is_still_accepted` | old persisted plain-form identities stop parsing |

```sh
cargo test -p tsbridge-core
cargo clippy -p tsbridge-core --all-targets      # must stay silent
```

## Scope: identity is not the myTeamSpeak account key

These are two unrelated secrets and a shell should not conflate them.

| | what it is | where it comes from |
|---|---|---|
| TS3 identity | P-256 private key + hash-cash counter, gives the server-visible UID | generated locally on first launch |
| myTeamSpeak account key | 32 B AES key, unwrapped from `login.key` with the account's wrapping key | server login response |

The account key does not contain the identity private key. See
`docs/myteamspeak.md` for the account side.
