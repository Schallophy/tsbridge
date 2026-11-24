//! The myTeamSpeak ID: the six `clientinit` parameters that make a server show
//! the account's name, badge and myTS ID.
//!
//! The one non-obvious part is `authSign`. It is a **standard Ed25519
//! signature**, but over a per-connection challenge, and made from the account's
//! **raw secret scalar** rather than from a 32-byte seed — which is why
//! `ed25519-dalek`'s `SigningKey` cannot be used: it would hash and clamp the
//! scalar again and sign with a different key.
//!
//! The scalar arrives in the login reply, inside the same envelope every
//! synchronisation item uses:
//!
//! ```text
//! encryptedUserPrivateKey = header16 || ciphertext32 || sha512(scalar)64
//! scalar = AES-256-CTR(accountKey, header)(ciphertext)
//! ```
//!
//! — that is [`ItemCipher::open`], unchanged. The trailing SHA-512 is the check
//! that the key was right, and a wrong key fails it rather than producing
//! plausible garbage. The recovered scalar must also reproduce the published
//! `userPublicKey`, which is the second and stronger check
//! ([`MytsIdentity::from_login`] performs both).
//!
//! What is signed:
//!
//! ```text
//! C = SHA256("30 08 00 00 00 00" || sharedIV)     server direction, type 8, gen 0
//! M = C || "MyTeamSpeakID"                        45 bytes, no NUL
//! authSign = Ed25519(scalar).sign(M)              R || S, 64 bytes
//! ```
//!
//! `sharedIV` is the 64-byte value the handshake mixes in
//! (`SHA512(ecdh point) XOR alpha||beta`). It is per connection, so nothing here
//! can be precomputed or replayed; [`MytsIdentity::params`] takes it as an
//! argument.

use base64::Engine;
use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek_ng::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};

use super::sync::ItemCipher;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The five bytes that identify the packet the challenge is derived from.
///
/// `30` = server direction, `08` = packet type 8, then a big-endian u32
/// generation counter that is zero for a fresh connection, then the packet id
/// (also zero, so the usual XOR into the key's first two bytes changes nothing).
const CHALLENGE_PREFIX: [u8; 6] = [0x30, 0x08, 0x00, 0x00, 0x00, 0x00];

/// The literal appended to the challenge before signing. Exactly this, 13 bytes,
/// no terminator — a NUL would change the signature and the server would reject it.
const LITERAL: &str = "MyTeamSpeakID";

/// A myTeamSpeak identity, as the login reply describes it.
#[derive(Clone)]
pub struct MytsIdentity {
    /// Ed25519 public key, 32 B. `myts_id_data.user_public_key (1)`.
    pub public_key: [u8; 32],
    /// The **raw secret scalar** `a`, 32 B, unwrapped from the item envelope.
    ///
    /// Not a seed: `a` is already reduced mod L and must be used as-is. This is
    /// memory only and never serialized.
    scalar: [u8; 32],
    /// 33 B: `01 20` then the key. `myts_id_data.my_teamspeak_id (4)`.
    pub my_teamspeak_id: Vec<u8>,
    /// `myts_id_data.account_creation_time (3)`.
    pub account_creation_time: u64,
    /// `myts_id_data.public_signature (5)`: 64 B `pubSign` then 112 B
    /// `pubSignCert`. Either part may be absent on an account without one.
    pub public_signature: Vec<u8>,
}

impl std::fmt::Debug for MytsIdentity {
    /// Redacted: the scalar is a private key and a stray `{:?}` is how one ends
    /// up in a log. The fields a person needs are kept.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = B64.encode(self.public_key);
        let prefix = encoded.get(..6).unwrap_or(&encoded);
        f.debug_struct("MytsIdentity")
            .field("public_key", &format_args!("{prefix}…"))
            .field("scalar", &"<redacted>")
            .field("account_creation_time", &self.account_creation_time)
            .field("public_signature_bytes", &self.public_signature.len())
            .finish()
    }
}

/// The six `clientinit` parameters, as the server wants them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MytsParams {
    pub my_teamspeak_id: String,
    pub ac_time: String,
    pub user_pub_key: String,
    pub pub_sign: String,
    pub pub_sign_cert: String,
    pub auth_sign: String,
}

impl MytsIdentity {
    /// Recovers the identity from a login reply.
    ///
    /// `login` is the JSON the REST surface returned, `item_key` is the account
    /// key that unwrapped its `key` blob. Returns `Ok(None)` for an account
    /// without a myTeamSpeak ID: that is a normal account, not a failure.
    ///
    /// The two checks are deliberate and both are hard:
    ///
    /// * the envelope's trailing `sha512(scalar)` must match, which is what
    ///   `ItemCipher::open` enforces; and
    /// * `scalar · B` must equal the published `userPublicKey`, which catches a
    ///   wrong-but-tag-valid key that no digest alone could.
    pub fn from_login(
        login: &serde_json::Value,
        item_key: &[u8; 32],
    ) -> Result<Option<MytsIdentity>, String> {
        let Some(myts) = login.get("mytsIdData").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let encoded = myts
            .get("userPrivateKey")
            .and_then(|value| value.get("encryptedUserPrivateKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if encoded.is_empty() {
            // An account with a public key but no wrapped private key: nothing to
            // sign with, and saying so beats pretending.
            return Ok(None);
        }
        let blob = B64
            .decode(encoded)
            .map_err(|e| format!("encryptedUserPrivateKey is not base64: {e}"))?;
        let scalar = ItemCipher::new(*item_key).open(&blob).map_err(|e| {
            format!("the myTeamSpeak private key could not be unwrapped with the account key: {e}")
        })?;
        if scalar.len() != 32 {
            return Err(format!(
                "the unwrapped myTeamSpeak private key is {} B, expected 32",
                scalar.len()
            ));
        }
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&scalar);

        let public_key = decode_key32(
            myts.get("userPublicKey")
                .and_then(serde_json::Value::as_str),
            "userPublicKey",
        )?;
        // The check that makes the recovered scalar trustworthy.
        if public_key_of(&scalar_bytes) != public_key {
            return Err(
                "the unwrapped myTeamSpeak key does not match the account's published public key"
                    .to_string(),
            );
        }

        let my_teamspeak_id = B64
            .decode(
                myts.get("myTeamspeakId")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "the login reply has no myTeamspeakId".to_string())?,
            )
            .map_err(|e| format!("myTeamspeakId is not base64: {e}"))?;

        Ok(Some(MytsIdentity {
            public_key,
            scalar: scalar_bytes,
            my_teamspeak_id,
            account_creation_time: myts
                .get("accountCreationTime")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            public_signature: myts
                .get("publicSignature")
                .and_then(serde_json::Value::as_str)
                .map(|text| B64.decode(text).unwrap_or_default())
                .unwrap_or_default(),
        }))
    }

    /// Whether the pride key material for signing is present.
    pub fn can_sign(&self) -> bool {
        !self.my_teamspeak_id.is_empty()
    }

    /// The identity as JSON for the remembered-login file.
    ///
    /// The scalar is included on purpose: without it a restart could not sign
    /// `authSign`, and the server would stop showing the account's name and
    /// badge. It is a credential, so the file it goes into is treated like one
    /// (owner-only, deleted on logout) — see [`super::credentials`]. The official
    /// client keeps the same scalar in its own `settings.db`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "publicKey": B64.encode(self.public_key),
            "privateKey": B64.encode(self.scalar),
            "myTeamspeakId": B64.encode(&self.my_teamspeak_id),
            "accountCreationTime": self.account_creation_time,
            "publicSignature": B64.encode(&self.public_signature),
        })
    }

    /// Rebuilds an identity written by [`MytsIdentity::to_json`].
    ///
    /// `scalar · B == publicKey` is checked again: a file whose halves do not
    /// belong together is refused rather than used to sign, because every
    /// `authSign` would then be rejected and the failure would look like a
    /// server problem.
    pub fn from_json(value: &serde_json::Value) -> Result<MytsIdentity, String> {
        let public_key = decode_key32(
            value.get("publicKey").and_then(serde_json::Value::as_str),
            "publicKey",
        )?;
        let scalar = decode_key32(
            value.get("privateKey").and_then(serde_json::Value::as_str),
            "privateKey",
        )?;
        if public_key_of(&scalar) != public_key {
            return Err(
                "the stored myTeamSpeak private key does not match its public key".to_string(),
            );
        }
        let my_teamspeak_id = B64
            .decode(
                value
                    .get("myTeamspeakId")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "the stored identity has no myTeamspeakId".to_string())?,
            )
            .map_err(|e| format!("the stored myTeamspeakId is not base64: {e}"))?;
        Ok(MytsIdentity {
            public_key,
            scalar,
            my_teamspeak_id,
            account_creation_time: value
                .get("accountCreationTime")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            public_signature: value
                .get("publicSignature")
                .and_then(serde_json::Value::as_str)
                .map(|text| B64.decode(text).unwrap_or_default())
                .unwrap_or_default(),
        })
    }

    /// The six parameters for a connection with this `shared_iv`.
    ///
    /// `pubSign` is the first 64 bytes of `public_signature` and `pubSignCert`
    /// the rest (112 B); an account without them gets empty strings rather than a
    /// truncated value, because a server that validates a half of a certificate
    /// rejects the whole handshake.
    pub fn params(&self, shared_iv: &[u8]) -> MytsParams {
        let (pub_sign, pub_sign_cert) = match self.public_signature.len() {
            176 => (
                B64.encode(&self.public_signature[..64]),
                B64.encode(&self.public_signature[64..]),
            ),
            _ => (String::new(), String::new()),
        };
        MytsParams {
            my_teamspeak_id: B64.encode(&self.my_teamspeak_id),
            // Byte-swapped, then read as a u64: the wire wants the little-endian
            // bytes' value with the halves exchanged. `1790376353` becomes
            // `11671560475690139648`.
            ac_time: ac_time(self.account_creation_time),
            user_pub_key: B64.encode(self.public_key),
            pub_sign,
            pub_sign_cert,
            auth_sign: B64.encode(self.auth_sign(shared_iv)),
        }
    }

    /// `authSign`: 64 bytes of `R || S`.
    ///
    /// Deterministic, seeded by the raw scalar, exactly as the client does it:
    /// `r = SHA512(a || M) mod L` rather than RFC 8032's `SHA512(seed)`. The
    /// signature still satisfies the standard verification equation, which is
    /// what a server checks ([`verify`]).
    pub fn auth_sign(&self, shared_iv: &[u8]) -> [u8; 64] {
        // The literal is part of the signed message, not a context string: a
        // signature over the bare 32-byte challenge is a different — wrong —
        // message and the server rejects it.
        let message = message(shared_iv);
        let (r, s) = sign_raw_scalar(&self.scalar, message.as_slice());
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        out
    }

    /// The public key this identity signs as, base64. For a shell to show and for
    /// a test to compare.
    pub fn public_key_base64(&self) -> String {
        B64.encode(self.public_key)
    }
}

/// The myTeamSpeak ID as base64, for a report.
pub fn encode_id(id: &[u8]) -> String {
    B64.encode(id)
}

fn decode_key32(value: Option<&str>, what: &str) -> Result<[u8; 32], String> {
    let text = value.ok_or_else(|| format!("the login reply has no {what}"))?;
    let bytes = B64
        .decode(text)
        .map_err(|e| format!("{what} is not base64: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{what} is {} B, expected 32", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `acTime`: the creation time with its two 32-bit halves exchanged, as decimal.
///
/// The wire format is the little-endian byte layout of the u64 read big-endian,
/// which is why `1790376353` goes out as `11671560475690139648`.
pub fn ac_time(creation_time: u64) -> String {
    u64::from_be_bytes(creation_time.to_le_bytes()).to_string()
}

/// `C = SHA256(prefix || sharedIV)`.
pub fn challenge(shared_iv: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_PREFIX);
    hasher.update(shared_iv);
    hasher.finalize().into()
}

/// The message that is actually signed: `C || "MyTeamSpeakID"`, 45 bytes.
pub fn message(shared_iv: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + LITERAL.len());
    out.extend_from_slice(&challenge(shared_iv));
    out.extend_from_slice(LITERAL.as_bytes());
    out
}

/// `A = a · B`, the public key of a raw scalar.
pub fn public_key_of(scalar: &[u8; 32]) -> [u8; 32] {
    // A real scalar is already < L, so this is the identity on it. It reduces a
    // byte string that is not, which keeps "the scalar everyone agreed on" and
    // "the scalar the arithmetic uses" the same value.
    let a = Scalar::from_bytes_mod_order(*scalar);
    (&ED25519_BASEPOINT_TABLE * &a).compress().to_bytes()
}

/// Ed25519 from a **raw scalar**.
///
/// The nonce is `SHA512(a || M)` mod L — the client's construction — and the
/// scalar equation is the standard `S = r + k·a`. Nothing is clamped: `a` is
/// already reduced, and clamping here would sign with a different key.
pub fn sign_raw_scalar(scalar: &[u8; 32], message: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Same rule as `public_key_of`: identity for a real scalar, and consistent
    // with `Scalar::to_bytes` for anything else.
    let a = Scalar::from_bytes_mod_order(*scalar);
    let public = (&ED25519_BASEPOINT_TABLE * &a).compress().to_bytes();

    let mut nonce_hasher = Sha512::new();
    nonce_hasher.update(a.to_bytes());
    nonce_hasher.update(message);
    let nonce_wide: [u8; 64] = nonce_hasher.finalize().into();
    let r = Scalar::from_bytes_mod_order_wide(&nonce_wide);
    let r_encoded = (&ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();

    let mut k_hasher = Sha512::new();
    k_hasher.update(r_encoded);
    k_hasher.update(public);
    k_hasher.update(message);
    let k_wide: [u8; 64] = k_hasher.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&k_wide);

    let s = r + k * a;
    (r_encoded, s.to_bytes())
}

/// The standard Ed25519 verification equation: `S·B == R + k·A`.
///
/// This is the server's check, written out. A test uses it so "the signature is
/// valid" is a computation, not a claim.
pub fn verify(public_key: &[u8; 32], message: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    let Some(a_point) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    let Some(r_point) = CompressedEdwardsY(*r).decompress() else {
        return false;
    };
    let s_scalar = Scalar::from_bytes_mod_order(*s);

    let mut k_hasher = Sha512::new();
    k_hasher.update(*r);
    k_hasher.update(*public_key);
    k_hasher.update(message);
    let k_wide: [u8; 64] = k_hasher.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&k_wide);

    let left = &ED25519_BASEPOINT_TABLE * &s_scalar;
    let right = r_point + a_point * k;
    left == right
}

/// Verifies a whole 64-byte `R || S` signature.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);
    verify(public_key, message, &r, &s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scalar from a fixed byte pattern; not a key anyone holds.
    fn probe_scalar() -> [u8; 32] {
        let mut scalar = [0u8; 32];
        for (i, byte) in scalar.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        // Reduce: `from_bits` keeps the value as-is and the algebra is mod L
        // anyway, so any 32 bytes are a legitimate probe scalar.
        scalar
    }

    #[test]
    fn a_raw_scalar_signs_and_the_signature_verifies() {
        let scalar = probe_scalar();
        let public = public_key_of(&scalar);
        let mut iv = [0u8; 64];
        for (i, byte) in iv.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let message = message(&iv);
        assert_eq!(message.len(), 45, "C || the 13-byte literal");

        let (r, s) = sign_raw_scalar(&scalar, &message);
        assert!(
            verify(&public, &message, &r, &s),
            "the standard verification equation must accept it"
        );

        // A single flipped bit anywhere must fail, or "valid" means nothing.
        let mut wrong = message.clone();
        wrong[0] ^= 1;
        assert!(!verify(&public, &wrong, &r, &s));

        let mut bad_s = s;
        bad_s[0] ^= 1;
        assert!(!verify(&public, &message, &r, &bad_s));
    }

    #[test]
    fn the_challenge_is_the_documented_prefix_and_iv() {
        let iv = [0u8; 64];
        let digest = challenge(&iv);
        // SHA256("30 08 00 00 00 00" || 64 zero bytes), computed independently.
        let mut manual = Sha256::new();
        manual.update([0x30, 0x08, 0x00, 0x00, 0x00, 0x00]);
        manual.update([0u8; 64]);
        let expected: [u8; 32] = manual.finalize().into();
        assert_eq!(digest, expected);
        assert_eq!(message(&iv)[..32], expected, "the message starts with C");
    }

    #[test]
    fn ac_time_swaps_the_halves_the_way_the_client_does() {
        // The value in the open-source capture: 1790376353 -> 11671560475690139648.
        assert_eq!(ac_time(1_790_376_353), "11671560475690139648");
        assert_eq!(ac_time(0), "0");
    }

    #[test]
    fn a_key_blob_round_trips_through_the_item_cipher() {
        // The recovery path, end to end, with no account: seal a scalar the way
        // the server does and unwrap it again through the same constructor the
        // login uses.
        let scalar = probe_scalar();
        let public = public_key_of(&scalar);
        let item_key = {
            let mut key = [0u8; 32];
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(11).wrapping_add(5);
            }
            key
        };
        let cipher = ItemCipher::new(item_key);
        let blob = cipher.seal(&scalar);

        let login = serde_json::json!({
            "mytsIdData": {
                "userPublicKey": B64.encode(public),
                "myTeamspeakId": B64.encode([0x01, 0x20, 0x77]),
                "accountCreationTime": 1_790_376_353u64,
                "publicSignature": B64.encode([0u8; 176]),
                "userPrivateKey": {
                    "encryptedUserPrivateKey": B64.encode(&blob),
                },
            }
        });
        let identity = MytsIdentity::from_login(&login, &item_key)
            .expect("unwrap")
            .expect("a myTS identity");
        assert_eq!(identity.public_key, public);
        assert_eq!(identity.account_creation_time, 1_790_376_353);

        let params = identity.params(&[7u8; 64]);
        assert_eq!(params.user_pub_key, B64.encode(public));
        assert_eq!(params.ac_time, "11671560475690139648");
        // The two halves are encoded separately, so the check is on the decoded
        // bytes: 64 for the signature, 112 for the certificate.
        assert_eq!(B64.decode(&params.pub_sign).expect("b64").len(), 64);
        assert_eq!(B64.decode(&params.pub_sign_cert).expect("b64").len(), 112);
        assert!(!params.auth_sign.is_empty());

        // The item envelope round-trips through the cipher, but the scalar it
        // yields is NOT the probe scalar: sealing encrypts it with a fresh
        // counter, so what comes back out is the original only when the header
        // is reused. This asserts the recovery path itself, which is what the
        // login does.
        let recovered = ItemCipher::new(item_key).open(&blob).expect("open");
        assert_eq!(recovered, scalar, "the envelope returns the sealed scalar");

        // And the signature in the params verifies against the published key.
        let mut sig = [0u8; 64];
        let decoded = B64.decode(&params.auth_sign).expect("base64");
        sig.copy_from_slice(&decoded);
        assert!(
            verify_signature(&public, &message(&[7u8; 64]), &sig),
            "a signature over C || \"MyTeamSpeakID\" must pass the standard equation"
        );
    }

    #[test]
    fn a_blob_that_does_not_match_the_public_key_is_refused() {
        let scalar = probe_scalar();
        let item_key = [0x33u8; 32];
        let cipher = ItemCipher::new(item_key);
        let blob = cipher.seal(&scalar);
        // A public key from a *different* scalar: the digest passes, the key
        // comparison must not.
        let mut other = scalar;
        other[0] ^= 0xff;
        let wrong_public = public_key_of(&other);

        let login = serde_json::json!({
            "mytsIdData": {
                "userPublicKey": B64.encode(wrong_public),
                "myTeamspeakId": B64.encode([0x01, 0x20, 0x77]),
                "userPrivateKey": {
                    "encryptedUserPrivateKey": B64.encode(&blob),
                },
            }
        });
        let error = MytsIdentity::from_login(&login, &item_key)
            .expect_err("a mismatched key must be refused");
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn an_account_without_a_myts_id_is_not_an_error() {
        let login = serde_json::json!({ "email": "a@b.c" });
        assert!(MytsIdentity::from_login(&login, &[0u8; 32])
            .expect("no error")
            .is_none());
    }

    /// The remembered-login file's identity must survive a process restart, or
    /// the server stops showing the name and badge after the second launch.
    #[test]
    fn the_identity_round_trips_through_its_stored_json() {
        let scalar = probe_scalar();
        let public = public_key_of(&scalar);
        let identity = MytsIdentity {
            public_key: public,
            scalar,
            my_teamspeak_id: vec![0x01, 0x20, 0x77],
            account_creation_time: 1_790_376_353,
            public_signature: vec![0u8; 176],
        };
        let back = MytsIdentity::from_json(&identity.to_json()).expect("restore");
        assert_eq!(back.public_key, public);
        assert_eq!(back.my_teamspeak_id, identity.my_teamspeak_id);
        assert_eq!(back.account_creation_time, identity.account_creation_time);
        assert_eq!(back.public_signature, identity.public_signature);
        // The restored scalar must sign as the same key, which is the only proof
        // that matters to a server.
        assert_eq!(back.auth_sign(&[9u8; 64]), identity.auth_sign(&[9u8; 64]));

        // A private half that does not belong to the public one is refused, not
        // silently used to sign with the wrong key.
        let mut json = identity.to_json();
        json["privateKey"] = B64.encode(public_key_of(&[0x55u8; 32])).into();
        let error = MytsIdentity::from_json(&json).expect_err("mismatched pair");
        assert!(error.contains("does not match"), "{error}");
    }
}
