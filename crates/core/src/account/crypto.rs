//! The crypto the myTeamSpeak web client performs in the browser, reproduced
//! byte for byte.
//!
//! Three derivations and one wrapping format, two of which are quirky in the
//! original and are reproduced exactly:
//!
//! ```text
//! hashedPassword(pw, email)          PBKDF2-HMAC-SHA512(pw, email.toLower()+"ts3Login"+pw,  10000, 384)
//! hashedEncryptionPassword(pw, email) PBKDF2-HMAC-SHA512(email, pw+"ts3Encryption"+email,  10000, 256)
//! hashRecoveryKey(key)               base64(SHA-512("ts3RecoveryKey" + key.trim()))
//! ```
//!
//! The second one really does use the *email* as the PBKDF2 password and the
//! *plaintext password* in the salt. That is not a transcription error: the web
//! helper is declared as `hashedEncriptionPassword(p, N)` and always called as
//! `hashedEncriptionPassword(email, password)`, so `p` is the email. Verified
//! against the live page's own return values (see `research/myts-login/selftest.mjs`).
//!
//! PBKDF2 is written out here rather than pulled in as a crate: it is one block
//! of HMAC-SHA512 per output block, the derivations above need at most three, and
//! the `pbkdf2` crate's current release wants a `digest` generation this tree
//! does not resolve to. Twenty lines against a dependency that would force a
//! second parallel copy of `sha2` is the wrong trade.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

/// The AES-256 key length used by every wrapping operation.
pub const KEY_LEN: usize = 32;

/// PBKDF2 iterations for every password-derived key.
///
/// Fixed by the server's own implementation: a key derived with a different
/// count decrypts to garbage, and the account would look corrupted rather than
/// wrongly configured. One constant so a wrong value cannot be right in one
/// place and wrong in another.
pub const PBKDF2_ITERATIONS: u32 = 10_000;

/// The version byte in front of an sjcl GCM blob. Anything else is a format this
/// code has never seen and must not guess at.
const SJCL_VERSION: u8 = 2;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// PBKDF2-HMAC-SHA512.
///
/// `out` may be longer than one digest (48 bytes, the login hash, is 1.5);
/// blocks are counted from 1 as RFC 8018 says, and each block is
/// `F(P, S, c, i)` with the counter appended big-endian.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let iterations = iterations.max(1);
    let mut offset = 0;
    let mut block: u32 = 1;
    while offset < out.len() {
        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(password).expect("HMAC takes any key length");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u: [u8; 64] = mac.finalize().into_bytes().into();
        let mut acc = u;
        for _ in 1..iterations {
            let mut mac =
                <HmacSha512 as Mac>::new_from_slice(password).expect("HMAC takes any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (slot, byte) in acc.iter_mut().zip(u.iter()) {
                *slot ^= byte;
            }
        }
        let remaining = out.len() - offset;
        let take = remaining.min(64);
        out[offset..offset + take].copy_from_slice(&acc[..take]);
        offset += take;
        block += 1;
    }
}

/// The stored login credential: what replaces the plaintext password in
/// `/client/login` and in `settings.db`'s `Account` blob.
pub fn hashed_password(password: &str, email: &str) -> String {
    // ASCII-only lowercasing, matching the official client: Unicode case folding
    // would change a non-ASCII address into a different salt.
    let salt = format!("{}ts3Login{}", ascii_lowercase(email), password);
    let mut out = [0u8; 48];
    pbkdf2_hmac_sha512(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut out,
    );
    B64.encode(out)
}

/// Candidate AES keys that wrap the account key, derived from a plaintext
/// password.
///
/// **The first entry is the one that matters.** It is the derivation the
/// open-source `ts3java` client implements for `accountKey`:
///
/// ```text
/// salt = ascii_lower(email) + "ts3Encryption" + password
/// key  = PBKDF2-HMAC-SHA512(password = password, salt, 10_000, 32 bytes)
/// ```
///
/// Note where the parts sit: the **email is in the salt and the password is the
/// PBKDF2 secret**, which is the opposite of how the SPA helper's parameters read
/// (`hashedEncriptionPassword(p, N)` with `pbkdf2(N, salt)`). That inversion is
/// exactly what made a password login succeed at `/client/login` — which only
/// uses the *other* derivation — and then fail to unwrap `key`, leaving every
/// item locked.
///
/// The remaining entries are kept because the SPA helper exists and some account
/// may have been wrapped by it (a password changed through the web UI goes through
/// that path). Every candidate costs 10 000 PBKDF2 iterations (~3 ms) and a wrong
/// one is rejected by the GCM tag with no side effects, so trying them all is
/// cheap; the first that verifies is reported by name, which settles which
/// convention this account uses.
pub fn wrapper_candidates(password: &str, email: &str) -> Vec<(&'static str, [u8; KEY_LEN])> {
    fn derive(
        name: &'static str,
        salt_left: &str,
        salt_right: &str,
        kdf_password: &str,
    ) -> (&'static str, [u8; KEY_LEN]) {
        let salt = format!("{salt_left}ts3Encryption{salt_right}");
        let mut key = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(
            kdf_password.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut key,
        );
        (name, key)
    }

    // Lowercasing here is ASCII-only on purpose: the official client lowercases
    // bytewise and leaves everything outside ASCII alone, so a non-ASCII address
    // must not go through Unicode case folding.
    let lower = ascii_lowercase(email);
    let lower_pw = ascii_lowercase(password);

    let mut out = Vec::with_capacity(7);
    // 1. The ts3java reading, and the one a password login needs:
    //    salt = lower(email) + "ts3Encryption" + password, PBKDF2 secret = password.
    out.push(derive(
        "ts3Encryption (lower(email), password as secret)",
        &lower,
        password,
        password,
    ));
    // 2. The SPA helper as its parameter names read: (password, email).
    out.push(derive("hashedEncryptionPassword", password, email, email));
    // 3. Email lower-cased on both sides, matching `hashedPassword`'s salt rule.
    out.push(derive(
        "hashedEncryptionPassword (email lowercased)",
        password,
        &lower,
        &lower,
    ));
    // 4. Salt email lower-cased, PBKDF2 secret as typed.
    out.push(derive(
        "hashedEncryptionPassword (salt email lowercased)",
        password,
        &lower,
        email,
    ));
    // 5. Arguments swapped on the helper reading: the password is the PBKDF2 secret.
    out.push(derive(
        "hashedEncryptionPassword (arguments swapped)",
        email,
        password,
        password,
    ));
    // 6. Both lower-cased on the swapped reading too.
    out.push(derive(
        "hashedEncryptionPassword (swapped, lowercased)",
        &lower,
        &lower_pw,
        &lower_pw,
    ));
    // 7. The login hash as the PBKDF2 secret, in case the client's
    //    `Account_Manager` treats the stored credential as the secret.
    let login_hash = hashed_password(password, email);
    out.push(derive(
        "hashedEncryptionPassword (login hash as secret)",
        password,
        email,
        &login_hash,
    ));

    out
}

/// Lowercases ASCII letters only, the way the official client does.
///
/// Not `str::to_lowercase`: that applies Unicode case folding, which turns some
/// addresses into different bytes than the client would use, and the salt is a
/// byte string — a "İ" folded to "i̇" is a different salt and therefore a
/// different key.
fn ascii_lowercase(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// The canonical wrapper derivation, matching the open-source `ts3java` client.
///
/// ```text
/// salt = ascii_lower(email) + "ts3Encryption" + password
/// key  = PBKDF2-HMAC-SHA512(password = password, salt, 10_000, 32 bytes)
/// ```
///
/// The password is the PBKDF2 **secret** and the email sits in the salt. The
/// SPA's helper looks like the same derivation but passes the email as the secret
/// and the password as part of the salt, which is a different 32-byte value; that
/// inversion is what made a password login look like a wrapper mismatch.
pub fn hashed_encryption_password(password: &str, email: &str) -> [u8; KEY_LEN] {
    let salt = format!("{}ts3Encryption{}", ascii_lowercase(email), password);
    let mut out = [0u8; KEY_LEN];
    pbkdf2_hmac_sha512(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut out,
    );
    out
}

/// What the 2FA / regenerate-recovery-keys endpoints expect in place of the
/// recovery code the user typed.
pub fn hash_recovery_key(recovery_key: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(b"ts3RecoveryKey");
    hasher.update(recovery_key.trim().as_bytes());
    B64.encode(hasher.finalize())
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Base64 of a key, for the one value a client legitimately stores between runs.
pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    B64.encode(key)
}

/// The inverse of [`encode_key`], or `None` when the text is not a 32-byte key.
///
/// Deliberately total rather than an error: a stored credential with a garbled
/// key should still be usable for a login, and the only consequence of dropping
/// it is that items report `locked`.
pub fn decode_key(text: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = B64.decode(text.trim()).ok()?;
    bytes.try_into().ok()
}

/// Unwraps the login response's `key` field: an sjcl "versioned GCM blob".
///
/// Layout, which is **not** the usual `ciphertext||tag`:
///
/// ```text
/// [1 B version=2][16 B tag][12 B nonce][ciphertext]
/// ```
///
/// The tag sits in front of the nonce, so the input has to be reassembled as
/// `ciphertext||tag` before handing it to AES-GCM. Getting this order wrong is
/// silent right up to the tag check, which then fails with no explanation.
pub fn unwrap_key(wrapped_b64: &str, aes_key: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], String> {
    let blob = B64
        .decode(wrapped_b64.trim())
        .map_err(|e| format!("key is not valid base64: {e}"))?;
    if blob.len() < 1 + TAG_LEN + NONCE_LEN {
        return Err(format!(
            "wrapped key is {} B, too short to be an sjcl blob",
            blob.len()
        ));
    }
    if blob[0] != SJCL_VERSION {
        return Err(format!(
            "unexpected key blob version {} (only {SJCL_VERSION} is known)",
            blob[0]
        ));
    }
    let tag = &blob[1..1 + TAG_LEN];
    let nonce = &blob[1 + TAG_LEN..1 + TAG_LEN + NONCE_LEN];
    let ciphertext = &blob[1 + TAG_LEN + NONCE_LEN..];

    let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);

    let cipher = Aes256Gcm::new_from_slice(aes_key).expect("32 bytes is a valid AES-256 key");
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), sealed.as_slice())
        .map_err(|_| "GCM tag mismatch: this is not the wrapping key for that blob".to_string())?;

    if plain.len() != KEY_LEN {
        return Err(format!(
            "unwrapped key is {} B, expected {KEY_LEN}",
            plain.len()
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plain);
    Ok(key)
}

/// Wraps a raw key into the same layout `unwrap_key` reads.
///
/// Only needed for a password/email change, which is `unwrap` with the old key
/// and `wrap` with the new one — exactly what the web client's `generateKey()`
/// does. A fresh 12-byte nonce is generated unless one is supplied, which the
/// tests use to pin a byte-exact result.
pub fn wrap_key(raw: &[u8], aes_key: &[u8; KEY_LEN], nonce: Option<[u8; NONCE_LEN]>) -> String {
    let nonce = nonce.unwrap_or_else(rand::random::<[u8; NONCE_LEN]>);
    let cipher = Aes256Gcm::new_from_slice(aes_key).expect("32 bytes is a valid AES-256 key");
    // AES-GCM returns `ciphertext||tag`; the blob wants the two swapped.
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), raw)
        .expect("AES-GCM encryption cannot fail for a 16-byte tag");
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    let mut blob = Vec::with_capacity(1 + TAG_LEN + NONCE_LEN + ciphertext.len());
    blob.push(SJCL_VERSION);
    blob.extend_from_slice(tag);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(ciphertext);
    B64.encode(blob)
}

/// The item cipher.
///
/// ```text
/// blob      = header16 || ct || sha512(plaintext)
/// plaintext = AES-256-CTR(accountKey, header)(ct)
/// ```
///
/// The counter is the whole 16-byte header read as a **little-endian 128-bit
/// integer**, incremented per block with the carry rippling upward. That is what
/// the open-source `ts3java` client does (`incrementLittleEndian` over all 16
/// bytes) and why it cannot use its platform's own CTR mode. `ctr::Ctr128LE`
/// implements exactly this, so the block arithmetic lives in a tested crate.
///
/// An earlier version of this function used a 32-bit word-0 counter, which
/// agrees with the real cipher until a carry would leave byte 3. The live items
/// happened not to cross that boundary, so both passed the trailer check — and
/// the difference would have shown up as a corrupted item the first time a
/// header started near `0xffff_ff_ff`. The fixed vector in
/// `tests/account_contract.rs` uses a header that wraps immediately, so this
/// cannot silently regress.
pub fn item_cipher(key: &[u8; KEY_LEN], header: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes_gcm::aes::cipher::{KeyIvInit, StreamCipher};
    use aes_gcm::aes::Aes256;
    use ctr::Ctr128LE;

    let mut cipher = Ctr128LE::<Aes256>::new(key.into(), header.into());
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

/// A fresh 16-byte header for a new item.
///
/// Random rather than deterministic: the counter is per item, and reusing a
/// header across two different plaintexts under the same key would leak their
/// XOR to anyone who sees both blobs. Only byte 0 is constrained, because the
/// counter is 128-bit and a short item cannot walk it anywhere near a wrap.
pub fn item_header() -> [u8; 16] {
    rand::random::<[u8; 16]>()
}

/// A UUID-v4 string, for the items a client is expected to mint itself
/// (bookmarks). Written out because pulling in `uuid` for 6 lines would add a
/// second `getrandom` to the graph.
pub fn uuid_v4() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = |range: std::ops::Range<usize>| -> String {
        bytes[range]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation parameters are the ones the server expects.
    ///
    /// A wrong iteration count does not fail loudly: the key derives, the
    /// decrypt produces bytes, and the account looks corrupted. Pinning the
    /// numbers here means a change has to be deliberate.
    #[test]
    fn the_derivation_parameters_are_pinned() {
        assert_eq!(PBKDF2_ITERATIONS, 10_000, "PBKDF2 iteration count");
        assert_eq!(KEY_LEN, 32, "AES-256 key length");
        assert_eq!(SJCL_VERSION, 2, "sjcl blob version byte");
        assert_eq!(TAG_LEN, 16, "GCM tag length");
        assert_eq!(NONCE_LEN, 12, "GCM nonce length");
    }

    /// A known password and salt derive a stable key.
    ///
    /// This is the anchor the other tests rely on: if the derivation changed,
    /// every expected ciphertext below would change too, and this test says so
    /// in one place instead of in twenty.
    #[test]
    fn the_derivation_is_stable() {
        let mut first = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", b"fixed-salt", PBKDF2_ITERATIONS, &mut first);

        let mut second = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", b"fixed-salt", PBKDF2_ITERATIONS, &mut second);

        assert_eq!(first, second, "the same input must derive the same key");

        // A different salt must derive a different key, or the salt is ignored.
        let mut other = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", b"other-salt", PBKDF2_ITERATIONS, &mut other);
        assert_ne!(first, other, "the salt does not affect the key");
    }

    /// A zero iteration count is clamped rather than producing a key from one
    /// round, which would be trivially reversible.
    #[test]
    fn zero_iterations_are_clamped() {
        let mut zero = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", b"salt", 0, &mut zero);

        let mut one = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", b"salt", 1, &mut one);

        assert_eq!(zero, one, "0 iterations should behave as 1, not as nothing");
    }

    /// Every expected value below was read out of the live page's own functions
    /// on https://www.myteamspeak.com/login (`window.hashedPassword`,
    /// `window.hashedEncryptionPassword`), so these are not self-fulfilling.
    /// Same fixtures as `research/myts-login/selftest.mjs`.
    #[test]
    fn login_hash_matches_the_browser() {
        assert_eq!(
            hashed_password("P1ss", "Mail@Ex.com"),
            "hCgQOBQSEQcJ38o3h8hJsirtqda0uJNIonLr/c4maSmkAlY+bXbNVmgnDmYmk6i2"
        );
    }

    /// The wrapper derivation, which is **not** the same shape as the login hash
    /// even though the SPA exposes both helpers side by side.
    ///
    /// `ts3java` (the open-source client this pins) derives it as
    /// `PBKDF2(secret = password, salt = lower(email) + "ts3Encryption" + password)`.
    /// Note the inversion: the password is the PBKDF2 secret here, while in the
    /// login hash it is part of the salt. Getting that backwards produces a
    /// 32-byte value that unwraps nothing, which is what "logged in but every
    /// item is locked" looked like.
    ///
    /// The expected bytes come from the same browser vector `selftest.mjs` pins
    /// for `window.hashedEncryptionPassword("P1ss","Mail@Ex.com")`, which uses the
    /// *other* convention — so this asserts the two readings differ, and that the
    /// list offers both.
    #[test]
    fn the_wrapper_derivation_puts_the_password_in_the_kdf_secret() {
        // The canonical (ts3java) shape.
        let salt = format!("{}ts3Encryption{}", "mail@ex.com", "P1ss");
        let mut canonical = [0u8; KEY_LEN];
        pbkdf2_hmac_sha512(b"P1ss", salt.as_bytes(), PBKDF2_ITERATIONS, &mut canonical);
        assert_eq!(canonical, hashed_encryption_password("P1ss", "Mail@Ex.com"));

        // The SPA's argument order, which is a different value.
        let mut sponge = [0u8; KEY_LEN];
        let sponge_salt = format!("{}ts3Encryption{}", "P1ss", "Mail@Ex.com");
        pbkdf2_hmac_sha512(
            b"Mail@Ex.com",
            sponge_salt.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut sponge,
        );
        assert_ne!(canonical, sponge, "the two readings must not collide");
        assert_eq!(
            B64.encode(sponge),
            "2UJPNrdOQMQ/GATNlvG2SuQLR39mqE6hBNrW9rDcp7Y="
        );

        // And the candidate list must offer the canonical one first, so a
        // password login succeeds on the first try rather than the sixth.
        let candidates = wrapper_candidates("P1ss", "Mail@Ex.com");
        assert_eq!(candidates[0].1, canonical);
        assert!(
            candidates.iter().any(|(_, key)| *key == sponge),
            "the SPA reading must still be offered as a fallback"
        );
    }

    /// Lowercasing is ASCII-only, because the salt is a byte string and Unicode
    /// case folding would give a non-ASCII address a different key than the
    /// official client computes.
    #[test]
    fn lowering_the_email_is_ascii_only() {
        assert_eq!(ascii_lowercase("Mail@Ex.Com"), "mail@ex.com");
        // U+0130 (LATIN CAPITAL LETTER I WITH DOT) folds to two code points under
        // Unicode rules, but the client leaves it alone.
        assert_eq!(ascii_lowercase("İstanbul@Ex.com"), "İstanbul@ex.com");
    }

    /// A fixed vector for the item cipher, with a header that wraps on the second
    /// block. Generated independently with node's AES-ECB
    /// (`itemcipher_vectors.mjs`); the wrap bytes are the whole point, because a
    /// 32-bit-word counter would differ here and nowhere else.
    #[test]
    fn the_item_cipher_wraps_a_full_128_bit_counter() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);

        // Block 0 and 1 for the plain header.
        let header: [u8; 16] = std::array::from_fn(|i| 0x40 + i as u8);
        let zeros = [0u8; 32];
        let ks = item_cipher(&key, &header, &zeros);
        assert_eq!(
            &ks[..16],
            hex("a37edf3f975abaef937b62c78d5bb157").as_slice()
        );
        assert_eq!(
            &ks[16..],
            hex("d745bdcd17c049b6870f0ada4a1b0a6b").as_slice()
        );

        // A header whose counter is all ones: block 1 carries into bytes 4..15.
        let wrap: [u8; 16] = hex("ffffffff505152535455565758595a5b")
            .try_into()
            .expect("16 bytes");
        let zeros = [0u8; 48];
        let ks = item_cipher(&key, &wrap, &zeros);
        assert_eq!(
            &ks[..16],
            hex("eb726ee00c5658c6bd2820e8def4514f").as_slice()
        );
        assert_eq!(
            &ks[16..32],
            hex("591872b67c766a9bba9a8cc741553cff").as_slice(),
            "block 1 must carry out of byte 3 into byte 4"
        );
        assert_eq!(
            &ks[32..],
            hex("aa79cf503c5cbac1a45504ed14ce61ab").as_slice(),
            "block 2 continues from 01 00 00 00 51 52 ..."
        );

        fn hex(text: &str) -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
                .collect()
        }
    }

    /// The salt takes the password verbatim, including case; the email is the
    /// only part that is lowercased. Getting that backwards is a silent
    /// "wrong password" at login time.
    #[test]
    fn login_hash_lowercases_only_the_email() {
        assert_eq!(
            hashed_password("P1ss", "mail@ex.com"),
            hashed_password("P1ss", "Mail@Ex.com")
        );
        assert_ne!(
            hashed_password("p1ss", "Mail@Ex.com"),
            hashed_password("P1ss", "Mail@Ex.com")
        );
    }

    #[test]
    fn recovery_key_hash_is_plain_sha512_of_a_prefixed_code() {
        let got = hash_recovery_key("ABCD-EFGH-IJKL-MNOP");
        let mut hasher = Sha512::new();
        hasher.update(b"ts3RecoveryKeyABCD-EFGH-IJKL-MNOP");
        assert_eq!(got, B64.encode(hasher.finalize()));
        // The web form trims what the user pasted.
        assert_eq!(got, hash_recovery_key("  ABCD-EFGH-IJKL-MNOP\n"));
    }

    /// Pinned blob: raw key `01..20`, AES key `a0..bf`, nonce `10..1b`. The
    /// expected base64 was produced independently with WebCrypto (the same
    /// primitive the browser uses), so a change in our layout would show up here
    /// rather than as an unexplainable tag mismatch in the field.
    #[test]
    fn sjcl_blob_layout_is_version_tag_nonce_ciphertext() {
        let raw: Vec<u8> = (1u8..=32).collect();
        let aes: [u8; 32] = std::array::from_fn(|i| 0xa0 + i as u8);
        let nonce: [u8; 12] = std::array::from_fn(|i| 0x10 + i as u8);
        let wrapped = wrap_key(&raw, &aes, Some(nonce));
        assert_eq!(
            wrapped,
            "AqM8IsMiONFBZgpjZF0+r84QERITFBUWFxgZGhuVtHYK20GyupNzZx2UPbOk4kAP2/rppNpAgRgwmtlsCA=="
        );

        let blob = B64.decode(&wrapped).unwrap();
        assert_eq!(blob[0], 2, "version byte");
        assert_eq!(blob.len(), 1 + 16 + 12 + 32, "ver|tag|nonce|ct");
        assert_eq!(
            unwrap_key(&wrapped, &aes).unwrap().as_slice(),
            raw.as_slice()
        );
    }

    /// The tag is the only thing that can tell a correct wrapping key from a
    /// wrong one — there is no checksum in the plaintext. This is the property
    /// the login path relies on when it tries several candidate keys.
    #[test]
    fn a_wrong_wrapping_key_is_rejected_by_the_tag() {
        let raw: Vec<u8> = (1u8..=32).collect();
        let aes: [u8; 32] = std::array::from_fn(|i| 0x40 + i as u8);
        let wrapped = wrap_key(&raw, &aes, Some([7u8; 12]));

        let mut wrong = aes;
        wrong[31] ^= 0x01;
        let err = unwrap_key(&wrapped, &wrong).unwrap_err();
        assert!(err.contains("tag"), "unexpected error: {err}");
    }

    #[test]
    fn short_and_misversioned_blobs_fail_with_a_reason() {
        assert!(unwrap_key(&B64.encode([2u8; 10]), &[0u8; 32]).is_err());
        let mut blob = vec![3u8];
        blob.extend_from_slice(&[0u8; 28]);
        assert!(unwrap_key(&B64.encode(blob), &[0u8; 32])
            .unwrap_err()
            .contains("version"));
    }

    /// PBKDF2 emits several blocks for the 48-byte login hash; the second block
    /// must be the RFC counter value 2, not a repeat of block 1.
    #[test]
    fn pbkdf2_second_block_uses_the_counter() {
        let mut one = [0u8; 64];
        let mut two = [0u8; 64];
        pbkdf2_hmac_sha512(b"pw", b"salt", 1, &mut one);
        pbkdf2_hmac_sha512(b"pw", b"salt", 2, &mut two);
        assert_ne!(one, two, "iteration count must change the result");

        let mut combined = [0u8; 128];
        pbkdf2_hmac_sha512(b"pw", b"salt", 1, &mut combined);
        assert_eq!(&combined[..64], &one[..]);
        assert_ne!(&combined[64..], &one[..], "block 2 must not repeat block 1");
    }

    #[test]
    fn uuid_is_v4_shaped() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4", "version nibble");
        let variant = id.as_bytes()[19];
        assert!(
            matches!(variant, b'8' | b'9' | b'a' | b'b'),
            "variant nibble was {}",
            variant as char
        );
        assert_ne!(id, uuid_v4(), "two calls must not collide");
    }
}
