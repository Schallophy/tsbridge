//! Pins the identity string format that leaves this library.
//!
//! `identity_to_ts_str` is what every shell persists and passes back on the next
//! connect, so its output has to be *the* form the real TeamSpeak client uses —
//! not merely something tsclientlib can re-import. Two formats both parse:
//!
//! * `counterV<base64 tomcrypt DER>` — plain; readable, not what TS3 stores
//! * `counterV<obfuscated base64 ..>` — what the real client stores in
//!   `settings.db` (`ProtobufItems.identity.unique_identity`)
//!
//! The second one is the contract. It matters beyond cosmetics: a user who
//! migrates from the official client should be able to hand over the string from
//! its settings verbatim, and a string we report should be pasteable back into
//! that client without it deciding the identity is corrupt.
//!
//! The fixture below is the public test key from `tsproto-types`
//! (`crypto.rs::TEST_PRIV_KEY`), so no real user secret lives in this repository.
//! The expected obfuscated text was cross-checked byte-for-byte against the real
//! client's stored identities during the myTeamSpeak research (decode →
//! re-encode reproduced two live strings exactly). That check is reproducible
//! offline: `research/myts-login/explore/identity_doc_check.mjs` (2/2 exact,
//! and a tampered inner key no longer re-encodes to the stored string).

use tsbridge_core::{identity_to_ts_str, Identity};

/// Public fixture from `tsproto-types::crypto::tests::TEST_PRIV_KEY`.
const TEST_PRIV_KEY: &str = "MG0DAgeAAgEgAiAIXJBlj1hQbaH0Eq0DuLlCmH8bl+veTAO2+k9EQjEYSgIgNnImcmKo7ls5mExb6skfK2Tw+u54aeDr0OP1ITsC/50CIA8M5nmDBnmDM/gZ//4AAAAAAAAAAAAAAAAAAAAZRzOI";

/// `to_ts_obfuscated()` of the fixture, without the counter prefix.
const TEST_OBFUSCATED: &str = "OfydZwzLwCCWm3smUImF+mI+6W1fV1lhW1UpASZABXEQe1h0XnoPAA8ZEABhJXoDSF4Id2FYdj82Un0GfFZ5X1Nce18DCUoFDCFJBlcSCgN6AmNCT0AGVlYBcUUBLGMBLGRFcC81MENJQThNNW5tREJubURNL2daLy80QUFBQUFBQUFBQUFBQUFBQUFBQUFaUnpPSQ==";

/// The counter `upgrade_level(8)` picks for the fixture's public key: the first
/// offset whose SHA-1 hash-cash level reaches 8. It is deterministic, so pinning
/// it turns any change in the hash-cash algorithm into a test failure.
const TEST_COUNTER: u64 = 354;

fn fixture_identity() -> Identity {
    Identity::new_from_str(TEST_PRIV_KEY).expect("import fixture key")
}

#[test]
fn identity_string_uses_the_obfuscated_form() {
    let identity = fixture_identity();
    let stored = identity_to_ts_str(&identity);

    assert_eq!(
        identity.counter(),
        TEST_COUNTER,
        "hash-cash counter for the fixture drifted (algorithms.rs changed?)"
    );
    assert_eq!(
        stored,
        format!("{TEST_COUNTER}V{TEST_OBFUSCATED}"),
        "identity string must match the TeamSpeak client's stored format"
    );
    assert!(
        !stored.contains(TEST_PRIV_KEY),
        "the plain DER form must not leak through the obfuscated encoder"
    );
}

#[test]
fn identity_string_survives_a_round_trip() {
    // What a shell does: persist the reported string, hand it back next launch.
    let first = fixture_identity();
    let stored = identity_to_ts_str(&first);

    let second = Identity::new_from_ts_str(&stored).expect("re-parse our own output");
    assert_eq!(second.counter(), first.counter(), "counter must survive");
    assert_eq!(
        second.key().to_ts(),
        first.key().to_ts(),
        "the private key must survive"
    );
    assert_eq!(
        second.key().to_pub().get_uid(),
        first.key().to_pub().get_uid(),
        "the derived server-visible UID must be identical, or the server sees a new user"
    );
    assert_eq!(
        identity_to_ts_str(&second),
        stored,
        "re-emitting must be byte-identical, so storage does not drift"
    );
}

#[test]
fn plain_der_input_is_still_accepted() {
    // Backwards compatibility with anything already persisted by an older build:
    // `import_str` tries plain base64 first, obfuscated second.
    let plain = format!("{TEST_COUNTER}V{TEST_PRIV_KEY}");
    let identity = Identity::new_from_ts_str(&plain).expect("plain form still parses");
    assert_eq!(
        identity_to_ts_str(&identity),
        format!("{TEST_COUNTER}V{TEST_OBFUSCATED}")
    );
}
