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

/// The account stores identities as `IDENTITY` items whose field 1 is the
/// `counterVkey` a returning client must reuse. Writing it keeps every other
/// field, which is what makes a second install come back with the same UID
/// instead of a new one.
#[test]
fn account_identity_round_trip_keeps_other_fields() {
    use tsbridge_core::account::proto::{field_string, field_varint};
    use tsbridge_core::account::sync::{set_identity_string, AccountIdentity};

    let original = "42VsomeObfuscatedKey==";
    // 17 = identity payload; 1 = uniqueIdentity, 2 = idName, 3 = nickname, 5 = isDefault
    let mut inner = Vec::new();
    inner.extend(field_string(1, original));
    inner.extend(field_string(2, "Schallophy"));
    inner.extend(field_string(3, "ann"));
    inner.extend(field_varint(5, 1));
    let mut item_data = Vec::new();
    item_data.extend(field_string(2, "item-uuid"));
    item_data.extend(field_string(3, "version-uuid"));
    item_data.extend(field_bytes_for(17, &inner));

    let parsed = AccountIdentity::parse(&item_data).unwrap().unwrap();
    assert_eq!(parsed.identity, original);
    assert_eq!(parsed.name, "Schallophy");
    assert_eq!(parsed.nickname, "ann");
    assert!(parsed.is_default);

    let replaced = "99VanotherKey==";
    let rewritten = set_identity_string(&item_data, replaced).unwrap();
    let after = AccountIdentity::parse(&rewritten).unwrap().unwrap();
    assert_eq!(after.identity, replaced);
    assert_eq!(after.name, "Schallophy", "other fields must survive");
    assert_eq!(after.nickname, "ann");
    assert!(after.is_default);

    // An identity item without a key reads as "not an identity" rather than as
    // an empty string a shell might store.
    let nameless = {
        let mut inner = Vec::new();
        inner.extend(field_string(2, "x"));
        let mut data = Vec::new();
        data.extend(field_bytes_for(17, &inner));
        data
    };
    assert!(AccountIdentity::parse(&nameless).unwrap().is_none());
}

/// The account's **first** identity is built here, not asked of another client.
///
/// A user switching away from the official client is exactly the user who has no
/// IDENTITY item yet, so "connect once with the official client" is not advice
/// they can take. The item is five fields, all known, so it is constructed and
/// then read back through the same parser a shell uses.
#[test]
fn a_first_identity_is_built_and_reads_back() {
    use tsbridge_core::account::proto::Message;
    use tsbridge_core::account::sync::{build_identity, AccountIdentity, IdentityDraft};

    let draft = IdentityDraft {
        uuid: "11111111-2222-4333-8444-555555555555".to_string(),
        item_version: "66666666-7777-4888-8999-aaaaaaaaaaaa".to_string(),
        identity: "42VsomeObfuscatedKey==".to_string(),
        name: "Default".to_string(),
        nickname: "Schallophy".to_string(),
    };
    let blob = build_identity(&draft).expect("an identity is built");

    // It must read back as an identity, carrying the string it was built from.
    let parsed = AccountIdentity::parse(&blob)
        .expect("parse")
        .expect("a new identity is an identity");
    assert_eq!(parsed.identity, "42VsomeObfuscatedKey==");
    assert_eq!(parsed.name, "Default");
    assert_eq!(parsed.nickname, "Schallophy");
    assert_eq!(parsed.phonetic_name, "");
    assert!(
        parsed.is_default,
        "the only identity must be marked default, or a pick cannot choose it \
         without a bookmark pointing at it"
    );

    // The envelope must be a *new* item: item_type names the class, the versions
    // are the ones supplied, and the manipulation flag says "never synced".
    let message = Message::parse(&blob).expect("message");
    assert_eq!(
        message.varint(6),
        Some(1),
        "item_type is the class number, and IDENTITY is 1"
    );
    assert_eq!(message.string(2), Some(draft.uuid.as_str()));
    assert_eq!(message.string(3), Some(draft.item_version.as_str()));
    assert_eq!(
        message.varint(4),
        Some(0),
        "a created item is ITEM_ADDED, not a change"
    );
    assert_eq!(
        message.string(5),
        Some("ffffffff-ffff-ffff-ffff-ffffffffffff"),
        "a new item supersedes nothing"
    );
    assert_eq!(message.string(7), Some(""));
    assert_eq!(message.string(8), Some(""));
    assert!(
        message.varint(9).is_some(),
        "the official client stamps a timestamp (f9) on every item it stores; \
         an item without one is not the shape it writes"
    );

    // An empty identity is refused rather than stored as a blank item a later
    // connect would treat as corrupt.
    let empty = IdentityDraft {
        identity: "  ".to_string(),
        ..draft
    };
    assert!(build_identity(&empty).is_err());
}

fn field_bytes_for(number: u32, value: &[u8]) -> Vec<u8> {
    tsbridge_core::account::proto::field_bytes(number, value)
}
