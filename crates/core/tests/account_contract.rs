//! The account side's contract: the derivations, the protobuf writer, the
//! `settings.db` reader, and the exact bytes the server protocol expects.
//!
//! Everything pinned here was measured against the live service or against the
//! browser's own functions (`research/myts-login/selftest.mjs`), not against the
//! implementation. A test that only asserts "we agree with ourselves" would pass
//! through every silent crypto change.

use tsbridge_core::account::crypto;
use tsbridge_core::account::proto::{self, Message};
use tsbridge_core::account::sqlite::{Cell, Database};
use tsbridge_core::account::sync::{
    self, Capability, Item, ItemCipher, ItemClass, ItemFolder, ItemMeta, Sync, SyncState,
    SyncStatus, ENVELOPE_LEN, HEADER_LEN,
};

// ── crypto ──────────────────────────────────────────────────────────────────

/// The two derivations the account needs, each pinned against the vector the
/// live web page returns for the same fixture.
///
/// `hashed_password` is the login token: `PBKDF2(password, lower(email) +
/// "ts3Login" + password, 10 000, 384 bits)`.
///
/// `hashed_encryption_password` is the **wrapper**, and its shape is different:
/// `PBKDF2(password, lower(email) + "ts3Encryption" + password, 10 000, 256)` —
/// the password is the KDF secret, and the email is lower-cased in the salt. That
/// is what the open-source `ts3java` client implements for its `accountKey`. The
/// SPA exposes a helper with the arguments swapped (email as the secret), which
/// yields a different 32 bytes; the candidate list keeps it as a fallback, but it
/// is not what a password login should try first.
#[test]
fn the_two_derivations_match_their_reference_vectors() {
    assert_eq!(
        crypto::hashed_password("P1ss", "Mail@Ex.com"),
        "hCgQOBQSEQcJ38o3h8hJsirtqda0uJNIonLr/c4maSmkAlY+bXbNVmgnDmYmk6i2"
    );

    // Canonical: salt = lower(email) + "ts3Encryption" + password, secret = password.
    let wrapper = crypto::hashed_encryption_password("P1ss", "Mail@Ex.com");
    assert_eq!(wrapper.len(), crypto::KEY_LEN);
    let salt = "mail@ex.comts3EncryptionP1ss";
    assert_eq!(
        wrapper,
        {
            let mut out = [0u8; crypto::KEY_LEN];
            pbkdf2(b"P1ss", salt.as_bytes(), &mut out);
            out
        },
        "the wrapper must put the password in the KDF secret and the email in the salt"
    );

    // The SPA's swapped reading is a different value; the list offers it second.
    let swapped = {
        let mut out = [0u8; crypto::KEY_LEN];
        pbkdf2(b"Mail@Ex.com", b"P1ssts3EncryptionMail@Ex.com", &mut out);
        out
    };
    assert_ne!(wrapper, swapped);
    assert_eq!(
        base64(&swapped),
        "2UJPNrdOQMQ/GATNlvG2SuQLR39mqE6hBNrW9rDcp7Y="
    );

    assert_eq!(
        crypto::hash_recovery_key("ABCD-EFGH-IJKL-MNOP"),
        base64(&sha512(b"ts3RecoveryKeyABCD-EFGH-IJKL-MNOP"))
    );
}

/// A login with a password must offer several wrapper shapes, canonical first,
/// and every one of them must be a real 32-byte key. The order matters: the first
/// candidate is tried before a fallback that costs another five PBKDF2 runs.
#[test]
fn a_password_login_offers_the_wrapper_shapes_in_order() {
    let candidates = crypto::wrapper_candidates("P1ss", "Mail@Ex.com");
    assert!(candidates.len() >= 2);
    assert_eq!(
        candidates[0].1,
        crypto::hashed_encryption_password("P1ss", "Mail@Ex.com"),
        "the canonical shape must be first"
    );
    for (name, key) in &candidates {
        assert_eq!(key.len(), crypto::KEY_LEN, "{name}");
    }
    // Every candidate must be distinct: two names producing one key would mean a
    // shape is not actually being varied.
    for i in 0..candidates.len() {
        for j in (i + 1)..candidates.len() {
            assert_ne!(
                candidates[i].1, candidates[j].1,
                "{} and {} collide",
                candidates[i].0, candidates[j].0
            );
        }
    }
}

/// A wrapped key is `[ver=2][tag 16][nonce 12][ciphertext 32]`, and the only way
/// to know a wrapping key is right is the GCM tag.
#[test]
fn a_wrapped_key_round_trips_and_rejects_a_wrong_wrapper() {
    let raw: Vec<u8> = (1u8..=32).collect();
    let aes: [u8; 32] = std::array::from_fn(|i| 0xa0 + i as u8);
    let nonce: [u8; 12] = std::array::from_fn(|i| 0x10 + i as u8);
    let wrapped = crypto::wrap_key(&raw, &aes, Some(nonce));
    let blob = decode_base64(&wrapped);
    assert_eq!(blob[0], 2);
    assert_eq!(blob.len(), 1 + 16 + 12 + 32);
    assert_eq!(
        crypto::unwrap_key(&wrapped, &aes).unwrap().as_slice(),
        &raw[..]
    );

    let mut wrong = aes;
    wrong[0] ^= 0x01;
    assert!(crypto::unwrap_key(&wrapped, &wrong).is_err());
}

// ── protobuf ────────────────────────────────────────────────────────────────

/// The proto layer must be byte-preserving: an edited item is re-encrypted and
/// the server checks `sha512(plaintext)`, so a reader that normalises field order
/// or drops defaults changes bytes nobody asked to change — and the write fails in
/// a way that looks like a key problem.
#[test]
fn a_message_survives_parse_and_encode_unchanged() {
    let bytes = proto::field_string(2, "44a2699b-293e-a021-ae4a-617533bb07dc");
    let mut message = Message::parse(&bytes).unwrap();
    message.upsert_varint(20, 1);
    message.upsert_bytes(1, vec![0xff; 5]);
    let encoded = message.encode();
    let re = Message::parse(&encoded).unwrap();
    assert_eq!(re.string(2), Some("44a2699b-293e-a021-ae4a-617533bb07dc"));
    assert_eq!(re.varint(20), Some(1));
    assert_eq!(re.bytes(1), Some(&[0xff; 5][..]));
    assert_eq!(re.encode(), encoded);
}

// ── sync: the wire shapes ───────────────────────────────────────────────────

/// `requestServerItems` asks for all eight classes, each with `not_in_db=false`.
/// All eight, including the three that are legitimately empty: "no items" and
/// "class missing" are different answers.
#[test]
fn the_read_payload_asks_for_every_class() {
    let payload = Sync::read_payload("SESSION");
    let mut expected = proto::field_string(1, "SESSION");
    for class in ItemClass::ALL {
        let mut message = proto::field_varint(1, class.id() as u64);
        message.extend(proto::field_varint(4, 0));
        expected.extend(proto::field_bytes(2, &message));
    }
    assert_eq!(
        payload, expected,
        "read payload drifted from the measured shape"
    );
}

/// An incremental read carries the cursors it already has and omits the ones it
/// does not. This is what turns a quiet account's read from 8862 B into 59 B, and
/// it is the difference between "read everything every time" and "ask what moved".
#[test]
fn a_delta_read_carries_the_cursors_it_has() {
    let known = SyncState {
        global_version: "GLOBAL-VER".to_string(),
        class_version: [(ItemClass::Bookmark, "BOOKMARK-VER".to_string())]
            .into_iter()
            .collect(),
        ..SyncState::default()
    };

    let payload = Sync::delta_payload("SESSION", Some(&known));
    let message = Message::parse(&payload).unwrap();
    assert_eq!(message.string(1), Some("SESSION"));
    assert_eq!(message.string(3), Some("GLOBAL-VER"));

    let classes: Vec<_> = message.all(2).filter_map(|f| f.as_bytes()).collect();
    assert_eq!(
        classes.len(),
        ItemClass::ALL.len(),
        "every class is still listed"
    );
    let bookmark = Message::parse(classes[0]).unwrap();
    assert_eq!(
        bookmark.varint(1).unwrap_or(0),
        ItemClass::Bookmark.id() as u64
    );
    assert_eq!(
        bookmark.string(2),
        Some("BOOKMARK-VER"),
        "the cursor the state has must be sent"
    );
    // A class with no cursor is asked for whole: no version field at all.
    let identity = Message::parse(classes[1]).unwrap();
    assert_eq!(identity.string(2), None);
    assert_eq!(identity.varint(4), Some(0), "not_in_db is still false");
}

/// A state with no cursors asks for everything, which is what the first read and
/// a post-write read-back need.
#[test]
fn a_read_without_cursors_asks_for_the_whole_account() {
    assert_eq!(
        Sync::delta_payload("SESSION", None),
        Sync::read_payload("SESSION")
    );
    assert!(!SyncState::default().has_cursors());
}

/// A delta only speaks about the classes that moved: applying it must leave every
/// other class alone rather than deleting it.
#[test]
fn a_delta_replaces_only_the_classes_it_names() {
    // What a full read established.
    let mut accumulated = SyncState {
        items: vec![
            item(ItemClass::Bookmark, "b1", vec![1]),
            item(ItemClass::Bookmark, "b2", vec![2]),
            item(ItemClass::AddOn, "a1", vec![3]),
        ],
        global_version: "gv-1".to_string(),
        class_version: [
            (ItemClass::Bookmark, "bv-1".to_string()),
            (ItemClass::AddOn, "av-1".to_string()),
        ]
        .into_iter()
        .collect(),
        ..SyncState::default()
    };

    // A delta that names only BOOKMARK.
    let delta = SyncState {
        status: SyncStatus::NotInSync,
        global_version: "gv-2".to_string(),
        class_version: [(ItemClass::Bookmark, "bv-2".to_string())]
            .into_iter()
            .collect(),
        items: vec![
            item(ItemClass::Bookmark, "b1", vec![9]),
            item(ItemClass::Bookmark, "b3", vec![7]),
        ],
    };

    accumulated.apply(&delta);

    // BOOKMARK was replaced wholesale: b1 changed, b2 is gone (it was deleted
    // somewhere else), b3 is new.
    let bookmarks: Vec<&str> = accumulated
        .of_class(ItemClass::Bookmark)
        .map(|i| i.uuid.as_str())
        .collect();
    assert_eq!(bookmarks, vec!["b1", "b3"]);
    assert_eq!(accumulated.item("b1").unwrap().blob, vec![9]);
    // ADD_ON was not named, so it survived untouched.
    assert_eq!(accumulated.item("a1").unwrap().blob, vec![3]);
    // Cursors: BOOKMARK moved, ADD_ON kept its older value.
    assert_eq!(
        accumulated
            .class_version
            .get(&ItemClass::Bookmark)
            .map(String::as_str),
        Some("bv-2")
    );
    assert_eq!(
        accumulated
            .class_version
            .get(&ItemClass::AddOn)
            .map(String::as_str),
        Some("av-1")
    );
    assert_eq!(accumulated.global_version, "gv-2");
    assert_eq!(accumulated.status, SyncStatus::NotInSync);
}

/// The empty reply a quiet account gets (59 B, no class messages) must be a no-op,
/// not a "everything was deleted".
#[test]
fn an_empty_delta_changes_nothing() {
    let mut accumulated = SyncState {
        items: vec![
            item(ItemClass::Bookmark, "b1", vec![1]),
            item(ItemClass::Identity, "i1", vec![2]),
        ],
        global_version: "gv-1".to_string(),
        class_version: [(ItemClass::Bookmark, "bv-1".to_string())]
            .into_iter()
            .collect(),
        ..SyncState::default()
    };

    let delta = SyncState {
        status: SyncStatus::NotInSync,
        global_version: "gv-1".to_string(),
        ..SyncState::default()
    };
    accumulated.apply(&delta);

    assert_eq!(accumulated.items.len(), 2, "nothing may be dropped");
    assert_eq!(accumulated.item("b1").unwrap().blob, vec![1]);
    assert_eq!(accumulated.item("i1").unwrap().blob, vec![2]);
    assert_eq!(accumulated.global_version, "gv-1");
}

/// An upsert carries version **and** blob, one item per request, plus the
/// current `globalversion`. Leaving the blob out erases the item; that is the
/// failure this test exists to make impossible to ship.
#[test]
fn an_upsert_carries_version_blob_and_globalversion() {
    let payload = Sync::upsert_payload(
        "SESSION",
        ItemClass::Bookmark,
        Some("CLASS-VER"),
        "UUID",
        "ITEM-VER",
        &[1, 2, 3],
        "GLOBAL-VER",
    );
    let message = Message::parse(&payload).unwrap();
    assert_eq!(message.string(1), Some("SESSION"));
    assert_eq!(message.string(3), Some("GLOBAL-VER"));

    let class_message = message.message(2).unwrap();
    // BOOKMARK is class 0 and proto3 omits it, but a writer must still be
    // explicit here: the server accepted this form for every class.
    assert_eq!(class_message.varint(1), Some(0));
    assert_eq!(class_message.string(2), Some("CLASS-VER"));
    let details: Vec<_> = class_message.all(3).collect();
    assert_eq!(details.len(), 1, "exactly one detail per request");

    let detail = Message::parse(details[0].as_bytes().unwrap()).unwrap();
    assert_eq!(detail.string(1), Some("UUID"));
    assert_eq!(detail.string(2), Some("ITEM-VER"));
    assert_eq!(detail.bytes(3), Some(&[1u8, 2, 3][..]));
    assert_eq!(
        detail.varint(4),
        None,
        "a delete flag next to a version is rejected"
    );
}

/// A delete is `uuid + item_delte_on_server=1` and **no version**: carrying one
/// makes the server reject the whole request with `103`.
#[test]
fn a_delete_carries_the_flag_and_no_version() {
    let payload = Sync::delete_payload(
        "SESSION",
        ItemClass::AddOn,
        Some("CLASS-VER"),
        "UUID",
        "GLOBAL-VER",
    );
    let message = Message::parse(&payload).unwrap();
    let class_message = message.message(2).unwrap();
    assert_eq!(class_message.varint(1), Some(4));
    assert_eq!(class_message.string(2), Some("CLASS-VER"));
    let detail = Message::parse(class_message.all(3).next().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(detail.string(1), Some("UUID"));
    assert_eq!(detail.varint(2), None);
    assert_eq!(detail.varint(3), None);
    assert_eq!(detail.varint(4), Some(1));
}

/// A reply is only trusted after it parses: `300` is the sole accepted write
/// status, and an unparseable body must not be read as success.
#[test]
fn reply_codes_map_to_the_documented_statuses() {
    let reply = [0x08, 0xAC, 0x02]; // field 1 = 300
    assert_eq!(Sync::decode_write_reply(&reply), SyncStatus::InSync);
    assert!(Sync::decode_write_reply(&reply).accepted());
    assert_eq!(
        Sync::decode_write_reply(&[0x08, 0x67]),
        SyncStatus::Critical
    );
    assert!(!Sync::decode_write_reply(&[0x08, 0x67]).accepted());
    assert!(!Sync::decode_write_reply(&[0xff]).accepted());
    assert_eq!(
        SyncStatus::from_code(301).name(),
        "NOT_IN_SYNC",
        "301 means the local copy is behind, never that a write succeeded"
    );
}

/// A reply with a class message that has no `itemclass` is BOOKMARK, not an
/// error: proto3 omits a zero, and refusing that message drops every bookmark.
#[test]
fn a_reply_without_an_itemclass_is_a_bookmark() {
    let bookmark = Item {
        uuid: "b0000000-0000-0000-0000-000000000001".to_string(),
        class: ItemClass::Bookmark,
        item_version: "ver-1".to_string(),
        blob: vec![9; 20],
        deleted: false,
        meta: Default::default(),
    };
    let mut class_message = proto::field_string(2, "CLASS-VER");
    let mut detail = proto::field_string(1, &bookmark.uuid);
    detail.extend(proto::field_string(2, &bookmark.item_version));
    detail.extend(proto::field_bytes(3, &bookmark.blob));
    class_message.extend(proto::field_bytes(3, &detail));

    let mut reply = proto::field_varint(1, 301);
    reply.extend(proto::field_bytes(2, &class_message));
    reply.extend(proto::field_string(3, "GLOBAL-VER"));

    let state = Sync::decode_reply(&reply).unwrap();
    assert_eq!(state.status, SyncStatus::NotInSync);
    assert_eq!(state.global_version, "GLOBAL-VER");
    assert_eq!(
        state
            .class_version
            .get(&ItemClass::Bookmark)
            .map(String::as_str),
        Some("CLASS-VER")
    );
    assert_eq!(state.items.len(), 1);
    assert_eq!(state.items[0].class, ItemClass::Bookmark);
    assert_eq!(state.items[0].blob, bookmark.blob);
}

// ── the class table, including the TS6 half ─────────────────────────────────

/// The class numbers are read off the server binaries' own embedded descriptors,
/// not off documentation. TS3 3.13.9 defines 0–7 with `ROOM_CATEGORY = 7` and no
/// 8 at all; TS6 6.0.0-beta14 defines `… ITEM_FOLDER = 6, GROUP_CHATS = 7,
/// CONTACTS = 8`.
#[test]
fn the_class_table_covers_both_products() {
    // TS3's eight.
    assert_eq!(ItemClass::from_id(0), Some(ItemClass::Bookmark));
    assert_eq!(ItemClass::from_id(6), Some(ItemClass::ItemFolder));
    assert_eq!(ItemClass::from_id(7), Some(ItemClass::RoomCategory));
    // TS6's extra one, which TS3 never sends.
    assert_eq!(ItemClass::from_id(8), Some(ItemClass::Contacts));
    assert_eq!(ItemClass::Contacts.name(), "CONTACTS");
    assert_eq!(ItemClass::Contacts.id(), 8);
    // A number neither product defines is still "unknown", not invented.
    assert_eq!(ItemClass::from_id(9), None);

    assert_eq!(
        ItemClass::ALL.len(),
        9,
        "all eight TS3 classes plus CONTACTS"
    );
    assert!(ItemClass::ALL.contains(&ItemClass::Contacts));
}

/// Class 7 is the same number under two names. The enum keeps TS3's name because
/// this core targets TS3, but a shell may ask for it by either spelling.
#[test]
fn class_seven_answers_to_both_names() {
    assert_eq!(
        ItemClass::parse("ROOM_CATEGORY"),
        Some(ItemClass::RoomCategory)
    );
    assert_eq!(
        ItemClass::parse("roomCategory"),
        Some(ItemClass::RoomCategory)
    );
    assert_eq!(
        ItemClass::parse("GROUP_CHATS"),
        Some(ItemClass::RoomCategory)
    );
    assert_eq!(
        ItemClass::parse("groupChats"),
        Some(ItemClass::RoomCategory)
    );
    assert_eq!(ItemClass::parse("7"), Some(ItemClass::RoomCategory));
    // But the rendered name stays TS3's, so a shell's labels do not change under
    // it when talking to a TS3 server.
    assert_eq!(ItemClass::RoomCategory.name(), "ROOM_CATEGORY");

    assert_eq!(ItemClass::parse("CONTACTS"), Some(ItemClass::Contacts));
    assert_eq!(ItemClass::parse("contacts"), Some(ItemClass::Contacts));
    assert_eq!(ItemClass::parse("8"), Some(ItemClass::Contacts));
    // And something made up is refused rather than silently mapped to a class.
    assert_eq!(ItemClass::parse("NOT_A_CLASS"), None);
}

/// The read request asks for every class the client can name, including TS6's
/// contacts. Asking a TS3 server for class 8 is harmless — it simply answers
/// nothing — and asking a TS6 server is the only way contacts arrive.
#[test]
fn the_read_request_asks_for_the_contacts_class_too() {
    let payload = Sync::read_payload("SESSION");
    let message = Message::parse(&payload).expect("parse");
    let classes: Vec<u32> = message
        .all(2)
        .filter_map(|field| field.as_bytes())
        .filter_map(|bytes| Message::parse(bytes).ok())
        .map(|class| class.varint(1).unwrap_or(0) as u32)
        .collect();
    let mut expected: Vec<u32> = (0..=8).collect();
    expected.sort();
    let mut actual = classes.clone();
    actual.sort();
    assert_eq!(actual, expected, "nine class messages, 0 through 8");
}

/// A class-8 (TS6 CONTACTS) item is decoded, kept in the state, written to a
/// backup and read back. TS3 has no such class, so a live TS3 account can never
/// show this; the shape comes from TS6's own descriptor.
#[test]
fn a_contacts_item_survives_decode_state_and_backup() {
    // A minimal Item_Data: uuid, version, type 8, and a Contact payload in f25.
    let uuid = "c0000000-0000-0000-0000-000000000001";
    let mut contact = proto::field_string(1, "@someone:matrix.example");
    contact.extend(proto::field_string(2, "a note"));
    let mut plain = proto::field_string(2, uuid);
    plain.extend(proto::field_string(3, "item-version"));
    plain.extend(proto::field_varint(6, ItemClass::Contacts.id() as u64));
    plain.extend(proto::field_bytes(25, &contact));

    // Wrap it in a reply the way the service does: class 8, no cursor (the class
    // is present but has no version of its own in this fixture), one detail.
    let mut detail = proto::field_string(1, uuid);
    detail.extend(proto::field_string(2, "item-version"));
    detail.extend(proto::field_bytes(3, &plain));
    let mut class = proto::field_varint(1, ItemClass::Contacts.id() as u64);
    class.extend(proto::field_bytes(3, &detail));
    let mut reply = proto::field_varint(1, 301);
    reply.extend(proto::field_bytes(2, &class));
    reply.extend(proto::field_string(3, "global"));

    let state = Sync::decode_reply(&reply).expect("decode");
    assert_eq!(state.items.len(), 1, "the class-8 item is not dropped");
    let item = &state.items[0];
    assert_eq!(item.class, ItemClass::Contacts);
    assert_eq!(item.class.name(), "CONTACTS");
    assert_eq!(state.of_class(ItemClass::Contacts).count(), 1);

    // It folds into an accumulated state by class, like any other.
    let mut accumulated = SyncState::default();
    accumulated.apply(&state);
    assert_eq!(accumulated.of_class(ItemClass::Contacts).count(), 1);

    // And a backup carries it verbatim, so a restore can replay it.
    let backup = sync::Backup::of(&accumulated);
    let json = backup.to_json();
    let entry = json["items"]
        .as_array()
        .and_then(|items| items.iter().find(|entry| entry["className"] == "CONTACTS"))
        .expect("the contact is in the backup");
    assert_eq!(entry["classId"], 8);
    assert_eq!(entry["uuid"], uuid);

    let restored = sync::Backup::from_json(&json).expect("read the backup");
    assert_eq!(restored.items.len(), 1);
    assert_eq!(restored.items[0].class, ItemClass::Contacts);
    assert_eq!(
        restored.items[0].blob, plain,
        "the blob a restore replays is the original"
    );
}

// ── placement: parent, sort_order, folders ─────────────────────────────────

/// The eight bookmarks of the reference account, in the order the official
/// client draws them, with their \`sort_order\` values exactly as the local
/// database holds them.
///
/// This is the vector that pins the **link, not a rank** rule: \`sort_order\`
/// names the item that comes *before* this one, and the first bookmark has an
/// empty string. Sorted as text or as a number, this list comes out wrong;
/// following the links reproduces it exactly.
const CHAIN: [(&str, &str); 8] = [
    ("fcfe1a38-6f0b-443d-1322-375386efee5a", ""),
    (
        "973984d8-8a72-00d9-b040-77c5e40f74ba",
        "fcfe1a38-6f0b-443d-1322-375386efee5a",
    ),
    (
        "cad3333c-e055-cc63-fac2-88d381f51afe",
        "973984d8-8a72-00d9-b040-77c5e40f74ba",
    ),
    (
        "9e699eaa-8301-d672-e504-aa2826f5c8ee",
        "cad3333c-e055-cc63-fac2-88d381f51afe",
    ),
    (
        "50a610ee-cea5-040a-f5fd-b646dcef6bd7",
        "9e699eaa-8301-d672-e504-aa2826f5c8ee",
    ),
    (
        "39d83b7b-1f0b-59ac-110b-110e066a4201",
        "50a610ee-cea5-040a-f5fd-b646dcef6bd7",
    ),
    (
        "44a2699b-293e-a021-ae4a-617533bb07dc",
        "39d83b7b-1f0b-59ac-110b-110e066a4201",
    ),
    (
        "969a51db-8500-0000-0000-000000000000",
        "44a2699b-293e-a021-ae4a-617533bb07dc",
    ),
];

#[test]
fn sort_order_is_a_link_to_the_previous_item_not_a_rank() {
    let links: Vec<(String, String)> = CHAIN
        .iter()
        .map(|(uuid, link)| (uuid.to_string(), link.to_string()))
        .collect();

    let ordered = sync::order_by_sort_order(&links);
    let expected: Vec<String> = CHAIN.iter().map(|(uuid, _)| uuid.to_string()).collect();
    assert_eq!(
        ordered, expected,
        "following the links reproduces the order the client draws"
    );

    // And the naive reading is wrong, which is why this vector is here: the real
    // order is not the uuid order.
    let mut alphabetical: Vec<&str> = CHAIN.iter().map(|(uuid, _)| *uuid).collect();
    alphabetical.sort();
    assert_ne!(
        alphabetical,
        expected.iter().map(String::as_str).collect::<Vec<_>>(),
        "the real order is not the uuid order"
    );
}

/// A cycle and a link to an item outside the list. The first must terminate,
/// the second must not drop the row: losing a bookmark is worse than showing it
/// last.
#[test]
fn ordering_terminates_on_a_cycle_and_keeps_a_foreign_link() {
    let cycle = vec![
        ("a".to_string(), "b".to_string()),
        ("b".to_string(), "a".to_string()),
    ];
    let ordered = sync::order_by_sort_order(&cycle);
    assert_eq!(ordered.len(), 2, "every row survives a cycle");
    assert_eq!(ordered, vec!["a".to_string(), "b".to_string()]);

    // "b"'s predecessor is outside this list, so "b" is a head and "a" follows.
    let foreign = vec![
        ("a".to_string(), "b".to_string()),
        ("b".to_string(), "somewhere-else".to_string()),
    ];
    assert_eq!(
        sync::order_by_sort_order(&foreign),
        vec!["b".to_string(), "a".to_string()],
        "a foreign link is a chain head, not a lost item"
    );
}

/// \`Item_Folder\` is field 22 of a class-6 \`Item_Data\`: a name and the class it
/// groups. The live account has class 6 present but empty, so the bytes here are
/// constructed from the schema rather than captured.
#[test]
fn a_folder_parses_its_name_and_the_class_it_groups() {
    let mut folder = proto::field_string(1, "Work");
    folder.extend(proto::field_varint(2, ItemClass::Bookmark.id() as u64));
    let mut plain = proto::field_string(2, "f0000000-0000-0000-0000-000000000001");
    plain.extend(proto::field_bytes(22, &folder));

    let parsed = ItemFolder::parse(&plain).expect("parse").expect("a folder");
    assert_eq!(parsed.name, "Work");
    assert_eq!(parsed.folder_type, Some(ItemClass::Bookmark));
    assert_eq!(
        parsed.folder_type_id, 0,
        "BOOKMARK is class 0, omitted on the wire"
    );

    // Class 8 is CONTACTS: TS6 defines it, so a folder may legitimately group
    // contacts. That is the newer half of the same number space.
    let mut contacts = proto::field_string(1, "Friends");
    contacts.extend(proto::field_varint(2, ItemClass::Contacts.id() as u64));
    let plain = proto::field_bytes(22, &contacts);
    let parsed = ItemFolder::parse(&plain).expect("parse").expect("a folder");
    assert_eq!(parsed.folder_type, Some(ItemClass::Contacts));
    assert_eq!(parsed.folder_type_id, 8);

    // A class number this build does not define is kept as a number instead of
    // being guessed at, so a future class is visible rather than dropped.
    let mut unknown = proto::field_string(1, "Later");
    unknown.extend(proto::field_varint(2, 99));
    let plain = proto::field_bytes(22, &unknown);
    let parsed = ItemFolder::parse(&plain).expect("parse").expect("a folder");
    assert_eq!(parsed.folder_type, None);
    assert_eq!(parsed.folder_type_id, 99, "the number is still reportable");

    // A bookmark is not a folder.
    let bookmark = plain_item("b0000000-0000-0000-0000-000000000002", b"Book");
    assert_eq!(ItemFolder::parse(&bookmark).unwrap(), None);
}

/// Absent and empty are the same placement. The reference account writes the
/// fields as zero-length strings, and a JSON file that omits them describes the
/// identical tree.
#[test]
fn an_item_with_no_parent_is_at_the_top_level() {
    let absent = proto::field_string(2, "b0000000-0000-0000-0000-000000000003");
    let meta = ItemMeta::parse(&absent).unwrap();
    assert!(meta.is_root());
    assert_eq!(meta.sort_order, "");

    // What the live blobs actually carry: both fields present with length 0.
    let mut empty = proto::field_string(2, "b0000000-0000-0000-0000-000000000004");
    empty.extend(proto::field_bytes(7, b""));
    empty.extend(proto::field_bytes(8, b""));
    let meta = ItemMeta::parse(&empty).unwrap();
    assert!(meta.is_root());
    assert_eq!(meta, ItemMeta::default());

    let mut placed = proto::field_string(2, "b0000000-0000-0000-0000-000000000005");
    placed.extend(proto::field_string(
        7,
        "f0000000-0000-0000-0000-000000000001",
    ));
    placed.extend(proto::field_string(
        8,
        "b0000000-0000-0000-0000-000000000004",
    ));
    let meta = ItemMeta::parse(&placed).unwrap();
    assert!(!meta.is_root());
    assert_eq!(meta.parent, "f0000000-0000-0000-0000-000000000001");
    assert_eq!(meta.sort_order, "b0000000-0000-0000-0000-000000000004");
}

/// A folder with two bookmarks in it and one bookmark outside: the tree must be a
/// pre-order walk with the children indented, and the chain inside each list must
/// be honoured.
#[test]
fn hierarchy_rebuilds_folders_and_indents_their_children() {
    let folder = "f0000000-0000-0000-0000-0000000000f1";
    let inside_a = "b0000000-0000-0000-0000-0000000000a1";
    let inside_b = "b0000000-0000-0000-0000-0000000000a2";
    let outside = "b0000000-0000-0000-0000-0000000000b1";

    let items = vec![
        // A folder named Work, holding bookmarks.
        folder_item(folder, "Work"),
        // First child: an empty link, which is how the client writes the first
        // item of a list.
        child_item(inside_a, folder, "", "Inside A"),
        child_item(inside_b, folder, inside_a, "Inside B"),
        // A top-level bookmark with no folder.
        child_item(outside, "", "", "Outside"),
    ];
    let state = SyncState {
        items,
        ..SyncState::default()
    };

    let tree = sync::hierarchy(&state, None);
    assert!(
        tree.unplaced.is_empty(),
        "all four are readable: {:?}",
        tree.unplaced
    );

    let flat: Vec<(&str, usize)> = tree
        .entries
        .iter()
        .map(|node| (node.uuid.as_str(), node.depth))
        .collect();
    assert_eq!(
        flat,
        vec![(folder, 0), (inside_a, 1), (inside_b, 1), (outside, 0)],
        "pre-order, children under their folder"
    );
    assert_eq!(tree.entries[0].folder_for, Some(ItemClass::Bookmark));
    assert_eq!(tree.entries[0].name, "Work");
    assert_eq!(tree.entries[1].name, "Inside A");
    assert_eq!(tree.entries[1].parent, folder);
}

/// An item whose \`parent\` names something that is not a folder still has to
/// appear. It is reported as unplaced *and* kept at the top level, because a
/// bookmark that silently vanished is the worst outcome of the three.
#[test]
fn an_item_with_an_unknown_parent_is_kept_at_the_top_and_reported() {
    let orphan = "b0000000-0000-0000-0000-0000000000c1";
    let state = SyncState {
        items: vec![child_item(orphan, "not-a-folder", "", "Orphan")],
        ..SyncState::default()
    };

    let tree = sync::hierarchy(&state, None);
    assert_eq!(tree.entries.len(), 1, "the row is not lost");
    assert_eq!(tree.entries[0].uuid, orphan);
    assert_eq!(tree.entries[0].depth, 0);
    assert_eq!(tree.unplaced, vec![orphan.to_string()]);
}

/// A sealed item cannot be placed without the key, and pretending otherwise is
/// how an import silently flattens. With the key, the placement comes out of the
/// plaintext and the tree is complete.
#[test]
fn a_locked_item_is_reported_instead_of_being_flattened() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let cipher = ItemCipher::new(key);
    let folder = "f0000000-0000-0000-0000-0000000000d1";
    let child = "b0000000-0000-0000-0000-0000000000d2";

    let sealed_folder = cipher.seal(&folder_plain(folder, "Sealed"));
    let sealed_child = cipher.seal(&child_plain(child, folder, "", "Hidden"));
    let state = SyncState {
        items: vec![
            item(ItemClass::ItemFolder, folder, sealed_folder),
            item(ItemClass::Bookmark, child, sealed_child),
        ],
        ..SyncState::default()
    };

    // Without the key: nothing is placed, and both are named.
    let blind = sync::hierarchy(&state, None);
    assert!(blind.entries.is_empty());
    assert_eq!(blind.unplaced.len(), 2);

    // With the key: the same tree the plaintext would have given.
    let tree = sync::hierarchy(&state, Some(&cipher));
    assert!(tree.unplaced.is_empty());
    assert_eq!(tree.entries.len(), 2);
    assert_eq!(tree.entries[0].uuid, folder);
    assert_eq!(tree.entries[0].folder_for, Some(ItemClass::Bookmark));
    assert_eq!(tree.entries[1].uuid, child);
    assert_eq!(tree.entries[1].depth, 1);
}

/// A detail carries f7/f8 when the blob is plain, and the decoder keeps them; a
/// sealed blob must not be half-read as a message.
#[test]
fn the_reply_decoder_keeps_the_placement_of_plaintext_details_only() {
    let uuid = "b0000000-0000-0000-0000-0000000000e1";
    let parent = "f0000000-0000-0000-0000-0000000000e2";
    let mut plain = proto::field_string(2, uuid);
    plain.extend(proto::field_string(7, parent));
    plain.extend(proto::field_string(
        8,
        "b0000000-0000-0000-0000-0000000000e3",
    ));

    let key: [u8; 32] = std::array::from_fn(|i| (i * 3) as u8);
    let sealed = ItemCipher::new(key).seal(&plain);
    assert_ne!(
        ItemMeta::parse(&sealed).unwrap_or_default().parent,
        parent,
        "a sealed blob does not leak its placement as if it were a message"
    );

    let mut detail = proto::field_string(1, uuid);
    detail.extend(proto::field_string(2, "ver"));
    detail.extend(proto::field_bytes(3, &plain));
    let mut class = proto::field_varint(1, ItemClass::Bookmark.id() as u64);
    class.extend(proto::field_string(2, "CLASS"));
    class.extend(proto::field_bytes(3, &detail));
    let mut reply = proto::field_varint(1, 301);
    reply.extend(proto::field_bytes(2, &class));
    reply.extend(proto::field_string(3, "GLOBAL"));

    let state = Sync::decode_reply(&reply).expect("decode");
    let decoded = &state.items[0];
    assert_eq!(decoded.meta.parent, parent);
    assert_eq!(
        decoded.meta.sort_order,
        "b0000000-0000-0000-0000-0000000000e3"
    );
}

/// A backup records the placement so a reader does not have to decrypt to see the
/// tree, and a restore still replays the blob itself.
#[test]
fn a_backup_writes_the_placement_and_reads_it_back() {
    let uuid = "b0000000-0000-0000-0000-0000000000f1";
    let mut plain = proto::field_string(2, uuid);
    plain.extend(proto::field_string(7, "folder"));
    plain.extend(proto::field_string(8, "previous"));
    let meta = ItemMeta::parse(&plain).expect("parse");

    let state = SyncState {
        items: vec![Item {
            uuid: uuid.to_string(),
            class: ItemClass::Bookmark,
            item_version: "ver".to_string(),
            blob: plain.clone(),
            deleted: false,
            meta,
        }],
        ..SyncState::default()
    };

    let json = sync::Backup::of(&state).to_json();
    let entry = &json["items"][0];
    assert_eq!(entry["parent"], "folder");
    assert_eq!(entry["sortOrder"], "previous");

    let back = sync::Backup::from_json(&json).expect("read the backup");
    assert_eq!(back.items.len(), 1);
    assert_eq!(back.items[0].meta.parent, "folder");
    assert_eq!(back.items[0].meta.sort_order, "previous");
    assert_eq!(
        back.items[0].blob, plain,
        "the blob is what a restore replays"
    );
}

/// A class-6 \`Item_Data\`: a folder with a name, whose placement is the top level.
fn folder_item(uuid: &str, name: &str) -> Item {
    let plain = folder_plain(uuid, name);
    Item {
        uuid: uuid.to_string(),
        class: ItemClass::ItemFolder,
        item_version: "version".to_string(),
        blob: plain.clone(),
        deleted: false,
        meta: ItemMeta::parse(&plain).expect("parse"),
    }
}

fn folder_plain(uuid: &str, name: &str) -> Vec<u8> {
    let mut plain = proto::field_string(2, uuid);
    plain.extend(proto::field_string(3, "version"));
    plain.extend(proto::field_varint(6, ItemClass::ItemFolder.id() as u64));
    plain.extend(proto::field_string(7, ""));
    plain.extend(proto::field_string(8, ""));
    let mut folder = proto::field_string(1, name);
    folder.extend(proto::field_varint(2, ItemClass::Bookmark.id() as u64));
    plain.extend(proto::field_bytes(22, &folder));
    plain
}

/// A bookmark with a placement and a name.
fn child_plain(uuid: &str, parent: &str, sort_order: &str, name: &str) -> Vec<u8> {
    let mut plain = proto::field_string(2, uuid);
    plain.extend(proto::field_string(3, "version"));
    plain.extend(proto::field_string(7, parent));
    plain.extend(proto::field_string(8, sort_order));
    let mut bookmark = proto::field_string(1, name);
    bookmark.extend(proto::field_string(2, "ts.example.com"));
    bookmark.extend(proto::field_varint(3, 9987));
    plain.extend(proto::field_bytes(16, &bookmark));
    plain
}

fn child_item(uuid: &str, parent: &str, sort_order: &str, name: &str) -> Item {
    let plain = child_plain(uuid, parent, sort_order, name);
    Item {
        uuid: uuid.to_string(),
        class: ItemClass::Bookmark,
        item_version: "version".to_string(),
        blob: plain.clone(),
        deleted: false,
        meta: ItemMeta::parse(&plain).expect("parse"),
    }
}

// ── the item cipher ─────────────────────────────────────────────────────────

/// The fixed vector: key `00..1f`, header `40..4f`. Expected blocks were produced
/// independently with node's AES-ECB (`itemcipher_vectors.mjs`), and they encode
/// the counter rule the open-source `ts3java` client uses — a 16-byte
/// little-endian counter incremented per block.
#[test]
fn the_item_cipher_matches_the_fixed_vector() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let header: [u8; 16] = std::array::from_fn(|i| 0x40 + i as u8);
    let cipher = ItemCipher::new(key);

    // The keystream is visible indirectly: encrypt a known plaintext and check
    // the bytes. A single-byte plaintext gives the first 16-byte block's first
    // byte, which is enough to catch a wrong key or a wrong counter start.
    let blob = cipher.seal_with(b"t", header);
    assert_eq!(blob.len(), 1 + ENVELOPE_LEN);
    assert_eq!(
        &blob[..HEADER_LEN],
        &header,
        "the header is stored verbatim"
    );
    // 0x74 XOR keystream[0]; keystream block 0 begins a3 7e df 3f …
    assert_eq!(blob[HEADER_LEN], 0x74 ^ 0xa3);

    // Block 1 is what proves the counter rule: a plaintext longer than 16 B
    // reaches the second block, whose keystream begins d7 45 …
    let plain: Vec<u8> = (0u8..20).collect();
    let blob = cipher.seal_with(&plain, header);
    assert_eq!(
        blob[HEADER_LEN + 16],
        plain[16] ^ 0xd7,
        "block 1's keystream must come from the header incremented by one"
    );
    assert_eq!(cipher.open(&blob).unwrap(), plain);
}

/// The counter is the whole 16-byte header read little-endian, so an increment
/// **carries out of byte 3 into byte 4**. A 32-bit word-0 counter would keep
/// bytes 4..15 fixed and produce a different keystream here — and nowhere else,
/// which is why this vector is the one that pins the choice.
#[test]
fn the_counter_carries_across_the_whole_header() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let header: [u8; 16] = [
        0xff, 0xff, 0xff, 0xff, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
        0x5b,
    ];
    let cipher = ItemCipher::new(key);
    let plain: Vec<u8> = (0u8..48).collect();
    let blob = cipher.seal_with(&plain, header);
    assert_eq!(blob[HEADER_LEN], plain[0] ^ 0xeb);
    assert_eq!(
        blob[HEADER_LEN + 16],
        plain[16] ^ 0x59,
        "block 1 carries into byte 4: the input is 00 00 00 00 51 52 ..."
    );
    assert_eq!(
        blob[HEADER_LEN + 32],
        plain[32] ^ 0xaa,
        "block 2 is 01 00 00 00 51 52 ..."
    );
    assert_eq!(cipher.open(&blob).unwrap(), plain);
}

/// Any length, in both directions, with no length rule at all.
#[test]
fn the_item_cipher_handles_any_length() {
    let key: [u8; 32] = std::array::from_fn(|i| (i * 7) as u8);
    let cipher = ItemCipher::new(key);
    for size in [0usize, 1, 15, 16, 17, 281, 363, 1200, 5000] {
        let plain: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(31)).collect();
        let blob = cipher.seal(&plain);
        assert_eq!(blob.len(), size + ENVELOPE_LEN);
        // A fresh header each time, so two seals of the same plaintext differ.
        assert_eq!(cipher.open(&blob).unwrap(), plain, "{size} B round trip");
    }
    let first = cipher.seal(b"same");
    let second = cipher.seal(b"same");
    assert_ne!(
        first[..HEADER_LEN],
        second[..HEADER_LEN],
        "two seals must not reuse a counter"
    );
}

/// The trailing SHA-512 is the only integrity check the format has, so a wrong
/// key or a corrupted byte must be rejected rather than produce garbage.
#[test]
fn a_corrupted_item_is_rejected() {
    let key: [u8; 32] = std::array::from_fn(|i| (i * 3) as u8);
    let cipher = ItemCipher::new(key);
    let plain = b"a bookmark whose bytes matter".to_vec();
    let blob = cipher.seal(&plain);

    let mut flipped = blob.clone();
    flipped[HEADER_LEN] ^= 0x01;
    assert!(cipher.open(&flipped).is_err(), "a flipped ciphertext byte");

    let mut wrong = ItemCipher::new([0u8; 32]);
    if key != [0u8; 32] {
        assert!(wrong.open(&blob).is_err(), "a wrong key");
    }
    wrong = ItemCipher::new(std::array::from_fn(|i| (i * 3) as u8 ^ 0xff));
    assert!(wrong.open(&blob).is_err(), "a key one nibble off");

    assert!(
        cipher.open(&blob[..ENVELOPE_LEN - 1]).is_err(),
        "truncated framing"
    );
}

/// A plaintext `Item_Data` needs no key at all, and a wrapped one is
/// `Encrypted` only when the session actually holds the key.
#[test]
fn capability_follows_the_key_not_the_disk() {
    let uuid = "a0000000-0000-0000-0000-000000000001";
    let plain = plain_item(uuid, b"");
    let plain_item_struct = item(ItemClass::AddOn, uuid, plain.clone());

    assert_eq!(
        sync::capability_of(&plain_item_struct, None),
        Capability::Plaintext,
        "a bare Item_Data needs no key"
    );
    assert!(sync::is_plain_item_data(&plain));

    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let cipher = ItemCipher::new(key);
    let wrapped = item(
        ItemClass::Bookmark,
        uuid,
        cipher.seal(&plain_item(uuid, b"Lobby")),
    );
    assert_eq!(
        sync::capability_of(&wrapped, Some(&cipher)),
        Capability::Encrypted,
        "with the key, a wrapped item is writable"
    );
    assert_eq!(
        sync::capability_of(&wrapped, None),
        Capability::Locked,
        "without the key it is not, and is reported as locked rather than guessed at"
    );
    assert_eq!(Capability::Encrypted.max_plaintext(), None, "no ceiling");
    assert!(Capability::Encrypted.writable());
    assert!(!Capability::Locked.writable());

    // Read through the same helper the renderer uses.
    assert_eq!(
        sync::read_plain(&wrapped, Some(&cipher)).unwrap(),
        plain_item(uuid, b"Lobby")
    );
    assert!(sync::read_plain(&wrapped, None).is_err());
}

/// A new bookmark is built from an existing one, keeping every field this code
/// does not understand, and is readable again as a bookmark.
#[test]
fn a_bookmark_is_built_from_a_template_and_reads_back() {
    let template = plain_item("c0000000-0000-0000-0000-000000000001", b"");
    let draft = sync::BookmarkDraft {
        uuid: "c0000000-0000-0000-0000-000000000002".to_string(),
        item_version: "c0000000-0000-0000-0000-000000000003".to_string(),
        name: "Lobby".to_string(),
        address: "ts.example.com".to_string(),
        port: 9987,
        nickname: "me".to_string(),
    };
    let built = sync::build_bookmark(&template, &draft).unwrap();
    let parsed = Message::parse(&built).unwrap();
    assert_eq!(parsed.string(2), Some(draft.uuid.as_str()));
    assert_eq!(parsed.string(3), Some(draft.item_version.as_str()));
    let bookmark = sync::Bookmark::parse(&built)
        .unwrap()
        .expect("still a bookmark");
    assert_eq!(bookmark.name, "Lobby");
    assert_eq!(bookmark.address, "ts.example.com");
    assert_eq!(bookmark.port, 9987);
    assert_eq!(bookmark.nickname, "me");
    // Every field the caller did not name is inherited from the template — that
    // is the entire reason a template is used instead of a hand-built message. A
    // bookmark that lost `send_mytsid` would silently change what the client
    // sends when it joins.
    assert!(bookmark.send_mytsid);

    // …but the identity of the item is *not* inherited. A new bookmark that
    // claimed "unmodified" and carried the template's `last_known_version`
    // looked exactly like one on the server, so a three-way comparison would
    // see it as editing somebody else's revision.
    assert_eq!(
        parsed.varint(4),
        Some(sync::ITEM_ADDED),
        "a new bookmark must read as an add"
    );
    assert_eq!(
        parsed.string(5),
        Some(sync::UNPUBLISHED_VERSION),
        "a new bookmark supersedes nothing"
    );
}

/// The rule for a created item, pinned against the official client's own
/// never-uploaded rows: `manipulated = 0` and `last_known_version` all-ones.
///
/// Evidence lives in `research/myts-login/explore/item_shape_summary.mjs`; this
/// test is the guard, so the shape cannot drift without a failing build.
#[test]
fn a_new_item_is_marked_as_an_add_and_supersedes_nothing() {
    let template = plain_item("c0000000-0000-0000-0000-000000000011", b"");
    let draft = sync::BookmarkDraft {
        uuid: "c0000000-0000-0000-0000-000000000012".to_string(),
        item_version: "c0000000-0000-0000-0000-000000000013".to_string(),
        name: "Fresh".to_string(),
        address: "a.b".to_string(),
        port: 9987,
        nickname: String::new(),
    };
    let built = sync::build_bookmark(&template, &draft).unwrap();
    let parsed = Message::parse(&built).unwrap();
    assert_eq!(parsed.varint(4), Some(sync::ITEM_ADDED));
    assert_eq!(parsed.string(5), Some(sync::UNPUBLISHED_VERSION));
    assert_eq!(
        sync::UNPUBLISHED_VERSION,
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    );
    // A field the template carried and this code does not model survives.
    assert_eq!(parsed.bytes(1), Message::parse(&template).unwrap().bytes(1));
}

/// An edit of a committed item keeps a real `last_known_version`.
///
/// the official upload carries `manipulated = 3` and the version the item had
/// before, which is what `mark_changed` writes.
#[test]
fn an_edit_remembers_the_version_it_replaced() {
    let mut plain = plain_item("c0000000-0000-0000-0000-000000000014", b"");
    let mut message = Message::parse(&plain).unwrap();
    sync::mark_changed(&mut message, "previous-version");
    plain = message.encode();
    let parsed = Message::parse(&plain).unwrap();
    assert_eq!(parsed.varint(4), Some(sync::ITEM_NOT_MANIPULATED));
    assert_eq!(parsed.string(5), Some("previous-version"));
}

/// A template with a field this code knows nothing about keeps it, byte for
/// byte, through the rewrite. Losing an unknown field is how a new bookmark ends
/// up subtly different from every existing one.
#[test]
fn a_bookmark_rewrite_preserves_fields_it_does_not_understand() {
    let uuid = "c0000000-0000-0000-0000-000000000004";
    let mut template = plain_item(uuid, b"");
    // A high-numbered field this crate has no meaning for.
    let mut unknown = proto::field_varint(1, 9);
    unknown.extend(proto::field_bytes(2, b"unknown payload"));
    template.extend(proto::field_bytes(31, &unknown));

    let draft = sync::BookmarkDraft {
        uuid: "c0000000-0000-0000-0000-000000000005".to_string(),
        item_version: "c0000000-0000-0000-0000-000000000006".to_string(),
        name: "Short".to_string(),
        address: "a.b".to_string(),
        port: 8765,
        nickname: "n".to_string(),
    };
    let built = sync::build_bookmark(&template, &draft).unwrap();
    let parsed = Message::parse(&built).unwrap();
    assert_eq!(
        parsed.bytes(31),
        Message::parse(&template).unwrap().bytes(31),
        "the unknown field was dropped or rewritten"
    );
}

/// A bookmark password is a secret in a snapshot, so it is opt-in: the item list
/// reports whether one exists, and only a command that asks for it gets the
/// value. This is the same rule the account key follows.
#[test]
fn bookmark_passwords_are_presence_only_until_asked_for() {
    let key: [u8; 32] = std::array::from_fn(|i| (i * 11) as u8);
    let cipher = ItemCipher::new(key);

    // A bookmark with a server password and a channel password, built the way
    // the real client stores one.
    let uuid = "b0000000-0000-0000-0000-00000000000a";
    let mut inner = proto::field_string(1, "Lobby");
    inner.extend(proto::field_string(2, "ts.example.com"));
    inner.extend(proto::field_varint(3, 9987));
    inner.extend(proto::field_string(4, "me"));
    inner.extend(proto::field_string(7, "server-pw"));
    inner.extend(proto::field_string(9, "channel-pw"));
    let mut plain = proto::field_bytes(2, uuid.as_bytes());
    plain.extend(proto::field_bytes(3, b"v"));
    plain.extend(proto::field_bytes(16, &inner));

    let state = SyncState {
        items: vec![item(ItemClass::Bookmark, uuid, cipher.seal(&plain))],
        ..SyncState::default()
    };

    let hidden = tsbridge_core::account::describe(&state, Some(&cipher), false);
    let json = hidden[0].to_json();
    let bookmark = &json["bookmark"];
    assert_eq!(bookmark["hasServerPassword"], true);
    assert_eq!(bookmark["hasChannelPassword"], true);
    assert!(
        bookmark.get("serverPassword").is_none(),
        "the value must not be in a default render"
    );
    assert!(bookmark.get("channelPassword").is_none());
    assert!(
        !json.to_string().contains("server-pw"),
        "a default render leaked the password: {json}"
    );

    let shown = tsbridge_core::account::describe(&state, Some(&cipher), true);
    let json = shown[0].to_json();
    assert_eq!(json["bookmark"]["serverPassword"], "server-pw");
    assert_eq!(json["bookmark"]["channelPassword"], "channel-pw");
}

/// A bookmark with no password reports no presence, so a shell can draw "none"
/// rather than a padlock it has to guess about.
#[test]
fn a_bookmark_without_passwords_says_so() {
    let key: [u8; 32] = std::array::from_fn(|i| (i * 13) as u8);
    let cipher = ItemCipher::new(key);
    let uuid = "b0000000-0000-0000-0000-00000000000b";
    let plain = plain_item(uuid, b"Open server");
    let state = SyncState {
        items: vec![item(ItemClass::Bookmark, uuid, cipher.seal(&plain))],
        ..SyncState::default()
    };
    let views = tsbridge_core::account::describe(&state, Some(&cipher), true);
    let bookmark = &views[0].to_json()["bookmark"];
    assert_eq!(bookmark["hasServerPassword"], false);
    assert_eq!(bookmark["hasChannelPassword"], false);
    assert_eq!(bookmark["serverPassword"], "");
}

// ── settings.db ─────────────────────────────────────────────────────────────

/// Reads the two tables the account side needs, including a value that has to
/// go through the overflow chain (an `Item_Data` for a big item is far larger
/// than one page, and the overflow reader is the one place a mis-shifted header
/// would produce plausible-looking garbage instead of an error).
#[test]
fn the_database_reader_returns_the_account_row_and_items() {
    let item = plain_item("d0000000-0000-0000-0000-000000000001", &vec![b'z'; 5000]);
    let path = std::env::temp_dir().join(format!(
        "tsbridge-account-contract-{}.db",
        crypto::uuid_v4()
    ));
    std::fs::write(&path, fixture(&item)).expect("write the fixture database");

    let db = Database::open(&path).unwrap();
    let account_rows = db.rows("AccountData").unwrap();
    assert_eq!(
        account_rows.len(),
        2,
        "the Account row and the Checksum row"
    );
    let raw = account_rows
        .iter()
        .find(|row| row.get(&1).and_then(Cell::as_text).as_deref() == Some("Account"))
        .expect("an Account row")
        .get(&2)
        .and_then(Cell::as_bytes)
        .expect("the Account row's value");
    let account = Message::parse(raw).unwrap();
    assert_eq!(account.string(1), Some("someone@example.com"));
    assert_eq!(account.bytes(5).unwrap().len(), crypto::KEY_LEN);
    assert_eq!(
        db.columns("AccountData").unwrap(),
        vec!["timestamp", "key", "value"]
    );

    // The item is larger than a page, so this also proves the overflow chain is
    // reassembled into exactly the bytes that were stored.
    let rows = db.rows("ProtobufItems").unwrap();
    assert_eq!(rows.len(), 2);
    let stored = rows
        .iter()
        .filter_map(|row| row.get(&2).and_then(Cell::as_bytes))
        // Field 2 of an `Item_Data` is the uuid, tagged `0x12`; the Checksum
        // row's bytes are not a message at all.
        .find(|value| value.first() == Some(&0x12))
        .expect("the item row");
    assert_eq!(stored, item.as_slice(), "overflow reassembly is byte-exact");

    let (email, hash) = tsbridge_core::account::remembered_login(&path).unwrap();
    assert_eq!(email, "someone@example.com");
    assert_eq!(hash.len(), 64, "the base64 login hash");
    let wrapper = tsbridge_core::account::wrapper_key_from_db(&path).unwrap();
    assert_eq!(wrapper.len(), crypto::KEY_LEN);

    let _ = std::fs::remove_file(&path);
}

// ── fixtures ────────────────────────────────────────────────────────────────

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn sha512(data: &[u8]) -> [u8; 64] {
    crypto::sha512(data)
}

/// PBKDF2-HMAC-SHA512, for the one place a test needs to derive the wrapper from
/// first principles rather than through the function under test.
fn pbkdf2(password: &[u8], salt: &[u8], out: &mut [u8]) {
    crypto::pbkdf2_hmac_sha512(password, salt, 10_000, out);
}

fn item(class: ItemClass, uuid: &str, blob: Vec<u8>) -> Item {
    Item {
        uuid: uuid.to_string(),
        class,
        item_version: "ver".to_string(),
        blob,
        deleted: false,
        meta: Default::default(),
    }
}

/// An `Item_Data` with the two fields that make it recognisable: the sync uuid
/// (field 2) and a bookmark message (field 16).
fn plain_item(uuid: &str, name: &[u8]) -> Vec<u8> {
    let mut bookmark = proto::field_string(1, &String::from_utf8_lossy(name));
    bookmark.extend(proto::field_string(2, "ts.example.com"));
    bookmark.extend(proto::field_varint(3, 9987));
    let mut plain = proto::field_bytes(2, uuid.as_bytes());
    plain.extend(proto::field_bytes(3, b"version"));
    plain.extend(proto::field_bytes(16, &bookmark));
    plain
}

// ── a five-page settings.db: master, two tables, one overflow chain ─────────

const PAGE: usize = 4096;
/// 4096 - 35, the SQLite spill threshold for a table leaf cell.
const MAX_LOCAL: usize = PAGE - 35;
/// `((U-12)*32/255)-23`.
const MIN_LOCAL: usize = ((PAGE - 12) * 32 / 255) - 23;

/// SQLite's varint is **big-endian**: the high seven-bit group comes first and
/// the last byte carries the low bits. (The protobuf varint next door is
/// little-endian, which is exactly how a fixture ends up 12× too large.)
fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut groups = Vec::new();
    let mut value = value;
    while value > 0x7f {
        groups.push((value & 0x7f) as u8);
        value >>= 7;
    }
    groups.push(value as u8);
    for byte in groups[1..].iter().rev() {
        out.push(byte | 0x80);
    }
    out.push(groups[0]);
}

fn text(value: &[u8]) -> (u64, Vec<u8>) {
    (13 + 2 * value.len() as u64, value.to_vec())
}

fn blob(value: &[u8]) -> (u64, Vec<u8>) {
    (12 + 2 * value.len() as u64, value.to_vec())
}

fn integer(value: i64) -> (u64, Vec<u8>) {
    if value == 0 {
        (8, Vec::new())
    } else {
        (1, vec![value as u8])
    }
}

fn record(fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut header = vec![0u8];
    for (serial, _) in fields {
        write_varint(*serial, &mut header);
    }
    header[0] = header.len() as u8;
    let mut out = header;
    for (_, body) in fields {
        out.extend_from_slice(body);
    }
    out
}

/// Lays out a leaf page, spilling a payload that does not fit into overflow
/// pages, exactly the way SQLite does it.
///
/// `overflow` is the page number to hand to the first overflow page, and the
/// remaining pages are consumed from `next_page` in order.
fn write_leaf(file: &mut [u8], page_number: usize, cells: &[(i64, Vec<u8>)], mut next_page: usize) {
    let start = (page_number - 1) * PAGE;
    let header_at = if page_number == 1 { 100 } else { 0 };
    {
        let header = &mut file[start + header_at..start + header_at + 8];
        header[0] = 13;
        header[1] = 0;
        header[3..5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        header[7] = 0;
    }
    let mut content_end = PAGE;
    let mut pointers = Vec::new();
    for (rowid, payload) in cells {
        let mut cell = Vec::new();
        write_varint(payload.len() as u64, &mut cell);
        write_varint(*rowid as u64, &mut cell);

        let (local_len, tail) = if payload.len() <= MAX_LOCAL {
            (payload.len(), &payload[..0])
        } else {
            let candidate = MIN_LOCAL + (payload.len() - MIN_LOCAL) % (PAGE - 4);
            let local = if candidate > MAX_LOCAL {
                MIN_LOCAL
            } else {
                candidate
            };
            (local, &payload[local..])
        };
        cell.extend_from_slice(&payload[..local_len]);
        if !tail.is_empty() {
            // Consume one page per 4092 bytes of tail; each page starts with the
            // number of the next one in the chain.
            let chunk_count = tail.len().div_ceil(PAGE - 4);
            let first = next_page;
            for index in 0..chunk_count {
                let from = index * (PAGE - 4);
                let to = ((index + 1) * (PAGE - 4)).min(tail.len());
                let page_start = (next_page - 1) * PAGE;
                let successor = if index + 1 < chunk_count {
                    next_page + 1
                } else {
                    0
                };
                file[page_start..page_start + 4].copy_from_slice(&(successor as u32).to_be_bytes());
                file[page_start + 4..page_start + 4 + (to - from)].copy_from_slice(&tail[from..to]);
                next_page += 1;
            }
            cell.extend_from_slice(&(first as u32).to_be_bytes());
        }

        content_end -= cell.len();
        file[start + content_end..start + content_end + cell.len()].copy_from_slice(&cell);
        pointers.push(content_end as u16);
    }
    for (index, pointer) in pointers.iter().enumerate() {
        let at = start + header_at + 8 + index * 2;
        file[at..at + 2].copy_from_slice(&pointer.to_be_bytes());
    }
    file[start + header_at + 5..start + header_at + 7]
        .copy_from_slice(&(content_end as u16).to_be_bytes());
}

/// Master (1), `AccountData` (2), `ProtobufItems` (3), then overflow pages.
fn fixture(item: &[u8]) -> Vec<u8> {
    let overflow_pages = (item.len().saturating_sub(MIN_LOCAL)) / (PAGE - 4) + 1;
    let mut file = vec![0u8; PAGE * (3 + overflow_pages)];
    file[..16].copy_from_slice(b"SQLite format 3\0");
    file[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
    file[18] = 1; // rollback journal, not WAL
    file[19] = 1;
    file[21] = 64;
    file[22] = 32;
    file[23] = 32;
    file[24] = 32;
    let pages = (3 + overflow_pages) as u32;
    file[28..32].copy_from_slice(&pages.to_be_bytes());

    // sqlite_master: one row per table, columns type/name/tbl_name/rootpage/sql.
    let master_rows = [
        record(&[
            text(b"table"),
            text(b"AccountData"),
            text(b"AccountData"),
            integer(2),
            text(b"CREATE TABLE AccountData (timestamp INTEGER UNSIGNED NOT NULL, key VARCHAR NOT NULL UNIQUE, value VARCHAR)"),
        ]),
        record(&[
            text(b"table"),
            text(b"ProtobufItems"),
            text(b"ProtobufItems"),
            integer(3),
            text(b"CREATE TABLE ProtobufItems (timestamp INTEGER UNSIGNED NOT NULL, key VARCHAR NOT NULL, value VARCHAR)"),
        ]),
    ];
    write_leaf(
        &mut file,
        1,
        &[(1, master_rows[0].clone()), (2, master_rows[1].clone())],
        4,
    );

    let mut account = proto::field_string(1, "someone@example.com");
    account.extend(proto::field_string(2, &"h".repeat(64)));
    account.extend(proto::field_string(
        3,
        "00000000-0000-4000-8000-000000000001",
    ));
    account.extend(proto::field_string(4, "someone"));
    account.extend(proto::field_bytes(5, &[0x11; crypto::KEY_LEN]));
    let account_rows = [
        record(&[integer(1), text(b"Account"), blob(&account)]),
        record(&[integer(1), text(b"Checksum"), blob(&[0x42; 20])]),
    ];
    write_leaf(
        &mut file,
        2,
        &[(1, account_rows[0].clone()), (2, account_rows[1].clone())],
        4,
    );

    let item_rows = [
        // The Checksum row: bytes that are not an Item_Data, so it must be
        // skipped rather than treated as an item with an empty uuid.
        record(&[integer(1), text(b"Checksum"), blob(&[0x42; 20])]),
        record(&[integer(1), text(b"0"), blob(item)]),
    ];
    write_leaf(
        &mut file,
        3,
        &[(1, item_rows[0].clone()), (2, item_rows[1].clone())],
        4,
    );
    file
}
