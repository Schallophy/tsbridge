//! The three-way compare: a baseline that survives a restart, and a report that
//! says whose change is whose.
//!
//! Both halves of item 9 are here:
//!
//! * a **persisted baseline** — digests plus cursors, written to disk and read
//!   back, so "what did we last agree on" survives the process;
//! * a **three-way compare** — baseline vs local vs server — that names the field
//!   each side changed and refuses to pick a winner when both changed the same
//!   field differently.
//!
//! The last test drives the whole thing over the recorded server: read, change the
//! server between two reads, and assert the conflict is *reported* rather than
//! silently overwritten.

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litespeak_core::account::http::{Endpoints, Http, LoginRequest};
use litespeak_core::account::merge::{self, Action, Baseline, Change, LocalItem};
use litespeak_core::account::proto;
use litespeak_core::account::sync::{self, Item, ItemCipher, ItemClass, SyncState};
use serde_json::json;

const PASSWORD: &str = "replay-only-password";
const EMAIL: &str = "replay@example.invalid";
const ACCOUNT_KEY: [u8; 32] = [0x5a; 32];
const ACCOUNT_UUID: &str = "00000000-0000-4000-8000-0000000000aa";
const GLOBAL: &str = "00000000-0000-4000-8000-000000000001";
const CLASS_VERSION: &str = "00000000-0000-4000-8000-0000000000c1";

/// A bookmark `Item_Data` with the fields a person edits.
fn bookmark(uuid: &str, name: &str, address: &str, port: u64) -> Vec<u8> {
    let mut message = proto::field_string(2, uuid);
    message.extend(proto::field_string(3, "sync-version"));
    message.extend(proto::field_varint(4, 3));
    message.extend(proto::field_string(5, "last-known"));
    message.extend(proto::field_varint(6, ItemClass::Bookmark.id() as u64));
    message.extend(proto::field_varint(9, 1700));
    let mut inner = proto::field_string(1, name);
    inner.extend(proto::field_string(2, address));
    inner.extend(proto::field_varint(3, port));
    message.extend(proto::field_bytes(16, &inner));
    message
}

fn local(uuid: &str, plain: Vec<u8>) -> LocalItem {
    LocalItem {
        uuid: uuid.to_string(),
        class: ItemClass::Bookmark,
        plain,
    }
}

fn state_with(items: &[(String, Vec<u8>)]) -> SyncState {
    let mut class_version = BTreeMap::new();
    class_version.insert(ItemClass::Bookmark, CLASS_VERSION.to_string());
    SyncState {
        status: sync::SyncStatus::NotInSync,
        global_version: GLOBAL.to_string(),
        class_version,
        items: items
            .iter()
            .map(|(uuid, plain)| Item {
                uuid: uuid.clone(),
                class: ItemClass::Bookmark,
                item_version: "item-version".to_string(),
                blob: plain.clone(),
                deleted: false,
                meta: Default::default(),
            })
            .collect(),
    }
}

/// One side unchanged: both agree, nothing to do, and the report says so rather
/// than leaving an empty list a reader cannot interpret.
#[test]
fn identical_sides_are_in_sync_with_no_fields_to_show() {
    let uuid = "b0000000-0000-0000-0000-000000000001";
    let plain = bookmark(uuid, "Home", "home.example.invalid", 9987);
    let local_side = vec![local(uuid, plain.clone())];
    let server = state_with(&[(uuid.to_string(), plain.clone())]);

    let plan = merge::compare(None, &local_side, &server, None);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].action, Action::InSync);
    assert!(plan.items[0].fields.is_empty() || !plan.items[0].fields.iter().any(|f| f.is_change()));
    assert!(!plan.has_conflicts());
    assert!(plan.is_empty());
}

/// A baseline with the agreed state, then only the server moves: the item has to
/// be **pulled**, and the field that moved has to be named.
#[test]
fn a_server_only_change_is_reported_as_a_pull_and_names_the_field() {
    let uuid = "b0000000-0000-0000-0000-000000000002";
    let agreed = bookmark(uuid, "Home", "home.example.invalid", 9987);
    let server_moved = bookmark(uuid, "Home", "new.example.invalid", 9987);

    let local_side = vec![local(uuid, agreed.clone())];
    let baseline_side = vec![local(uuid, agreed.clone())];
    let baseline = Baseline::of(
        &state_with(&[(uuid.to_string(), agreed.clone())]),
        ACCOUNT_UUID,
        &baseline_side,
        None,
        "2026-01-01T00:00:00Z",
    );
    assert_eq!(baseline.items.len(), 1, "the agreed item is recorded");

    let plan = merge::compare(
        Some(&baseline),
        &local_side,
        &state_with(&[(uuid.to_string(), server_moved)]),
        None,
    );
    assert_eq!(plan.items[0].action, Action::Pull);
    let changed: Vec<&merge::FieldDelta> = plan.items[0]
        .fields
        .iter()
        .filter(|field| field.is_change())
        .collect();
    assert_eq!(changed.len(), 1, "only the address moved");
    assert_eq!(changed[0].key, "bookmark.2");
    assert_eq!(changed[0].label, "address");
    assert_eq!(changed[0].local, Change::Unchanged);
    assert_eq!(changed[0].server, Change::Modified);
    assert!(!changed[0].is_conflict());
}

/// Both sides changed **different** fields: that is a merge, and the union has
/// both edits. This is the case a naive implementation gets wrong by refusing to
/// do anything useful or by picking one side wholesale.
#[test]
fn changes_to_different_fields_merge_into_one_item() {
    let uuid = "b0000000-0000-0000-0000-000000000003";
    let agreed = bookmark(uuid, "Home", "home.example.invalid", 9987);
    let local_moved = bookmark(uuid, "My Home", "home.example.invalid", 9987);
    let server_moved = bookmark(uuid, "Home", "home.example.invalid", 9988);

    let local_side = vec![local(uuid, local_moved.clone())];
    let baseline_side = vec![local(uuid, agreed.clone())];
    let baseline = Baseline::of(
        &state_with(&[(uuid.to_string(), agreed)]),
        ACCOUNT_UUID,
        &baseline_side,
        None,
        "2026-01-01T00:00:00Z",
    );
    let plan = merge::compare(
        Some(&baseline),
        &local_side,
        &state_with(&[(uuid.to_string(), server_moved)]),
        None,
    );

    assert_eq!(plan.items[0].action, Action::Merge);
    assert!(!plan.has_conflicts());
    let fields = plan.items[0].fields.clone();
    let name = fields.iter().find(|f| f.key == "bookmark.1").expect("name");
    assert_eq!(name.local, Change::Modified);
    assert_eq!(name.server, Change::Unchanged);
    let port = fields.iter().find(|f| f.key == "bookmark.3").expect("port");
    assert_eq!(port.local, Change::Unchanged);
    assert_eq!(port.server, Change::Modified);

    // The union: the local name and the server's port.
    let merged = plan.items[0].merged.as_ref().expect("a merged plaintext");
    let parsed = sync::Bookmark::parse(merged)
        .expect("parse")
        .expect("a bookmark");
    assert_eq!(parsed.name, "My Home", "the local edit survives");
    assert_eq!(parsed.port, 9988, "the server edit survives");
    assert_eq!(
        parsed.address, "home.example.invalid",
        "untouched fields stay"
    );
}

/// Both sides changed the **same** field differently: a conflict, named, and no
/// merged plaintext is invented.
#[test]
fn the_same_field_changed_differently_is_a_conflict_and_is_never_merged() {
    let uuid = "b0000000-0000-0000-0000-000000000004";
    let agreed = bookmark(uuid, "Home", "home.example.invalid", 9987);
    let local_moved = bookmark(uuid, "Mine", "home.example.invalid", 9987);
    let server_moved = bookmark(uuid, "Theirs", "home.example.invalid", 9987);

    let local_side = vec![local(uuid, local_moved)];
    let baseline_side = vec![local(uuid, agreed.clone())];
    let baseline = Baseline::of(
        &state_with(&[(uuid.to_string(), agreed)]),
        ACCOUNT_UUID,
        &baseline_side,
        None,
        "2026-01-01T00:00:00Z",
    );
    let plan = merge::compare(
        Some(&baseline),
        &local_side,
        &state_with(&[(uuid.to_string(), server_moved)]),
        None,
    );

    assert_eq!(plan.items[0].action, Action::Conflict);
    assert!(plan.has_conflicts());
    assert!(
        plan.items[0].merged.is_none(),
        "a conflict must never produce a merged message"
    );
    let conflict = plan.items[0]
        .fields
        .iter()
        .find(|field| field.is_conflict())
        .expect("a conflicting field");
    assert_eq!(conflict.key, "bookmark.1");
    assert_eq!(conflict.local, Change::Modified);
    assert_eq!(conflict.server, Change::Modified);
}

/// Both sides changing to the **same** value is agreement, not a conflict. This
/// is what makes "two machines made the same edit" quiet instead of alarming.
#[test]
fn both_sides_reaching_the_same_value_is_agreement() {
    let uuid = "b0000000-0000-0000-0000-000000000005";
    let agreed = bookmark(uuid, "Home", "home.example.invalid", 9987);
    let same = bookmark(uuid, "Shared", "home.example.invalid", 9987);

    let local_side = vec![local(uuid, same.clone())];
    let baseline_side = vec![local(uuid, agreed.clone())];
    let baseline = Baseline::of(
        &state_with(&[(uuid.to_string(), agreed)]),
        ACCOUNT_UUID,
        &baseline_side,
        None,
        "2026-01-01T00:00:00Z",
    );
    let plan = merge::compare(
        Some(&baseline),
        &local_side,
        &state_with(&[(uuid.to_string(), same)]),
        None,
    );
    assert_eq!(plan.items[0].action, Action::InSync);
    assert!(!plan.has_conflicts());
}

/// A item only the local side has is a **push**, and must not be recorded as
/// agreed — otherwise the next compare reads "the server removed it" and proposes
/// deleting the thing that was waiting to be uploaded.
#[test]
fn a_new_local_item_is_a_push_and_is_not_recorded_as_agreed() {
    let uuid = "b0000000-0000-0000-0000-000000000006";
    let plain = bookmark(uuid, "New", "new.example.invalid", 9987);
    let local_side = vec![local(uuid, plain)];
    let server = state_with(&[]);

    let plan = merge::compare(None, &local_side, &server, None);
    assert_eq!(plan.items[0].action, Action::Push);
    assert!(!plan.has_baseline, "nothing was ever agreed");

    // Recording now must leave it out, because the two sides do not hold it
    // identically.
    let recorded = Baseline::of(&server, ACCOUNT_UUID, &local_side, None, "now");
    assert!(
        recorded.items.is_empty(),
        "a pending item must not be recorded as agreed"
    );
}

/// Only the server has it: a pull, and no local write is proposed as a delete.
#[test]
fn a_server_only_item_is_a_pull_and_does_not_look_like_a_local_delete() {
    let uuid = "b0000000-0000-0000-0000-000000000007";
    let plain = bookmark(uuid, "Remote", "remote.example.invalid", 9987);
    let plan = merge::compare(None, &[], &state_with(&[(uuid.to_string(), plain)]), None);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].action, Action::Pull);
}

/// The baseline round-trips through disk, and a version it does not know is
/// refused instead of guessed at.
#[test]
fn the_baseline_survives_a_restart_and_refuses_an_unknown_version() {
    let uuid = "b0000000-0000-0000-0000-000000000008";
    let plain = bookmark(uuid, "Saved", "saved.example.invalid", 9987);
    let local_side = vec![local(uuid, plain.clone())];
    let server = state_with(&[(uuid.to_string(), plain)]);

    let baseline = Baseline::of(
        &server,
        ACCOUNT_UUID,
        &local_side,
        None,
        "2026-01-01T00:00:00Z",
    );
    let path = temp_dir().join("baseline-roundtrip.json");
    merge::save(&path, &baseline).expect("save");

    let loaded = merge::load(&path).expect("load").expect("a baseline");
    assert_eq!(loaded.account_uuid, ACCOUNT_UUID);
    assert_eq!(loaded.global_version, GLOBAL);
    assert_eq!(loaded.class_version, baseline.class_version);
    assert_eq!(loaded.items.len(), 1);
    assert_eq!(loaded.items[0].uuid, uuid);

    // Field digests, not content: the file must not contain the bookmark's
    // plaintext.
    let text = std::fs::read_to_string(&path).expect("read the file");
    assert!(
        !text.contains("saved.example.invalid"),
        "no plaintext in a baseline"
    );
    assert!(text.contains("bookmark.2"), "the field digests are there");

    // And a wrong version is an error, not a silently empty baseline.
    let mut value = baseline.to_json();
    value["version"] = json!(99);
    let error = Baseline::from_json(&value).expect_err("a future baseline must be refused");
    assert!(error.contains("version 99"), "{error}");

    let _ = std::fs::remove_file(&path);
}

/// The cursors in the baseline are what tells a client "nothing moved while you
/// were away" — and they are *not* used to ask for a partial read.
#[test]
fn the_baseline_cursors_are_compared_but_never_used_for_a_partial_read() {
    let uuid = "b0000000-0000-0000-0000-000000000009";
    let plain = bookmark(uuid, "Cursors", "c.example.invalid", 9987);
    let local_side = vec![local(uuid, plain.clone())];
    let server = state_with(&[(uuid.to_string(), plain)]);
    let baseline = Baseline::of(&server, ACCOUNT_UUID, &local_side, None, "now");

    assert!(baseline.cursors_match(&server), "same cursors");
    let mut moved = server.clone();
    moved.class_version.insert(
        ItemClass::Bookmark,
        "00000000-0000-4000-8000-000000000999".to_string(),
    );
    assert!(!baseline.cursors_match(&moved), "a class cursor moved");
    let mut new_global = server.clone();
    new_global.global_version = "00000000-0000-4000-8000-000000000998".to_string();
    assert!(!baseline.cursors_match(&new_global));
    // An older baseline with no cursors can never claim a match.
    assert!(!Baseline::default().cursors_match(&server));

    let plan = merge::compare(Some(&baseline), &local_side.clone(), &server, None);
    assert!(plan.cursors_match);
    let plan = merge::compare(Some(&baseline), &local_side, &moved, None);
    assert!(!plan.cursors_match);
}

/// A compare with no baseline cannot attribute a change, so it must not silently
/// claim the sides agree or that one side is authoritative.
#[test]
fn a_compare_without_a_baseline_cannot_attribute_a_change() {
    let uuid = "b0000000-0000-0000-0000-00000000000a";
    let local_plain = bookmark(uuid, "Mine", "x.example.invalid", 9987);
    let server_plain = bookmark(uuid, "Theirs", "x.example.invalid", 9987);
    let plan = merge::compare(
        None,
        &[local(uuid, local_plain)],
        &state_with(&[(uuid.to_string(), server_plain)]),
        None,
    );
    assert!(!plan.has_baseline);
    assert!(
        plan.items[0].action != Action::Push && plan.items[0].action != Action::Pull,
        "with no baseline neither side can be called authoritative, got {:?}",
        plan.items[0].action
    );
}

/// The revision bookkeeping the server rewrites on every store must not make an
/// untouched item look edited, or every write by any client would conflict.
#[test]
fn revision_bookkeeping_is_excluded_from_the_digest() {
    let uuid = "b0000000-0000-0000-0000-00000000000b";
    let first = bookmark(uuid, "Same", "s.example.invalid", 9987);
    let mut second = bookmark(uuid, "Same", "s.example.invalid", 9987);
    // Rewrite f3, f4, f5 and f9 the way a server store would.
    let mut message = proto::Message::parse(&second).expect("parse");
    message.upsert_string(3, "another-sync-version");
    message.upsert_varint(4, 1);
    message.upsert_string(5, "another-known");
    message.upsert_varint(9, 1800);
    second = message.encode();

    assert_ne!(first, second, "the blobs differ");
    assert_eq!(
        merge::Fingerprint::of(&first).unwrap().fields,
        merge::Fingerprint::of(&second).unwrap().fields,
        "but the comparable fields do not"
    );
}

/// The command is parsed by the one entry point, so a shell cannot reach the
/// compare through a side door with different argument rules.
#[test]
fn sync_merge_parses_through_the_command_entry_point() {
    use litespeak_core::account::AccountCommand;

    let parsed = AccountCommand::parse("sync_merge", r#"{"local":"/tmp/backup.json"}"#)
        .expect("an account command")
        .expect("valid arguments");
    let name = parsed.name();
    match parsed {
        AccountCommand::Merge {
            local,
            baseline,
            record,
        } => {
            assert_eq!(local, PathBuf::from("/tmp/backup.json"));
            assert!(baseline.is_none());
            assert!(!record, "the default is a report, never a record");
        }
        other => panic!("parsed as {}", other.name()),
    }
    assert_eq!(name, "sync_merge");

    let parsed = AccountCommand::parse(
        "sync_merge",
        r#"{"local":"/tmp/b.json","baseline":"/tmp/sync.json","record":true}"#,
    )
    .expect("an account command")
    .expect("valid arguments");
    match parsed {
        AccountCommand::Merge {
            baseline, record, ..
        } => {
            assert_eq!(
                baseline.as_deref(),
                Some(std::path::Path::new("/tmp/sync.json"))
            );
            assert!(record);
        }
        other => panic!("parsed as {}", other.name()),
    }

    // A missing local file is rejected at parse time, so no network read is spent
    // on an impossible command.
    let error = AccountCommand::parse("sync_merge", "{}")
        .expect("an account command")
        .expect_err("local is required");
    assert!(error.contains("local"), "{error}");

    // And a command that is not an account command is not claimed.
    assert!(AccountCommand::parse("send_text", "{}").is_none());
}

/// A session with no account key cannot compare an encrypted item, and saying so
/// is the only correct answer: "unreadable" is not "the server removed it" and not
/// "unchanged".
#[test]
fn an_unreadable_server_item_is_named_instead_of_proposed_for_deletion() {
    let uuid = "b0000000-0000-0000-0000-000000000010";
    let plain = bookmark(uuid, "Sealed", "sealed.example.invalid", 9987);
    let sealed = ItemCipher::new(ACCOUNT_KEY).seal(&plain);

    let mut state = state_with(&[(uuid.to_string(), sealed.clone())]);
    // The item is on the server, sealed; this session has no key.
    state.items[0].blob = sealed;
    let plan = merge::compare(None, &[local(uuid, plain.clone())], &state, None);

    assert_eq!(plan.unreadable, vec![uuid.to_string()], "named, not silent");
    assert!(
        plan.items.is_empty(),
        "no plan is invented for an item that could not be read"
    );
    assert!(!plan.has_conflicts());
    let json = plan.to_json();
    assert_eq!(json["unreadable"][0], uuid);
    assert_eq!(json["items"].as_array().map(Vec::len), Some(0));

    // With the key the same state compares normally.
    let cipher = ItemCipher::new(ACCOUNT_KEY);
    let seen = merge::compare(None, &[local(uuid, plain)], &state, Some(&cipher));
    assert!(seen.unreadable.is_empty());
    assert_eq!(seen.items.len(), 1);
    assert_eq!(seen.items[0].action, Action::InSync);
}

/// The report a shell renders, pinned by name: `action`, `local`, `server` and
/// `label` are contract strings, and a rename shows up as "the panel silently
/// stopped working".
#[test]
fn the_report_names_every_action_and_field_in_the_contract() {
    let uuid = "b0000000-0000-0000-0000-00000000000c";
    let agreed = bookmark(uuid, "Home", "home.example.invalid", 9987);

    let cases: [(&str, Action); 5] = [
        ("same", Action::InSync),
        ("local", Action::Push),
        ("server", Action::Pull),
        ("merge", Action::Merge),
        ("conflict", Action::Conflict),
    ];

    for (label, action) in cases {
        let local_plain = match action {
            Action::InSync => agreed.clone(),
            Action::Pull => agreed.clone(),
            _ => bookmark(uuid, "Mine", "home.example.invalid", 9987),
        };
        let server_plain = match action {
            Action::InSync => agreed.clone(),
            Action::Push => agreed.clone(),
            Action::Pull => bookmark(uuid, "Theirs", "home.example.invalid", 9987),
            Action::Merge => bookmark(uuid, "Home", "home.example.invalid", 9988),
            Action::Conflict => bookmark(uuid, "Theirs", "home.example.invalid", 9987),
        };
        let baseline = Baseline::of(
            &state_with(&[(uuid.to_string(), agreed.clone())]),
            ACCOUNT_UUID,
            &[local(uuid, agreed.clone())],
            None,
            "now",
        );
        let plan = merge::compare(
            Some(&baseline),
            &[local(uuid, local_plain)],
            &state_with(&[(uuid.to_string(), server_plain)]),
            None,
        );
        assert_eq!(plan.items[0].action, action, "case {label}");
        let json = plan.to_json();
        assert_eq!(json["items"][0]["action"], action.name(), "case {label}");

        // Every case names the fields it disagrees on, and a conflicting field
        // is flagged rather than left for the caller to infer from two changes.
        for field in json["items"][0]["fields"].as_array().into_iter().flatten() {
            assert!(
                ["unchanged", "added", "modified", "removed"]
                    .contains(&field["local"].as_str().unwrap_or("")),
                "local change naming: {field}"
            );
            assert!(
                ["unchanged", "added", "modified", "removed"]
                    .contains(&field["server"].as_str().unwrap_or("")),
                "server change naming: {field}"
            );
            assert!(
                !field["label"].as_str().unwrap_or("").is_empty(),
                "a field is labelled: {field}"
            );
        }
    }
}

/// The counts in the report are the counts in the plan, so a UI never shows a
/// number the engine did not mean.
#[test]
fn the_report_counts_agree_with_the_plan() {
    let a = "b0000000-0000-0000-0000-00000000000d";
    let b = "b0000000-0000-0000-0000-00000000000e";
    let c = "b0000000-0000-0000-0000-00000000000f";
    let base_a = bookmark(a, "A", "a.example.invalid", 9987);
    let base_b = bookmark(b, "B", "b.example.invalid", 9987);
    let base_c = bookmark(c, "C", "c.example.invalid", 9987);

    // A: in sync. B: server renamed (pull). C: local renamed (push).
    let local_side = vec![
        local(a, base_a.clone()),
        local(b, base_b.clone()),
        local(c, bookmark(c, "C mine", "c.example.invalid", 9987)),
    ];
    let baseline = Baseline::of(
        &state_with(&[
            (a.to_string(), base_a.clone()),
            (b.to_string(), base_b.clone()),
            (c.to_string(), base_c.clone()),
        ]),
        ACCOUNT_UUID,
        &[
            local(a, base_a.clone()),
            local(b, base_b.clone()),
            local(c, base_c),
        ],
        None,
        "now",
    );
    let server = state_with(&[
        (a.to_string(), base_a),
        (
            b.to_string(),
            bookmark(b, "B theirs", "b.example.invalid", 9987),
        ),
        (c.to_string(), bookmark(c, "C", "c.example.invalid", 9987)),
    ]);
    let plan = merge::compare(Some(&baseline), &local_side, &server, None);
    assert_eq!(plan.count(Action::InSync), 1);
    assert_eq!(plan.count(Action::Pull), 1);
    assert_eq!(plan.count(Action::Push), 1);
    assert_eq!(plan.count(Action::Conflict), 0);

    let json = plan.to_json();
    for action in [Action::InSync, Action::Push, Action::Pull, Action::Merge] {
        assert_eq!(
            json[action.name()].as_u64().unwrap_or(0) as usize,
            plan.count(action),
            "{} count",
            action.name()
        );
    }
    assert_eq!(json["conflict"].as_u64().unwrap_or(0) as usize, 0);
    assert_eq!(json["conflicts"], false);
    assert!(
        json["cursorsMatch"].as_bool().unwrap_or(false),
        "same cursors"
    );
}

// ── the whole thing over the recorded server ────────────────────────────────

struct Replay {
    port: u16,
    stop: Arc<AtomicBool>,
    /// The bookmark the server currently holds, and the mutation a test applies
    /// to move it between reads.
    name: Arc<Mutex<String>>,
    acceptor: Option<std::thread::JoinHandle<()>>,
}

impl Replay {
    fn start(name: &str) -> Replay {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let name = Arc::new(Mutex::new(name.to_string()));
        let acceptor = {
            let stop = Arc::clone(&stop);
            let name = Arc::clone(&name);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    let name = Arc::clone(&name);
                    std::thread::spawn(move || {
                        let _ = serve(stream, &name);
                    });
                }
            })
        };
        Replay {
            port,
            stop,
            name,
            acceptor: Some(acceptor),
        }
    }

    fn context(&self) -> litespeak_core::account::AccountContext {
        litespeak_core::account::AccountContext {
            http: Http::with_endpoints(Endpoints {
                rest: format!("http://127.0.0.1:{}/api", self.port),
                cloud: format!("http://127.0.0.1:{}", self.port),
                allow_plain_http: true,
            }),
            legacy_db: None,
            backup_dir: temp_dir(),
            credential_file: None,
            baseline_file: None,
        }
    }

    fn rename(&self, name: &str) {
        *self.name.lock().unwrap_or_else(|e| e.into_inner()) = name.to_string();
    }
}

impl Drop for Replay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.acceptor.take() {
            let _ = handle.join();
        }
    }
}

fn serve(stream: TcpStream, name: &Arc<Mutex<String>>) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body)?;
    }

    let tail = path.rsplit_once("/api").map(|(_, t)| t).unwrap_or(&path);
    let (status, ctype, reply) = if method == "POST" && tail == "/client/login" {
        let wrapper = litespeak_core::account::crypto::hashed_encryption_password(PASSWORD, EMAIL);
        let key = litespeak_core::account::crypto::wrap_key(&ACCOUNT_KEY, &wrapper, None);
        let body = serde_json::to_vec(&json!({
            "error": "ERROR_LOGIN_OK",
            "session": "00000000-0000-4000-8000-000000009000",
            "email": EMAIL,
            "username": "Replay",
            "uuid": ACCOUNT_UUID,
            "key": key,
        }))
        .expect("json");
        (200, "application/json", body)
    } else if method == "GET" && tail == "/me" {
        let body =
            serde_json::to_vec(&json!({"user": {"username": "Replay", "uuid": ACCOUNT_UUID}}))
                .expect("json");
        (200, "application/json", body)
    } else if method == "POST" && path == "/synchronization" {
        let name = name.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // Cursors derived from the content: a rename moves both, which is what a
        // real store does and what tells a client "re-check".
        let class_cursor = cursor_for("class", &name);
        let global_cursor = cursor_for("global", &name);
        let uuid = "b0000000-0000-0000-0000-0000000000ff";
        let plain = bookmark(uuid, &name, "conflict.example.invalid", 9987);
        let blob = ItemCipher::new(ACCOUNT_KEY).seal(&plain);
        let mut detail = proto::field_string(1, uuid);
        detail.extend(proto::field_string(2, "item-version"));
        detail.extend(proto::field_bytes(3, &blob));
        let mut class = proto::field_varint(1, ItemClass::Bookmark.id() as u64);
        class.extend(proto::field_string(2, &class_cursor));
        class.extend(proto::field_bytes(3, &detail));
        let mut reply = proto::field_varint(1, 301);
        reply.extend(proto::field_bytes(2, &class));
        reply.extend(proto::field_string(3, &global_cursor));
        (200, "application/json", reply)
    } else {
        (404, "text/plain", b"not found".to_vec())
    };

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.len()
    );
    let mut writer = stream;
    writer.write_all(head.as_bytes())?;
    writer.write_all(&reply)?;
    writer.flush()
}

/// A stable pseudo-uuid for one string, so the fixture's cursors move exactly
/// when its content does.
fn cursor_for(tag: &str, value: &str) -> String {
    // FNV-1a: tiny, deterministic, and no dependency. Only used by this test
    // fixture, never by the library.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in tag.bytes().chain(value.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("00000000-0000-4000-8000-{hash:012}")
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("litespeak-merge-tests");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the replay server never started");
}

/// The end-to-end claim of item 9: record an agreement, let the server change
/// while "we were away", and the next compare reports the two-sided edit as a
/// **conflict** instead of silently overwriting it.
#[test]
fn a_server_change_while_away_is_reported_as_a_conflict_not_overwritten() {
    let server = Replay::start("Shared");
    wait_ready(server.port);
    let context = server.context();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let login = LoginRequest {
        email: EMAIL.to_string(),
        password: Some(PASSWORD.to_string()),
        ..LoginRequest::default()
    };
    let outcome = runtime
        .block_on(litespeak_core::account::login(&context, &login))
        .expect("login");
    let cipher = ItemCipher::new(outcome.account.key.expect("key"));
    let state = runtime
        .block_on(litespeak_core::account::read_items(
            &context,
            &outcome.account,
        ))
        .expect("read");

    // What both sides hold now.
    let uuid = state.items[0].uuid.clone();
    let local_side = vec![LocalItem {
        uuid: uuid.clone(),
        class: ItemClass::Bookmark,
        plain: sync::read_plain(&state.items[0], Some(&cipher)).expect("plain"),
    }];
    let baseline = Baseline::of(&state, ACCOUNT_UUID, &local_side, Some(&cipher), "now");
    assert_eq!(baseline.items.len(), 1);

    // The other machine changes the name; locally the name is also changed, to
    // something else. Whichever it was, the read has to see the new server state.
    server.rename("Theirs");
    let mut our_copy = local_side.clone();
    let mut ours = sync::Bookmark::parse(&our_copy[0].plain)
        .expect("parse")
        .expect("bookmark");
    ours.name = "Mine".to_string();
    let mut message = proto::Message::parse(&our_copy[0].plain).expect("parse");
    message
        .edit_nested(16, |bookmark| {
            bookmark.upsert_string(1, &ours.name);
            Ok(())
        })
        .expect("edit");
    our_copy[0].plain = message.encode();

    let after = runtime
        .block_on(litespeak_core::account::read_items(
            &context,
            &outcome.account,
        ))
        .expect("read after the server moved");
    let plan = merge::compare(Some(&baseline), &our_copy, &after, Some(&cipher));

    assert_eq!(
        plan.items[0].action,
        Action::Conflict,
        "both sides edited the name"
    );
    assert!(plan.has_conflicts());
    let field = plan.items[0]
        .fields
        .iter()
        .find(|delta| delta.is_conflict())
        .expect("the conflicting field is named");
    assert_eq!(field.key, "bookmark.1");
    assert_eq!(field.label, "name");
    assert!(plan.items[0].merged.is_none(), "never invent a winner");

    // And the cursors say the server moved, which is the cheap half of the
    // answer: a client can know to re-check without reading every item.
    assert!(!plan.cursors_match, "the server's cursors moved");
}
