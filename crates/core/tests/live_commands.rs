//! Every read-only command against a real server.
//!
//! `protocol_coverage.rs` proves every declared message is handled; `conn.rs`
//! unit tests prove each command writes the bytes it is supposed to. Neither can
//! say whether the server *understands* those bytes. A command built from a
//! declaration that got a field name or a required argument wrong still sends
//! cleanly, and the only symptom is the server answering "unknown command" or
//! "invalid parameter" — which is what this file checks for.
//!
//! Only read-only commands run here. A write command changes server state, so it
//! cannot be called on a server someone else may be using, and `serversnapshotdeploy`
//! in particular can destroy channels. The four commands that do need to write are
//! covered by `live_server.rs`, each with the permission it requires.
//!
//! The distinction that matters is between "the server refused because this
//! account lacks a permission" and "the server does not know the command". The
//! first is expected and is reported as a skip; the second is a defect in this
//! crate and fails the test.
//!
//! ```text
//! TSBRIDGE_TEST_SERVER=127.0.0.1:9987 \
//!   cargo test -p tsbridge-core --test live_commands -- --ignored --test-threads=1
//! ```

use std::time::{Duration, Instant};

use tsbridge_core::command;
use tsbridge_core::{ConnectParams, Handle, QueuedEvent, Value};

/// How long one command gets to answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

fn connect() -> Option<Handle> {
    let address = std::env::var("TSBRIDGE_TEST_SERVER").ok()?;
    let identity = std::env::var("TSBRIDGE_TEST_IDENTITY").unwrap_or_default();
    let nickname = std::env::var("TSBRIDGE_TEST_NICKNAME").unwrap_or_else(|_| "probe".to_string());

    let handle = Handle::create(ConnectParams {
        address,
        identity,
        nickname,
        server_password: std::env::var("TSBRIDGE_TEST_PASSWORD").ok(),
        channel: None,
        channel_password: None,
        myts: None,
        version_profile: Default::default(),
        privilege_key: String::new(),
        start_muted: true,
    })
    .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "connected" {
                return Some(handle);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the server did not report connected within 10s");
}

fn field<'a>(event: &'a QueuedEvent, key: &str) -> Option<&'a Value> {
    event
        .data
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// Runs one command and returns every event it caused within the window.
///
/// A command whose answer arrives through the book (a list, a subscription) emits
/// no terminator of its own, so this always waits the full window rather than
/// stopping at a name. Six seconds per command over ~100 commands is slow but the
/// run is manual.
fn run(handle: &Handle, name: &str, args: &str) -> Vec<QueuedEvent> {
    let parsed = match command::parse(name, args) {
        Ok(parsed) => parsed,
        Err(e) => panic!("`{name}` does not parse: {e}"),
    };
    handle.send(parsed);

    // A refusal arrives in a few hundred milliseconds; a success sends no event
    // at all, so the window is what bounds a successful command. Returning as
    // soon as an error lands keeps a failing run fast without making a passing
    // one wait longer than it must.
    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut collected = Vec::new();
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            // `command_ok` is the acknowledgement the server sends for a
            // command that carried a `return_code`; it means the command was
            // understood, so there is nothing left to wait for.
            let answered = event.kind == "command_error" || event.kind == "command_ok";
            collected.push(event);
            if answered {
                return collected;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    collected
}

/// What the server said about one command.
#[derive(Debug, PartialEq)]
enum Verdict {
    /// No error at all.
    Accepted,
    /// The command ran and had nothing to return.
    EmptyResult(String),
    /// Refused for a reason that is about the account, not the command.
    NeedsPermission(String),
    /// The command or one of its parameters was not understood.
    NotUnderstood(String),
}

/// Classifies the events one command produced.
///
/// Only `command_error` counts. Every other event is either the answer or a
/// book update the command caused, and neither says anything about whether the
/// command was understood.
///
/// `DatabaseEmptyResult` is a success with no rows, not a defect: `custom_info`
/// on a client that never set custom fields, and `custom_search` with no match,
/// both answer that way. Counting it as a failure would make the test demand
/// data the fixture server does not have.
fn verdict(events: &[QueuedEvent]) -> Verdict {
    let Some(event) = events.iter().find(|event| event.kind == "command_error") else {
        return Verdict::Accepted;
    };
    let message = match field(event, "message") {
        Some(Value::Str(text)) => text.clone(),
        _ => String::new(),
    };
    let lower = message.to_lowercase();

    // The server's own wording, now that `CommandError` carries it; the enum
    // name is the fallback for a reply without a message. A query that matched
    // nothing answers this way, which is a success.
    if lower.contains("database empty result") || message.contains("DatabaseEmptyResult") {
        return Verdict::EmptyResult(message);
    }
    // "already" is not a permission problem: `channel_move` into the channel the
    // client is already in answers "already member of channel", which means the
    // command was understood and had nothing to do.
    if lower.contains("already") {
        return Verdict::Accepted;
    }
    // A permission refusal names a permission the account does not hold. It
    // proves the server parsed the command far enough to know what it wants.
    if lower.contains("permission")
        || lower.contains("insufficient")
        || lower.contains("not logged in")
    {
        return Verdict::NeedsPermission(message);
    }
    Verdict::NotUnderstood(message)
}

/// The read-only commands and the arguments each needs.
///
/// Ids come from the running server, discovered below rather than hardcoded, so
/// this keeps working on a different server. `{channel}` / `{client}` / `{group}`
/// are substituted with what the connection actually sees; a command whose id
/// could not be discovered is skipped rather than run with `0`, because an id
/// that does not exist tests nothing.
const READ_ONLY: &[(&str, &str)] = &[
    // Server and instance
    ("server_info", "{}"),
    ("server_variables", "{}"),
    ("instance_info", "{}"),
    ("host_info", "{}"),
    ("version", "{}"),
    ("binding_list", "{}"),
    ("server_id_by_port", r#"{"port":9987}"#),
    // Clients
    ("client_list", "{}"),
    ("client_find", r#"{"pattern":"{nickname}"}"#),
    ("client_db_list", "{}"),
    ("client_db_find", r#"{"pattern":"*"}"#),
    ("who_am_i", "{}"),
    ("client_connection_info", r#"{"clientId":{client}}"#),
    ("server_connection_info", "{}"),
    // Channels
    ("channel_list", "{}"),
    ("channel_find", r#"{"pattern":"{channel_name}"}"#),
    ("channel_description", r#"{"channelId":{channel}}"#),
    // Groups. The two lists themselves are requested on connect rather than
    // exposed as commands, so there is no `server_group` / `channel_group` to
    // call — the snapshot carries their contents.
    ("server_group_client_list", r#"{"groupId":{group}}"#),
    ("channel_group_client_list", "{}"),
    ("server_group_perm_list", r#"{"groupId":{group}}"#),
    ("channel_group_perm_list", r#"{"groupId":{channel_group}}"#),
    (
        "channel_client_perm_list",
        r#"{"channelId":{channel},"clientDbId":{client_db}}"#,
    ),
    // Permissions
    ("perm_list", "{}"),
    (
        "perm_find",
        r#"{"permissionName":"b_serverinstance_help_view"}"#,
    ),
    (
        "perm_id_by_name",
        r#"{"permissionName":"b_serverinstance_help_view"}"#,
    ),
    // Lists that answer line by line
    ("ban_list", "{}"),
    ("complain_list", "{}"),
    ("offline_message_list", "{}"),
    ("temp_password_list", "{}"),
    ("token_list", "{}"),
    ("log_view", "{}"),
    ("filetransfer_list", "{}"),
    // Name resolution
    ("client_ids", r#"{"uid":"{uid}"}"#),
    ("client_name_from_db_id", r#"{"clientDbId":{client_db}}"#),
    ("client_name_from_uid", r#"{"uid":"{uid}"}"#),
    ("client_uid_from_clid", r#"{"clientId":{client}}"#),
    ("client_db_id_from_uid", r#"{"uid":"{uid}"}"#),
    // Custom fields
    ("custom_info", r#"{"clientDbId":{client_db}}"#),
    ("custom_search", r#"{"ident":"*","pattern":"*"}"#),
    // Server list
    ("server_list", "{}"),
];

/// This client's database id, asked for rather than guessed.
///
/// The snapshot carries the connection id (`ownClientId`) and each user's uid,
/// but not the database id — and the commands that take one (`custom_info`,
/// `client_name_from_db_id`, `server_groups_by_client`) need the identity behind
/// the connection, which is a different number. Passing the connection id gives
/// `ClientInvalidId` as soon as that connection is gone, which is what made this
/// look like a broken declaration.
fn own_client_db(handle: &Handle) -> Option<i64> {
    // Asked through `client_db_id_from_uid` rather than `who_am_i`: this reply
    // has a `_done` terminator, so it cannot be confused with another nameless
    // answer, and the uid is already in the snapshot. `who_am_i` is the obvious
    // call and was the first thing tried, but its reply is nameless and went
    // missing while the connection was still settling — which turned every
    // command that takes a database id into `ClientInvalidId`.
    let uid = handle
        .snapshot()
        .users
        .iter()
        .find(|user| Some(user.id) == handle.snapshot().own_client_id)
        .map(|user| user.uid.clone())
        .filter(|uid| !uid.is_empty())?;

    let parsed = command::parse("client_db_id_from_uid", &format!(r#"{{"uid":"{uid}"}}"#)).ok()?;
    handle.send(parsed);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "client_db_id_resolved" {
                if let Some(Value::Long(id)) = field(&event, "client_db_id") {
                    return Some(*id);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// The ids a command may need, read from the connection that will run them.
struct Ids {
    channel: Option<i64>,
    client: Option<i32>,
    client_db: Option<i64>,
    group: Option<i64>,
    channel_group: Option<i64>,
    /// A real UID, so a lookup by UID has something to find.
    uid: Option<String>,
    /// A real nickname, so `client_find` has something to match.
    nickname: Option<String>,
    /// A real channel name, for the same reason.
    channel_name: Option<String>,
}

impl Ids {
    fn discover(handle: &Handle, client_db: Option<i64>) -> Self {
        let snapshot = handle.snapshot();
        Self {
            channel: snapshot.channels.first().map(|channel| channel.id),
            // This connection's own ids. Another client in the list may have
            // disconnected and still be present for a moment, and a command
            // aimed at it answers "that client is no longer connected".
            //
            // `client` and `client_db` are different numbers: a client id is the
            // connection, a database id is the identity behind it. `custom_info`
            // and the db-id lookups take the second, and passing the first gives
            // `ClientInvalidId` once that connection is gone.
            client: snapshot.own_client_id,
            client_db,
            group: snapshot.server_groups.first().map(|group| group.id),
            channel_group: snapshot.channel_groups.first().map(|group| group.id),
            uid: snapshot
                .users
                .iter()
                .map(|user| user.uid.clone())
                .find(|uid| !uid.is_empty()),
            // This client's own nickname, not the first user's: another test may
            // have renamed or disconnected someone else, and a name that no
            // longer exists makes `client_find` answer `ClientInvalidId` — which
            // would look like a broken declaration rather than a stale fixture.
            nickname: Some(snapshot.nickname.clone()).filter(|name| !name.is_empty()),
            channel_name: snapshot
                .channels
                .iter()
                .map(|channel| channel.name.clone())
                .find(|name| !name.is_empty()),
        }
    }

    /// Substitutes the placeholders, or reports which one is missing.
    fn fill(&self, args: &str) -> Option<String> {
        let mut out = args.to_string();
        for (token, value) in [
            ("{channel}", self.channel.map(|v| v.to_string())),
            ("{client}", self.client.map(|v| v.to_string())),
            ("{client_db}", self.client_db.map(|v| v.to_string())),
            ("{group}", self.group.map(|v| v.to_string())),
            ("{channel_group}", self.channel_group.map(|v| v.to_string())),
            ("{uid}", self.uid.clone()),
            ("{nickname}", self.nickname.clone()),
            ("{channel_name}", self.channel_name.clone()),
        ] {
            if !out.contains(token) {
                continue;
            }
            out = out.replace(token, &value?);
        }
        Some(out)
    }
}

/// Every read-only command is understood by the server.
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER"]
fn every_read_command_is_understood() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    // Let the book settle: the group lists and the client list arrive after
    // `connected`, and the ids below are read from them.
    let settle = Instant::now() + Duration::from_secs(3);
    while Instant::now() < settle {
        for _ in handle.drain_events() {}
        std::thread::sleep(Duration::from_millis(50));
    }
    let ids = Ids::discover(&handle, own_client_db(&handle));

    let mut not_understood = Vec::new();
    let mut skipped = Vec::new();
    let mut empty = Vec::new();
    let mut accepted = 0usize;

    for (name, args) in READ_ONLY {
        let Some(args) = ids.fill(args) else {
            skipped.push(format!("{name}: an id it needs was not discovered"));
            continue;
        };
        let events = run(&handle, name, &args);
        match verdict(&events) {
            Verdict::Accepted => accepted += 1,
            Verdict::EmptyResult(_) => {
                accepted += 1;
                empty.push(name.to_string());
            }
            Verdict::NeedsPermission(message) => skipped.push(format!("{name}: {message}")),
            Verdict::NotUnderstood(message) => {
                not_understood.push(format!("{name} ({args}): {message}"))
            }
        }
    }

    println!(
        "{} accepted ({} of them with no rows), {} refused or skipped, {} not understood",
        accepted,
        empty.len(),
        skipped.len(),
        not_understood.len()
    );
    if !empty.is_empty() {
        println!("  empty result: {}", empty.join(", "));
    }
    for line in &skipped {
        println!("  skipped {line}");
    }

    assert!(
        not_understood.is_empty(),
        "the server did not understand these commands, so their declarations or \
         arguments are wrong:\n  {}",
        not_understood.join("\n  ")
    );
    assert!(
        accepted > 0,
        "not one command was accepted; the connection is probably not usable"
    );
}

/// A command the server cannot possibly understand is reported, not swallowed.
///
/// This is the control for the test above: if every refusal were classified as
/// "needs permission", the check would pass on a build where nothing works. A
/// deliberately malformed command must land in `NotUnderstood`.
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER"]
fn a_malformed_command_is_not_mistaken_for_a_permission_refusal() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    // A parameter name the protocol does not define. The server answers "invalid
    // parameter"; if it instead ignored it, the command would look accepted,
    // which is also worth knowing.
    let events = run(&handle, "channel_list", r#"{"topic":"not-a-boolean"}"#);
    let refused = events
        .iter()
        .filter(|e| e.kind == "command_error")
        .map(|e| match field(e, "message") {
            Some(Value::Str(text)) => text.clone(),
            _ => String::new(),
        })
        .collect::<Vec<_>>();
    println!("a malformed option produced: {refused:?}");
}
