//! Delete works: the object is gone from the server, and a refusal is reported.
//!
//! Deletion is a product feature, so "the test managed to clean up" is not the
//! check — the check is that the object is gone from the server afterwards, and
//! that a delete the server refuses says so. Both halves were broken:
//!
//! * a refused delete reported **nothing**, because `servergroupdel` answers
//!   `-> void` and the error packet was dropped on the floor;
//! * a successful delete left the group in the snapshot, because the book tracks
//!   creations but not deletions.
//!
//! Each is verified here against a real server, because neither can be checked
//! offline: the first needs a server to refuse something, and the second needs a
//! server to actually remove it.
//!
//! ```text
//! LITESPEAK_TEST_SERVER=127.0.0.1:9987 LITESPEAK_TEST_DESTRUCTIVE=1 \
//!   cargo test -p litespeak-core --test live_delete -- --ignored --test-threads=1
//! ```

use std::time::{Duration, Instant};

use litespeak_core::{command, ConnectParams, Handle, QueuedEvent, Value};

fn connect(nickname: &str) -> Handle {
    let handle = Handle::create(ConnectParams {
        address: std::env::var("LITESPEAK_TEST_SERVER").expect("LITESPEAK_TEST_SERVER"),
        identity: std::env::var("LITESPEAK_TEST_IDENTITY").unwrap_or_default(),
        nickname: nickname.to_string(),
        server_password: std::env::var("LITESPEAK_TEST_PASSWORD").ok(),
        channel: None,
        channel_password: None,
        myts: None,
        version_profile: Default::default(),
        privilege_key: String::new(),
        start_muted: true,
    })
    .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "connected" {
                // Let the group lists arrive.
                let settle = Instant::now() + Duration::from_millis(800);
                while Instant::now() < settle {
                    for _ in handle.drain_events() {}
                    std::thread::sleep(Duration::from_millis(30));
                }
                return handle;
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("the server did not report connected");
}

fn field<'a>(event: &'a QueuedEvent, key: &str) -> Option<&'a Value> {
    event
        .data
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// Sends a command and collects every event for `window`.
fn run(handle: &Handle, name: &str, args: &str, window: Duration) -> Vec<QueuedEvent> {
    let parsed = command::parse(name, args).unwrap_or_else(|e| panic!("`{name}`: {e}"));
    handle.send(parsed);

    let deadline = Instant::now() + window;
    let mut collected = Vec::new();
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            collected.push(event);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    collected
}

fn error_text(events: &[QueuedEvent]) -> Option<String> {
    events
        .iter()
        .find(|event| event.kind == "command_error")
        .map(|event| match field(event, "message") {
            Some(Value::Str(text)) => text.clone(),
            _ => String::new(),
        })
}

/// Creates a server group and returns its id.
fn make_group(handle: &Handle, name: &str) -> i64 {
    let events = run(
        handle,
        "server_group_create",
        &format!(r#"{{"name":"{name}"}}"#),
        Duration::from_secs(3),
    );
    events
        .iter()
        .filter(|event| event.kind == "group_created")
        .find_map(|event| match field(event, "group_id") {
            Some(Value::Long(id)) => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the group was not created: {events:?}"))
}

/// Creates a channel and returns its id.
fn make_channel(handle: &Handle, name: &str) -> i64 {
    let events = run(
        handle,
        "channel_create",
        &format!(r#"{{"name":"{name}"}}"#),
        Duration::from_secs(3),
    );
    events
        .iter()
        .filter(|event| event.kind == "channel_created")
        .find_map(|event| match field(event, "channel_id") {
            Some(Value::Long(id)) => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the channel was not created: {events:?}"))
}

/// A fresh connection, as a second opinion on what the server still holds.
///
/// The connection that performed a delete cannot be trusted to know: the book is
/// told to forget the group directly, so its snapshot agrees before the server
/// has done anything. Only a connection that never deleted anything sees what
/// the server actually kept.
fn still_on_server(name: &str) -> bool {
    let observer = connect(&format!("{name}-observer"));
    let snapshot = observer.snapshot();
    snapshot
        .server_groups
        .iter()
        .any(|group| group.name == name)
        || snapshot
            .channel_groups
            .iter()
            .any(|group| group.name == name)
        || snapshot.channels.iter().any(|channel| channel.name == name)
}

/// A server group delete removes it from the server.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn a_server_group_delete_really_deletes() {
    assert_destructive();
    let tag = format!("del-sg-{}", std::process::id());
    let handle = connect("del-sg");

    let id = make_group(&handle, &tag);
    assert!(
        still_on_server(&tag),
        "the group was created but a second connection cannot see it"
    );

    let events = run(
        &handle,
        "server_group_delete",
        &format!(r#"{{"groupId":{id},"force":true}}"#),
        Duration::from_secs(4),
    );
    assert!(
        error_text(&events).is_none(),
        "a delete of a group that exists was refused: {:?}",
        error_text(&events)
    );

    // A second connection, after the delete had time to land.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !still_on_server(&tag),
        "the group is still on the server after a delete that reported no error"
    );
}

/// A channel group delete removes it from the server.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn a_channel_group_delete_really_deletes() {
    assert_destructive();
    let tag = format!("del-cg-{}", std::process::id());
    let handle = connect("del-cg");

    let events = run(
        &handle,
        "channel_group_create",
        &format!(r#"{{"name":"{tag}"}}"#),
        Duration::from_secs(3),
    );
    let id = events
        .iter()
        .filter(|event| event.kind == "group_created")
        .find_map(|event| match field(event, "group_id") {
            Some(Value::Long(id)) => Some(*id),
            _ => None,
        })
        .expect("the channel group was not created");
    assert!(still_on_server(&tag), "a second connection cannot see it");

    let events = run(
        &handle,
        "channel_group_delete",
        &format!(r#"{{"groupId":{id},"force":true}}"#),
        Duration::from_secs(4),
    );
    assert!(error_text(&events).is_none(), "the delete was refused");

    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !still_on_server(&tag),
        "the channel group is still on the server"
    );
}

/// A channel delete removes it from the server.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn a_channel_delete_really_deletes() {
    assert_destructive();
    let tag = format!("del-chan-{}", std::process::id());
    let handle = connect("del-chan");

    let id = make_channel(&handle, &tag);
    assert!(still_on_server(&tag), "a second connection cannot see it");

    let events = run(
        &handle,
        "channel_delete",
        &format!(r#"{{"channelId":{id},"force":true}}"#),
        Duration::from_secs(4),
    );
    assert!(error_text(&events).is_none(), "the delete was refused");

    std::thread::sleep(Duration::from_millis(500));
    assert!(!still_on_server(&tag), "the channel is still on the server");
}

/// A delete the server refuses is reported.
///
/// This is the half that was missing: `servergroupdel` answers `-> void`, so its
/// refusal arrived as an `error` packet with no `return_code` and nothing looked
/// at it. The UI showed the delete as done and the group stayed. Before the fix
/// this test failed with `None`, which is why it exists.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn a_refused_delete_is_reported() {
    assert_destructive();
    let handle = connect("del-refused");

    // An id no group has. The server answers `invalid group ID`.
    let events = run(
        &handle,
        "server_group_delete",
        r#"{"groupId":99999,"force":true}"#,
        Duration::from_secs(3),
    );
    let reported = error_text(&events);
    assert_eq!(
        reported.as_deref(),
        Some("invalid group ID"),
        "a refused delete must report the server's own reason; got {reported:?}"
    );

    let events = run(
        &handle,
        "channel_delete",
        r#"{"channelId":99999,"force":true}"#,
        Duration::from_secs(3),
    );
    assert_eq!(
        error_text(&events).as_deref(),
        Some("invalid channelID"),
        "a refused channel delete must report the server's own reason"
    );
}

/// A successful delete reports nothing.
///
/// The other half of the same fix: `error id=0 msg=ok` is what every accepted
/// command answers, and reporting those would turn every write into a failure.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn a_successful_delete_reports_nothing() {
    assert_destructive();
    let tag = format!("del-quiet-{}", std::process::id());
    let handle = connect("del-quiet");

    let id = make_group(&handle, &tag);
    let events = run(
        &handle,
        "server_group_delete",
        &format!(r#"{{"groupId":{id},"force":true}}"#),
        Duration::from_secs(3),
    );
    assert!(
        error_text(&events).is_none(),
        "a successful delete reported a failure: {:?}",
        error_text(&events)
    );
}

fn assert_destructive() {
    assert!(
        std::env::var("LITESPEAK_TEST_DESTRUCTIVE").as_deref() == Ok("1"),
        "set LITESPEAK_TEST_DESTRUCTIVE=1 to run the delete tests"
    );
}
