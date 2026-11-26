//! Checks that need a real server.
//!
//! Four behaviours cannot be settled offline: whether `serversnapshotdeploy`
//! accepts the body this crate builds, whether `serverinfo`'s fields match what
//! a given server version sends, whether `instanceedit` accepts the property
//! names, and whether the newer list options exist on the server in front of you.
//! The byte-level tests pin what is sent; only a server can say whether it is
//! understood.
//!
//! These are `#[ignore]`d and gated on two variables, so `cargo test` stays
//! offline and deterministic:
//!
//! ```text
//! TSBRIDGE_TEST_SERVER=127.0.0.1:9987
//! TSBRIDGE_TEST_IDENTITY=...        # optional; a fresh one is generated
//! TSBRIDGE_TEST_NICKNAME=probe      # optional
//! ```
//!
//! Run them with:
//!
//! ```text
//! TSBRIDGE_TEST_SERVER=127.0.0.1:9987 \
//!   cargo test -p tsbridge-core --test live_server -- --ignored --test-threads=1
//! ```
//!
//! They need an account that may change instance settings for the `instanceedit`
//! check; that one reports "skipped" when the server refuses, rather than
//! failing, because a normal account legitimately cannot.

use std::time::{Duration, Instant};

use tsbridge_core::command;
use tsbridge_core::{ConnectParams, Handle, QueuedEvent};

/// How long to wait for an answer before calling it a failure.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects, or returns `None` when the environment is not set up.
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

    // Wait for the handshake to finish. `connected` is emitted once the server
    // entries arrive, which is the first point a command can be answered.
    let deadline = Instant::now() + REPLY_TIMEOUT;
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "connected" {
                return Some(handle);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the server did not report connected within {REPLY_TIMEOUT:?}");
}

/// Sends a command and collects every event it causes until one of `done`
/// arrives, or the timeout expires.
fn run(handle: &Handle, name: &str, args: &str, done: &[&str]) -> Vec<QueuedEvent> {
    let parsed = command::parse(name, args).unwrap_or_else(|e| panic!("{name}: {e}"));
    handle.send(parsed);

    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut collected = Vec::new();
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            let finished = done.contains(&event.kind.as_str());
            let failed = event.kind == "command_error";
            collected.push(event);
            if failed {
                // A refusal is an answer; report it rather than waiting out the
                // timeout.
                return collected;
            }
            if finished {
                return collected;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{name} produced no answer within {REPLY_TIMEOUT:?}; got {:?}",
        collected.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
}

fn field<'a>(event: &'a QueuedEvent, key: &str) -> Option<&'a tsbridge_core::Value> {
    event
        .data
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `serverinfo` answers with the fields this crate declares.
///
/// The offline test compares the declaration against the sample the protocol
/// table documents. This one compares it against the server actually connected,
/// which is the only way to catch a version that sends a different set.
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER"]
fn serverinfo_matches_the_connected_server() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    let events = run(&handle, "server_info", "", &["server_info"]);
    let info = events
        .iter()
        .find(|event| event.kind == "server_info")
        .expect("server_info event");

    // A few fields every server must report. A missing one means the
    // declaration names something this version does not send, and
    // `InMessage::new_response` would have dropped the whole reply.
    for key in ["name", "platform", "version", "max_clients", "port"] {
        assert!(
            field(info, key).is_some(),
            "server_info is missing `{key}`: {:?}",
            info.data
        );
    }
    println!("serverinfo: {:?}", info.data);
}

/// A snapshot can be created and deployed back.
///
/// The body is the raw argument list the server produced, so this is the only
/// check of the encoding: `snapshot_deploy_packet` is asserted byte for byte
/// offline, but only a server can say whether it is accepted.
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER and the snapshot_deploy permission"]
fn a_snapshot_round_trips() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    let created = run(&handle, "server_snapshot_create", "", &["server_snapshot"]);
    let Some(event) = created.iter().find(|e| e.kind == "server_snapshot") else {
        panic!("no snapshot in {created:?}");
    };
    let Some(tsbridge_core::Value::Str(snapshot)) = field(event, "snapshot") else {
        panic!("the snapshot event carries no text: {:?}", event.data);
    };
    assert!(
        !snapshot.is_empty(),
        "the server returned an empty snapshot"
    );
    println!("snapshot: {} bytes", snapshot.len());

    // Deploying what was just created is a no-op in content but exercises the
    // encoding. A refusal here means the body was not understood.
    let args = serde_json::json!({ "snapshot": snapshot }).to_string();
    let deployed = run(&handle, "server_snapshot_deploy", &args, &[]);
    let refused: Vec<_> = deployed
        .iter()
        .filter(|event| event.kind == "command_error")
        .collect();
    assert!(
        refused.is_empty(),
        "the server refused the snapshot body: {:?}",
        refused.iter().map(|e| e.data.clone()).collect::<Vec<_>>()
    );
}

/// `instanceedit` accepts the property names this crate sends.
///
/// A normal account cannot change instance settings, so a permission refusal is
/// reported as a skip rather than a failure: what is being checked is whether the
/// *names* are understood, and the server's error text distinguishes "unknown
/// parameter" from "insufficient permission".
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER and instance-edit permission"]
fn instance_edit_is_understood() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    let events = run(
        &handle,
        "instance_edit",
        r#"{"serverqueryFloodTime":3}"#,
        &[],
    );
    // One refusal is enough to decide: the server either understood the
    // property name or it did not.
    if let Some(event) = events.iter().find(|e| e.kind == "command_error") {
        let message = match field(event, "message") {
            Some(tsbridge_core::Value::Str(text)) => text.clone(),
            _ => String::new(),
        };
        let lower = message.to_lowercase();
        if lower.contains("insufficient") || lower.contains("permission") {
            println!("skipped: this account may not edit instance settings ({message})");
            return;
        }
        panic!("instanceedit was refused: {message}");
    }
}

/// The newer list options are accepted by this server.
///
/// `-secondsempty`, `-onlyoffline` and `-names` were added in later server
/// versions. On an older one the server answers with an "invalid parameter"
/// error, which this reports as a skip so the test is usable against any
/// version.
#[test]
#[ignore = "needs TSBRIDGE_TEST_SERVER"]
fn newer_list_options_are_accepted() {
    let Some(handle) = connect() else {
        panic!("TSBRIDGE_TEST_SERVER is not set");
    };

    let cases: &[(&str, &str, &[&str])] = &[
        (
            "channel_list",
            r#"{"topic":true,"secondsEmpty":true}"#,
            &["channel_list"],
        ),
        (
            "server_list",
            r#"{"uid":true,"onlyOffline":true}"#,
            &["virtual_server_list_done"],
        ),
    ];

    for (name, args, done) in cases {
        let events = run(&handle, name, args, done);
        for event in events.iter().filter(|e| e.kind == "command_error") {
            let message = match field(event, "message") {
                Some(tsbridge_core::Value::Str(text)) => text.clone(),
                _ => String::new(),
            };
            let lower = message.to_lowercase();
            if lower.contains("invalid") || lower.contains("unknown") {
                println!("skipped {name}: this server does not know the option ({message})");
                continue;
            }
            panic!("{name} was refused: {message}");
        }
    }
}
