//! Pins the two things a Rust shell relies on that the JSON boundary cannot
//! provide: a typed snapshot, and a `Session` that can be dropped from an async
//! context without taking the process down.
//!
//! Both are about *linking the crate*, not about the protocol, so they live in
//! an integration test: they exercise the public surface the way a desktop shell
//! would, and a change to the private layout cannot accidentally make them pass.

use std::sync::mpsc;
use std::time::Duration;

use tsbridge_core::{account::AccountConfig, Session, SessionConfig};

/// A session with no address and no socket, which is all these tests need.
fn account_session() -> Session {
    Session::account_only(AccountConfig::default()).expect("account-only session")
}

#[test]
fn a_snapshot_comes_back_typed() {
    let session = account_session();
    // The point of this accessor is that it does not go through JSON: a Rust
    // shell reads fields, it does not parse a string.
    let snapshot = session.snapshot();
    assert_eq!(snapshot.own_client_id, None);
    assert!(snapshot.users.is_empty());
    // And the JSON path still exists for the other shells.
    assert!(session.snapshot_json().contains("\"rev\""));
}

/// The panic this guards against is not reproducible on every run — it depends
/// on which thread drops the last reference. So the test drops from inside a
/// multi-thread runtime on purpose, which is the shape a Tauri/Dioxus command
/// handler has, and repeats it: a single lucky pass would prove nothing.
#[test]
fn dropping_a_session_inside_an_async_context_does_not_panic() {
    for _ in 0..8 {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");

        let (done_tx, done_rx) = mpsc::channel();
        runtime.spawn(async move {
            let session = account_session();
            // Dropped here, on a worker thread, with the runtime still running.
            drop(session);
            let _ = done_tx.send(());
        });

        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the drop must complete; a panic here would abort the worker");
        drop(runtime);
    }
}

/// A connection handle that never connects still has a runtime, and dropping it
/// is the same hazard. `connect` fails to open a socket against an address that
/// cannot resolve, but the handle (and its runtime) exist as soon as the call
/// returns, which is what this drops.
#[test]
fn dropping_a_connect_handle_inside_an_async_context_does_not_panic() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let (done_tx, done_rx) = mpsc::channel();
    runtime.spawn(async move {
        let config = SessionConfig {
            address: "127.0.0.1:1".to_string(),
            identity: String::new(),
            nickname: "test".to_string(),
            server_password: None,
            channel: None,
            channel_password: None,
            version: Default::default(),
            privilege_key: String::new(),
            start_muted: false,
        };
        if let Ok(session) = Session::connect(config) {
            drop(session);
        }
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the drop must complete");
}

/// A connection session must not build an account side of its own.
///
/// That is the whole point of sharing one: a desktop shell opens a session per
/// server, and a second runtime with two threads per tab — plus a second,
/// independent login — is what made switching servers expensive.
#[test]
fn a_connection_session_does_not_build_its_own_account_side() {
    let config = SessionConfig {
        address: "127.0.0.1:1".to_string(),
        identity: String::new(),
        nickname: "test".to_string(),
        server_password: None,
        channel: None,
        channel_password: None,
        version: Default::default(),
        privilege_key: String::new(),
        start_muted: false,
    };
    let session = Session::connect(config).expect("handle");
    assert!(
        session.snapshot().account.email.is_empty(),
        "a connection-only session has no account side to report"
    );
    // And the account side really is absent, not merely empty: asking it to do
    // something reports that it could not be started.
    let error = session.exec("sync_list", "{}");
    assert!(
        error.contains("account"),
        "expected a missing-account error, got {error:?}"
    );
}

/// One account, several connections: the account session survives the
/// connections that borrow it, which is what lets a desktop shell switch
/// servers without logging in again.
#[test]
fn one_account_can_back_several_connections() {
    let account = account_session();

    let config = |address: &str| SessionConfig {
        address: address.to_string(),
        identity: String::new(),
        nickname: "test".to_string(),
        server_password: None,
        channel: None,
        channel_password: None,
        version: Default::default(),
        privilege_key: String::new(),
        start_muted: false,
    };

    let first = Session::connect_with_account(config("127.0.0.1:1"), &account).expect("first");
    let second = Session::connect_with_account(config("127.0.0.1:2"), &account).expect("second");

    // Both borrowed it, neither took it: the account still answers after the
    // connections exist, and dropping one connection does not affect the other.
    drop(first);
    assert!(
        account.exec("sync_list", "{}").is_empty(),
        "the account must still be usable after a connection that borrowed it is gone"
    );
    drop(second);
}
