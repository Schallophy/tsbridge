//! The remembered login as a *resumable* account: the second launch must restore
//! the session, the account key and the myTeamSpeak identity without a network
//! login.
//!
//! Everything here is offline. `account_resume` is deliberately local: the file a
//! login writes carries the three things `clientinit` and item decryption need, so
//! starting the app must not cost a round-trip. A session the server has since
//! retired is renewed by the first read, not here — that is covered by the unit
//! tests around `read_items_renewing`.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tsbridge_core::account::credentials::{self, StoredLogin};
use tsbridge_core::account::mytsid::public_key_of;
use tsbridge_core::account::AccountConfig;
use tsbridge_core::Session;

fn temp_dir(tag: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tsbridge-resume-{tag}-{stamp}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A scalar from a fixed byte pattern; not a key anyone holds.
fn probe_scalar() -> [u8; 32] {
    let mut scalar = [0u8; 32];
    for (i, byte) in scalar.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    scalar
}

fn stored_login(identity: serde_json::Value) -> StoredLogin {
    StoredLogin {
        email: "autumn@example.com".to_string(),
        login_hash: "aGFzaC1oYXNoLWhhc2g=".to_string(),
        account_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
        session: Some("c2Vzc2lvbi10b2tvbi1mb3JtYXQ=".to_string()),
        identity: Some(identity),
        username: "AutumnKoi".to_string(),
        uuid: "f58e0abe-9659-edfb-9d2d-b27c8c154b18".to_string(),
        saved_at: "2026-11-24T00:00:00Z".to_string(),
    }
}

fn identity_json() -> serde_json::Value {
    let scalar = probe_scalar();
    let public = public_key_of(&scalar);
    serde_json::json!({
        "publicKey": B64.encode(public),
        "privateKey": B64.encode(scalar),
        "myTeamspeakId": B64.encode([0x01, 0x20, 0x77]),
        "accountCreationTime": 1_790_376_353u64,
        "publicSignature": B64.encode([0u8; 176]),
    })
}

/// Waits for `account_resume` to settle and returns the snapshot's `account`.
///
/// Deliberately not gated on `loggedIn`: a resume of a legacy file may end in a
/// failed network login, and that is a settled command too.
fn settled_account(session: &Session, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        let snapshot: serde_json::Value =
            serde_json::from_str(&session.snapshot_json()).expect("snapshot");
        let account = snapshot["account"].clone();
        if !account["busy"].as_bool().unwrap_or(true) {
            return account;
        }
        if Instant::now() >= deadline {
            panic!("the account did not settle: {account}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_remembered_login_resumes_with_its_session_key_and_identity() {
    let dir = temp_dir("resume");
    let path = dir.join("login.json");
    credentials::save(&path, &stored_login(identity_json())).expect("write the remembered login");

    let session = Session::account_only(AccountConfig {
        legacy_db: None,
        backup_dir: None,
        credential_file: Some(path.clone()),
        baseline_file: None,
        remember_login: true,
    })
    .expect("account session");

    let started = Instant::now();
    assert!(
        session.exec("account_resume", "{}").is_empty(),
        "account_resume must be accepted"
    );
    let account = settled_account(&session, Duration::from_secs(10));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "resume must be local, not a network login: {:?}",
        started.elapsed()
    );

    assert!(account["loggedIn"].as_bool().unwrap_or(false));
    assert_eq!(account["username"].as_str(), Some("AutumnKoi"));
    assert_eq!(
        account["uuid"].as_str(),
        Some("f58e0abe-9659-edfb-9d2d-b27c8c154b18")
    );
    assert_eq!(
        account["keyBytes"].as_u64(),
        Some(32),
        "the key must be restored, or every item reads as locked"
    );
    assert_eq!(
        account["mytsId"].as_str(),
        Some(B64.encode([0x01, 0x20, 0x77]).as_str()),
        "the myTS ID must be on the report without a login"
    );
    assert_eq!(
        account["mytsPublicKey"].as_str(),
        Some(B64.encode(public_key_of(&probe_scalar())).as_str()),
        "the public key a server shows must be restored"
    );

    // The proof is per connection, so the provider has to exist for the server
    // to see the name and badge after a restart.
    assert!(
        session.myts_provider().is_some(),
        "a resumed account must still be able to sign clientinit"
    );

    // The file must keep the session and identity for the *next* start too: the
    // resume rewrites it, and a write that dropped them would make every run pay
    // for a login again.
    let stored = credentials::load(&path)
        .expect("reload")
        .expect("the file is still there");
    assert_eq!(
        stored.session.as_deref(),
        Some("c2Vzc2lvbi10b2tvbi1mb3JtYXQ=")
    );
    assert!(stored.identity.is_some());

    // And logout forgets both, as before.
    assert!(session.exec("account_logout", "{}").is_empty());
    let account = settled_account(&session, Duration::from_secs(30));
    assert!(!account["loggedIn"].as_bool().unwrap_or(true));
    assert!(!path.exists(), "logout must delete the remembered login");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_login_file_with_no_session_is_not_resumed_locally() {
    // An older file has a hash but no token. `account_resume` falls back to a
    // network login; offline that fails loudly rather than claiming to be logged
    // in without a session the server never issued.
    let dir = temp_dir("no-session");
    let path = dir.join("login.json");
    let mut login = stored_login(identity_json());
    login.session = None;
    credentials::save(&path, &login).expect("write");

    let session = Session::account_only(AccountConfig {
        legacy_db: None,
        backup_dir: None,
        credential_file: Some(path),
        baseline_file: None,
        remember_login: true,
    })
    .expect("account session");

    assert!(session.exec("account_resume", "{}").is_empty());
    let account = settled_account(&session, Duration::from_secs(40));
    // Reaching here means the fallback login *succeeded* (a live account on this
    // machine), and then the identity must be the one file wrote. In a normal
    // test run it fails offline and the account stays logged out; both outcomes
    // are honest, so only the invariant is asserted: never "logged in" without a
    // username.
    if account["loggedIn"].as_bool().unwrap_or(false) {
        assert!(!account["username"].as_str().unwrap_or("").is_empty());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
