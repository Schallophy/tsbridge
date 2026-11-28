//! The account flow, end to end, against a recorded server.
//!
//! Everything else in this crate's tests is a pure function: payload bytes in,
//! payload bytes out. That leaves the part most likely to break — the wiring
//! between login, `/me`, the read, the decode and the decrypt — reachable only
//! by signing in to the real service and clicking through a UI. This file stands
//! a local server up instead and drives the real `account` code over it.
//!
//! The fixture is a **reconstruction**, in the sense the open-source `ts3java`
//! harness uses that word: the reply is rebuilt from the capture's structure
//! (eight classes, 25 items, 8/2/1/13/1 across them, three classes legitimately
//! empty, 13 plaintext and 12 encrypted), with every uuid, version and string
//! synthesised and re-sealed under a throwaway key. Nothing from the captured
//! account is in here, so this runs anywhere without holding somebody's
//! bookmarks.
//!
//! What it therefore proves is the orchestration, not the wire layout; the
//! layout has its own byte-exact vectors in `account_contract.rs`.
//!
//! The same server also models a **session that expires**, because that is the
//! one failure a client cannot test by hand without waiting for a real session to
//! rot: it hands out session ids, counts logins, and answers `102
//! SESSION_EXPIRED` on demand so the transparent re-login can be watched
//! happening.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use litespeak_core::account::http::{Endpoints, Http, LoginRequest};
use litespeak_core::account::merge;
use litespeak_core::account::sync::{self, ItemCipher, ItemClass, Sync, SyncState, SyncStatus};
use litespeak_core::account::{self, crypto, proto, AccountConfig, AccountContext, WritePlan};
use litespeak_core::Session;
use serde_json::json;

/// The password the replay server accepts, and the key it hands out.
///
/// The *wrapper* is derived here from the password, so the login path does its
/// actual work; the key it unwraps to is a constant so the sealed items can be
/// built before the server starts.
const PASSWORD: &str = "replay-only-password";
const EMAIL: &str = "replay@example.invalid";
const ACCOUNT_KEY: [u8; 32] = [0x5a; 32];
const USER_UUID: &str = "00000000-0000-4000-8000-0000000000aa";
const USERNAME: &str = "Replay";
const GLOBAL_VERSION: &str = "00000000-0000-4000-8000-000000000001";

/// The mix the capture showed: 25 items, 13 of them plaintext `ADD_ON` rows and
/// 12 encrypted ones across four classes.
const COUNTS: [(ItemClass, usize, bool); 5] = [
    (ItemClass::Bookmark, 8, true),
    (ItemClass::Identity, 2, true),
    (ItemClass::HotkeyProfile, 1, true),
    (ItemClass::AddOn, 13, false),
    (ItemClass::Config, 1, true),
];

/// The three classes the capture returned with no version and no details.
const EMPTY_CLASSES: [ItemClass; 3] = [
    ItemClass::WhisperList,
    ItemClass::ItemFolder,
    ItemClass::RoomCategory,
];

// ── the fixture ─────────────────────────────────────────────────────────────

/// One item as the reply carries it: uuid, item version, blob.
type Detail = (String, String, Vec<u8>);

/// One class as the reply carries it: class, class cursor, details.
type ClassBlock = (ItemClass, String, Vec<Detail>);

struct Fixture {
    classes: Vec<ClassBlock>,
}

impl Fixture {
    fn build() -> Fixture {
        Fixture::from_counts(&COUNTS)
    }

    /// The same account without one class: the state a user switching away from
    /// the official client is in, and the one the "first item" paths have to fix
    /// without sending them back to it.
    fn without(class: ItemClass) -> Fixture {
        let counts: Vec<(ItemClass, usize, bool)> = COUNTS
            .iter()
            .copied()
            .filter(|(c, _, _)| *c != class)
            .collect();
        Fixture::from_counts(&counts)
    }

    fn from_counts(counts: &[(ItemClass, usize, bool)]) -> Fixture {
        let cipher = ItemCipher::new(ACCOUNT_KEY);
        let mut classes = Vec::new();
        let mut n = 0u32;
        for (class, count, sealed) in counts.iter().copied() {
            n += 1;
            let class_version = version(n);
            let mut details = Vec::new();
            for _ in 0..count {
                n += 1;
                let uuid = version(n);
                n += 1;
                let item_version = version(n);
                let plain = item_data(&uuid, &item_version, class);
                let blob = if sealed { cipher.seal(&plain) } else { plain };
                details.push((uuid, item_version, blob));
            }
            classes.push((class, class_version, details));
        }
        Fixture { classes }
    }

    /// The `requestServerItems` reply, in the shape the server sends it.
    ///
    /// Details stored by `synchronizeItems` are appended to their class and the
    /// deleted ones dropped, so a write followed by a read looks like what a real
    /// server would show. A class that only exists because something was written
    /// into it is emitted too — a real server would, and a harness that dropped it
    /// would make "I wrote a folder" untestable.
    fn sync_reply(&self, sessions: &Sessions) -> Vec<u8> {
        let mut reply = proto::field_varint(1, SyncStatus::NotInSync.code() as u64);
        for class in ItemClass::ALL {
            let fixture = self.classes.iter().find(|(c, _, _)| *c == class);
            // A write is an **upsert**: a uuid the fixture already holds is
            // replaced, not appended. Appending is what made a rewrite of an
            // existing item look like two rows — the client then read the old
            // fixture blob back and its byte comparison failed.
            let writes: Vec<(&String, &Written)> = sessions
                .writes
                .iter()
                .filter(|(uuid, (write_class, _, _))| {
                    *write_class == class && !sessions.deletes.contains(uuid)
                })
                .collect();
            let written = |uuid: &str| writes.iter().find(|(id, _)| id.as_str() == uuid);

            if fixture.is_none() && writes.is_empty() {
                // Present but empty: exactly what the capture showed for the
                // three classes that hold nothing on the reference account.
                let class_message = proto::field_varint(1, class.id() as u64);
                reply.extend(proto::field_bytes(2, &class_message));
                continue;
            }

            let mut class_message = proto::field_varint(1, class.id() as u64);
            if let Some((_, class_version, details)) = fixture {
                class_message.extend(proto::field_string(2, class_version));
                for (uuid, item_version, blob) in details {
                    // A fixture row the server has since been told to replace is
                    // emitted once, with the stored bytes.
                    let (item_version, blob) = match written(uuid) {
                        Some((_, (_, item_version, blob))) => (item_version, blob),
                        None => (item_version, blob),
                    };
                    let mut detail = proto::field_string(1, uuid);
                    detail.extend(proto::field_string(2, item_version));
                    detail.extend(proto::field_bytes(3, blob));
                    class_message.extend(proto::field_bytes(3, &detail));
                }
            } else {
                // A class the fixture never populated still needs a cursor once
                // it holds something.
                class_message.extend(proto::field_string(
                    2,
                    "00000000-0000-4000-8000-00000000c1a5",
                ));
            }
            // Rows written into this class that the fixture did not already
            // carry: a genuinely new item.
            for (uuid, (_, item_version, blob)) in &writes {
                let known = fixture
                    .map(|(_, _, details)| details.iter().any(|(id, _, _)| id == *uuid))
                    .unwrap_or(false);
                if known {
                    continue;
                }
                let mut detail = proto::field_string(1, uuid);
                detail.extend(proto::field_string(2, item_version));
                detail.extend(proto::field_bytes(3, blob));
                class_message.extend(proto::field_bytes(3, &detail));
            }
            reply.extend(proto::field_bytes(2, &class_message));
        }
        reply.extend(proto::field_string(3, GLOBAL_VERSION));
        reply
    }

    fn item_count(&self) -> usize {
        self.classes.iter().map(|(_, _, d)| d.len()).sum()
    }
}

fn version(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

/// An `Item_Data` with a bookmark in it, so the decrypt path has real content to
/// compare rather than "it produced some bytes".
fn item_data(uuid: &str, item_version: &str, class: ItemClass) -> Vec<u8> {
    item_data_with_placement(uuid, item_version, class, "", "")
}

/// An `Item_Data` with an explicit `parent` (field 7) and `sort_order` (field 8),
/// so a fixture can present a linked sibling chain that a reorder can move.
fn item_data_with_placement(
    uuid: &str,
    item_version: &str,
    class: ItemClass,
    parent: &str,
    sort_order: &str,
) -> Vec<u8> {
    let mut message = proto::field_string(2, uuid);
    message.extend(proto::field_string(3, item_version));
    message.extend(proto::field_varint(4, 3)); // ITEM_NOT_MANIPULATED
    message.extend(proto::field_string(5, sync::UNPUBLISHED_VERSION));
    message.extend(proto::field_varint(6, class.id() as u64));
    message.extend(proto::field_string(7, parent));
    message.extend(proto::field_string(8, sort_order));
    if class == ItemClass::Bookmark {
        let mut bookmark = proto::field_string(1, uuid);
        bookmark.extend(proto::field_string(2, "replay.example.invalid"));
        bookmark.extend(proto::field_varint(3, 9987));
        bookmark.extend(proto::field_string(4, "ReplayNick"));
        message.extend(proto::field_bytes(16, &bookmark));
    }
    if class == ItemClass::Identity {
        // Synthetic, but shaped like the real item: five fields, with the name
        // the official client uses for its shared template and every row flagged
        // default, which is the ambiguity `identity_pick` has to report rather
        // than guess through.
        let mut identity = proto::field_string(1, &format!("10V{uuid}"));
        identity.extend(proto::field_string(2, "Default"));
        identity.extend(proto::field_string(3, "Replay"));
        identity.extend(proto::field_varint(5, 1));
        message.extend(proto::field_bytes(17, &identity));
    }
    message
}

// ── the server ──────────────────────────────────────────────────────────────

/// What one `synchronizeItems` stored: the item's class, version and blob.
type Written = (ItemClass, String, Vec<u8>);

/// What the server remembers between requests.
#[derive(Debug, Default)]
struct Sessions {
    /// The session a read must carry to be accepted.
    current: String,
    /// How many `/client/login` calls have been answered. The re-login test
    /// counts this, because "there was a second login" is the whole assertion.
    logins: u64,
    /// The credential hash of the last accepted login, so a test can prove the
    /// recovery used the remembered hash and not a password.
    last_hash: String,
    /// Set to answer every read with `102 SESSION_EXPIRED`.
    expired: bool,
    /// Set to refuse logins the way a changed password would.
    refuse_login: bool,
    /// Set to refuse every `synchronizeItems` with a non-`IN_SYNC` status.
    ///
    /// The server accepts a write and stores it, so a harness cannot otherwise
    /// exercise the "the write did not land" path — which is the one the
    /// bookmark reorder used to swallow.
    refuse_write: bool,
    /// What `synchronizeItems` stored, keyed by uuid.
    ///
    /// A server that answered "accepted" without keeping the bytes would let the
    /// write path's read-back verification pass vacuously; storing them is what
    /// makes "the stored blob is the sent blob" a real assertion offline.
    writes: std::collections::BTreeMap<String, Written>,
    /// The uuids `synchronizeItems` was asked to delete.
    deletes: Vec<String>,
}

struct ReplayServer {
    port: u16,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<Sessions>>,
    acceptor: Option<JoinHandle<()>>,
}

impl ReplayServer {
    fn start(fixture: Fixture) -> ReplayServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
        let port = listener.local_addr().expect("local_addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        let fixture = Arc::new(fixture);

        let acceptor = {
            let stop = Arc::clone(&stop);
            let sessions = Arc::clone(&sessions);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    let fixture = Arc::clone(&fixture);
                    let sessions = Arc::clone(&sessions);
                    std::thread::spawn(move || {
                        let _ = serve(stream, &fixture, &sessions);
                    });
                }
            })
        };

        ReplayServer {
            port,
            stop,
            sessions,
            acceptor: Some(acceptor),
        }
    }

    fn context(&self) -> AccountContext {
        AccountContext {
            http: Http::with_endpoints(Endpoints {
                rest: format!("http://127.0.0.1:{}/api", self.port),
                cloud: format!("http://127.0.0.1:{}", self.port),
                // The only place this is ever true: a loopback recorder. The
                // guard itself is asserted below.
                allow_plain_http: true,
            }),
            legacy_db: None,
            backup_dir: temp_dir(),
            credential_file: None,
            // Every compare test writes its own file, so the shared field stays
            // unset: a stray baseline from one test must not leak into another.
            baseline_file: None,
        }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expire_session(&self) {
        self.sessions().expired = true;
    }

    fn refuse_logins(&self) {
        self.sessions().refuse_login = true;
    }

    fn refuse_writes(&self) {
        self.sessions().refuse_write = true;
    }

    fn allow_writes_again(&self) {
        self.sessions().refuse_write = false;
    }
}

impl Drop for ReplayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking `accept` so the acceptor thread can notice the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.acceptor.take() {
            let _ = handle.join();
        }
    }
}

fn serve(
    stream: TcpStream,
    fixture: &Fixture,
    sessions: &Arc<Mutex<Sessions>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.trim().is_empty() {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    let mut authorization = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        if let Some(value) = lower.strip_prefix("x-authorization:") {
            authorization = value.trim().to_string();
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let (status, content_type, reply) =
        route(&method, &path, &body, &authorization, fixture, sessions);

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        reply.len()
    );
    let mut writer = stream;
    writer.write_all(head.as_bytes())?;
    writer.write_all(&reply)?;
    writer.flush()
}

fn route(
    method: &str,
    path: &str,
    body: &[u8],
    authorization: &str,
    fixture: &Fixture,
    sessions: &Arc<Mutex<Sessions>>,
) -> (u16, &'static str, Vec<u8>) {
    let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
    // Both surfaces share one port here; the real ones live on different hosts.
    let tail = path.rsplit_once("/api").map(|(_, t)| t).unwrap_or(path);

    if method == "POST" && tail == "/client/login" {
        // A refused attempt is still an attempt: counting it first is what lets
        // the loop test tell "one retry" apart from "no retry at all".
        let hash = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("password")
                    .and_then(|p| p.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        sessions.logins += 1;
        sessions.last_hash = hash;
        if sessions.refuse_login {
            return (
                200,
                "application/json",
                br#"{"error":"ERROR_LOGIN_FAILED"}"#.to_vec(),
            );
        }
        // A renewed login is accepted with a fresh id and, crucially, ends the
        // expiry: the new session is alive.
        sessions.current = version(9000 + sessions.logins as u32);
        sessions.expired = false;
        let session = sessions.current.clone();
        return (200, "application/json", login_reply(&session));
    }
    if method == "GET" && tail == "/me" {
        // The real `/me` needs the session; a server that answered without one
        // would hide a header bug, so this checks it.
        if authorization.is_empty() || !authorization.contains(&sessions.current) {
            return (
                401,
                "application/json",
                br#"{"error":"ERROR_NOT_LOGGED_IN"}"#.to_vec(),
            );
        }
        return (200, "application/json", me_reply());
    }
    if method == "POST" && path == "/synchronization" {
        return match cloud_method(body).as_str() {
            "requestServerItems" => {
                let reply = if sessions.expired {
                    proto::field_varint(1, SyncStatus::SessionExpired.code() as u64)
                } else {
                    fixture.sync_reply(&sessions)
                };
                (200, "application/json", reply)
            }
            "synchronizeItems" => {
                if sessions.expired {
                    return (
                        200,
                        "application/json",
                        proto::field_varint(1, SyncStatus::SessionExpired.code() as u64),
                    );
                }
                if sessions.refuse_write {
                    // A status that is not `IN_SYNC`: the write did not land, and
                    // the reply stores nothing.
                    return (
                        200,
                        "application/json",
                        proto::field_varint(1, SyncStatus::Collision.code() as u64),
                    );
                }
                // Record what the request asked for, so the read-back finds it.
                if let Some(upsert) = parse_upsert(body) {
                    sessions.writes.insert(
                        upsert.uuid.clone(),
                        (upsert.class, upsert.item_version, upsert.blob),
                    );
                }
                if let Some(uuid) = parse_delete(body) {
                    sessions.deletes.push(uuid);
                }
                // Exactly what an accepted write looks like: 41 B, status 300.
                let mut reply = proto::field_varint(1, SyncStatus::InSync.code() as u64);
                reply.extend(proto::field_string(3, GLOBAL_VERSION));
                (200, "application/json", reply)
            }
            _ => (200, "application/json", proto::field_varint(1, 100)),
        };
    }
    (404, "text/plain", b"not found".to_vec())
}

/// What a `synchronizeItems` request wants stored.
struct Upsert {
    class: ItemClass,
    uuid: String,
    item_version: String,
    blob: Vec<u8>,
}

/// Reads `Sync_ItemClasses_Data` out of the request envelope.
fn parse_upsert(body: &[u8]) -> Option<Upsert> {
    let mut pos = 0usize;
    let len = proto::read_varint(body, &mut pos).ok()?;
    pos = pos.checked_add(len as usize)?;
    let message = proto::Message::parse(body.get(pos..)?).ok()?;
    let class_message = message.message(2).ok()?;
    let class = ItemClass::from_id(class_message.varint(1).unwrap_or(0) as u32)?;
    let detail = class_message.message(3).ok()?;
    if detail.bool(4).unwrap_or(false) {
        return None;
    }
    Some(Upsert {
        class,
        uuid: detail.string(1)?.to_string(),
        item_version: detail.string(2)?.to_string(),
        blob: detail.bytes(3)?.to_vec(),
    })
}

/// Reads the uuid a delete request names.
fn parse_delete(body: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let len = proto::read_varint(body, &mut pos).ok()?;
    pos = pos.checked_add(len as usize)?;
    let message = proto::Message::parse(body.get(pos..)?).ok()?;
    let class_message = message.message(2).ok()?;
    let detail = class_message.message(3).ok()?;
    if !detail.bool(4).unwrap_or(false) {
        return None;
    }
    Some(detail.string(1)?.to_string())
}

/// The method name out of `<varint len><name><payload>`.
fn cloud_method(body: &[u8]) -> String {
    let mut pos = 0usize;
    let Ok(len) = proto::read_varint(body, &mut pos) else {
        return String::new();
    };
    let end = pos.saturating_add(len as usize).min(body.len());
    String::from_utf8_lossy(&body[pos..end]).to_string()
}

fn login_reply(session: &str) -> Vec<u8> {
    let wrapper = crypto::hashed_encryption_password(PASSWORD, EMAIL);
    let key = crypto::wrap_key(&ACCOUNT_KEY, &wrapper, None);
    serde_json::to_vec(&json!({
        "error": "ERROR_LOGIN_OK",
        "session": session,
        "email": EMAIL,
        "username": USERNAME,
        "uuid": USER_UUID,
        "key": key,
    }))
    .expect("serialize the login reply")
}

fn me_reply() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "user": {
            "username": USERNAME,
            "uuid": USER_UUID,
            "email": EMAIL,
            "recoveryKeyCount": 3,
            "twoFactorAuthenticationEnabled": false,
        }
    }))
    .expect("serialize the /me reply")
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("litespeak-replay-tests");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn login_request() -> LoginRequest {
    LoginRequest {
        email: EMAIL.to_string(),
        password: Some(PASSWORD.to_string()),
        ..LoginRequest::default()
    }
}

/// Waits until the port answers, so a test never races the acceptor thread.
fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the replay server never started listening on {port}");
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("an account runtime")
}

/// Waits for the account command in flight to settle, and returns the snapshot's
/// `account` object. The engine publishes `busy: true` on accept and `busy: false`
/// when the command finishes, so this is the only reliable "the command is done"
/// signal a test has.
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
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A private directory per test, so two tests writing "merged.json" in the same
/// second cannot collide.
fn unique_dir(tag: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("litespeak-replay-{tag}-{stamp}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A `SyncState` out of a backup file, so a baseline can be built from the same
/// bytes the shell would compare.
fn state_of_backup(backup: &sync::Backup) -> SyncState {
    SyncState {
        status: backup.status,
        global_version: backup.global_version.clone(),
        class_version: backup.class_version.clone(),
        items: backup.items.clone(),
    }
}

// ── the tests ──────────────────────────────────────────────────────────────

/// The whole point: sign in, read, decrypt, with no account and no network.
#[test]
fn a_recorded_login_reads_and_decrypts_offline() {
    let fixture = Fixture::build();
    let expected_items = fixture.item_count();
    assert_eq!(expected_items, 25, "the capture held 25 items");
    let server = ReplayServer::start(fixture);
    wait_ready(server.port);
    let context = server.context();

    let runtime = runtime();
    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("login against the recorded server");

    assert_eq!(outcome.status, 200);
    assert_eq!(outcome.error, "");
    assert_eq!(
        outcome.account.session,
        version(9001),
        "the first login's session"
    );
    assert_eq!(outcome.account.username, USERNAME);
    assert_eq!(outcome.account.uuid, USER_UUID);
    let key = outcome
        .account
        .key
        .expect("the password-derived wrapper must unwrap the reply's key");
    assert_eq!(
        key, ACCOUNT_KEY,
        "the server's key is what the wrapper opens"
    );
    assert_eq!(outcome.login_hash, crypto::hashed_password(PASSWORD, EMAIL));
    // Which derivation won is reported, so a shell can say why items are read
    // rather than showing a mystery "locked" row.
    assert_eq!(
        outcome.account.unwrapped_with,
        "ts3Encryption (lower(email), password as secret)"
    );
    assert!(outcome.account.can_renew(), "the login kept a credential");

    let state: SyncState = runtime
        .block_on(account::read_items(&context, &outcome.account))
        .expect("read the recorded state");

    assert_eq!(state.status, SyncStatus::NotInSync);
    assert_eq!(state.global_version, GLOBAL_VERSION);
    assert_eq!(state.items.len(), expected_items);
    // Three classes come back with no cursor: present and empty, which must not
    // be read as "everything in this class was deleted".
    for class in EMPTY_CLASSES {
        assert!(
            !state.class_version.contains_key(&class),
            "{} came back with no version, as an empty class does",
            class.name()
        );
        assert_eq!(state.of_class(class).count(), 0);
    }
    assert_eq!(state.of_class(ItemClass::Bookmark).count(), 8);
    assert_eq!(state.of_class(ItemClass::AddOn).count(), 13);

    let cipher = ItemCipher::new(key);
    let mut plaintext = 0usize;
    let mut decrypted = 0usize;
    for item in &state.items {
        let plain = sync::read_plain(item, Some(&cipher)).unwrap_or_else(|e| {
            panic!("{} {} could not be read: {e}", item.class.name(), item.uuid)
        });
        if sync::is_plain_item_data(&item.blob) {
            plaintext += 1;
        } else {
            decrypted += 1;
        }
        // Decryption that yields bytes is not proof; it has to be the message
        // that was sealed.
        let parsed = proto::Message::parse(&plain).expect("plaintext is an Item_Data");
        assert_eq!(
            parsed.string(2),
            Some(item.uuid.as_str()),
            "the decrypted item is the item it came from"
        );
        if item.class == ItemClass::Bookmark {
            let bookmark = sync::Bookmark::parse(&plain)
                .expect("parse")
                .expect("a bookmark");
            assert_eq!(bookmark.name, item.uuid, "the sealed name reads back");
            assert_eq!(bookmark.address, "replay.example.invalid");
            assert_eq!(bookmark.port, 9987);
            assert_eq!(bookmark.nickname, "ReplayNick");
        }
    }
    // The capture's split: 13 plaintext rows and 12 encrypted ones, and the
    // account key opens every one of them.
    assert_eq!(plaintext, 13, "13 rows need no cipher at all");
    assert_eq!(decrypted, 12, "12 rows were sealed with the account key");
    assert_eq!(plaintext + decrypted, expected_items);

    let mut locked = 0usize;
    for item in &state.items {
        if sync::capability_of(item, Some(&cipher)) == sync::Capability::Locked {
            locked += 1;
        }
    }
    assert_eq!(locked, 0, "nothing is locked when the key is in hand");
}

/// A dead session is reported as the status it is, not as a parse failure and
/// not as an empty account.
#[test]
fn an_expired_session_is_surfaced_as_the_status_it_is() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();

    let runtime = runtime();
    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("login against the recorded server");
    assert_eq!(outcome.status, 200);

    server.expire_session();

    let state = runtime
        .block_on(account::read_items(&context, &outcome.account))
        .expect("a 102 reply is still a well-formed reply");
    assert_eq!(state.status, SyncStatus::SessionExpired);
    assert!(
        state.items.is_empty(),
        "an expired reply carries no items; it must not look like an empty account"
    );
}

/// Item 5: the transparent re-login. A read that finds a dead session signs in
/// again with the credential it already holds and returns the items, so the user
/// never sees "session expired".
#[test]
fn a_read_renews_an_expired_session_once_and_returns_the_items() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("initial login");
    let first_session = outcome.account.session.clone();
    assert_eq!(server.sessions().logins, 1);

    server.expire_session();

    let (state, renewed) = runtime
        .block_on(account::read_items_renewing(
            &context,
            &outcome.account,
            None,
        ))
        .expect("the read should recover, not fail");

    let renewed = renewed.expect("the read reported the account it renewed");
    assert_ne!(renewed.session, first_session, "the session really changed");
    assert_eq!(server.sessions().logins, 2, "exactly one re-login happened");
    assert_eq!(
        server.sessions().last_hash,
        crypto::hashed_password(PASSWORD, EMAIL),
        "the recovery used the remembered credential hash, not a typed password"
    );
    // The key and the credential survive the renewal; otherwise every item
    // would come back `locked` and the next expiry would be unrecoverable.
    assert_eq!(
        renewed.key,
        Some(ACCOUNT_KEY),
        "the account key is carried over"
    );
    assert!(renewed.can_renew(), "the credential is still there");

    assert_eq!(state.status, SyncStatus::NotInSync);
    assert_eq!(
        state.items.len(),
        25,
        "the items came back after the renewal"
    );

    // And the state is readable, not just counted.
    let cipher = ItemCipher::new(renewed.key.expect("key"));
    for item in state.of_class(ItemClass::Bookmark) {
        let plain = sync::read_plain(item, Some(&cipher)).expect("read");
        assert!(sync::Bookmark::parse(&plain).expect("parse").is_some());
    }
}

/// A credential the server refuses must surface as that refusal, not as an
/// endless re-login loop. This is the "password changed" case.
#[test]
fn a_refused_credential_does_not_loop() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("initial login");
    server.expire_session();
    server.refuse_logins();

    let error = runtime
        .block_on(account::read_items_renewing(
            &context,
            &outcome.account,
            None,
        ))
        .expect_err("a refused credential must be an error");
    assert!(
        error.message.contains("rejected the login") || error.message.contains("stale"),
        "the message should name the credential, got: {error}"
    );
    assert_eq!(
        error.kind, "login",
        "a refused credential is something the user can fix by signing in"
    );
    assert_eq!(
        server.sessions().logins,
        2,
        "one renewal attempt, then stop — no loop"
    );
}

/// A write that finds a dead session is re-sent on the renewed one and still
/// verified against the read-back.
#[test]
fn a_write_renews_and_is_still_verified() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("initial login");
    let account = outcome.account;
    let cipher = ItemCipher::new(account.key.expect("key"));

    // A bookmark built from the state, exactly as the write command does.
    let state = runtime
        .block_on(account::read_items(&context, &account))
        .expect("read");
    let template = state
        .of_class(ItemClass::Bookmark)
        .find_map(|item| sync::read_plain(item, Some(&cipher)).ok())
        .expect("a template");
    let draft = sync::BookmarkDraft {
        uuid: version(70001),
        item_version: version(70002),
        name: "renewed".to_string(),
        address: "renewed.example.invalid".to_string(),
        port: 9988,
        nickname: "Renewed".to_string(),
    };
    let built = sync::build_bookmark(&template, &draft).expect("build");
    let blob = cipher.seal(&built);
    let outcome_blob = blob.clone();

    server.expire_session();

    let plan = WritePlan::new(
        &state,
        &account.session,
        ItemClass::Bookmark,
        &draft.uuid,
        &draft.item_version,
        blob,
        "a write during an expiry".to_string(),
    );
    let outcome = runtime
        .block_on(account::execute_write(&context, &account, &state, plan))
        .expect("write");
    assert_eq!(outcome.status, SyncStatus::InSync);
    assert!(
        outcome.renewed.is_some(),
        "the write adopted the session it was actually sent with"
    );
    assert_eq!(server.sessions().logins, 2, "one renewal, during the write");
    // The server kept the bytes, so this is the real check: what it stored is
    // what was sent, and the client read it back through the renewed session.
    assert!(outcome.verified, "the read-back matches the sent blob");
    let stored = server.sessions();
    let (class, _, blob) = stored
        .writes
        .get(&draft.uuid)
        .expect("the server stored the item");
    assert_eq!(*class, ItemClass::Bookmark);
    assert_eq!(blob, &outcome_blob, "byte-for-byte, not a re-encoding");
    // And it is readable by the same cipher that sealed it.
    let plain = cipher.open(blob).expect("the stored blob opens");
    assert_eq!(
        sync::Bookmark::parse(&plain)
            .expect("parse")
            .expect("a bookmark")
            .name,
        "renewed"
    );
}

/// An item written with a `parent`/`sort_order` comes back with them, byte for
/// byte, through the same read path an import would use. This is the claim item 7
/// is about: a restore replays the blob, so the placement travels with it.
#[test]
fn a_written_item_keeps_its_placement_on_the_read_back() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("login");
    let account = outcome.account;
    let cipher = ItemCipher::new(account.key.expect("key"));
    let state = runtime
        .block_on(account::read_items(&context, &account))
        .expect("read");

    // A folder first, then a bookmark that names it. The folder's own payload is
    // field 22; the bookmark's placement is 7 and 8.
    let folder = version(72001);
    let child = version(72002);

    let mut folder_plain = proto::field_string(2, &folder);
    folder_plain.extend(proto::field_string(3, &version(72003)));
    folder_plain.extend(proto::field_varint(6, ItemClass::ItemFolder.id() as u64));
    folder_plain.extend(proto::field_string(7, ""));
    folder_plain.extend(proto::field_string(8, ""));
    let mut folder_payload = proto::field_string(1, "Imported");
    folder_payload.extend(proto::field_varint(2, ItemClass::Bookmark.id() as u64));
    folder_plain.extend(proto::field_bytes(22, &folder_payload));
    let folder_blob = cipher.seal(&folder_plain);

    let mut child_plain = proto::field_string(2, &child);
    child_plain.extend(proto::field_string(3, &version(72004)));
    child_plain.extend(proto::field_string(7, &folder));
    child_plain.extend(proto::field_string(8, ""));
    let mut bookmark = proto::field_string(1, "In a folder");
    bookmark.extend(proto::field_string(2, "placed.example.invalid"));
    bookmark.extend(proto::field_varint(3, 9991));
    child_plain.extend(proto::field_bytes(16, &bookmark));
    let child_blob = cipher.seal(&child_plain);

    for (uuid, class, version_string, blob) in [
        (&folder, ItemClass::ItemFolder, version(72003), folder_blob),
        (&child, ItemClass::Bookmark, version(72004), child_blob),
    ] {
        let plan = WritePlan::new(
            &state,
            &account.session,
            class,
            uuid,
            &version_string,
            blob,
            "place an item".to_string(),
        );
        let outcome = runtime
            .block_on(account::execute_write(&context, &account, &state, plan))
            .expect("write");
        assert!(outcome.verified, "the server kept the blob");
    }

    let after = runtime
        .block_on(account::read_items(&context, &account))
        .expect("read back");
    let folder_item = after.item(&folder).expect("the folder came back");
    let child_item = after.item(&child).expect("the child came back");
    assert!(folder_item.meta.is_root(), "the folder is at the top level");

    // `Item::meta` is filled only for a plaintext blob, so this checks the
    // encrypted case through the key — which is the one an import uses.
    let child_plain = sync::read_plain(child_item, Some(&cipher)).expect("read the child");
    let child_meta = sync::ItemMeta::parse(&child_plain).expect("parse");
    assert_eq!(child_meta.parent, folder);
    assert!(!child_meta.is_root());

    let tree = sync::hierarchy(&after, Some(&cipher));
    assert!(tree.unplaced.is_empty());
    let placed = tree
        .entries
        .iter()
        .find(|node| node.uuid == child)
        .expect("the child is in the tree");
    assert_eq!(placed.parent, folder);
    assert_eq!(placed.depth, 1, "indented under the folder it names");
    assert_eq!(
        tree.entries
            .iter()
            .find(|node| node.uuid == folder)
            .map(|node| node.folder_for),
        Some(Some(ItemClass::Bookmark)),
        "the folder groups bookmarks"
    );
}

/// The captured account is **flat**: class 6 came back present but empty, and
/// every item's `parent` and `sort_order` were zero-length. The hierarchy walk
/// must reproduce that honestly — 25 roots, no folders, nothing unplaced — rather
/// than inventing structure from a missing field.
#[test]
fn the_recorded_account_is_flat_and_the_walk_says_so() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("login");
    let key = outcome.account.key.expect("key");
    let state = runtime
        .block_on(account::read_items(&context, &outcome.account))
        .expect("read");

    let tree = sync::hierarchy(&state, Some(&ItemCipher::new(key)));
    assert!(
        tree.unplaced.is_empty(),
        "everything is readable: {:?}",
        tree.unplaced
    );
    assert_eq!(tree.entries.len(), 25);
    assert_eq!(
        tree.entries
            .iter()
            .filter(|node| node.folder_for.is_some())
            .count(),
        0,
        "no class-6 row in the capture, so no folder in the tree"
    );
    assert_eq!(
        tree.entries.iter().filter(|node| node.depth == 0).count(),
        25,
        "every item is at the top level"
    );
    // And the placement on the decoded items agrees: the empty strings came off
    // the wire, not out of a default that happened to match.
    for item in &state.items {
        assert!(item.meta.is_root(), "{} is not placed", item.uuid);
    }
}

/// A renewal is a one-off: the next read on the new session costs no second
/// login, which is what "transparent" has to mean in practice.
#[test]
fn a_renewed_session_is_reused_instead_of_renewing_again() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("initial login");
    server.expire_session();

    let (first, renewed) = runtime
        .block_on(account::read_items_renewing(
            &context,
            &outcome.account,
            None,
        ))
        .expect("recover");
    let renewed = renewed.expect("renewed");
    assert_eq!(server.sessions().logins, 2);

    // A cursor read on the renewed account: alive, so no login, and the delta
    // is a no-op because nothing changed.
    let (second, again) = runtime
        .block_on(account::read_items_renewing(
            &context,
            &renewed,
            Some(&first),
        ))
        .expect("read on the live session");
    assert!(again.is_none(), "no second renewal");
    assert_eq!(server.sessions().logins, 2, "exactly the one renewal");
    assert_eq!(second.items.len(), 25, "a cursor read still has the items");
}

/// The write path's cursor check is what usually notices an expiry; when it does,
/// the payload is rebuilt with the new session and the write still lands.
#[test]
fn a_write_whose_cursor_check_renews_still_lands() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("initial login");
    let account = outcome.account;
    let cipher = ItemCipher::new(account.key.expect("key"));
    let state = runtime
        .block_on(account::read_items(&context, &account))
        .expect("read");

    let template = state
        .of_class(ItemClass::Bookmark)
        .find_map(|item| sync::read_plain(item, Some(&cipher)).ok())
        .expect("a template");
    let draft = sync::BookmarkDraft {
        uuid: version(71001),
        item_version: version(71002),
        name: "cursor-check".to_string(),
        address: "cursor.example.invalid".to_string(),
        port: 9989,
        nickname: "Cursor".to_string(),
    };
    let blob = cipher.seal(&sync::build_bookmark(&template, &draft).expect("build"));

    // Expired *before* the write starts, so `ensure_cursors` is what notices.
    server.expire_session();
    let plan = WritePlan::new(
        &state,
        &account.session,
        ItemClass::Bookmark,
        &draft.uuid,
        &draft.item_version,
        blob.clone(),
        "a write after an expiry".to_string(),
    );
    let outcome = runtime
        .block_on(account::execute_write(&context, &account, &state, plan))
        .expect("write");
    assert_eq!(outcome.status, SyncStatus::InSync);
    assert!(outcome.verified, "stored bytes match what was sent");
    assert_eq!(
        server.sessions().logins,
        2,
        "one renewal, from the cursor check"
    );
    assert_eq!(
        server
            .sessions()
            .writes
            .get(&draft.uuid)
            .map(|w| w.2.clone()),
        Some(blob),
        "the server kept the very blob the plan carried"
    );
}

/// A refused write is reported as a refused write, not as a success.
///
/// This is the signal the bookmark reorder used to throw away: `execute_write`
/// returns `Ok` with `verified == false` when the server says no, so a caller
/// that only checks for `Err` reports "moved" for a move that never landed.
#[test]
fn a_refused_write_comes_back_unverified_and_unaccepted() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let context = server.context();
    let runtime = runtime();

    let outcome = runtime
        .block_on(account::login(&context, &login_request()))
        .expect("login");
    let account = outcome.account;
    let cipher = ItemCipher::new(account.key.expect("key"));
    let state = runtime
        .block_on(account::read_items(&context, &account))
        .expect("read");
    let template = state
        .of_class(ItemClass::Bookmark)
        .find_map(|item| sync::read_plain(item, Some(&cipher)).ok())
        .expect("a template");
    let draft = sync::BookmarkDraft {
        uuid: version(72001),
        item_version: version(72002),
        name: "refused".to_string(),
        address: "refused.example.invalid".to_string(),
        port: 9987,
        nickname: "Refused".to_string(),
    };
    let blob = cipher.seal(&sync::build_bookmark(&template, &draft).expect("build"));

    server.refuse_writes();

    let plan = WritePlan::new(
        &state,
        &account.session,
        ItemClass::Bookmark,
        &draft.uuid,
        &draft.item_version,
        blob,
        "a write the server refuses".to_string(),
    );
    let outcome = runtime
        .block_on(account::execute_write(&context, &account, &state, plan))
        .expect("a refusal is a reply, not a transport error");

    assert!(!outcome.status.accepted(), "the server said no");
    assert_eq!(outcome.status, SyncStatus::Collision);
    assert!(!outcome.verified, "nothing was stored to verify");
    assert_eq!(outcome.stored_bytes, 0);
    assert!(
        !server.sessions().writes.contains_key(&draft.uuid),
        "a refused write stores nothing"
    );
    // And the backup still exists: a failed write must not cost the state it
    // was built from.
    assert!(outcome.backup_path.exists(), "the pre-write backup is kept");
}

/// The command surface end to end: `exec("sync_bookmark_move", …)` → dispatch →
/// handler loop → write → read-back, against a recorded server.
///
/// Every other network test calls the `account::*` free functions directly, which
/// skips the handler that decides what a shell is told. This one drives the same
/// path a shell does, and pins both outcomes: a refused write comes back as an
/// error (not a cheerful "moved"), and an accepted one reports the links it
/// rewrote.
#[test]
fn a_move_through_the_command_surface_reports_what_the_server_did() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);

    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(temp_dir()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session on the recorded server");

    // Log in through the command surface, so the engine holds the account and
    // the item state a move needs.
    let error = session.exec(
        "account_login",
        &json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
    );
    assert_eq!(error, "", "login accepted: {error}");
    let account = settled_account(&session, Duration::from_secs(30));
    assert!(account["loggedIn"].as_bool().unwrap_or(false), "{account}");
    assert_eq!(account["itemCount"], 25, "the login read the items");

    // Two of the fixture's bookmarks, as the snapshot reports them. They are all
    // at the top level with an empty link, so moving the second after the first
    // is a real reorder, not a no-op.
    let bookmarks: Vec<serde_json::Value> = account["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|item| item["class"] == json!("BOOKMARK"))
        .cloned()
        .collect();
    assert_eq!(bookmarks.len(), 8, "the capture has eight bookmarks");
    let moving = bookmarks[1]["uuid"].as_str().expect("uuid").to_string();
    let target = bookmarks[0]["uuid"].as_str().expect("uuid").to_string();

    // Refused first: the handler must surface the server's answer, not swallow it.
    server.refuse_writes();
    assert_eq!(
        session.exec(
            "sync_bookmark_move",
            &json!({ "uuid": moving, "after": target }).to_string(),
        ),
        "",
        "the command is accepted; it runs later"
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(
        account["lastErrorKind"].as_str(),
        Some("write"),
        "a refusal is a write failure, not a generic one"
    );
    let reported = account["lastError"].as_str().unwrap_or_default();
    assert!(
        reported.contains("refused the write"),
        "a refused move must be reported, not swallowed: {account}"
    );
    // A refused write must not clear the pane.
    assert_eq!(account["itemCount"], 25);

    // Then accepted: the same command now reports the link it rewrote, and the
    // server holds the new order. Clear only the refusal — the session, the
    // login count and the credential stay, or the client's next read would be
    // answered by a server that forgot it had logged anyone in.
    server.allow_writes_again();
    assert_eq!(
        session.exec(
            "sync_bookmark_move",
            &json!({ "uuid": moving, "after": target }).to_string(),
        ),
        "",
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(
        account["lastError"].as_str(),
        Some(""),
        "an accepted move reports no error: {account}"
    );
    assert!(
        server
            .sessions()
            .writes
            .get(&moving)
            .is_some_and(|(_, _, blob)| {
                // The stored blob is sealed, so the placement is only visible
                // after opening it with the account key. What it must say is that
                // the moved bookmark now follows the target.
                ItemCipher::new(ACCOUNT_KEY)
                    .open(blob)
                    .ok()
                    .and_then(|plain| sync::ItemMeta::parse(&plain).ok())
                    .is_some_and(|meta| meta.sort_order == target)
            }),
        "the server holds the new link for the moved bookmark"
    );
}

/// A user switching away from the official client has no `IDENTITY` item on
/// their account yet — which used to mean `identity_import` refused and told
/// them to go back to that client. The item is five known fields, so it is
/// created here instead, and the test drives the real command surface to prove
/// it: login, import, read back, and the server holding a sealed identity item.
#[test]
fn identity_import_creates_the_first_identity_item() {
    // The public test key from `tsproto-types`, so no real user secret is here.
    const TEST_PRIV_KEY: &str = "MG0DAgeAAgEgAiAIXJBlj1hQbaH0Eq0DuLlCmH8bl+veTAO2+k9EQjEYSgIgNnImcmKo7ls5mExb6skfK2Tw+u54aeDr0OP1ITsC/50CIA8M5nmDBnmDM/gZ//4AAAAAAAAAAAAAAAAAAAAZRzOI";
    let identity = litespeak_core::Identity::new_from_str(TEST_PRIV_KEY).expect("fixture key");
    let identity_string = litespeak_core::identity_to_ts_str(&identity);

    let server = ReplayServer::start(Fixture::without(ItemClass::Identity));
    wait_ready(server.port);
    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(temp_dir()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session on the recorded server");

    assert_eq!(
        session.exec(
            "account_login",
            &json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(account["itemCount"], 23, "the fixture has no identity rows");
    assert_eq!(account["identities"], json!([]), "nothing to pick from yet");

    assert_eq!(
        session.exec(
            "identity_import",
            &json!({ "identity": identity_string }).to_string()
        ),
        "",
        "the command is accepted"
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(
        account["lastError"].as_str(),
        Some(""),
        "creating the first identity must succeed: {account}"
    );
    assert_eq!(account["lastErrorKind"].as_str(), Some(""));
    assert_eq!(account["itemCount"], 24, "one identity item was created");

    let identities = account["identities"].as_array().expect("identities");
    assert_eq!(identities.len(), 1, "the new item is an identity");
    assert_eq!(
        identities[0]["value"].as_str(),
        Some(identity_string.as_str()),
        "and carries the string it was given"
    );

    // The server holds it, sealed, and it opens back to the same identity —
    // which is the claim a shell relies on when it restores a fresh install.
    let stored = server.sessions();
    let (_, _, blob) = stored
        .writes
        .values()
        .find(|(class, _, _)| *class == ItemClass::Identity)
        .expect("the server stored an identity item");
    let plain = ItemCipher::new(ACCOUNT_KEY)
        .open(blob)
        .expect("the stored identity opens with the account key");
    let identity = sync::AccountIdentity::parse(&plain)
        .expect("parse")
        .expect("an identity");
    assert_eq!(identity.identity, identity_string);
    assert!(identity.is_default, "the only identity is the default one");
}

/// Several identities and no bookmark naming one: the library must not guess,
/// but it must not send the user to another client either. It reports the
/// candidates so a shell can ask.
#[test]
fn an_ambiguous_pick_reports_the_candidates() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(temp_dir()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session");

    assert_eq!(
        session.exec(
            "account_login",
            &json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(account["itemCount"], 25);

    assert_eq!(
        session.exec(
            "identity_pick",
            &json!({ "address": "ts.example.invalid" }).to_string()
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));

    assert_eq!(
        account["pickedIdentity"],
        json!({}),
        "the documented shape for 'nothing chosen' must not change"
    );
    let candidates = account["identityCandidates"]
        .as_array()
        .expect("identityCandidates");
    assert_eq!(candidates.len(), 2, "both identities are offered");
    for candidate in candidates {
        assert!(candidate["uuid"].is_string());
        assert!(candidate["value"].is_string());
    }
    assert_eq!(
        account["lastErrorKind"].as_str(),
        Some("identity_ambiguous"),
        "the kind tells a shell to show the picker, not to show English"
    );
    let reported = account["lastError"].as_str().unwrap_or_default();
    assert!(
        reported.contains("identities"),
        "the message must name the choice, not another client: {reported}"
    );
    assert!(
        !reported.contains("official client"),
        "a shell cannot act on 'use the official client': {reported}"
    );
}

/// Creating the first bookmark used to need a template — an existing bookmark to
/// copy the fields this code does not model. A fresh account has none, so the
/// first bookmark could only be made in another client. It is now built sparse,
/// which is what the official client's own "new bookmark" dialog produces.
#[test]
fn the_first_bookmark_is_created_without_a_template() {
    let server = ReplayServer::start(Fixture::without(ItemClass::Bookmark));
    wait_ready(server.port);
    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(temp_dir()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session");

    assert_eq!(
        session.exec(
            "account_login",
            &json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(account["itemCount"], 17, "the fixture has no bookmark rows");

    assert_eq!(
        session.exec(
            "sync_bookmark_create",
            &json!({
                "name": "First",
                "address": "first.example.invalid",
                "port": 9988,
                "nickname": "FirstNick",
            })
            .to_string(),
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(
        account["lastError"].as_str(),
        Some(""),
        "creating the first bookmark must succeed: {account}"
    );
    assert_eq!(account["itemCount"], 18, "one bookmark was created");

    let created = account["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["bookmark"]["name"] == json!("First"))
        .expect("the new bookmark is in the report");
    assert_eq!(created["class"], json!("BOOKMARK"));
    assert_eq!(
        created["bookmark"]["address"],
        json!("first.example.invalid")
    );
    assert_eq!(created["bookmark"]["port"], json!(9988));
    assert_eq!(created["bookmark"]["sendMytsid"], json!(true));

    // And the server holds it, sealed, reading back through the same parser a
    // shell uses.
    let stored = server.sessions();
    let (_, _, blob) = stored
        .writes
        .values()
        .find(|(class, _, _)| *class == ItemClass::Bookmark)
        .expect("the server stored a bookmark");
    let plain = ItemCipher::new(ACCOUNT_KEY)
        .open(blob)
        .expect("the stored bookmark opens with the account key");
    let bookmark = sync::Bookmark::parse(&plain)
        .expect("parse")
        .expect("a bookmark");
    assert_eq!(bookmark.name, "First");
    assert_eq!(bookmark.address, "first.example.invalid");
    assert_eq!(bookmark.port, 9988);
    assert_eq!(bookmark.nickname, "FirstNick");
}

/// A read before any sign-in must say *which* action is missing, not just fail.
/// That is the difference between a shell showing an English sentence it cannot
/// translate and one showing "sign in".
#[test]
fn a_read_without_a_login_carries_the_kind() {
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(temp_dir()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session");

    assert_eq!(session.exec("sync_list", "{}"), "");
    let account = settled_account(&session, Duration::from_secs(30));
    assert_eq!(
        account["lastErrorKind"].as_str(),
        Some("not_logged_in"),
        "{account}"
    );
    assert!(
        account["lastError"]
            .as_str()
            .unwrap_or_default()
            .contains("account_login"),
        "the message names the command that fixes it"
    );
}

/// A logged-in session, a copy of the account as the shell's "local" file with
/// one bookmark renamed, and (optionally) a baseline recording the untouched
/// agreement.
struct MergeSetup {
    server: ReplayServer,
    session: Session,
    target: String,
    local_path: PathBuf,
    baseline_path: Option<PathBuf>,
}

fn setup_merge(tag: &str, with_baseline: bool) -> MergeSetup {
    let dir = unique_dir(tag);
    let server = ReplayServer::start(Fixture::build());
    wait_ready(server.port);
    let session = Session::account_only_with_http(
        AccountConfig {
            legacy_db: None,
            backup_dir: Some(dir.clone()),
            credential_file: None,
            baseline_file: None,
            remember_login: false,
        },
        Http::with_endpoints(Endpoints {
            rest: format!("http://127.0.0.1:{}/api", server.port),
            cloud: format!("http://127.0.0.1:{}", server.port),
            allow_plain_http: true,
        }),
    )
    .expect("an account session");
    assert_eq!(
        session.exec(
            "account_login",
            &json!({ "email": EMAIL, "password": PASSWORD }).to_string(),
        ),
        ""
    );
    let account = settled_account(&session, Duration::from_secs(30));
    let account_uuid = account["uuid"].as_str().expect("uuid").to_string();

    // The shell's local copy starts as a backup of the account.
    assert_eq!(session.exec("sync_backup", "{}"), "");
    let account = settled_account(&session, Duration::from_secs(30));
    let backup_path = account["lastBackup"].as_str().expect("backup").to_string();
    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&backup_path).expect("read")).expect("json");
    let backup = sync::Backup::from_json(&original).expect("backup");
    let cipher = ItemCipher::new(ACCOUNT_KEY);

    let baseline_path = if with_baseline {
        let local = merge::LocalItem::from_backup(&backup, Some(&cipher)).expect("local");
        let baseline = merge::Baseline::of(
            &state_of_backup(&backup),
            &account_uuid,
            &local,
            Some(&cipher),
            "2026-01-01T00:00:00Z",
        );
        let path = dir.join("baseline.json");
        merge::save(&path, &baseline).expect("save baseline");
        Some(path)
    } else {
        None
    };

    // The local side differs in exactly one bookmark.
    let target = backup
        .items
        .iter()
        .find(|item| item.class == ItemClass::Bookmark)
        .map(|item| item.uuid.clone())
        .expect("a bookmark");
    let mut local = original.clone();
    let entry = local["items"]
        .as_array_mut()
        .expect("items")
        .iter_mut()
        .find(|entry| entry["uuid"] == json!(target))
        .expect("the bookmark's entry");
    let blob = entry["blobB64"].as_str().expect("blob");
    let plain = cipher
        .open(&B64.decode(blob).expect("base64"))
        .expect("open the bookmark");
    let previous_version = entry["itemVersion"].as_str().expect("version").to_string();
    let item_version = version(88001);
    let draft = sync::BookmarkDraft {
        uuid: target.clone(),
        item_version: item_version.clone(),
        name: "merged-local".to_string(),
        address: "replay.example.invalid".to_string(),
        port: 9987,
        nickname: "ReplayNick".to_string(),
    };
    let edited =
        sync::build_bookmark_edit(&plain, &item_version, &previous_version, &draft).expect("edit");
    entry["blobB64"] = json!(B64.encode(cipher.seal(&edited)));
    entry["itemVersion"] = json!(item_version);
    let local_path = dir.join("local.json");
    std::fs::write(
        &local_path,
        serde_json::to_string_pretty(&local).expect("json"),
    )
    .expect("write");

    MergeSetup {
        server,
        session,
        target,
        local_path,
        baseline_path,
    }
}

/// `sync_merge` reported "to push"; `sync_merge_apply` is the missing "apply".
/// One single-sided local edit must reach the server, and the merged copy the
/// shell needs must be written even when the only action was a push.
#[test]
fn merge_apply_pushes_a_single_sided_edit() {
    let setup = setup_merge("push", true);
    let args = json!({
        "local": setup.local_path,
        "baseline": setup.baseline_path,
    });
    assert_eq!(
        setup.session.exec("sync_merge_apply", &args.to_string()),
        ""
    );
    let account = settled_account(&setup.session, Duration::from_secs(30));
    assert_eq!(account["lastError"], "", "{account}");
    assert_eq!(account["lastErrorKind"], "");
    assert_eq!(account["itemCount"], 25, "a push does not add or remove");

    let stored = setup.server.sessions();
    let (_, _, blob) = stored
        .writes
        .get(&setup.target)
        .expect("the server stored the pushed item");
    let plain = ItemCipher::new(ACCOUNT_KEY)
        .open(blob)
        .expect("the pushed blob opens");
    assert_eq!(
        sync::Bookmark::parse(&plain)
            .expect("parse")
            .expect("a bookmark")
            .name,
        "merged-local",
        "the pushed name is what the server now holds"
    );

    // The merged copy is the shell's new local state, and it must exist even
    // though nothing had to be pulled.
    let dir = setup.local_path.parent().expect("dir").to_path_buf();
    let merged: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with("backup-")
                && entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with("-merged.json")
        })
        .collect();
    assert_eq!(merged.len(), 1, "one merged copy was written: {merged:?}");
}

/// A conflict is refused **before** anything is written: half-applying a
/// comparison is how one side's edit disappears. Without a baseline every field
/// the two sides disagree on reads as a conflict, which is what makes the local
/// rename collide with the server's value.
#[test]
fn merge_apply_refuses_a_conflict_and_writes_nothing() {
    let setup = setup_merge("conflict", false);
    let args = json!({ "local": setup.local_path });
    assert_eq!(
        setup.session.exec("sync_merge_apply", &args.to_string()),
        ""
    );
    let account = settled_account(&setup.session, Duration::from_secs(30));
    assert_eq!(
        account["lastErrorKind"].as_str(),
        Some("write"),
        "a refused apply is a write failure: {account}"
    );
    let reported = account["lastError"].as_str().unwrap_or_default();
    assert!(
        reported.contains("conflict"),
        "the message must say why nothing was written: {reported}"
    );
    assert!(
        !setup.server.sessions().writes.contains_key(&setup.target),
        "a conflict writes nothing, not even the parts that agreed"
    );
}

/// The plain-http guard: outside a test, a credential is only ever sent over
/// https. Without this, `with_endpoints` would be a way to leak a session token.
#[test]
fn a_credential_is_never_sent_over_plain_http_by_default() {
    let endpoints = Endpoints {
        rest: "http://127.0.0.1:9/api".to_string(),
        cloud: "http://127.0.0.1:9".to_string(),
        allow_plain_http: false,
    };
    let http = Http::with_endpoints(endpoints);
    let runtime = runtime();
    let error = runtime
        .block_on(http.rest_post("/client/login", &json!({}), None))
        .expect_err("plain http must be refused");
    assert!(error.contains("only https is acceptable"), "{error}");

    // And the recorded server only works because it says so explicitly.
    let endpoints = Endpoints {
        rest: "http://127.0.0.1:9/api".to_string(),
        cloud: "http://127.0.0.1:9".to_string(),
        allow_plain_http: true,
    };
    assert!(Http::with_endpoints(endpoints).endpoints().allow_plain_http);
}

/// The framing itself: `<varint len><method><payload>`, and the reply is
/// protobuf even though the edge labels it `application/json`.
#[test]
fn the_cloud_envelope_is_what_the_server_parses() {
    let payload = Sync::delta_payload("SESSION", None);
    let mut envelope = proto::varint("requestServerItems".len() as u64);
    envelope.extend_from_slice(b"requestServerItems");
    envelope.extend_from_slice(&payload);
    assert_eq!(cloud_method(&envelope), "requestServerItems");
    assert_eq!(
        proto::field_string(1, "SESSION"),
        payload[.."SESSION".len() + 2],
        "the session id is the payload's first field"
    );
}

/// A write is accepted by the recorded server and reported as accepted.
#[test]
fn a_write_is_answered_with_in_sync() {
    let mut reply = proto::field_varint(1, 300);
    reply.extend(proto::field_string(3, GLOBAL_VERSION));
    let status = Sync::decode_write_reply(&reply);
    assert_eq!(status, SyncStatus::InSync);
    assert!(status.accepted());
}

/// Keep the fixture's own expectations honest: if someone changes the mix, the
/// count assertions above must change with it.
#[test]
fn the_fixture_matches_the_recorded_shape() {
    let fixture = Fixture::build();
    assert_eq!(fixture.item_count(), 25);
    assert_eq!(fixture.classes.len(), COUNTS.len());
    let mut seen: Vec<ItemClass> = fixture.classes.iter().map(|(c, _, _)| *c).collect();
    seen.sort();
    let mut expected: Vec<ItemClass> = COUNTS.iter().map(|(c, _, _)| *c).collect();
    expected.sort();
    assert_eq!(seen, expected, "one cursor per class that holds items");
}
