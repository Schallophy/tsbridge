//! A local web page for trying the account side by hand.
//!
//! ```text
//! cargo run -p tsbridge-account-demo            # http://127.0.0.1:8787
//! cargo run -p tsbridge-account-demo -- --port 9000 --legacy-db "C:\...\settings.db"
//! ```
//!
//! Why a separate crate instead of a `--serve` flag on the CLI: this is not part
//! of the library's surface. It links `tsbridge-core` exactly the way a real shell
//! does, which is the point — the page exercises the same `Session::exec` and the
//! same snapshot a Kotlin or Swift front end would read. If something is wrong
//! here, it is wrong in the library.
//!
//! Three deliberate choices:
//!
//! * **The account side only.** [`Session::account_only`] builds a handle with no
//!   connection, so the page works with no server address. The account has nothing
//!   to do with the connection; requiring one here would have been theatre.
//! * **Read-only commands.** Login, refresh, backup, logout. Creating or deleting
//!   an item is implemented in the library and tested, but wiring a button to it in
//!   a page that anyone can leave open is how a test account loses its bookmarks.
//! * **Loopback only, and origin-checked.** The password travels over
//!   `127.0.0.1`, never leaves the machine, and is not logged. The server refuses
//!   any `Host` that is not a loopback form and any request whose `Origin` is not
//!   this page, so another tab cannot drive the session.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use serde_json::{json, Value};
use tsbridge_core::account::AccountConfig;
use tsbridge_core::Session;

const PAGE: &str = include_str!("page.html");

struct App {
    session: Session,
    port: u16,
}

fn main() {
    let mut port = 8787u16;
    let mut legacy_db: Option<std::path::PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--port needs a number");
                    std::process::exit(2)
                });
            }
            "--legacy-db" => {
                legacy_db = args.next().map(std::path::PathBuf::from).or_else(|| {
                    eprintln!("--legacy-db needs a path");
                    std::process::exit(2)
                });
            }
            "-h" | "--help" => {
                println!(
                    "usage: tsbridge-account-demo [--port N] [--legacy-db <settings.db>]\n\
                     \n  --port       listen on 127.0.0.1:N (default 8787)\n  \
                     --legacy-db  an installed client's settings.db, pre-filled in the form"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let session = match Session::account_only(AccountConfig {
        legacy_db: legacy_db.clone(),
        backup_dir: None,
        // A test page wants the second launch to be silent, so it keeps a
        // credential under the user's app-data directory.
        credential_file: Some(credentials_path()),
        remember_login: true,
        baseline_file: Some(baseline_path()),
    }) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("could not start the account side: {e}");
            std::process::exit(1);
        }
    };

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("could not listen on 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };

    let app = Arc::new(App { session, port });
    println!("myTeamSpeak 账号测试页: http://127.0.0.1:{port}/");
    if let Some(db) = &legacy_db {
        println!("迁移用 settings.db: {}", db.display());
    }
    println!("Ctrl+C 结束。密码只经本机环回接口，不落盘。");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app = Arc::clone(&app);
                // One thread per request. A local page has one user and a handful
                // of requests per second; a pool would be more machinery than
                // this is worth.
                std::thread::spawn(move || {
                    if let Err(e) = handle(app, stream) {
                        log_line(&format!("request failed: {e}"));
                    }
                });
            }
            Err(e) => log_line(&format!("accept failed: {e}")),
        }
    }
}

/// Where the demo keeps the remembered login.
fn credentials_path() -> std::path::PathBuf {
    tsbridge_core::account::credentials::default_credential_file()
}

/// Where the demo keeps what both sides last agreed on, next to the credential.
fn baseline_path() -> std::path::PathBuf {
    tsbridge_core::account::merge::default_baseline_file()
}

fn log_line(line: &str) {
    // ASCII only: a non-UTF-8 console would otherwise mangle Chinese and make the
    // terminal output look like a crash.
    println!("[demo] {line}");
}

fn handle(app: Arc<App>, stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let Some(request_line) = read_line(&mut reader)? else {
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Headers we actually care about. Everything else is ignored, which is
    // correct for a page we wrote ourselves.
    let mut host = String::new();
    let mut origin = String::new();
    let mut content_length = 0usize;
    while let Some(line) = read_line(&mut reader)? {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => host = value.to_string(),
            "origin" => origin = value.to_string(),
            "content-length" => content_length = value.parse().unwrap_or(0),
            _ => {}
        }
    }

    // A body bigger than this is not a login form; refusing it keeps the parse
    // bounded without hashing megabytes from a stray request.
    if content_length > 64 * 1024 {
        return reply(
            stream,
            413,
            "application/json",
            b"{\"error\":\"body too large\"}",
        );
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    // ── the two guards ──
    //
    // Loopback-only binding already keeps other machines out. The Host check
    // stops DNS rebinding (a remote name resolving to 127.0.0.1 arrives with the
    // attacker's Host), and the Origin check stops any other page on this machine
    // from driving this session with a form post.
    if !is_loopback_host(&host) {
        return reply(
            stream,
            403,
            "application/json",
            b"{\"error\":\"host not allowed\"}",
        );
    }
    if !origin.is_empty() && !origin_matches(&origin, app.port) {
        return reply(
            stream,
            403,
            "application/json",
            b"{\"error\":\"origin not allowed\"}",
        );
    }

    let body_json: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };

    match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            reply(stream, 200, "text/html; charset=utf-8", PAGE.as_bytes())
        }
        ("GET", "/api/state") => {
            let state = build_state(&app);
            let text = serde_json::to_vec(&state).unwrap_or_else(|_| b"{}".to_vec());
            reply(stream, 200, "application/json", &text)
        }
        ("POST", "/api/login") => {
            // The database path is a *configuration*, not a login argument: apply
            // it first so `fromTs3Client` has something to read. Doing it here
            // rather than in a separate call keeps the form to one button.
            let path = legacy_db_from(&body_json);
            app.session.set_account_config(AccountConfig {
                legacy_db: path,
                backup_dir: None,
                credential_file: Some(credentials_path()),
                remember_login: true,
                baseline_file: Some(baseline_path()),
            });
            command(&app, stream, login_args(&body_json), "account_login")
        }
        ("POST", "/api/sync-list") => {
            // The demo always asks for the passwords: it is a local page whose
            // whole purpose is to show what the account holds, and the form has a
            // checkbox for it. The library's default stays "presence only".
            let reveal = body_json
                .get("revealSecrets")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            command(
                &app,
                stream,
                json!({ "revealSecrets": reveal }).to_string(),
                "sync_list",
            )
        }
        ("POST", "/api/sync-backup") => command(&app, stream, String::new(), "sync_backup"),
        // Read-only: asks the account which identity this server knows. The
        // result lands in the snapshot's `account.pickedIdentity`.
        ("POST", "/api/identity-pick") => {
            let address = body_json
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if address.trim().is_empty() {
                return reply(
                    stream,
                    400,
                    "application/json",
                    b"{\"error\":\"address is required\"}",
                );
            }
            command(
                &app,
                stream,
                json!({ "address": address }).to_string(),
                "identity_pick",
            )
        }
        // The compare is read-only; "record" writes only the local baseline.
        ("POST", "/api/sync-merge") => {
            let local = body_json
                .get("local")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if local.is_empty() {
                return reply(
                    stream,
                    400,
                    "application/json",
                    b"{\"error\":\"local backup path is required\"}",
                );
            }
            let record = body_json
                .get("record")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            command(
                &app,
                stream,
                json!({ "local": local, "record": record }).to_string(),
                "sync_merge",
            )
        }
        ("POST", "/api/logout") => command(&app, stream, String::new(), "account_logout"),
        _ => reply(
            stream,
            404,
            "application/json",
            b"{\"error\":\"not found\"}",
        ),
    }
}

/// Runs one command and answers with the rejection, or `ok`.
///
/// The rejection is the only thing `exec` returns: a command that starts reports
/// its result later through the snapshot and an event, and the page polls for it.
fn command(app: &App, stream: TcpStream, args: String, name: &str) -> std::io::Result<()> {
    let error = app.session.exec(name, &args);
    let body = if error.is_empty() {
        json!({ "accepted": name })
    } else {
        json!({ "error": error })
    };
    let text = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    reply(stream, 200, "application/json", &text)
}

/// The migrated-login database path from the form, if the user typed one.
fn legacy_db_from(body: &Value) -> Option<std::path::PathBuf> {
    body.get("legacyDb")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

/// Builds the `account_login` arguments from the form.
///
/// Empty fields are omitted rather than sent as `""`: the command parser treats a
/// blank string as "not given", and an empty password would otherwise be hashed
/// into a credential that can only fail.
fn login_args(body: &Value) -> String {
    let text = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let mut args = serde_json::Map::new();
    let from_client = body
        .get("fromTs3Client")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    for key in ["email", "password", "otp", "recoveryKey"] {
        let value = text(key);
        if !value.is_empty() {
            args.insert(key.to_string(), Value::String(value));
        }
    }
    if from_client {
        args.insert("fromTs3Client".to_string(), Value::Bool(true));
    }
    Value::Object(args).to_string()
}

/// The snapshot, plus the events drained since the last poll.
///
/// Draining here rather than in the page is what keeps the queue from growing: the
/// library's queue is only emptied by a reader, and a page that ignored it would
/// accumulate one `account_status` per command forever.
fn build_state(app: &App) -> Value {
    let mut snapshot: Value =
        serde_json::from_str(&app.session.snapshot_json()).unwrap_or(Value::Null);
    let events: Vec<Value> = app
        .session
        .drain_events()
        .into_iter()
        .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
        .collect();
    if let Value::Object(map) = &mut snapshot {
        map.insert("events".to_string(), Value::Array(events));
    }
    snapshot
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    // Three shapes to fold to a bare name: `name:port`, `[v6]:port`, and a bare
    // `v6` literal (which has colons but no port). Treating the last colon of
    // `::1` as a port separator is the bug this branch exists to avoid.
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if host.matches(':').count() > 1 {
        host
    } else {
        match host.rsplit_once(':') {
            Some((left, right))
                if !left.is_empty() && right.chars().all(|c| c.is_ascii_digit()) =>
            {
                left
            }
            _ => host,
        }
    };
    matches!(name, "127.0.0.1" | "localhost" | "::1")
}

fn origin_matches(origin: &str, port: u16) -> bool {
    let origin = origin.trim().trim_end_matches('/');
    let allowed = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    allowed.iter().any(|candidate| candidate == origin)
}

fn read_line(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

fn reply(
    mut stream: TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    // No caching: a page that re-renders a snapshot must never be served from a
    // browser cache after the account changed.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Host guard is what stops DNS rebinding: a remote name that resolves to
    /// 127.0.0.1 arrives here with the attacker's name in `Host`, and the only
    /// thing that distinguishes it from a real local load is this check.
    #[test]
    fn only_loopback_hosts_are_accepted() {
        for good in [
            "127.0.0.1",
            "127.0.0.1:8787",
            "localhost",
            "localhost:8787",
            "[::1]",
            "[::1]:8787",
            "::1",
        ] {
            assert!(is_loopback_host(good), "{good} should be allowed");
        }
        for bad in [
            "evil.example",
            "evil.example:8787",
            "0.0.0.0",
            "192.168.1.5",
            "",
            "localhost.evil.com",
            "[::2]",
        ] {
            assert!(!is_loopback_host(bad), "{bad} must be refused");
        }
    }

    /// An `Origin` that is not this page means another tab on this machine tried
    /// to drive the session. An absent `Origin` is allowed: that is a plain
    /// navigation or a `curl` from the user, not a cross-site form post.
    #[test]
    fn foreign_origins_are_refused() {
        assert!(origin_matches("http://127.0.0.1:8787", 8787));
        assert!(origin_matches("http://localhost:8787/", 8787));
        assert!(origin_matches("http://[::1]:8787", 8787));
        assert!(!origin_matches("http://evil.example", 8787));
        assert!(!origin_matches("http://127.0.0.1:9000", 8787));
        assert!(
            !origin_matches("https://127.0.0.1:8787", 8787),
            "https is a different origin"
        );
    }

    /// A blank form field must be omitted, not sent as `""`: an empty password
    /// would be hashed into a credential that can only fail.
    #[test]
    fn blank_form_fields_are_omitted() {
        let args: Value = serde_json::from_str(&login_args(&json!({
            "email": " a@b.c ",
            "password": "",
            "otp": "   ",
            "recoveryKey": "ABCD-EFGH",
            "fromTs3Client": false
        })))
        .expect("login args must be JSON");

        assert_eq!(args["email"], "a@b.c", "trimmed");
        assert!(
            args.get("password").is_none(),
            "a blank password is not an argument"
        );
        assert!(
            args.get("otp").is_none(),
            "blank whitespace is not an argument"
        );
        assert_eq!(args["recoveryKey"], "ABCD-EFGH");
        assert!(args.get("fromTs3Client").is_none(), "false stays absent");
    }

    #[test]
    fn the_migration_flag_survives_the_form() {
        let args: Value = serde_json::from_str(&login_args(&json!({
            "fromTs3Client": true,
            "email": "",
            "password": ""
        })))
        .expect("login args must be JSON");
        assert_eq!(args["fromTs3Client"], true);
        assert!(args.get("email").is_none());
    }

    /// The page is compiled in, so a missing or renamed file is a build error
    /// rather than a 404 the first time someone opens the tool.
    #[test]
    fn the_page_is_embedded_and_names_its_endpoints() {
        assert!(PAGE.contains("<!doctype html>"));
        for endpoint in [
            "/api/state",
            "/api/login",
            "/api/sync-list",
            "/api/sync-backup",
            "/api/sync-merge",
            "/api/logout",
        ] {
            assert!(PAGE.contains(endpoint), "the page never calls {endpoint}");
        }
        assert!(
            PAGE.contains("name=\"viewport\""),
            "the page must work on a phone"
        );
        // The tree is a snapshot field, so the page has to read it: a UI that
        // only draws the flat list is the "folders are invisible" bug.
        assert!(
            PAGE.contains("account.hierarchy"),
            "the page must render the hierarchy"
        );
    }
}
