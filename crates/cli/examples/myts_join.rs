//! Probe: sign in, join a server, report what the server did with the myTeamSpeak
//! ID. Requires `MYTS_EMAIL` and `MYTS_PW`; writes nothing to disk.
//!
//! ```text
//! MYTS_EMAIL=… MYTS_PW=… cargo run -p tsbridge-cli --example myts_join -- 127.0.0.1 20
//! ```
//!
//! This is a diagnostic tool, not a contract test: it prints the library's own
//! log and the negotiated handshake details, which is how a rejected proof gets
//! traced back to the value it was signed over.
use std::io::Write as _;
use std::time::{Duration, Instant};

use tsbridge_core::account::AccountConfig;
use tsbridge_core::{Session, SessionConfig};

struct StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            let _ = writeln!(std::io::stderr(), "{} {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}
static LOGGER: StderrLogger = StderrLogger;

fn main() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);

    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1".to_string());
    let seconds: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(20);
    let email = std::env::var("MYTS_EMAIL").unwrap_or_default();
    let password = std::env::var("MYTS_PW").unwrap_or_default();
    if email.is_empty() || password.is_empty() {
        eprintln!("MYTS_EMAIL and MYTS_PW are required");
        std::process::exit(2);
    }

    let session = match Session::connect(SessionConfig {
        address,
        nickname: "myts-probe".to_string(),
        ..SessionConfig::default()
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    session.set_account_config(AccountConfig {
        // A probe must not leave a credential behind.
        credential_file: None,
        remember_login: false,
        ..AccountConfig::default()
    });
    let login = serde_json::json!({ "email": email, "password": password }).to_string();
    let rejection = session.exec("account_login", &login);
    if !rejection.is_empty() {
        eprintln!("login rejected: {rejection}");
        std::process::exit(1);
    }

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        session.drain_events();
        std::thread::sleep(Duration::from_millis(200));
    }
}
