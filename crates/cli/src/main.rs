//! Smoke test: prove the core talks to a real server without any FFI in the way.
//!
//! ```text
//! cargo run -p litespeak-cli -- ts.example.com "nickname" ["identity"] [seconds]
//! ```
//!
//! Prints every event and a snapshot whenever the revision changes, then exits.
//! If this works on a machine and the SwiftUI sample does not, the problem is the
//! C layer or the Swift wrapper, not the protocol — which is worth knowing before
//! hunting for an audio bug in the wrong place.
//!
//! It also demonstrates the shape a Rust desktop UI would use if the Windows or
//! Linux frontend ends up being egui or Tauri: link `litespeak-core` directly, no
//! C ABI, no dynamic library.

use std::time::{Duration, Instant};

use litespeak_core::{QueuedEvent, Session, SessionConfig, Value};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(address) = args.next() else {
        eprintln!("usage: litespeak-cli <host[:port]> [nickname] [identity] [seconds]");
        std::process::exit(2);
    };
    let nickname = args.next().unwrap_or_else(|| "litespeak-cli".to_string());
    let identity = args.next().unwrap_or_default();
    let seconds: u64 = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);

    let session = match Session::connect(SessionConfig {
        address: address.clone(),
        nickname,
        identity,
        ..SessionConfig::default()
    }) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("could not start the session: {e}");
            std::process::exit(1);
        }
    };

    println!("connecting to {address} for {seconds}s");

    let start = Instant::now();
    let mut last_rev: Option<u64> = None;
    let mut printed_identity = false;

    while start.elapsed() < Duration::from_secs(seconds) {
        for event in session.drain_events() {
            print_event(&event);
        }

        // The identity appears on the worker thread shortly after `connect`
        // returns. This is the string a shell must persist to keep its UID.
        if !printed_identity {
            if let Some(identity) = session.identity_ts_str() {
                println!("identity: {identity}");
                printed_identity = true;
            }
        }

        // The snapshot is cached by revision, so comparing it first avoids
        // parsing (and printing) the same member list 50 times a second.
        let snapshot = session.snapshot_json();
        let rev = serde_json::from_str::<serde_json::Value>(&snapshot)
            .ok()
            .and_then(|value| value.get("rev").and_then(|rev| rev.as_u64()));
        if rev != last_rev {
            last_rev = rev;
            println!("snapshot: {snapshot}");
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    println!("disconnecting");
    session.disconnect();
}

fn print_event(event: &QueuedEvent) {
    let mut line = format!("[{}]", event.kind);
    for (key, value) in &event.data {
        let text = match value {
            Value::Str(text) => text.clone(),
            Value::Int(number) => number.to_string(),
            Value::Long(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
        };
        line.push_str(&format!(" {key}={text}"));
    }
    println!("{line}");
}
