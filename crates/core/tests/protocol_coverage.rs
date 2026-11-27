//! Every protocol message the vendored tables define is accounted for.
//!
//! This is the check that kept getting skipped. Review rounds each found a
//! different missed class — declarations with `attributes=[]`, flags inside
//! `options.append(`, replies with no handler — because every audit started from
//! a different, partial source. This one starts from the generated tables, which
//! are what the code is built against, and requires every message to be either
//! used or listed here with a reason.
//!
//! A message that is in neither place fails. So does a name in the "explained"
//! lists that the tables no longer define, which is how a re-vendor that renames
//! something shows up.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The generated tables for this build.
///
/// Cargo keeps one directory per dependency hash, and cross-compilation adds
/// more under `target/<triple>/debug`. Only the host `target/debug` tree is
/// scanned and the newest file wins: a stale directory from an older graph or
/// another target would otherwise be read, and the counts would look like a
/// coverage gap when they are just the wrong file.
fn out_dir() -> PathBuf {
    let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/build");
    let entries = std::fs::read_dir(&build).unwrap_or_else(|e| {
        panic!("target/debug/build is missing ({e}); build the workspace first")
    });
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let out = entry.path().join("out");
        let table = out.join("s2c_messages.rs");
        if !table.is_file() || !out.join("c2s_messages.rs").is_file() {
            continue;
        }
        if let Ok(modified) = std::fs::metadata(&table).and_then(|m| m.modified()) {
            found.push((modified, out));
        }
    }
    found.sort_by_key(|(when, _)| *when);
    found
        .pop()
        .map(|(_, out)| out)
        .expect("no ts-bookkeeping output under target/debug/build")
}

/// The `InMessage` variants: the replies the parser can produce.
///
/// Variants are `\tName(InName),` — one tab, then a name, then `(`. The enum is
/// the right source rather than the struct list, because the generated file also
/// declares helper types (`MessageIterator`, the `Offline`/`Text` aliases) that
/// are not messages.
fn s2c_variants(file: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(file).expect("read generated table");
    let Some(after) = text.split("pub enum InMessage {").nth(1) else {
        panic!("InMessage enum is missing");
    };
    let mut names = BTreeSet::new();
    for line in after.lines() {
        if line == "}" {
            break;
        }
        if !line.starts_with('\t') || line.starts_with("\t\t") {
            continue;
        }
        let rest = &line[1..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if name.is_empty() || !rest[name.len()..].starts_with('(') {
            continue;
        }
        names.insert(name);
    }
    names
}

/// The c2s message names: `pub struct Out<Name>Message` with the prefix and
/// suffix removed, so the part and message halves of one declaration collapse.
fn c2s_names(file: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(file).expect("read generated table");
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("pub struct Out") else {
            continue;
        };
        let raw: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Some(name) = raw.strip_suffix("Message") {
            names.insert(name.to_string());
        }
    }
    names
}

/// The core sources, concatenated. One string is enough for "does this name
/// appear anywhere", which is all the check needs.
fn core_sources() -> String {
    fn scan(path: &Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            out.push_str(&std::fs::read_to_string(&path).expect("read source"));
            out.push('\n');
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = String::new();
    scan(&src, &mut out);
    out
}

/// c2s messages the core never names, each with the reason.
///
/// Keeping this explicit is the point: a new message with no entry here fails
/// the test, so the answer has to be written down rather than assumed.
const C2S_EXPLAINED: &[(&str, &str)] = &[
    // Built and sent by tsclientlib itself.
    (
        "ClientInit",
        "the library sends clientinit during the handshake",
    ),
    (
        "ClientInitIv",
        "the library sends clientinitiv during the handshake",
    ),
    ("Disconnect", "Connection::disconnect, which the core calls"),
    ("InitDownload", "Connection::download_file"),
    ("InitUpload", "Connection::upload_file"),
    (
        "SetConnectionInfo",
        "the library answers notifyconnectioninforequest with its own resender stats",
    ),
    (
        "Use",
        "a query client selects a virtual server; this connection is bound to one at connect time",
    ),
    (
        "ServerNotifyRegister",
        "ServerQuery only: a client connection is refused with `invalid client type`. A \
         client subscribes with `channelsubscribe` instead, which these commands did not do",
    ),
    (
        "ServerNotifyUnregister",
        "ServerQuery only, for the same reason",
    ),
    // Query protocol only: a regular client authenticates with an identity and
    // quits by closing the socket.
    (
        "Login",
        "query protocol: a regular client authenticates with an identity",
    ),
    ("Logout", "query protocol"),
    ("Quit", "query protocol: the core closes the socket instead"),
    // Sent through the bookkeeping API rather than as a raw message.
    (
        "SendTextMessage",
        "book.send_message for all three text targets",
    ),
    (
        "ClientPokeRequest",
        "book.send_message with MessageTarget::Poke",
    ),
];

/// Why a reply needs no handler in the core.
///
/// Each variant is a claim the test can check, which is the point: the first
/// version of this file accepted any string, and three reasons were false. A
/// prose reason cannot be verified; a typed one can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// The bookkeeping consumes it into its state and reports the change through
    /// `StreamItem::BookEvents`. Verified against `data.rs` and `m2bdecls.rs`.
    FoldedIntoBook,
    /// A dedicated `StreamItem` variant carries it. Verified against
    /// `StreamItem` in tsclientlib's `lib.rs` and the arms in `conn.rs`.
    StreamItem(&'static str),
    /// The reply type has no attributes at all, so there is nothing to emit.
    /// Verified against the generated struct.
    NoFields,
    /// The core asks a different question than the one this reply answers.
    /// Verified by checking that the request the core sends is named in the
    /// reason.
    OtherRequest(&'static str),
    /// tsclientlib itself matches on this variant. Verified by finding the
    /// `InMessage::` arm in its `lib.rs`.
    HandledByLibrary,
    /// Consumed by tsproto during the handshake, before any `InMessage` exists.
    /// Verified by finding the wire command name in `tsproto/src/client.rs`.
    ConsumedByHandshake(&'static str),
}

/// s2c replies the core never names, each with a checkable reason.
const S2C_EXPLAINED: &[(&str, Reason)] = &[
    // Consumed into the bookkeeping state, then reported as property changes
    // through `StreamItem::BookEvents`.
    ("ChannelCreated", Reason::FoldedIntoBook),
    ("ChannelDeleted", Reason::FoldedIntoBook),
    ("ChannelDescriptionChanged", Reason::FoldedIntoBook),
    ("ChannelList", Reason::FoldedIntoBook),
    ("ChannelMoved", Reason::FoldedIntoBook),
    ("ChannelPermissionHints", Reason::FoldedIntoBook),
    ("ChannelSubscribed", Reason::FoldedIntoBook),
    ("ChannelUnsubscribed", Reason::FoldedIntoBook),
    ("ClientChannelGroupChanged", Reason::FoldedIntoBook),
    ("ClientEnterView", Reason::FoldedIntoBook),
    ("ClientLeftView", Reason::FoldedIntoBook),
    ("ClientMoved", Reason::FoldedIntoBook),
    ("ClientPermissionHints", Reason::FoldedIntoBook),
    ("ClientServerGroupAdded", Reason::FoldedIntoBook),
    ("ClientServerGroupRemoved", Reason::FoldedIntoBook),
    ("ClientUpdated", Reason::FoldedIntoBook),
    ("ServerEdited", Reason::FoldedIntoBook),
    ("ServerUpdated", Reason::FoldedIntoBook),
    // Dedicated StreamItem variants.
    ("FileDownload", Reason::StreamItem("FileDownload")),
    ("FileUpload", Reason::StreamItem("FileUpload")),
    (
        "FiletransferStatus",
        Reason::StreamItem("FiletransferFailed"),
    ),
    ("CommandError", Reason::StreamItem("MessageResult")),
    // No attributes in the generated struct.
    ("ChannelListFinished", Reason::NoFields),
    // Answered by tsclientlib before the core sees it.
    (
        "ClientConnectionInfoUpdateRequest",
        Reason::HandledByLibrary,
    ),
    ("InitServer", Reason::HandledByLibrary),
    // Consumed by tsproto during the handshake: the raw command bytes are read
    // before any `InMessage` is built, so there is no variant to match.
    (
        "InitIvExpand2",
        Reason::ConsumedByHandshake("initivexpand2"),
    ),
    // Answered by a different request than the one the core sends.
    ("ChannelListResponse", Reason::OtherRequest("channellist")),
];

/// Reasons that cannot be checked from the protocol tables.
#[test]
fn every_c2s_message_is_used_or_explained() {
    let out = out_dir();
    let defined = c2s_names(&out.join("c2s_messages.rs"));
    let sources = core_sources();
    let explained: BTreeSet<&str> = C2S_EXPLAINED.iter().map(|(name, _)| *name).collect();

    let unaccounted: Vec<&String> = defined
        .iter()
        .filter(|name| !sources.contains(&format!("Out{name}")))
        .filter(|name| !explained.contains(name.as_str()))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "these c2s messages are neither used nor listed in C2S_EXPLAINED: {unaccounted:?}"
    );

    // The other direction: an explanation for a message the table no longer
    // defines means a re-vendor renamed something and the reason is stale.
    let stale: Vec<&&str> = explained
        .iter()
        .filter(|name| !defined.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "C2S_EXPLAINED names messages the table does not define: {stale:?}"
    );
}

#[test]
fn every_s2c_message_is_used_or_explained() {
    let out = out_dir();
    let defined = s2c_variants(&out.join("s2c_messages.rs"));
    let sources = core_sources();
    let explained: BTreeSet<&str> = S2C_EXPLAINED.iter().map(|(name, _)| *name).collect();

    let unaccounted: Vec<&String> = defined
        .iter()
        .filter(|name| !sources.contains(&format!("InMessage::{name}")))
        .filter(|name| !explained.contains(name.as_str()))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "these s2c replies are neither handled nor listed in S2C_EXPLAINED: {unaccounted:?}"
    );

    let stale: Vec<&&str> = explained
        .iter()
        .filter(|name| !defined.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "S2C_EXPLAINED names replies the table does not define: {stale:?}"
    );
}

/// Every reason is checked against the thing that makes it true.
///
/// This is what the first version of this file lacked: it accepted any string,
/// and three reasons were false. A typed reason cannot be false without a test
/// failing.
#[test]
fn every_reason_is_verified_against_its_source() {
    let out = out_dir();
    let s2c_table = std::fs::read_to_string(out.join("s2c_messages.rs")).expect("read s2c table");

    // The bookkeeping handler: hand-written arms plus generated updates.
    let bookkeeping =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/tsclientlib/utils/ts-bookkeeping");
    let mut book_handled: BTreeSet<String> = BTreeSet::new();
    for source in [
        std::fs::read_to_string(bookkeeping.join("src/data.rs")).expect("read data.rs"),
        std::fs::read_to_string(out.join("m2bdecls.rs")).expect("read m2bdecls.rs"),
    ] {
        let mut rest = source.as_str();
        while let Some(pos) = rest.find("InMessage::") {
            rest = &rest[pos + "InMessage::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if !name.is_empty() {
                book_handled.insert(name);
            }
        }
    }

    // The StreamItem variants tsclientlib defines and the core handles.
    let tsclientlib = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/tsclientlib/tsclientlib/src/lib.rs"),
    )
    .expect("read tsclientlib");
    let stream_item_body = tsclientlib
        .split("pub enum StreamItem {")
        .nth(1)
        .expect("StreamItem enum");
    let stream_items: BTreeSet<String> = stream_item_body
        .lines()
        .take_while(|line| *line != "}")
        .filter_map(|line| {
            let rest = line.strip_prefix('\t')?;
            if rest.starts_with('\t') {
                return None;
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect();
    let handled_items = core_sources();

    // tsproto consumes the handshake commands as raw bytes, before any
    // `InMessage` exists, so those anchors live in its client.
    let tsproto_client = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/tsclientlib/tsproto/src/client.rs"),
    )
    .expect("read tsproto client");

    let mut failures = Vec::new();
    for (name, reason) in S2C_EXPLAINED {
        match reason {
            Reason::FoldedIntoBook => {
                if !book_handled.contains(*name) {
                    failures.push(format!(
                        "{name}: claims FoldedIntoBook but the bookkeeping never handles it"
                    ));
                }
            }
            Reason::StreamItem(item) => {
                if !stream_items.contains(*item) {
                    failures.push(format!(
                        "{name}: claims StreamItem::{item}, which tsclientlib does not define"
                    ));
                } else if !handled_items.contains(&format!("StreamItem::{item}")) {
                    failures.push(format!(
                        "{name}: claims StreamItem::{item}, which the core never matches"
                    ));
                }
            }
            Reason::NoFields => {
                // The reply must carry nothing: either no `Part` struct at all,
                // or a `Part` with no fields. A `list: Vec<…>` field on the outer
                // struct does not count as data.
                let marker = format!("pub struct In{name}Part ");
                if let Some(pos) = s2c_table.find(&marker) {
                    let block = s2c_table[pos..].split("\n}").next().unwrap_or("");
                    if block
                        .lines()
                        .any(|line| line.trim_start().starts_with("pub "))
                    {
                        failures.push(format!(
                            "{name}: claims NoFields but its Part declares attributes"
                        ));
                    }
                }
            }
            Reason::OtherRequest(request) => {
                // The request the core actually sends must be named, and the core
                // must send it.
                if !handled_items.contains(&format!("\"{request}\"")) {
                    failures.push(format!(
                        "{name}: claims the core sends {request}, which it never does"
                    ));
                }
            }
            Reason::HandledByLibrary => {
                if !tsclientlib.contains(&format!("InMessage::{name}")) {
                    failures.push(format!(
                        "{name}: claims the library handles it, but lib.rs never matches it"
                    ));
                }
            }
            Reason::ConsumedByHandshake(command) => {
                if !tsproto_client.contains(&format!("\"{command}\"")) {
                    failures.push(format!(
                        "{name}: claims tsproto consumes `{command}` during the handshake, which it never names"
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "unverified reasons:\n  {}",
        failures.join("\n  ")
    );
}

/// The counts, pinned so a re-vendor that adds messages is noticed.
#[test]
fn the_tables_have_the_expected_size() {
    let out = out_dir();
    let c2s = c2s_names(&out.join("c2s_messages.rs"));
    let s2c = s2c_variants(&out.join("s2c_messages.rs"));
    assert_eq!(c2s.len(), 145, "c2s message count drifted");
    assert_eq!(s2c.len(), 89, "s2c reply count drifted: {s2c:?}");
}
