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

/// s2c replies the core never names, each with the reason.
///
/// Three groups, and the distinction matters: the first two never reach
/// `handle_message` at all because tsclientlib consumes them first, so looking
/// for an `InMessage::` arm there would never find one no matter how complete
/// the implementation is.
const S2C_EXPLAINED: &[(&str, &str)] = &[
    // Consumed into the bookkeeping state, then reported as property changes
    // through `StreamItem::BookEvents`. The snapshot diff is what turns them into
    // `user_joined`, `channel_renamed` and friends.
    (
        "ChannelCreated",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelDeleted",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelDescriptionChanged",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelList",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelListFinished",
        "marks the end of the channel list; nothing to emit",
    ),
    (
        "ChannelMoved",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelPermissionHints",
        "folded into the book; the core requests permoverview instead",
    ),
    (
        "ChannelSubscribed",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ChannelUnsubscribed",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientChannelGroupChanged",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientChatComposing",
        "typing notification; no UI surface in this crate",
    ),
    (
        "ClientConnectionInfoUpdateRequest",
        "answered by tsclientlib with its own resender stats",
    ),
    (
        "ClientEnterView",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientLeftView",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientMoved",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientNeededPermissions",
        "reported through command_error, which carries missing_permission",
    ),
    ("ClientPermissionHints", "folded into the book"),
    (
        "ClientServerGroupAdded",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientServerGroupRemoved",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ClientSetServerQueryLogin",
        "the password reply; only a query client acts on it",
    ),
    (
        "ClientUpdated",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "CommandError",
        "reported as the command_error event from StreamItem::MessageResult",
    ),
    // File transfers arrive as dedicated StreamItems, not as messages.
    (
        "FileDownload",
        "StreamItem::FileDownload carries the stream",
    ),
    ("FileUpload", "StreamItem::FileUpload carries the stream"),
    (
        "FileListFinished",
        "the file list reply is complete; the snapshot already has it",
    ),
    (
        "FiletransferStatus",
        "StreamItem::FiletransferFailed reports the failure",
    ),
    // Handshake.
    ("InitIvExpand", "the handshake IV; tsclientlib consumes it"),
    ("InitIvExpand2", "the handshake IV; tsclientlib consumes it"),
    ("InitServer", "the handshake reply; tsclientlib consumes it"),
    // Folded into the book or handled by the library.
    (
        "ServerEdited",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    (
        "ServerUpdated",
        "folded into the book, surfaced via StreamItem::BookEvents",
    ),
    // Answered by a different request than the one the core sends.
    (
        "ChannelListResponse",
        "the core sends channellist and reads the notifychannellist stream instead",
    ),
];

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

/// A reason that claims a reply is folded into the bookkeeping has to be true.
///
/// This is the check that was missing. The first version of this file accepted
/// any string as a reason, and three of them were wrong: `PluginCommand`,
/// `ChannelChanged` and `ChannelPasswordChanged` all said "folded into the book"
/// while the bookkeeping's `handle_command` only matches `TextMessage`,
/// `ClientPoke` and `CommandError` plus whatever the generator emits. All three
/// reached the core as ordinary messages and were dropped.
///
/// So the claim is verified against the two places that can make it true: the
/// hand-written match arms in `data.rs`, and the generated `m2bdecls.rs`.
#[test]
fn every_book_claim_matches_the_bookkeeping() {
    let bookkeeping =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/tsclientlib/utils/ts-bookkeeping");

    let hand_written = std::fs::read_to_string(bookkeeping.join("src/data.rs"))
        .expect("read the bookkeeping handler");
    let mut handled: BTreeSet<String> = BTreeSet::new();
    let mut rest = hand_written.as_str();
    while let Some(pos) = rest.find("InMessage::") {
        rest = &rest[pos + "InMessage::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if !name.is_empty() {
            handled.insert(name);
        }
    }

    let out = out_dir();
    let generated =
        std::fs::read_to_string(out.join("m2bdecls.rs")).expect("read the generated book updates");
    let mut rest = generated.as_str();
    while let Some(pos) = rest.find("InMessage::") {
        rest = &rest[pos + "InMessage::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if !name.is_empty() {
            handled.insert(name);
        }
    }

    let liars: Vec<&str> = S2C_EXPLAINED
        .iter()
        .filter(|(_, reason)| reason.contains("book"))
        .map(|(name, _)| *name)
        .filter(|name| !handled.contains(*name))
        .collect();
    assert!(
        liars.is_empty(),
        "these replies claim to be folded into the book but the bookkeeping never handles them: {liars:?}"
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
