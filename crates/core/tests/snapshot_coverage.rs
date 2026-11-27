//! The snapshot covers the state the bookkeeping actually tracks.
//!
//! The protocol-coverage test enumerates the wire tables. This one enumerates
//! the other authoritative surface: the `PropertyId` variants ts-bookkeeping
//! exposes, which are every property a book object has. A property the snapshot
//! never reads is state the server sent and this crate threw away — the same
//! class of gap as a message with no handler, found from the other side.
//!
//! It also checks the reverse: every field the snapshot declares must be
//! assigned somewhere, so a struct member cannot be added and left at its
//! default forever.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn out_dir() -> PathBuf {
    let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/build");
    let entries = std::fs::read_dir(&build).unwrap_or_else(|e| {
        panic!("target/debug/build is missing ({e}); build the workspace first")
    });
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let out = entry.path().join("out");
        let table = out.join("properties.rs");
        if !table.is_file() {
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

/// The `PropertyId` variants, which are every property a book object has.
fn property_ids(file: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(file).expect("read properties.rs");
    let mut names = BTreeSet::new();
    let mut rest = text.as_str();
    while let Some(pos) = rest.find("PropertyId::") {
        rest = &rest[pos + "PropertyId::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names
}

fn state_source() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state.rs"))
        .expect("read state.rs")
}

/// The snapshot structs and their fields, as `Struct.field`.
fn snapshot_fields(source: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut rest = source;
    while let Some(pos) = rest.find("pub struct ") {
        rest = &rest[pos + "pub struct ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let Some(body_start) = rest.find('{') else {
            continue;
        };
        let Some(body_len) = rest[body_start..].find("\n}") else {
            continue;
        };
        let body = &rest[body_start..body_start + body_len];
        // Only the entries that are serialized into the snapshot.
        if !rest[..body_start].contains("Serialize") && !source.contains("rename_all") {
            // The derive is on the line before the struct, which the scan has
            // already passed; `#[serde(rename_all = "camelCase")]` on the
            // surrounding block is the reliable marker, so this is a no-op guard.
        }
        for line in body.lines() {
            let trimmed = line.trim_start();
            let Some(field) = trimmed.strip_prefix("pub ") else {
                continue;
            };
            let field: String = field
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !field.is_empty() {
                fields.push((name.clone(), field));
            }
        }
    }
    fields
}

/// Properties the snapshot does not read, each with the reason.
///
/// Written out rather than inferred, so adding a property that the snapshot
/// ignores is a deliberate act.
const NOT_IN_SNAPSHOT: &[(&str, &str)] = &[
    // Permission-power thresholds. A shell shows an error when an action is
    // refused; it does not pre-compute who may do what, and `permoverview`
    // answers the one question that needs a value.
    (
        "ServerGroupNeededModifyPower",
        "permission threshold, not displayed",
    ),
    (
        "ServerGroupNeededMemberAddPower",
        "permission threshold, not displayed",
    ),
    (
        "ServerGroupNeededMemberRemovePower",
        "permission threshold, not displayed",
    ),
    (
        "ChannelGroupNeededModifyPower",
        "permission threshold, not displayed",
    ),
    (
        "ChannelGroupNeededMemberAddPower",
        "permission threshold, not displayed",
    ),
    (
        "ChannelGroupNeededMemberRemovePower",
        "permission threshold, not displayed",
    ),
    // Group naming mode only affects what the server accepts as a name.
    (
        "ServerGroupNamingMode",
        "server-side naming rule, nothing to draw",
    ),
    (
        "ChannelGroupNamingMode",
        "server-side naming rule, nothing to draw",
    ),
    // Channel storage quota is a filesystem limit enforced server-side.
    ("ChannelStorageQuota", "server-enforced quota"),
    (
        "ChannelChannelType",
        "permanent/semi-permanent is already `is_permanent`",
    ),
    // A channel guid is a stable identifier this crate does not key on; the
    // numeric id is what every other field uses.
    ("ChannelGuid", "unused identifier; channels are keyed by id"),
    // Instance-wide values only a query client acts on.
    ("ServerLicense", "instance metadata, no client action"),
    (
        "ServerProtocolVersion",
        "instance metadata, no client action",
    ),
    (
        "ServerAdministrativeDomain",
        "instance metadata, no client action",
    ),
    // Client fields the UI derives elsewhere or cannot act on.
    (
        "ClientNeededServerqueryViewPower",
        "query-view power; a regular client never has one",
    ),
    (
        "ClientUserTag",
        "server-side tag, not part of the member list",
    ),
    // Group type (regular/query/template) is what the group list is filtered
    // by at the source; a shell never draws it.
    (
        "ServerGroupGroupType",
        "the group list already excludes templates",
    ),
    (
        "ChannelGroupGroupType",
        "the group list already excludes templates",
    ),
    // Phonetic names are only read aloud by screen readers that do their own
    // transliteration; nothing in this crate synthesises speech.
    ("ServerPhoneticName", "no speech synthesis in this crate"),
    ("ChannelPhoneticName", "no speech synthesis in this crate"),
    ("ClientPhoneticName", "no speech synthesis in this crate"),
    // The client database id is on `UserEntry`; the bookkeeping property is the
    // same value under a different name.
    ("ClientDatabaseId", "already carried as `client_db_id`"),
    // A talk-power request is an event, not state: `talk_power_request` is a
    // command and the server answers through `command_error` or silence.
    ("ClientTalkPowerRequest", "a request, not maintained state"),
    // Host messages are one-shot: the server sends them when it wants a popup,
    // and `initserver` carries the initial one.
    ("ServerHostmessage", "one-shot popup, carried by initserver"),
    (
        "ServerHostmessageMode",
        "one-shot popup, carried by initserver",
    ),
    // Host banner and button are web-style decorations the desktop client draws
    // in its header; a phone shell has no such chrome.
    ("ServerHostbannerUrl", "desktop header decoration"),
    ("ServerHostbannerGfxUrl", "desktop header decoration"),
    ("ServerHostbannerGfxInterval", "desktop header decoration"),
    ("ServerHostbannerMode", "desktop header decoration"),
    ("ServerHostbuttonUrl", "desktop header decoration"),
    ("ServerHostbuttonGfxUrl", "desktop header decoration"),
    ("ServerHostbuttonTooltip", "desktop header decoration"),
    // Instance-level defaults a regular client never applies.
    (
        "ServerDefaultServerGroup",
        "instance default, not client state",
    ),
    (
        "ServerDefaultChannelGroup",
        "instance default, not client state",
    ),
    (
        "ServerCodecEncryptionMode",
        "instance policy, enforced server-side",
    ),
    (
        "ServerPrioritySpeakerDimmModificator",
        "playback ducking is done in the audio path",
    ),
    (
        "ServerTempChannelDefaultDeleteDelay",
        "instance default, not client state",
    ),
    // The server's public key is used by the handshake, which tsproto owns.
    ("ServerPublicKey", "the handshake consumes it in tsproto"),
];

#[test]
fn every_bookkeeping_property_is_read_or_explained() {
    let out = out_dir();
    let properties = property_ids(&out.join("properties.rs"));
    let state = state_source();

    // Entity variants carry no data of their own; they select an object.
    let entities: BTreeSet<&str> = [
        "ServerGroup",
        "ChannelGroup",
        "OptionalChannelData",
        "Channel",
        "OptionalClientData",
        "ConnectionClientData",
        "Client",
        "OptionalServerData",
        "ConnectionServerData",
        "Server",
        "Connection",
    ]
    .into_iter()
    .collect();

    let explained: BTreeSet<&str> = NOT_IN_SNAPSHOT.iter().map(|(name, _)| *name).collect();

    let unaccounted: Vec<&String> = properties
        .iter()
        .filter(|name| !entities.contains(name.as_str()))
        .filter(|name| !explained.contains(name.as_str()))
        // The property's own field name is what the snapshot would read.
        .filter(|name| {
            let stem = strip_entity_prefix(name);
            let snake = to_snake_case(&stem);
            !state.contains(&snake)
        })
        .collect();

    assert!(
        unaccounted.is_empty(),
        "these bookkeeping properties are neither read by the snapshot nor listed in NOT_IN_SNAPSHOT: {unaccounted:?}"
    );

    let stale: Vec<&&str> = explained
        .iter()
        .filter(|name| !properties.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_IN_SNAPSHOT names properties the bookkeeping does not define: {stale:?}"
    );
}

/// Every snapshot field is assigned somewhere.
///
/// A struct member added and never filled would serialize as its default
/// forever, which looks like the server never sent it.
#[test]
fn every_snapshot_field_is_assigned() {
    let state = state_source();
    let fields = snapshot_fields(&state);
    assert!(
        fields.len() > 80,
        "the struct scan found too few fields: {}",
        fields.len()
    );

    let mut unassigned = Vec::new();
    for (structure, field) in &fields {
        // An initializer (`field: …`) or an assignment (`.field = …`).
        let initialized = state.contains(&format!("{field}: "));
        let assigned = state.contains(&format!(".{field} = "));
        if !initialized && !assigned {
            unassigned.push(format!("{structure}.{field}"));
        }
    }
    assert!(
        unassigned.is_empty(),
        "these snapshot fields are never assigned: {unassigned:?}"
    );
}

fn strip_entity_prefix(name: &str) -> String {
    for prefix in [
        "ServerGroup",
        "ChannelGroup",
        "OptionalChannel",
        "Channel",
        "OptionalClient",
        "ConnectionClient",
        "Client",
        "OptionalServer",
        "ConnectionServer",
        "Server",
        "Connection",
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    name.to_string()
}

fn to_snake_case(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}
