//! Pins the event names that leave this library.
//!
//! The `type` strings in an event are public API: Kotlin, Swift and C shells
//! switch on them, and a rename shows up as "the feature silently stopped
//! working in one client". Comparing the source against a checked-in list makes
//! any rename a test failure instead of a surprise in the field.
//!
//! Adding an event is a deliberate act: add it here, in `docs/events.md`, and in
//! every shell that cares.

use std::collections::BTreeSet;

/// Every `QueuedEvent::new("…")` in the core sources.
fn emitted_names() -> BTreeSet<String> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(&src).expect("read core src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        for line in text.lines() {
            let Some(rest) = line.split_once("QueuedEvent::new(\"").map(|(_, rest)| rest) else {
                continue;
            };
            let Some(end) = rest.find('"') else { continue };
            names.insert(rest[..end].to_string());
        }
    }
    names
}

#[test]
fn every_emitted_event_is_in_the_documented_contract() {
    let documented: BTreeSet<&str> = [
        "connected",
        "disconnected",
        "reconnecting",
        "error",
        "command_error",
        "user_joined",
        "user_left",
        "user_moved",
        "user_renamed",
        "user_mute_changed",
        "user_away_changed",
        "channel_created",
        "channel_renamed",
        "channel_removed",
        "text_message",
        "poked",
        "file_list",
        "transfer_started",
        "transfer_progress",
        "transfer_done",
        "transfer_error",
    ]
    .into_iter()
    .collect();

    let emitted = emitted_names();

    let undocumented: Vec<_> = emitted
        .iter()
        .filter(|name| !documented.contains(name.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these events are emitted but not listed in docs/events.md: {undocumented:?}"
    );

    let missing: Vec<_> = documented
        .iter()
        .filter(|name| !emitted.contains(**name))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/events.md lists events nothing emits (dead contract): {missing:?}"
    );

    assert_eq!(emitted.len(), 21, "event count drifted: {emitted:?}");
}

#[test]
fn docs_and_contract_agree() {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/events.md");
    let text = std::fs::read_to_string(&docs).expect("docs/events.md must exist");
    for name in emitted_names() {
        let needle = format!("| `{name}` |");
        assert!(
            text.contains(&needle),
            "docs/events.md is missing the row `{needle}`"
        );
    }
}
