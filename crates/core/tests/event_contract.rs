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
///
/// Recursive, because the account side lives in `src/account/`: a one-level scan
/// would quietly stop guarding every event that module emits.
fn emitted_names() -> BTreeSet<String> {
    fn scan(path: &std::path::Path, names: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, names);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            for line in text.lines() {
                let Some(rest) = line.split_once("QueuedEvent::new(\"").map(|(_, rest)| rest)
                else {
                    continue;
                };
                let Some(end) = rest.find('"') else { continue };
                names.insert(rest[..end].to_string());
            }
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut names = BTreeSet::new();
    scan(&src, &mut names);
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
        "icon_ready",
        "icon_failed",
        "ban_listed",
        "ban_list_done",
        "complaint_listed",
        "complaint_list_done",
        "account_status",
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

    // The count is pinned so adding an event without updating this test and
    // docs/events.md fails here rather than drifting silently.
    assert_eq!(emitted.len(), 28, "event count drifted: {emitted:?}");
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

/// The documented field names for one event, taken from its table row.
///
/// The row format is `| \`type\` | \`field\` ty, \`field\` ty, … |`. Everything in
/// backticks in the second cell is a field name; the type words after it are
/// not. Parsing it here rather than keeping a second list means the document
/// stays the single place a field is named.
///
/// A field documented as `(absent …)` is conditional: it may legitimately be
/// missing from some emit sites, so it is only checked in the direction that
/// matters — a key the library writes must be documented, not the reverse.
fn documented_fields(text: &str, event: &str) -> Option<(Vec<String>, Vec<String>)> {
    let row = text
        .lines()
        .find(|line| line.starts_with(&format!("| `{event}` |")))?;
    let cells: Vec<&str> = row.split('|').collect();
    // ["", " `error` ", " `message` str, … ", ""]
    let fields_cell = cells.get(2)?;

    let mut required = Vec::new();
    let mut optional = Vec::new();
    // Split on the commas that separate fields, keeping each field's own
    // parenthetical with it, so "(absent …)" is seen next to its field name.
    let mut segment_start = 0usize;
    let segments: Vec<&str> = {
        let mut out = Vec::new();
        let mut depth = 0i32;
        for (index, ch) in fields_cell.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(&fields_cell[segment_start..index]);
                    segment_start = index + 1;
                }
                _ => {}
            }
        }
        out.push(&fields_cell[segment_start..]);
        out
    };

    for segment in segments {
        let Some(start) = segment.find('`') else {
            continue;
        };
        let after = &segment[start + 1..];
        let Some(end) = after.find('`') else { continue };
        let name = after[..end].to_string();
        if name.is_empty() {
            continue;
        }
        if segment.contains("(absent") {
            optional.push(name);
        } else {
            required.push(name);
        }
    }
    Some((required, optional))
}

/// The field keys an event's emit sites actually set, gathered from source.
///
/// A single pass over the source text: it remembers which event is "current"
/// (`QueuedEvent::new("…")`) and attributes every following `.str("key"`,
/// `.int("key"`, `.bool("key"` and `.long("key"` to it, until the next event
/// starts. That is why this is textual rather than type-driven: it reads what
/// the library *writes*, and it works across the multi-line argument lists and
/// `match` arms the emit sites actually use.
fn emitted_fields(event: &str) -> BTreeSet<String> {
    fn scan(path: &std::path::Path, event: &str, fields: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, event, fields);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            // Only production code: the `mod tests` half of a file emits events
            // to exercise the state machine, and those emissions are not part of
            // the contract. Without this cut, a test that builds a `user_moved`
            // with an extra field makes the real one look wrong.
            let text = match text.find("#[cfg(test)]") {
                Some(at) => &text[..at],
                None => text.as_str(),
            };

            // Every interesting token in order, so "which event is current" is
            // just the last one seen.
            let mut rest = text;
            let mut current: Option<String> = None;
            const SETTERS: [&str; 4] = [".str(", ".int(", ".bool(", ".long("];
            loop {
                let next_event = rest.find("QueuedEvent::new(\"");
                let next_field = SETTERS
                    .iter()
                    .filter_map(|marker| rest.find(marker).map(|at| (at, *marker)))
                    .min_by_key(|(at, _)| *at);

                match (next_event, next_field) {
                    (None, None) => break,
                    (Some(at), field) if field.is_none_or(|(f, _)| at <= f) => {
                        // A new event starts here.
                        let after = &rest[at + "QueuedEvent::new(\"".len()..];
                        let Some(end) = after.find('"') else { break };
                        current = Some(after[..end].to_string());
                        rest = &after[end + 1..];
                    }
                    (_, Some((at, marker))) => {
                        let after = &rest[at + marker.len()..];
                        let trimmed = after.trim_start();
                        // A key must be a string literal: `.str(variable, …)`
                        // exists too. Step past this setter either way, so the
                        // next iteration looks after it — resuming from `after`
                        // re-found the same marker and never advanced.
                        let Some(tail) = trimmed.strip_prefix('"') else {
                            rest = after;
                            continue;
                        };
                        let Some(end) = tail.find('"') else { break };
                        if current.as_deref() == Some(event) {
                            fields.insert(tail[..end].to_string());
                        }
                        rest = &tail[end + 1..];
                    }
                    (Some(_), None) => break,
                }
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut fields = BTreeSet::new();
    scan(&src, event, &mut fields);
    fields
}

#[test]
fn every_emitted_field_is_documented() {
    // The old contract test pinned event *names* only, so renaming a field —
    // `client_id` to `clientId`, say — left every test green and broke the
    // Swift shell silently. This closes that: a key written by the library has
    // to appear in the document, and a documented key has to be written.
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/events.md");
    let text = std::fs::read_to_string(&docs).expect("docs/events.md must exist");

    let mut checked = 0usize;
    for name in emitted_names() {
        let Some((required, optional)) = documented_fields(&text, &name) else {
            continue;
        };
        let emitted = emitted_fields(&name);
        if emitted.is_empty() {
            // An event with no fields at all (`disconnected`) is legitimate.
            assert!(
                required.is_empty() && optional.is_empty(),
                "{name} documents fields but emits none"
            );
            checked += 1;
            continue;
        }

        let undocumented: Vec<_> = emitted
            .iter()
            .filter(|field| !required.contains(field) && !optional.contains(field))
            .collect();
        assert!(
            undocumented.is_empty(),
            "{name} emits fields missing from docs/events.md: {undocumented:?}"
        );

        // Only the unconditional fields are required to appear at every emit
        // site; an `(absent …)` one may be left out.
        let unemitted: Vec<_> = required
            .iter()
            .filter(|field| !emitted.contains(*field))
            .collect();
        assert!(
            unemitted.is_empty(),
            "{name} documents fields nothing emits: {unemitted:?}"
        );
        checked += 1;
    }
    assert!(checked > 0, "no event rows were parsed from docs/events.md");
}
