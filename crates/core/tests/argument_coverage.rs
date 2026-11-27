//! Every command argument is actually read from the JSON.
//!
//! A field declared on a `Command` variant but never assigned by `command::parse`
//! stays at its default forever — the command runs, the argument is silently
//! ignored. That is the same silent-failure shape as a message with no handler,
//! found from the argument side instead of the wire side.
//!
//! This checks the other direction too: every JSON key the parser reads must
//! belong to a variant's field, so a renamed key in one place is not a key that
//! quietly matches nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn read(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name))
        .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// The `Command` variants and their field names, in source order.
fn variants() -> BTreeMap<String, Vec<String>> {
    let source = read("handle.rs");
    let Some(after) = source.split("pub enum Command {").nth(1) else {
        panic!("Command enum is missing");
    };
    // Walk to the matching brace; a variant's field defaults can contain `}`.
    let mut depth = 1usize;
    let mut end = after.len();
    for (index, ch) in after.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = index;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &after[..end];

    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in body.lines() {
        // A field is indented deeper than a variant header. Count leading spaces
        // rather than matching prefixes: `Login {` and `    field: T,` differ by
        // exactly one level.
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if indent == 8 {
            // Enum variant fields carry no visibility: `field: Type,`.
            if let Some(name) = current.as_ref() {
                let field = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
                let field: String = field
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !field.is_empty() && trimmed.contains(':') {
                    out.entry(name.clone()).or_default().push(field);
                }
            }
        } else if indent == 4 && !trimmed.starts_with("//") {
            let name: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if !name.is_empty() {
                current = Some(name.clone());
                out.entry(name).or_default();
            }
        }
    }
    out
}

/// The JSON keys `command::parse` reads, and the arguments it passes on.
fn parsed_keys() -> (BTreeSet<String>, BTreeSet<String>) {
    let source = read("command.rs");
    let mut keys = BTreeSet::new();
    let mut args = BTreeSet::new();

    // `str_field(&json, "x")`, `int_field(&json, "x")`, `long_field`,
    // `bool_field`, `optional_str`, `u8_field`, `flag`, `json.get("x")`.
    for marker in [
        "str_field(&json, \"",
        "int_field(&json, \"",
        "long_field(&json, \"",
        "bool_field(&json, \"",
        "optional_str(&json, \"",
        "u8_field(&json, \"",
        "flag(&json, \"",
        "json.get(\"",
    ] {
        let mut rest = source.as_str();
        while let Some(pos) = rest.find(marker) {
            rest = &rest[pos + marker.len()..];
            let key: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !key.is_empty() {
                keys.insert(key);
            }
        }
    }

    // The construction side: `field: …` inside any `Command::` literal. A
    // direct search is enough — the point is whether the name appears as an
    // assignment, and nesting (`json.get(..)` inside a field) would break a
    // brace-splitting scan.
    let mut rest = source.as_str();
    while let Some(pos) = rest.find("Command::") {
        rest = &rest[pos + "Command::".len()..];
        // Take the next 2000 characters as the literal's neighbourhood; a
        // variant's fields never span more than that.
        let window = &rest[..rest.len().min(2000)];
        for line in window.lines() {
            let trimmed = line.trim_start();
            // `field: value` or the shorthand `field,` (Rust 2018 field init
            // shorthand, used where the local has the same name).
            let candidate = trimmed
                .split_once(':')
                .map(|(key, _)| key)
                .unwrap_or_else(|| trimmed.trim_end_matches(','));
            let candidate = candidate.trim();
            if !candidate.is_empty()
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !candidate.starts_with("//")
            {
                args.insert(candidate.to_string());
            }
        }
        // Advance past this literal so the same block is not scanned again.
        if let Some(next) = rest.find("Command::") {
            rest = &rest[next..];
        } else {
            break;
        }
    }

    (keys, args)
}

fn to_camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for ch in name.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// Every field on every variant is assigned by the parser.
#[test]
fn every_command_field_is_parsed() {
    let variants = variants();
    let (keys, args) = parsed_keys();

    assert!(
        variants.len() > 100,
        "the variant scan found only {} entries; the enum changed shape",
        variants.len()
    );

    let mut unparsed = Vec::new();
    for (variant, fields) in &variants {
        for field in fields {
            // The parser writes `field: …` into the variant; the key it reads is
            // the camelCase form of the same name.
            let key = to_camel(field);
            let read_from_json = keys.contains(&key) || keys.contains(field);
            let built = args.contains(field);
            if !read_from_json && !built {
                unparsed.push(format!("{variant}.{field}"));
            }
        }
    }
    assert!(
        unparsed.is_empty(),
        "these command fields are never assigned by the parser: {unparsed:?}"
    );
}

/// Keys that legitimately have no field of the same name.
///
/// Two shapes: a tuple variant carries its value positionally (`SetInputMuted
/// (bool)` has no `muted` field), and a nested object is built before the
/// variant (`{"type": …}` inside a permission list). Both are read on purpose,
/// so listing them keeps the check honest instead of widening it until nothing
/// fails.
const KEY_WITHOUT_FIELD: &[(&str, &str)] = &[
    ("muted", "tuple variant: SetInputMuted(bool)"),
    ("enabled", "tuple variant: SetAudioEnabled(bool)"),
    ("nickname", "tuple variant: SetNickname(String)"),
    ("angle", "nested into SetUserPosition's Option<(f32, f32)>"),
    (
        "distance",
        "nested into SetUserPosition's Option<(f32, f32)>",
    ),
    ("type", "group type: stored as `group_type`"),
];

/// Every JSON key the parser reads maps to a field some variant declares.
///
/// A key with no field is a typo: the parser reads a name nothing stores.
#[test]
fn every_parsed_key_belongs_to_a_field() {
    let variants = variants();
    let (keys, _) = parsed_keys();

    let fields: BTreeSet<String> = variants
        .values()
        .flatten()
        .map(|field| to_camel(field))
        .collect();

    let explained: BTreeSet<&str> = KEY_WITHOUT_FIELD.iter().map(|(key, _)| *key).collect();
    let orphans: Vec<&String> = keys
        .difference(&fields)
        .filter(|key| !explained.contains(key.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "these JSON keys are read by the parser but no command field holds them: {orphans:?}"
    );
}

/// The counts, pinned so a new argument is noticed.
#[test]
fn the_argument_surface_has_the_expected_size() {
    let variants = variants();
    let total: usize = variants.values().map(Vec::len).sum();
    assert_eq!(variants.len(), 145, "command variant count drifted");
    assert_eq!(total, 306, "command field count drifted");
}
