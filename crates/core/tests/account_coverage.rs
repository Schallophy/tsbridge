//! The account side is accounted for the same way the protocol is.
//!
//! `protocol_coverage.rs` enumerates the wire tables and `snapshot_coverage.rs`
//! enumerates the bookkeeping properties. The account module was the last
//! surface with no such check, and it is a second command namespace with its own
//! state — so it gets the same treatment: every command name the parser accepts
//! must have a handler, and every field the report declares must be assigned.
//!
//! The account side is independent of any connection, so these tests need no
//! server and no network.

use std::collections::BTreeSet;
use std::path::Path;

/// The text up to the brace that closes the block `after` starts inside.
fn balanced_body(after: &str) -> &str {
    let mut depth = 1usize;
    for (index, ch) in after.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &after[..index];
                }
            }
            _ => {}
        }
    }
    after
}

fn account_source() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/account/mod.rs"))
        .expect("read account/mod.rs")
}

/// `account/command.rs`, where the command surface lives.
///
/// The enum, its parser and the name table were one `matches!` guard inside
/// `account/mod.rs`; they moved here so that adding a command is one edit
/// instead of four. Reading the table is therefore the same as reading the
/// dispatch, and reading `mod.rs` would find nothing.
fn command_source() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/account/command.rs"))
        .expect("read account/command.rs")
}

/// The names `AccountCommand::parse` accepts, read from `NAMES`.
///
/// The table is the gate: `parse` rejects anything not in it, so this list is
/// the accepted set rather than a copy of one.
fn accepted_names(source: &str) -> BTreeSet<String> {
    let Some(after) = source.split("pub const NAMES: &[&str] = &[").nth(1) else {
        panic!("the NAMES table is missing");
    };
    let Some(list) = after.split(']').next() else {
        panic!("the NAMES table is not closed");
    };
    let mut names = BTreeSet::new();
    for line in list.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if let Some(name) = trimmed.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
            names.insert(name.to_string());
        }
    }
    names
}

/// The `AccountCommand` variants.
fn variants(source: &str) -> BTreeSet<String> {
    let Some(after) = source.split("pub enum AccountCommand {").nth(1) else {
        panic!("AccountCommand is missing");
    };
    // Walk to the matching brace: a variant's fields contain `}` of their own
    // (struct literals in defaults), so splitting on a line that starts with `}`
    // stops at the wrong place.
    let body = balanced_body(after);
    let mut names = BTreeSet::new();
    for line in body.lines() {
        // Exactly one level of indent: variant lines, not their fields.
        if !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let rest = line.trim_start();
        if rest.starts_with("//") || rest.starts_with('#') {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if name.is_empty() {
            continue;
        }
        // `Name {`, `Name,` or `Name(...)`. Trim first: `Login {` has a space
        // before the brace, which an untrimmed prefix check misses.
        let after = rest[name.len()..].trim_start();
        if after.starts_with('{') || after.starts_with(',') || after.starts_with('(') {
            names.insert(name);
        }
    }
    names
}

/// Every accepted name has a variant and a handler.
///
/// The two directions catch different mistakes: a name in the `matches!` guard
/// with no `parse_known` arm would parse to nothing, and a variant with no
/// handler would be accepted and then ignored.
#[test]
fn every_account_command_is_dispatched() {
    let source = account_source();
    let commands = command_source();
    let names = accepted_names(&commands);
    let variants = variants(&commands);

    assert!(
        !names.is_empty(),
        "the name scan found nothing; the NAMES table changed shape"
    );
    assert_eq!(
        names.len(),
        variants.len(),
        "the parser accepts {} names but the enum has {} variants: names {names:?} variants {variants:?}",
        names.len(),
        variants.len()
    );

    // Each name maps to exactly one variant by construction; the check that
    // matters is that the handler exists. `parse` produces them, and the engine
    // matches on them, so a variant mentioned only in `parse` would be accepted
    // and dropped. The handler stayed in `mod.rs` when the surface moved.
    let engine = source
        .split("fn handle(")
        .nth(1)
        .or_else(|| source.split("fn run(").nth(1))
        .unwrap_or(&source);

    let unhandled: Vec<&String> = variants
        .iter()
        .filter(|variant| !engine.contains(&format!("AccountCommand::{variant}")))
        .collect();
    assert!(
        unhandled.is_empty(),
        "these account commands are accepted but never handled: {unhandled:?}"
    );
}

/// Every field of the account report is assigned.
///
/// A field declared and never written would serialize as its default forever,
/// which reads as "the account never reports this" rather than "nobody filled
/// it in".
#[test]
fn every_report_field_is_assigned() {
    let source = account_source();
    let Some(after) = source.split("pub struct AccountReport {").nth(1) else {
        panic!("AccountReport is missing");
    };
    let body = balanced_body(after);

    let mut fields = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        let field: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !field.is_empty() {
            fields.push(field);
        }
    }
    assert!(
        fields.len() > 15,
        "the field scan found too few fields: {}",
        fields.len()
    );

    let mut unassigned = Vec::new();
    for field in &fields {
        let initialized = source.contains(&format!("{field}: "));
        let assigned = source.contains(&format!(".{field} = "));
        if !initialized && !assigned {
            unassigned.push(field.clone());
        }
    }
    assert!(
        unassigned.is_empty(),
        "these AccountReport fields are never assigned: {unassigned:?}"
    );
}

/// The counts, pinned so a new command or field is noticed here.
#[test]
fn the_account_surface_has_the_expected_size() {
    let commands = command_source();
    assert_eq!(
        accepted_names(&commands).len(),
        16,
        "account command count drifted"
    );
    assert_eq!(
        variants(&commands).len(),
        16,
        "AccountCommand variant count drifted"
    );
}
