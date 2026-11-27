//! The account report reaches a shell, and every command reports once.
//!
//! `account_coverage.rs` checks that every command is dispatched and every
//! report field is assigned. That is not the same as the field reaching a shell:
//! the report is published through `Snapshot::set_account`, and a shell learns
//! it changed by receiving `account_status`.
//!
//! The reporting is structural rather than per-command: `accept` spawns every
//! command through one task whose tail publishes the settled report and pushes
//! `account_status`, including on a panic. This test pins that structure,
//! because a command added outside it would publish and never report.
//!
//! The other check is `rebuild_report`, the one place a settled report is built.
//! A field it does not mention keeps whatever the previous snapshot held, which
//! is how one account's profile would leak into the next login.

use std::path::Path;

fn account_source() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/account/mod.rs"))
        .expect("read account/mod.rs")
}

/// Every command goes through the one reporting path.
///
/// `accept` builds the report, spawns `run`, and its tail publishes and emits.
/// The three pieces are asserted together: without the spawn there is no place
/// for the tail, and without the tail a command would run silently.
#[test]
fn every_command_reports_through_one_path() {
    let source = account_source();

    // One `dispatch`, which is where a command enters.
    let accepts = source.matches("pub fn dispatch(").count();
    assert_eq!(accepts, 1, "there is more than one entry point: {accepts}");

    let Some(accept) = source.split("pub fn dispatch(").nth(1) else {
        panic!("dispatch is missing");
    };
    // The tail that reports, inside the spawn.
    assert!(
        accept.contains("account_status"),
        "dispatch does not emit account_status, so a shell never learns a report changed"
    );
    assert!(
        accept.contains("engine.publish(report)"),
        "dispatch does not publish the settled report"
    );
    assert!(
        accept.contains("rebuild_report"),
        "dispatch does not rebuild the report before publishing"
    );
    // `busy` is cleared before the publish, which is what makes a spinner stop.
    let busy_clear = accept.find("busy.store(false").unwrap_or(usize::MAX);
    let publish = accept.find("engine.publish(report)").unwrap_or(0);
    assert!(
        busy_clear < publish,
        "busy is cleared after the publish, so the final report says busy: true"
    );
    // A panic is turned into a reported error rather than a dead task.
    assert!(
        accept.contains("is_panic"),
        "a panicking command would leave busy set forever"
    );
}

/// Fields that hold the *result* of one command rather than current state.
///
/// `rebuild_report` deliberately leaves these alone: they are what the last
/// command produced, and clearing them on every unrelated command would erase
/// the answer before the shell read it.
const RESULT_FIELDS: &[(&str, &str)] = &[
    ("last_backup", "the path the last backup wrote"),
    ("hierarchy", "the item tree the last list returned"),
    ("merge", "the last compare's answer"),
    ("identities", "the identity list the last pick saw"),
    ("picked_identity", "the identity the last pick chose"),
];

/// `rebuild_report` and `forget_session` together cover every state field.
///
/// `rebuild_report` used to assign each field in one function. It now copies the
/// published snapshot and overwrites only what the command changed, while
/// `forget_session` is what clears a session's own fields — so a field is
/// covered by either one. Checking only `rebuild_report` would report the fields
/// it deliberately stopped touching as gaps; checking neither would let a new
/// field default forever.
#[test]
fn rebuild_report_covers_every_state_field() {
    let source = account_source();
    let Some(after) = source.split("fn rebuild_report(").nth(1) else {
        panic!("rebuild_report is missing");
    };
    // The function ends at the first line that is exactly `    }`.
    let mut body = String::new();
    for line in after.lines().skip(1) {
        if line == "    }" {
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    // What a logout clears is part of the same contract: the two functions are
    // "the report says what the command found, or says nothing at all".
    if let Some(after) = source.split("pub fn forget_session(").nth(1) {
        for line in after.lines().skip(1) {
            if line == "    }" {
                break;
            }
            body.push_str(line);
            body.push('\n');
        }
    }
    assert!(body.len() > 200, "the function body scan found too little");

    let Some(report_body) = source.split("pub struct AccountReport {").nth(1) else {
        panic!("AccountReport is missing");
    };
    let report_body = report_body.split("\n}").next().unwrap_or("");
    let fields: Vec<String> = report_body
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("pub ")?;
            let field: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!field.is_empty()).then_some(field)
        })
        .collect();
    assert!(
        fields.len() > 15,
        "the field scan found only {}",
        fields.len()
    );

    let results: std::collections::BTreeSet<&str> =
        RESULT_FIELDS.iter().map(|(name, _)| *name).collect();
    // A field is covered when the settled report writes it (`report.x`) or when
    // the logout path clears it (`self.x`, since `forget_session` is a method on
    // the report). Both are the same promise to a shell: this field never keeps
    // a previous session's value.
    let missing: Vec<&String> = fields
        .iter()
        .filter(|field| !results.contains(field.as_str()))
        .filter(|field| {
            !body.contains(&format!("report.{field}")) && !body.contains(&format!("self.{field}"))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "these AccountReport fields are never touched by rebuild_report or forget_session: {missing:?}"
    );
}

/// The failure path reports the error text.
///
/// A command that failed must still publish, with `last_error` set; otherwise
/// the previous success stays on screen. The check is on the shape of the
/// settled report rather than on one exact expression: the dispatch body has
/// been reorganised once already, and what matters is that the error reaches
/// both the snapshot and the event.
#[test]
fn a_failure_is_reported_with_its_message() {
    let source = account_source();
    let Some(accept) = source.split("pub fn dispatch(").nth(1) else {
        panic!("dispatch is missing");
    };
    assert!(
        accept.contains("rebuild_report(name, failure)"),
        "the settled report is not built from the command's failure"
    );
    assert!(
        accept.contains(".str(\"message\", message)"),
        "account_status does not carry the message"
    );
    assert!(
        accept.contains(".bool(\"ok\", ok)"),
        "account_status does not carry the outcome"
    );
    // And `rebuild_report` has to put that failure into the report itself,
    // otherwise a shell reading the snapshot keeps the last success.
    let Some(report) = source.split("fn rebuild_report(").nth(1) else {
        panic!("rebuild_report is missing");
    };
    assert!(
        report.contains("report.last_error = error.map(|e| e.message.clone())"),
        "the report does not carry the failure's message"
    );
}
