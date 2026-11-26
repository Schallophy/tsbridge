//! Every public function in the account submodules has a caller.
//!
//! Only `account/mod.rs` was audited before. The seven modules under it —
//! `merge`, `sqlite`, `http`, `proto`, `crypto`, `credentials`, `sync` — hold
//! the protocol work, and a public function with no caller there is a feature
//! that was written and never wired up: the same shape as a command with no
//! handler, one layer down.
//!
//! The check is a name search across the crate. It is coarse — a name reused as
//! a local would count as a caller — but the failure it prevents is coarse too:
//! a `pub fn` nothing mentions at all.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const SUBMODULES: &[&str] = &[
    "merge",
    "sqlite",
    "http",
    "proto",
    "crypto",
    "credentials",
    "sync",
    "mytsid",
];

fn account_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/account")
}

/// Every Rust source in the workspace, for the caller search.
///
/// Not just `core/src`: `default_baseline_file` is called by `account-demo`, and
/// a function used only by a shell is still used.
fn crate_sources() -> String {
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
    let mut out = String::new();
    // `CARGO_MANIFEST_DIR` is `crates/core`; its siblings are the shells.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for dir in ["crates", "src", "tests"] {
        scan(&workspace.join(dir), &mut out);
    }
    out
}

/// Whether a name is used somewhere other than its definition.
///
/// Counting is fragile — a method call is `.name(`, an associated one is
/// `Type::name(`, and a doc comment mentions `[`name`]` — so this asks the
/// simpler question: does the name appear at all outside `fn name`? A function
/// that nothing calls still appears in its own signature and in any doc link, so
/// the bar is "appears more than once".
fn is_used(sources: &str, name: &str) -> bool {
    let occurrences = sources.matches(name).count();
    let definitions = sources.matches(&format!("fn {name}")).count();
    occurrences > definitions
}

/// Public functions per submodule, and how often each name appears in the crate.
fn public_functions() -> Vec<(String, String, usize)> {
    let sources = crate_sources();
    let mut out = Vec::new();
    for module in SUBMODULES {
        let path = account_dir().join(format!("{module}.rs"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed.strip_prefix("pub fn ") else {
                // `pub async fn` too.
                let Some(rest) = trimmed.strip_prefix("pub async fn ") else {
                    continue;
                };
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    out.push((
                        module.to_string(),
                        name.clone(),
                        usize::from(is_used(&sources, &name)),
                    ));
                }
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push((
                    module.to_string(),
                    name.clone(),
                    usize::from(is_used(&sources, &name)),
                ));
            }
        }
    }
    out
}

/// Every public function is called from somewhere in the crate.
#[test]
fn every_account_function_has_a_caller() {
    let functions = public_functions();
    assert!(
        functions.len() > 100,
        "the scan found only {} functions; the submodules changed shape",
        functions.len()
    );

    // A definition counts as one occurrence (`name(`), so a function with a
    // single match has no caller.
    let uncalled: Vec<String> = functions
        .iter()
        .filter(|(_, _, used)| *used == 0)
        .map(|(module, name, _)| format!("{module}.{name}"))
        .collect();
    assert!(
        uncalled.is_empty(),
        "these account functions are public but never called: {uncalled:?}"
    );
}

/// Every submodule the module tree declares is in the list above.
///
/// A new submodule would otherwise be outside the audit silently.
#[test]
fn every_account_submodule_is_covered() {
    let declared: BTreeSet<String> = std::fs::read_to_string(account_dir().join("mod.rs"))
        .expect("read account/mod.rs")
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("pub mod ").or_else(|| {
                // `mod x;` is private but still a submodule worth auditing.
                trimmed.strip_prefix("mod ")
            })?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty() && rest.contains(';')).then_some(name)
        })
        .collect();

    let covered: BTreeSet<String> = SUBMODULES.iter().map(|m| m.to_string()).collect();

    let missing: Vec<&String> = declared.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "these account submodules are not in SUBMODULES, so their functions are unaudited: {missing:?}"
    );
}
