//! Keeps the C header and the implementation from drifting apart.
//!
//! The header *is* the ABI: `crates/c/build.rs` derives the Linux version script
//! from it, and every shell compiles against it. So both directions have to hold:
//!
//! * a function declared in the header must exist in `src/lib.rs`, or the shell
//!   links against something that is not there;
//! * a function exported in `src/lib.rs` must be declared in the header, or it is
//!   only reachable by someone who read the source — and it will not be in the
//!   version script, so on Linux it is not exported at all.
//!
//! This scans source text rather than using `bindgen`/`ctest` because it has to
//! run on four platforms with no extra tooling, and because the alternative —
//! generating the header — would lose the comments that explain the JSON shapes.

use std::collections::BTreeSet;

const HEADER: &str = include_str!("../../../include/tsbridge.h");
const IMPL: &str = include_str!("../src/lib.rs");

fn header_functions() -> BTreeSet<String> {
    const MARKER: &str = "TSBRIDGE_CALL ";
    let mut names = BTreeSet::new();
    let mut rest = HEADER;
    while let Some(position) = rest.find(MARKER) {
        rest = &rest[position + MARKER.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // The typedef line is `TSBRIDGE_CALL *TsBridgeLogCallback`, which yields
        // an empty name; only real declarations start with `tsbridge_`.
        if name.starts_with("tsbridge_") {
            names.insert(name);
        }
    }
    names
}

fn implemented_functions() -> BTreeSet<String> {
    const MARKER: &str = "pub extern \"C\" fn ";
    let mut names = BTreeSet::new();
    let mut rest = IMPL;
    while let Some(position) = rest.find(MARKER) {
        rest = &rest[position + MARKER.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.starts_with("tsbridge_") {
            names.insert(name);
        }
    }
    names
}

#[test]
fn header_and_implementation_declare_the_same_functions() {
    let header = header_functions();
    let impls = implemented_functions();

    assert!(
        !header.is_empty(),
        "no TSBRIDGE_CALL declarations found in the header"
    );

    let missing_impl: Vec<_> = header.difference(&impls).collect();
    assert!(
        missing_impl.is_empty(),
        "declared in include/tsbridge.h but not implemented: {missing_impl:?}"
    );

    let missing_header: Vec<_> = impls.difference(&header).collect();
    assert!(
        missing_header.is_empty(),
        "exported from src/lib.rs but undocumented in include/tsbridge.h: {missing_header:?}"
    );
}

#[test]
fn abi_version_matches_the_header() {
    let defined = IMPL
        .split("pub const ABI_VERSION: u32 = ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("ABI_VERSION in src/lib.rs");

    let documented = HEADER
        .split("#define TSBRIDGE_ABI_VERSION ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("TSBRIDGE_ABI_VERSION in include/tsbridge.h");

    assert_eq!(
        defined, documented,
        "the header and the library disagree about the ABI version; a shell \
         comparing them would refuse to load the library it was built for"
    );
}

#[test]
fn every_declared_function_is_prefixed() {
    // A stray helper without the prefix would be exported on Windows (Rust's
    // cdylib exports every `no_mangle` symbol) and would not be in the version
    // script on Linux — the worst combination: works here, missing there.
    for name in implemented_functions() {
        assert!(
            name.starts_with("tsbridge_"),
            "exported symbol `{name}` is outside the tsbridge_ namespace"
        );
    }
}
