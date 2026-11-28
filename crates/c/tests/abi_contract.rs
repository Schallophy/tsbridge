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

const HEADER: &str = include_str!("../../../include/litespeak.h");
const IMPL: &str = include_str!("../src/lib.rs");
const CORE: &str = include_str!("../../core/src/lib.rs");

fn header_functions() -> BTreeSet<String> {
    const MARKER: &str = "LITESPEAK_CALL ";
    let mut names = BTreeSet::new();
    let mut rest = HEADER;
    while let Some(position) = rest.find(MARKER) {
        rest = &rest[position + MARKER.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // The typedef line is `LITESPEAK_CALL *LiteSpeakLogCallback`, which yields
        // an empty name; only real declarations start with `litespeak_`.
        if name.starts_with("litespeak_") {
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
        if name.starts_with("litespeak_") {
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
        "no LITESPEAK_CALL declarations found in the header"
    );

    let missing_impl: Vec<_> = header.difference(&impls).collect();
    assert!(
        missing_impl.is_empty(),
        "declared in include/litespeak.h but not implemented: {missing_impl:?}"
    );

    let missing_header: Vec<_> = impls.difference(&header).collect();
    assert!(
        missing_header.is_empty(),
        "exported from src/lib.rs but undocumented in include/litespeak.h: {missing_header:?}"
    );
}

#[test]
fn abi_version_matches_the_header() {
    // The value now lives in the core, which is where the JNI shim reads it
    // from too; this checks the C header agrees with *that* definition.
    let defined = CORE
        .split("pub const ABI_VERSION: u32 = ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("ABI_VERSION in crates/core/src/lib.rs");

    // `crates/c` must be re-exporting it rather than keeping a private copy.
    assert!(
        IMPL.contains("pub use litespeak_core::ABI_VERSION;"),
        "crates/c must re-export the core's ABI_VERSION, not define its own"
    );

    let documented = HEADER
        .split("#define LITESPEAK_ABI_VERSION ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("LITESPEAK_ABI_VERSION in include/litespeak.h");

    assert_eq!(
        defined, documented,
        "the header and the library disagree about the ABI version; a shell \
         comparing them would refuse to load the library it was built for"
    );
}

#[test]
fn the_jni_shim_exposes_the_abi_version() {
    // Android has no header to read; it asks the loaded library instead, so the
    // symbol has to exist or the whole check silently becomes "assume 1".
    const JNI: &str = include_str!("../../jni/src/lib.rs");
    assert!(
        JNI.contains("Java_dev_litespeak_core_Native_nativeAbiVersion"),
        "crates/jni must export nativeAbiVersion so Android can verify the ABI"
    );
}

#[test]
fn the_swift_wrapper_expects_the_same_abi() {
    // The Swift wrapper hard-codes the number it was written against — that is
    // the point of an expectation — but a hard-coded copy is also the easiest
    // thing to forget on a bump. This fails instead of shipping a package that
    // refuses to open every session.
    const SWIFT: &str = include_str!("../../../swift/Sources/LiteSpeak/LiteSpeak.swift");
    let expected = SWIFT
        .split("public let litespeakAbiVersion: UInt32 = ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("litespeakAbiVersion in swift/Sources/LiteSpeak/LiteSpeak.swift");

    assert_eq!(
        litespeak_core::ABI_VERSION,
        expected,
        "swift/Sources/LiteSpeak/LiteSpeak.swift expects a different ABI than the \
         core defines; `Bridge.init` would reject every library this crate builds"
    );
}

#[test]
fn every_place_that_names_the_abi_agrees() {
    // Four files carry the number and all four must match: the core (the
    // definition), the C header (which is the ABI), and the two wrappers whose
    // expectation is deliberately a literal — an expectation read from the
    // library it checks would always agree with itself. `tools/bump-abi.sh`
    // writes all four from the core; this test is what notices when someone
    // edits one by hand.
    let core = litespeak_core::ABI_VERSION;
    let header = HEADER
        .split("#define LITESPEAK_ABI_VERSION ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("LITESPEAK_ABI_VERSION in include/litespeak.h");
    assert_eq!(core, header, "include/litespeak.h disagrees with the core");

    const SWIFT: &str = include_str!("../../../swift/Sources/LiteSpeak/LiteSpeak.swift");
    let swift = SWIFT
        .split("public let litespeakAbiVersion: UInt32 = ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("litespeakAbiVersion in swift/Sources/LiteSpeak/LiteSpeak.swift");
    assert_eq!(core, swift, "the Swift wrapper disagrees with the core");
}

#[test]
fn every_declared_function_is_prefixed() {
    // A stray helper without the prefix would be exported on Windows (Rust's
    // cdylib exports every `no_mangle` symbol) and would not be in the version
    // script on Linux — the worst combination: works here, missing there.
    for name in implemented_functions() {
        assert!(
            name.starts_with("litespeak_"),
            "exported symbol `{name}` is outside the litespeak_ namespace"
        );
    }
}
