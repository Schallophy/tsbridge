//! Limits the dynamic symbol table of the shared library to the C ABI.
//!
//! Without this, ELF `.so` files export every reachable symbol from the
//! statically linked dependencies as well; the version script also gives
//! `libtsbridge.so` a stable `soname`, so a shell linked against `libtsbridge.so.1`
//! keeps working across patch releases.
//!
//! The export list is *read out of `include/tsbridge.h`* rather than kept in a
//! second list here. A header that documents a function the library does not
//! export, or a function that is exported but undocumented, then shows up as a
//! link error or a missing entry instead of a toolchain-specific surprise on one
//! platform.
//!
//! Windows is the exception: it has no linker version script, so its export
//! table is whatever the toolchain decides and can be a superset of the header.
//! The Linux CI job is the one that compares the exact set.

/// Every `TSBRIDGE_CALL tsbridge_…` name in the public header.
fn exports_from_header(header: &str) -> Vec<String> {
    const MARKER: &str = "TSBRIDGE_CALL ";
    let mut names = Vec::new();
    let mut rest = header;
    while let Some(position) = rest.find(MARKER) {
        rest = &rest[position + MARKER.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if let Some(prefix) = name.strip_prefix("tsbridge_") {
            debug_assert!(!prefix.is_empty());
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    names
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let header_path = std::path::Path::new(&manifest).join("../../include/tsbridge.h");
    println!("cargo:rerun-if-changed={}", header_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let header = std::fs::read_to_string(&header_path).expect("read include/tsbridge.h");
    let exports = exports_from_header(&header);
    assert!(
        !exports.is_empty(),
        "include/tsbridge.h declares no tsbridge_* functions; the version script would hide everything"
    );

    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let map = std::path::Path::new(&out).join("tsbridge.map");

    let mut script = String::from("{\n  global:\n");
    for name in &exports {
        script.push_str(&format!("    {name};\n"));
    }
    script.push_str("  local:\n    *;\n};\n");
    std::fs::write(&map, script).expect("write version script");

    // `-cdylib`, not the plain `rustc-link-arg`: that one also applies to test
    // binaries, and an integration test does not contain the exported functions
    // -- the linker then fails with `version script assignment ... symbol not
    // defined` for every name in the header. The staticlib (the other
    // crate-type here) is unaffected either way: a `.a` has no dynamic symbol
    // table to restrict.
    println!(
        "cargo:rustc-link-arg-cdylib=-Wl,--version-script={}",
        map.display()
    );
    println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,libtsbridge.so.1");
}
