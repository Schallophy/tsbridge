#!/usr/bin/env bash
# Builds liblitespeak.so for Linux (x86_64 and aarch64) and a Windows DLL is
# produced by plain `cargo build --release` on Windows.
#
#   ./tools/build-linux.sh
#
# The version script in `crates/c/build.rs` gives the .so the soname
# `liblitespeak.so.1` and hides every symbol that is not part of the C ABI, so the
# copies here are the files a distro package or an AppImage should ship.

set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)

for target in "${TARGETS[@]}"; do
    rustup target add "$target" >/dev/null 2>&1 || true
    echo "building $target"
    cargo build --release --target "$target" -p litespeak
done

mkdir -p out/linux
for target in "${TARGETS[@]}"; do
    mkdir -p "out/linux/$target"
    cp "target/$target/release/liblitespeak.so" "out/linux/$target/liblitespeak.so"
    # The soname is what a linked binary records; ship it under both names so
    # the loader resolves the dependency without a symlink farm.
    cp "target/$target/release/liblitespeak.so" "out/linux/$target/liblitespeak.so.1"
    echo "built: out/linux/$target/liblitespeak.so"
done
