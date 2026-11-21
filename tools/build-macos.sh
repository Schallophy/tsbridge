#!/usr/bin/env bash
# Builds a universal libtsbridge.dylib for macOS and packages it as the
# XCFramework that `swift/Package.swift` consumes.
#
#   ./tools/build-macos.sh
#
# Both architectures are built separately and joined with `lipo`: an Apple
# Silicon-only dylib would fail to load under Rosetta or on the last Intel Macs,
# and `cargo build --target ...` produces one arch at a time.
#
# The install name becomes `@rpath/libtsbridge.dylib` so the app can embed and
# sign it with its own Team ID. Cargo's default is an absolute path into this
# checkout, which loads on this machine and nowhere else.

set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

for target in "${TARGETS[@]}"; do
    rustup target add "$target" >/dev/null 2>&1 || true
    echo "building $target"
    cargo build --release --target "$target" -p tsbridge
done

work=out/macos
rm -rf "$work"
mkdir -p "$work/include"
cp include/tsbridge.h "$work/include/tsbridge.h"
# An explicit module map keeps the Swift import name (`import tsbridge`) fixed,
# instead of letting it derive from whatever the framework ends up being called.
cat > "$work/include/module.modulemap" <<'EOF'
module tsbridge {
    header "tsbridge.h"
    link "tsbridge"
    export *
}
EOF

lipo -create \
    "target/aarch64-apple-darwin/release/libtsbridge.dylib" \
    "target/x86_64-apple-darwin/release/libtsbridge.dylib" \
    -output "$work/libtsbridge.dylib"

install_name_tool -id "@rpath/libtsbridge.dylib" "$work/libtsbridge.dylib"

# SwiftPM needs a binary *target*: a bare `-l` flag would require unsafeFlags,
# and a package with unsafeFlags cannot be consumed as a dependency.
rm -rf swift/Vendor/tsbridge.xcframework
mkdir -p swift/Vendor
xcodebuild -create-xcframework \
    -library "$work/libtsbridge.dylib" \
    -headers "$work/include" \
    -output swift/Vendor/tsbridge.xcframework

echo "built: swift/Vendor/tsbridge.xcframework"
echo "next: cd swift && swift build"
