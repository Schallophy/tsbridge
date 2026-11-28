#!/usr/bin/env bash
# Builds a universal liblitespeak.dylib for macOS and packages it as the
# XCFramework that `swift/Package.swift` consumes.
#
#   ./tools/build-macos.sh
#
# Both architectures are built separately and joined with `lipo`: an Apple
# Silicon-only dylib would fail to load under Rosetta or on the last Intel Macs,
# and `cargo build --target ...` produces one arch at a time.
#
# The install name becomes `@rpath/liblitespeak.dylib` so the app can embed and
# sign it with its own Team ID. Cargo's default is an absolute path into this
# checkout, which loads on this machine and nowhere else.

set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

for target in "${TARGETS[@]}"; do
    rustup target add "$target" >/dev/null 2>&1 || true
    echo "building $target"
    cargo build --release --target "$target" -p litespeak
done

work=out/macos
rm -rf "$work"
mkdir -p "$work/include"
cp include/litespeak.h "$work/include/litespeak.h"
# An explicit module map keeps the Swift import name (`import litespeak`) fixed,
# instead of letting it derive from whatever the framework ends up being called.
cat > "$work/include/module.modulemap" <<'EOF'
module litespeak {
    header "litespeak.h"
    link "litespeak"
    export *
}
EOF

lipo -create \
    "target/aarch64-apple-darwin/release/liblitespeak.dylib" \
    "target/x86_64-apple-darwin/release/liblitespeak.dylib" \
    -output "$work/liblitespeak.dylib"

install_name_tool -id "@rpath/liblitespeak.dylib" "$work/liblitespeak.dylib"

# SwiftPM needs a binary *target*: a bare `-l` flag would require unsafeFlags,
# and a package with unsafeFlags cannot be consumed as a dependency.
rm -rf swift/Vendor/litespeak.xcframework
mkdir -p swift/Vendor
xcodebuild -create-xcframework \
    -library "$work/liblitespeak.dylib" \
    -headers "$work/include" \
    -output swift/Vendor/litespeak.xcframework

echo "built: swift/Vendor/litespeak.xcframework"
echo "next: cd swift && swift build"
