#!/usr/bin/env sh
# Keep every place that names the ABI version in step.
#
# The number is defined once, in `crates/core/src/lib.rs`. Three other files
# carry a copy, and all three have to agree or a shell refuses to load the
# library it was built for:
#
#   include/litespeak.h                       the C header, which *is* the ABI
#   swift/Sources/LiteSpeak/LiteSpeak.swift    the Swift wrapper's expectation
#   <android>/app/.../core/Native.kt         the Android expectation
#
# The last two are deliberately hard-coded literals: an expectation that read
# the value from the library it is checking would always agree with itself. So
# they cannot be removed — only kept in sync, which is what this script does.
#
# Usage:
#   tools/bump-abi.sh <number>   set the core to <number> and copy it everywhere
#   tools/bump-abi.sh            report any disagreement, change nothing
#
# The Android path is outside this repository (it consumes the submodule), so it
# is located relative to this checkout and skipped with a note when absent.
set -eu
cd "$(dirname "$0")/.."

CORE=crates/core/src/lib.rs
HEADER=include/litespeak.h
SWIFT=swift/Sources/LiteSpeak/LiteSpeak.swift
ANDROID=shells/android/app/src/main/kotlin/dev/litespeak/core/Native.kt

current() {
    sed -n 's/^pub const ABI_VERSION: u32 = \([0-9][0-9]*\);$/\1/p' "$CORE"
}

read_at() {
    # $1 = file, $2 = sed expression that captures the number
    [ -f "$1" ] || { echo ""; return; }
    sed -n "$2" "$1" | head -1
}

report() {
    echo "core     $CORE  -> $(current)"
    echo "header   $HEADER -> $(read_at "$HEADER" 's/^#define LITESPEAK_ABI_VERSION \([0-9][0-9]*\)$/\1/p')"
    echo "swift    $SWIFT  -> $(read_at "$SWIFT" 's/^public let litespeakAbiVersion: UInt32 = \([0-9][0-9]*\)$/\1/p')"
    if [ -f "$ANDROID" ]; then
        echo "android  $ANDROID -> $(read_at "$ANDROID" 's/.*EXPECTED_ABI: Int = \([0-9][0-9]*\).*/\1/p')"
    else
        echo "android  $ANDROID -> (not present)"
    fi
}

if [ $# -eq 0 ]; then
    report
    exit 0
fi

NEW=$1
case "$NEW" in
    ''|*[!0-9]*)
        echo "usage: $0 <number>" >&2
        exit 2
        ;;
esac

sed -i "s/^pub const ABI_VERSION: u32 = [0-9][0-9]*;$/pub const ABI_VERSION: u32 = $NEW;/" "$CORE"
sed -i "s/^#define LITESPEAK_ABI_VERSION [0-9][0-9]*$/#define LITESPEAK_ABI_VERSION $NEW/" "$HEADER"
sed -i "s/^public let litespeakAbiVersion: UInt32 = [0-9][0-9]*$/public let litespeakAbiVersion: UInt32 = $NEW/" "$SWIFT"
if [ -f "$ANDROID" ]; then
    sed -i "s/EXPECTED_ABI: Int = [0-9][0-9]*/EXPECTED_ABI: Int = $NEW/" "$ANDROID"
fi

echo "ABI is now $NEW"
report
