#!/usr/bin/env sh
# Format our crates only. The vendored tsclientlib is upstream's code with
# upstream's formatting, and rewriting it would make every future rebase a
# merge conflict in every file.
set -eu
cd "$(dirname "$0")/.."
cargo fmt -p tsbridge-core -p tsbridge -p tsbridge-jni -p tsbridge-cli -p tsbridge-account-demo "$@"
