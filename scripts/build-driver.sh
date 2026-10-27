#!/usr/bin/env bash
# Builds corten-driver on the nightly pinned in crates/corten-lints (installing
# that toolchain if needed) and prints the binary's path on stdout.
# `cargo corten check` and `build` require it (owner decision 10): put it
# beside cargo-corten or point CORTEN_DRIVER at it.
#
# Usage: scripts/build-driver.sh [--release]
set -euo pipefail
cd "$(dirname "$0")/../crates/corten-lints"
profile=debug
for arg in "$@"; do
    [ "$arg" = --release ] && profile=release
done
# Reads rust-toolchain.toml in this directory.
rustup toolchain install >&2
# An explicit target directory, so CARGO_TARGET_DIR cannot move the binary.
cargo build --locked --target-dir "$PWD/target" "$@" >&2
printf '%s\n' "$PWD/target/$profile/corten-driver"
