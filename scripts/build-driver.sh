#!/usr/bin/env bash
# Builds corten-driver on the nightly pinned in crates/corten-lints (installing
# that toolchain if needed) and prints the binary's path on stdout.
# `cargo corten check` and `build` require it (owner decision 10). No release
# pins a driver built here, so pass it as `cargo corten check --unpinned-driver
# PATH` (owner decision 2026-11-22).
#
# Usage: scripts/build-driver.sh [--release]
set -euo pipefail
cd "$(dirname "$0")/../crates/corten-lints"
# Run from inside cargo (the checker's tests call this script when no driver is
# built), rustup's RUSTUP_TOOLCHAIN and cargo's RUSTC/RUSTDOC name the outer
# toolchain and override rust-toolchain.toml; the build then fails on stable
# with "can't find crate for `rustc_driver`" (seen 2026-11-26).
unset RUSTUP_TOOLCHAIN RUSTC RUSTDOC
profile=debug
for arg in "$@"; do
    [ "$arg" = --release ] && profile=release
done
# Reads rust-toolchain.toml in this directory.
rustup toolchain install >&2
# An explicit target directory, so CARGO_TARGET_DIR cannot move the binary.
# CORTEN_LINTS_TARGET_DIR overrides it, e.g. for a container sharing this
# checkout with the host, whose binary it would otherwise overwrite.
target=${CORTEN_LINTS_TARGET_DIR:-$PWD/target}
cargo build --locked --target-dir "$target" "$@" >&2
printf '%s\n' "$target/$profile/corten-driver"
