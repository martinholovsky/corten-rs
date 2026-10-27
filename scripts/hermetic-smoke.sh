#!/usr/bin/env bash
# Smoke test for `cargo corten build` (Linux): a benign crate builds and its
# provenance digest matches the binary; a build script that opens a TCP
# connection or writes outside the target directory fails inside the sandbox.
# The hostile build scripts belong to a dependency: the profile lints the
# workspace, so only a dependency's build script reaches the sandbox.
# Each hostile case first shows plain `cargo build` lets the build script do it.
#
# Usage: scripts/hermetic-smoke.sh <dir with cargo-corten and corten-sandbox>
set -euo pipefail
# Each test crate builds into its own target/.
unset CARGO_TARGET_DIR

bin_dir=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# The real toolchain cargo, as `cargo corten` sees it (not the rustup proxy).
cargo_bin=$(rustup which cargo)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

new_crate() { # name hostile_build_rs_body (empty: no dependency)
    local dir="$work/$1"
    mkdir -p "$dir/src"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n\n[workspace]\n' "$1" > "$dir/Cargo.toml"
    printf 'fn main() {\n    println!("hello");\n}\n' > "$dir/src/main.rs"
    if [ -n "$2" ]; then
        # The hostile build script lives in a dependency, which cargo builds
        # with --cap-lints allow: the profile's lints never see it, only the
        # sandbox stands between it and the machine.
        local dep="$dir/vendor/hostile"
        mkdir -p "$dep/src"
        printf '[package]\nname = "hostile"\nversion = "1.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$dep/Cargo.toml"
        printf 'pub fn noop() {}\n' > "$dep/src/lib.rs"
        printf '%s\n' "$2" > "$dep/build.rs"
        printf '{"files":{},"package":null}' > "$dep/.cargo-checksum.json"
        printf '\n[dependencies]\nhostile = "1.0.0"\n' >> "$dir/Cargo.toml"
        mkdir -p "$dir/.cargo"
        printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s"\n' "$dir/vendor" > "$dir/.cargo/config.toml"
    fi
    (cd "$dir" && "$cargo_bin" generate-lockfile -q)
    printf '%s\n' "$dir"
}

corten_build() { # dir, extra args...
    local dir=$1; shift
    (cd "$dir" && CARGO="$cargo_bin" CORTEN_SANDBOX="$bin_dir/corten-sandbox" "$bin_dir/cargo-corten" corten build "$@")
}

# 1. Benign crate: builds; the provenance digest matches.
ok=$(new_crate benign "")
corten_build "$ok" --sbom "$work/sbom.json" --provenance "$work/prov.json" || fail "benign build failed"
want=$(sha256sum "$ok/target/release/benign" | cut -d' ' -f1)
grep -q "\"sha256\":\"$want\"" "$work/prov.json" || fail "provenance digest does not match the binary"
grep -q '"purl":"pkg:cargo/benign@0.1.0"' "$work/sbom.json" || fail "SBOM lacks the package"
grep -q '"sandboxed":true' "$work/prov.json" || fail "provenance does not record the sandbox"
echo "ok 1 benign build, digest $want"

# 2. A build script that connects to the network.
listener_port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',$listener_port));s.listen();time.sleep(120)" &
listener=$!
trap 'kill "$listener" 2>/dev/null; rm -rf "$work"' EXIT
sleep 0.5
net=$(new_crate net "fn main() { std::net::TcpStream::connect(\"127.0.0.1:$listener_port\").expect(\"build script connect\"); }")
(cd "$net" && "$cargo_bin" build -q --release) || fail "control: plain cargo build of the network build script failed"
rm -rf "$net/target"
if corten_build "$net" 2>"$work/net.err"; then fail "network build script was not stopped"; fi
grep -q "build script connect" "$work/net.err" || fail "network build failed for another reason: $(tail -3 "$work/net.err")"
echo "ok 2 network refused in build script"

# 3. A build script that writes outside the target directory.
victim="$work/victim.txt"
wr=$(new_crate writer "fn main() { std::fs::write(\"$victim\", \"x\").expect(\"build script write\"); }")
(cd "$wr" && "$cargo_bin" build -q --release) || fail "control: plain cargo build of the writing build script failed"
[ -f "$victim" ] || fail "control: the build script did not write"
rm -f "$victim"; rm -rf "$wr/target"
if corten_build "$wr" 2>"$work/wr.err"; then fail "writing build script was not stopped"; fi
[ ! -f "$victim" ] || fail "the build script wrote outside the target directory"
grep -q "build script write" "$work/wr.err" || fail "write build failed for another reason: $(tail -3 "$work/wr.err")"
echo "ok 3 write outside target refused"
