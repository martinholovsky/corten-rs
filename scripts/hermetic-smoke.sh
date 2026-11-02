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

# The operator's dependency policy (deny by default): it admits the stub, so
# the sandbox, not the policy, is what stops the hostile build scripts.
policy="$work/operator.policy"
printf 'corten-dep-policy 1\nallow hostile\n' > "$policy"

corten_build() { # dir, extra args...
    local dir=$1; shift
    (cd "$dir" && CARGO="$cargo_bin" CORTEN_SANDBOX="$bin_dir/corten-sandbox" CORTEN_DEP_POLICY="$policy" "$bin_dir/cargo-corten" corten build "$@")
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

# 4. A build script that rewrites another dependency's vendored source (F5,
# docs/gates/phase-6.md). `rewriter`'s build script edits its sibling
# `victim`, which depends on it and so compiles after it. Plain cargo uses
# the rewritten source; inside the sandbox the vendored sources are
# read-only, so the rewrite fails and the binary keeps the original code.
tamper=$work/tamper
mkdir -p "$tamper/src" "$tamper/vendor/rewriter/src" "$tamper/vendor/victim/src" "$tamper/.cargo"
printf '[package]\nname = "tamper"\nversion = "0.1.0"\nedition = "2024"\n\n[workspace]\n\n[dependencies]\nvictim = "1.0.0"\nrewriter = "1.0.0"\n' > "$tamper/Cargo.toml"
printf 'fn main() {\n    println!("victim={} rewrite={}", victim::v(), rewriter::RESULT);\n}\n' > "$tamper/src/main.rs"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "%s"\n' "$tamper/vendor" > "$tamper/.cargo/config.toml"
printf '[package]\nname = "rewriter"\nversion = "1.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$tamper/vendor/rewriter/Cargo.toml"
# The build script's result is compiled in, since cargo hides build-script
# warnings of non-path dependencies.
printf 'pub const RESULT: &str = env!("REWRITE_RESULT");\n' > "$tamper/vendor/rewriter/src/lib.rs"
cat > "$tamper/vendor/rewriter/build.rs" <<'RS'
fn main() {
    let here = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    for name in ["victim-1.0.0", "victim"] {
        let target = here.parent().unwrap().join(name).join("src/lib.rs");
        if target.is_file() {
            let r = std::fs::write(&target, "pub fn v() -> u32 { 666 }\n");
            println!("cargo:rustc-env=REWRITE_RESULT={:?}", r.map_err(|e| e.kind()));
            return;
        }
    }
    println!("cargo:rustc-env=REWRITE_RESULT=victim not found");
}
RS
printf '[package]\nname = "victim"\nversion = "1.0.0"\nedition = "2021"\n\n[dependencies]\nrewriter = "1.0.0"\n' > "$tamper/vendor/victim/Cargo.toml"
printf 'pub fn v() -> u32 { 1 }\n' > "$tamper/vendor/victim/src/lib.rs"
for crate in rewriter victim; do
    printf '{"files":{},"package":null}' > "$tamper/vendor/$crate/.cargo-checksum.json"
done
(cd "$tamper" && "$cargo_bin" generate-lockfile -q)
cp -a "$tamper/vendor" "$work/tamper-vendor-pristine"
(cd "$tamper" && "$cargo_bin" build -q --release) || fail "control: plain cargo build of the rewriting build script failed"
out=$("$tamper/target/release/tamper")
[ "$out" = "victim=666 rewrite=Ok(())" ] || fail "control: plain cargo did not use the rewritten source: $out"
rm -rf "$tamper/target" "$tamper/vendor"
cp -a "$work/tamper-vendor-pristine" "$tamper/vendor"
printf 'corten-dep-policy 1\nallow hostile\nallow rewriter\nallow victim\n' > "$policy"
corten_build "$tamper" 2>"$work/tamper.err" || fail "tamper build failed: $(tail -3 "$work/tamper.err")"
out=$("$tamper/target/release/tamper")
[ "$out" = "victim=1 rewrite=Err(PermissionDenied)" ] || fail "the vendored source was not protected: $out"
echo "ok 4 rewrite of another dependency's vendored source refused"
