#!/usr/bin/env bash
# Decides whether a CI run needs the heavy test steps (nextest, the corpus,
# the hermetic smoke test, the Action self-test). Writes heavy=true or
# heavy=false to $GITHUB_OUTPUT and always prints the reason and the files
# it read, so a skipped step is never mistaken for a pass.
#
# Only a pull request can skip, and only when EVERY changed file is prose on
# the allowlist below. Anything else (an unknown path, an empty diff, a
# failed merge base, a push, a tag, the schedule, a manual run) is a full
# run. The cheap whole-tree checks (ledger, generated docs, applicability)
# never consult this script and always run. Unscoped runs behind it: every
# push to main, the weekly schedule, every v* tag (no caches) and manual
# runs (sota-devsecops rules/16 section 16.3).
#
# Usage: scripts/ci-scope.sh             (in CI; reads GITHUB_EVENT_NAME, GITHUB_BASE_REF)
#        scripts/ci-scope.sh --self-test (known-bad cases; exits 1 on any miss)
set -euo pipefail

# A changed path that cannot affect a heavy step: prose documentation.
# Generated docs live here too, and the cheap steps that always run check
# them. Crate READMEs are NOT listed: a crate may include its README.
is_prose() {
    # In `case`, `*` also matches `/`, so each docs pattern checks that the
    # rest of the path is a single file name, one level deep.
    local rest
    case $1 in
        README.md | CHANGELOG.md | AGENTS.md | CLAUDE.md | LICENSE-APACHE | LICENSE-MIT) return 0 ;;
        docs/gates/*.md) rest=${1#docs/gates/} ;;
        docs/*.md) rest=${1#docs/} ;;
        # Images only, any depth; the generated chart is checked by a cheap
        # step that always runs.
        docs/assets/*) return 0 ;;
        *) return 1 ;;
    esac
    [[ $rest != */* ]]
}

# Reads one path per line on stdin; prints "heavy" or "light" and the reason.
classify() {
    local path count=0 first_code=""
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        if [ -z "$first_code" ] && ! is_prose "$path"; then
            first_code=$path
        fi
    done
    if [ "$count" -eq 0 ]; then
        echo "heavy no changed files read: run everything"
    elif [ -n "$first_code" ]; then
        echo "heavy $count changed file(s), at least one outside the prose allowlist: $first_code"
    else
        echo "light all $count changed file(s) are prose on the allowlist"
    fi
}

self_test() {
    local failures=0 got want name
    check() { # name want files...
        name=$1 want=$2
        shift 2
        got=$(printf '%s\n' "$@" | classify | cut -d' ' -f1)
        if [ "$got" = "$want" ]; then
            echo "ok   $name"
        else
            echo "FAIL $name: wanted $want, got $got"
            failures=$((failures + 1))
        fi
    }
    check "docs only" light docs/netcap.md README.md
    check "gate report" light docs/gates/phase-6.md
    check "one crate file among docs" heavy docs/spec.md crates/corten-std/src/net.rs
    check "ledger change (the corpus reads it)" heavy ledger/cwe-ledger.csv
    check "corpus case" heavy corpus/CWE-22/good.rs
    check "workflow change" heavy .github/workflows/ci.yml
    check "lockfile" heavy Cargo.lock
    check "crate README (may be included)" heavy crates/cargo-corten/README.md
    check "markdown outside docs/" heavy corpus/README.md
    check "unknown top-level file" heavy rust-toolchain.toml
    check "nested docs path not on the list" heavy docs/sub/dir/x.md
    check "a path that only looks like docs" heavy docs.md.rs
    check "empty diff" heavy ""
    if [ "$failures" -ne 0 ]; then
        echo "ci-scope self-test: $failures failure(s)" >&2
        return 1
    fi
    echo "ci-scope self-test: all cases passed"
}

main() {
    if [ "${1:-}" = "--self-test" ]; then
        self_test
        return
    fi
    local out=${GITHUB_OUTPUT:-/dev/stdout} event=${GITHUB_EVENT_NAME:-unknown} decision files
    if [ "$event" != "pull_request" ]; then
        echo "scope: full run (event $event is never scoped)"
        echo "heavy=true" >>"$out"
        return
    fi
    if ! git fetch --no-tags --quiet origin "${GITHUB_BASE_REF:?}" ||
        ! files=$(git diff --name-only "origin/${GITHUB_BASE_REF}...HEAD"); then
        echo "scope: full run (could not compute the diff against ${GITHUB_BASE_REF})"
        echo "heavy=true" >>"$out"
        return
    fi
    echo "scope: changed files against origin/${GITHUB_BASE_REF}:"
    printf '%s\n' "$files" | sed 's/^/  /'
    decision=$(printf '%s\n' "$files" | classify)
    echo "scope: ${decision#* }"
    if [ "${decision%% *}" = light ]; then
        echo "heavy=false" >>"$out"
    else
        echo "heavy=true" >>"$out"
    fi
}

main "$@"
