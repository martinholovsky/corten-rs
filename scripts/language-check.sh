#!/usr/bin/env bash
# Checks the CWE applicability programs of one comparison language
# (audit/languages/<lang>/) against that language's pinned toolchain, and
# prints one verdict per CWE, derived from the programs, never typed by hand.
# It is the counterpart of scripts/applicability-check.sh, which does the
# same for Rust.
#
# Each file is CWE-<n>.<ext> or CWE-<n>.<variant>.<ext> and carries one
# header in its first lines:
#   // @compiles              must compile
#   // @rejected: <text>      must fail, with <text> in the compiler's output
# Verdict per CWE: writable if any `compiles` file passes; rejected if only
# `rejected` files exist and all pass. A file whose expectation fails makes
# the run fail. Compiling proves a form can be written; whether the program
# exhibits the weakness is the judgement stated in its comment.
#
# Toolchains (the CI job runs inside the same image, pinned by digest):
#   c    gcc -std=c17 -pedantic-errors -c, in docker.io/library/gcc:15.
#        Locally (programs are compiled, never run; the container still gets
#        no network, no capabilities and a read-only root):
#          podman run --rm --network=none --cap-drop=ALL \
#            --security-opt=no-new-privileges --read-only --tmpfs /tmp \
#            -v "$PWD":/src:ro -w /src \
#            docker.io/library/gcc@sha256:3a49295e08ff62055af03114fd1162403c7613f91b18b10da72b352ed9ea375b \
#            bash scripts/language-check.sh c
#        CC overrides the compiler.
#
# Usage: scripts/language-check.sh <lang> [CWE-n ...]
set -euo pipefail

usage() { echo "usage: $0 <c> [CWE-n ...]" >&2; exit 2; }
[ "$#" -ge 1 ] || usage
lang=$1
shift
case "$lang" in
    c) ext=c ;;
    *) usage ;;
esac

dir="$(cd "$(dirname "$0")/.." && pwd)/audit/languages/$lang"
[ -d "$dir" ] || { echo "no directory $dir" >&2; exit 2; }
cd "$dir"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

compile() {
    case "$lang" in
        c) "${CC:-gcc}" -std=c17 -pedantic-errors -c -o "$work/out.o" "$1" >"$work/log" 2>&1 ;;
    esac
}

selected=()
if [ "$#" -gt 0 ]; then
    for c in "$@"; do
        for f in "$c.$ext" "$c".*."$ext"; do [ -f "$f" ] && selected+=("$f"); done
    done
else
    for f in CWE-*."$ext"; do [ -f "$f" ] && selected+=("$f"); done
fi
[ "${#selected[@]}" -gt 0 ] || { echo "no programs found in $dir" >&2; exit 2; }

declare -A writable rejected
failures=0
files=0
for f in "${selected[@]}"; do
    files=$((files + 1))
    cwe=${f%%.*}
    header=$(grep -m1 -E '^// @(compiles|rejected:)' "$f" || true)
    case "$header" in
        "// @compiles")
            if compile "$f"; then writable[$cwe]=1
            else echo "FAIL $f: expected to compile"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        "// @rejected: "*)
            want=${header#// @rejected: }
            if ! compile "$f" && grep -qF -- "$want" "$work/log"; then rejected[$cwe]=1
            else echo "FAIL $f: expected the compiler to reject it with '$want'"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        *)
            echo "FAIL $f: no // @compiles or // @rejected: header"; failures=$((failures + 1)) ;;
    esac
done

cwes=$(printf '%s\n' "${selected[@]}" | sed 's/\..*//' | sort -u -t- -k2,2n)
n_writable=0 n_rejected=0 n_open=0
for c in $cwes; do
    if [ -n "${writable[$c]:-}" ]; then v=writable; n_writable=$((n_writable + 1))
    elif [ -n "${rejected[$c]:-}" ]; then v=rejected; n_rejected=$((n_rejected + 1))
    else v=undecided; n_open=$((n_open + 1)); fi
    printf '%s\t%s\n' "$c" "$v"
done
echo "$lang: files: $files  CWEs: $(printf '%s\n' "$cwes" | grep -c .)  writable: $n_writable  rejected: $n_rejected  undecided: $n_open  failing files: $failures" >&2
[ "$failures" -eq 0 ]
