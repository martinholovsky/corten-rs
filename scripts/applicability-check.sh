#!/usr/bin/env bash
# Checks every program in audit/applicability/ against stock rustc and prints
# one verdict per CWE, derived from the programs, never typed by hand.
#
# Each file is CWE-<n>.rs or CWE-<n>.<variant>.rs and carries one header:
#   //@ compiles: safe      must compile with -F unsafe_code (safe Rust)
#   //@ compiles: unsafe    must compile, and must FAIL with -F unsafe_code
#   //@ rejected: <text>    must fail, with <text> in rustc's output
# Verdict per CWE: safe if any `compiles: safe` file passes; else unsafe-only
# if a `compiles: unsafe` file passes and a `rejected` file shows the safe
# attempt fails; else rejected if only `rejected` files exist. A file whose
# expectation fails makes the run fail.
#
# Compiling proves a form can be written. Whether the program exhibits the
# weakness is a judgement, stated in the file's comment, for review.
#
# Usage: scripts/applicability-check.sh [CWE-n ...]
#   With CWE ids, checks only those; RUSTC overrides the compiler (default:
#   rustc on PATH, i.e. the toolchain pinned in rust-toolchain.toml).
set -euo pipefail
rustc=${RUSTC:-rustc}
cd "$(dirname "$0")/../audit/applicability"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

declare -A safe unsafe_ok rejected
failures=0
files=0
if [ "$#" -gt 0 ]; then
    selected=()
    for c in "$@"; do
        for f in "$c".rs "$c".*.rs; do [ -f "$f" ] && selected+=("$f"); done
    done
else
    selected=(CWE-*.rs)
fi
[ "${#selected[@]}" -gt 0 ] || { echo "no programs found" >&2; exit 2; }
for f in "${selected[@]}"; do
    files=$((files + 1))
    cwe=${f%%.*}
    header=$(grep -m1 -E '^//@ (compiles|rejected):' "$f" || true)
    # Variants carry dots in the file name, which rustc refuses as a crate name.
    crate=$(printf '%s' "${f%.rs}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '_')
    compile() { "$rustc" --edition 2024 --crate-type lib --crate-name "$crate" --emit=metadata -o "$work/out.rmeta" "$@" "$f" >"$work/log" 2>&1; }
    case "$header" in
        "//@ compiles: safe")
            if compile -F unsafe_code; then safe[$cwe]=1
            else echo "FAIL $f: expected to compile as safe Rust"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        "//@ compiles: unsafe")
            if compile && ! compile -F unsafe_code; then unsafe_ok[$cwe]=1
            else echo "FAIL $f: expected to compile only with unsafe"; failures=$((failures + 1)); fi ;;
        "//@ rejected: "*)
            want=${header#//@ rejected: }
            if ! compile && grep -qF -- "$want" "$work/log"; then rejected[$cwe]=1
            else echo "FAIL $f: expected rustc to reject it with '$want'"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        *)
            echo "FAIL $f: no //@ compiles: or //@ rejected: header"; failures=$((failures + 1)) ;;
    esac
done

cwes=$(printf '%s\n' "${selected[@]}" | sed 's/\..*//' | sort -u -t- -k2,2n)
n_safe=0 n_unsafe=0 n_rejected=0 n_open=0
for c in $cwes; do
    if [ -n "${safe[$c]:-}" ]; then v=safe; n_safe=$((n_safe + 1))
    elif [ -n "${unsafe_ok[$c]:-}" ] && [ -n "${rejected[$c]:-}" ]; then v=unsafe-only; n_unsafe=$((n_unsafe + 1))
    elif [ -n "${rejected[$c]:-}" ] && [ -z "${unsafe_ok[$c]:-}" ]; then v=rejected; n_rejected=$((n_rejected + 1))
    else v=undecided; n_open=$((n_open + 1)); fi
    printf '%s\t%s\n' "$c" "$v"
done
echo "files: $files  CWEs: $(printf '%s\n' "$cwes" | grep -c .)  safe: $n_safe  unsafe-only: $n_unsafe  rejected: $n_rejected  undecided: $n_open  failing files: $failures" >&2
[ "$failures" -eq 0 ]
