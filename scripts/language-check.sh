#!/usr/bin/env bash
# Checks the CWE applicability programs of one comparison language
# (audit/languages/<lang>/) against that language's pinned toolchain, and
# prints one verdict per CWE, derived from the programs, never typed by hand.
# It is the counterpart of scripts/applicability-check.sh, which does the
# same for Rust.
#
# Each file is CWE-<n>.<ext> or CWE-<n>.<variant>.<ext> and carries one
# header in its first lines (// or # as the language comments):
#   // @compiles              must compile without the escape hatch
#   // @compiles: hatch       must compile and use the escape hatch
#   // @rejected: <text>      must fail, with <text> in the compiler's output
# The escape hatch is what Rust's `unsafe` is to safe Rust: Java's JNI
# (native methods), java.lang.foreign and the jdk.unsupported sun.misc
# classes (Unsafe, Signal); Go's unsafe package and cgo (import "C");
# Python's ctypes. C and C++ have
# none. Verdict per CWE: writable if a `compiles` file passes; hatch-only if
# a `compiles: hatch` file passes and a `rejected` file shows the plain form
# fails; rejected if only `rejected` files exist. A file whose expectation
# fails makes the run fail. Compiling proves a form can be written; whether the program
# exhibits the weakness is the judgement stated in its comment.
#
# Toolchains (the CI job runs inside the same image, pinned by digest):
#   c    gcc -std=c17 -pedantic-errors -c, in docker.io/library/gcc:15 (gcc
#        15.3.0), pinned by the multi-arch index digest recorded 2026-11-10;
#        GCC 15 branch end of life: not looked up, check before bumping.
#        Locally (programs are compiled, never run; the container still gets
#        no network, no capabilities and a read-only root):
#          podman run --rm --network=none --cap-drop=ALL \
#            --security-opt=no-new-privileges --read-only --tmpfs /tmp \
#            -v "$PWD":/src:ro -w /src \
#            docker.io/library/gcc@sha256:51d7ef77d4e5ca232d635ce4a2a3154f18f9ccd01542a14bc06794e853ffddb9 \
#            bash scripts/language-check.sh c
#        CC overrides the compiler.
#   cpp  g++ -std=c++20 -pedantic-errors -c, in the same image (g++ 15.3.0);
#        run as for c with "cpp". CXX overrides the compiler.
#   java javac 25.0.5 (-Xlint:none), in docker.io/library/eclipse-temurin:25-jdk
#        pinned by its multi-arch index digest recorded 2026-11-10 (JDK 25 is
#        an LTS release; its end of life was not looked up). Locally, as for c
#        with that image and "java":
#          docker.io/library/eclipse-temurin@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507
#        JAVAC overrides the compiler.
#   go   go build (go1.27.4, GOTOOLCHAIN=local, cgo with the image's gcc), in
#        docker.io/library/golang:1 pinned by its multi-arch index digest
#        recorded 2026-11-10 (end of life not looked up). Locally, as for c
#        with that image and "go":
#          docker.io/library/golang@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0
#        GO overrides the toolchain.
#   python  compile() of the source by Python 3.15.2 (syntax and symbol-table
#        errors only; warnings do not count), in docker.io/library/python:3
#        pinned by its multi-arch index digest recorded 2026-11-10 (end of
#        life not looked up). Locally, as for c with that image and "python":
#          docker.io/library/python@sha256:8c9a3bf2d6dea60d60a2ae2a07c2b2fb1e7d8daed64b146b6792c74ae0d62ac4
#        PYTHON overrides the interpreter.
#
# Usage: scripts/language-check.sh <lang> [CWE-n ...]
set -euo pipefail

usage() { echo "usage: $0 <c|cpp|java|go|python> [CWE-n ...]" >&2; exit 2; }
[ "$#" -ge 1 ] || usage
lang=$1
shift
case "$lang" in
    c) ext=c ;;
    cpp) ext=cpp ;;
    java) ext=java ;;
    go) ext=go ;;
    python) ext=py ;;
    *) usage ;;
esac

dir="$(cd "$(dirname "$0")/.." && pwd)/audit/languages/$lang"
[ -d "$dir" ] || { echo "no directory $dir" >&2; exit 2; }
cd "$dir"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# go needs writable cache and module directories; keep them in the work dir,
# and never let it fetch another toolchain.
export GOCACHE="${GOCACHE:-$work/gocache}" GOPATH="${GOPATH:-$work/gopath}" GOTOOLCHAIN=local

compile() {
    case "$lang" in
        c) "${CC:-gcc}" -std=c17 -pedantic-errors -c -o "$work/out.o" "$1" >"$work/log" 2>&1 ;;
        cpp) "${CXX:-g++}" -std=c++20 -pedantic-errors -c -o "$work/out.o" "$1" >"$work/log" 2>&1 ;;
        java) rm -rf "$work/classes" && mkdir "$work/classes" &&
            "${JAVAC:-javac}" -Xlint:none -d "$work/classes" "$1" >"$work/log" 2>&1 ;;
        go) "${GO:-go}" build -o /dev/null "$1" >"$work/log" 2>&1 ;;
        python) "${PYTHON:-python3}" -I -c 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' "$1" >"$work/log" 2>&1 ;;
    esac
}

# Whether a program uses the language's escape hatch (a plain `compiles`
# program must not; a `compiles: hatch` program must).
uses_hatch() {
    case "$lang" in
        java) grep -qE 'sun\.misc\.|java\.lang\.foreign|(^|[[:space:]])native[[:space:]][^;]*\(' "$1" ;;
        go) grep -qE '^[[:space:]]*(import[[:space:]]+)?"(unsafe|C)"[[:space:]]*$' "$1" ;;
        python) grep -qE '^[[:space:]]*(import[[:space:]]+ctypes|from[[:space:]]+ctypes[[:space:]]+import)' "$1" ;;
        *) return 1 ;;
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

declare -A writable hatch rejected
failures=0
files=0
for f in "${selected[@]}"; do
    files=$((files + 1))
    cwe=${f%%.*}
    header=$(grep -m1 -E '^(//|#) @(compiles|rejected:)' "$f" || true)
    header=${header#// }
    header=${header#\# }
    case "$header" in
        "@compiles")
            if compile "$f" && ! uses_hatch "$f"; then writable[$cwe]=1
            else echo "FAIL $f: expected to compile without the escape hatch"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        "@compiles: hatch")
            if compile "$f" && uses_hatch "$f"; then hatch[$cwe]=1
            else echo "FAIL $f: expected to compile using the escape hatch"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        "@rejected: "*)
            want=${header#@rejected: }
            if ! compile "$f" && grep -qF -- "$want" "$work/log"; then rejected[$cwe]=1
            else echo "FAIL $f: expected the compiler to reject it with '$want'"; sed -n 1,5p "$work/log"; failures=$((failures + 1)); fi ;;
        *)
            echo "FAIL $f: no @compiles, @compiles: hatch or @rejected: header"; failures=$((failures + 1)) ;;
    esac
done

cwes=$(printf '%s\n' "${selected[@]}" | sed 's/\..*//' | sort -u -t- -k2,2n)
n_writable=0 n_hatch=0 n_rejected=0 n_open=0
for c in $cwes; do
    if [ -n "${writable[$c]:-}" ]; then v=writable; n_writable=$((n_writable + 1))
    elif [ -n "${hatch[$c]:-}" ] && [ -n "${rejected[$c]:-}" ]; then v='hatch-only'; n_hatch=$((n_hatch + 1))
    elif [ -n "${rejected[$c]:-}" ] && [ -z "${hatch[$c]:-}" ]; then v=rejected; n_rejected=$((n_rejected + 1))
    else v=undecided; n_open=$((n_open + 1)); fi
    printf '%s\t%s\n' "$c" "$v"
done
echo "$lang: files: $files  CWEs: $(printf '%s\n' "$cwes" | grep -c .)  writable: $n_writable  hatch-only: $n_hatch  rejected: $n_rejected  undecided: $n_open  failing files: $failures" >&2
[ "$failures" -eq 0 ]
