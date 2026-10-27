#!/usr/bin/env bash
# Runs a command with every descriptor above 2 that lacks close-on-exec
# closed. corten-sandbox refuses to start while such a descriptor is open
# (it would reach the sandboxed program past Landlock), and some parents
# leak them: the GitHub Actions runner hands its steps descriptors like 142
# and 145. Linux only (reads /proc).
#
# Usage: scripts/close-leaked-fds.sh COMMAND [ARGS]...
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: $0 COMMAND [ARGS]..." >&2; exit 2; }

leaked=()
for info in /proc/$$/fdinfo/*; do
    fd=${info##*/}
    [ "$fd" -gt 2 ] || continue
    # The glob's own directory descriptor is listed but already closed.
    [ -e "$info" ] || continue
    # Read with builtins only: a command substitution's pipe would reuse that
    # freed number and look leaked.
    flags=
    while read -r key value; do
        if [ "$key" = "flags:" ]; then flags=$value; fi
    done < "$info"
    [ -n "$flags" ] || { echo "close-leaked-fds: no flags for fd $fd" >&2; exit 1; }
    if (( (8#$flags & 8#2000000) == 0 )); then
        leaked+=("$fd")
    fi
done
for fd in "${leaked[@]}"; do
    eval "exec $fd>&-"
done
[ "${#leaked[@]}" -eq 0 ] || echo "close-leaked-fds: closed ${leaked[*]}" >&2
exec "$@"
