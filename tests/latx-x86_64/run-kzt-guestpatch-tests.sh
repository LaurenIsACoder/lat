#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cc=${CC:-cc}
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/latx-kzt-guestpatch.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

"$cc" -std=gnu99 -Wall -Wextra -Werror \
    -I"$repo/target/i386/latx/include" \
    -I"$repo/include" \
    "$repo/target/i386/latx/context/guestpatch.c" \
    "$repo/tests/latx-x86_64/kzt-guestpatch-test.c" \
    -o "$tmpdir/kzt-guestpatch-test"

"$tmpdir/kzt-guestpatch-test"
