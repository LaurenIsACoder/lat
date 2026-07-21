#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cc=${CC:-cc}
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/latx-kzt-guestdynamic.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

"$cc" -std=gnu99 -Wall -Wextra -Werror \
    -I"$repo/target/i386/latx/include" \
    -I"$repo/include" \
    "$repo/target/i386/latx/context/guestdynamic.c" \
    "$repo/tests/latx-x86_64/kzt-guestdynamic-test.c" \
    -o "$tmpdir/kzt-guestdynamic-test"

"$tmpdir/kzt-guestdynamic-test"
