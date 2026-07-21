#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cc=${CC:-cc}
glib_cflags=$(pkg-config --cflags glib-2.0)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/latx-kzt-guestobject.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

"$cc" -std=gnu99 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I"$repo/target/i386/latx/include" \
    -I"$repo/include" \
    -I"$repo/build64" \
    $glib_cflags \
    "$repo/target/i386/latx/context/guestobject.c" \
    "$repo/tests/latx-x86_64/kzt-guestobject-test.c" \
    -pthread \
    -o "$tmpdir/kzt-guestobject-test"

"$tmpdir/kzt-guestobject-test"
