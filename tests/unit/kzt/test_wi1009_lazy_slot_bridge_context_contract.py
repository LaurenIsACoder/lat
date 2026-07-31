#!/usr/bin/env python3

import pathlib
import sys


root = pathlib.Path(sys.argv[1]).resolve()
header = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")
context = (
    root / "target/i386/latx/context/box64context.c"
).read_text(encoding="utf-8")
meson = (
    root / "target/i386/latx/context/meson.build"
).read_text(encoding="utf-8")

for forbidden in (
    '#include "kzt_lazy_slot_bridge.h"',
    "kzt_lazy_slot_bridge_table_t kzt_lazy_slot_bridges;",
):
    if forbidden in header:
        raise AssertionError(
            f"box64context retains superseded lazy slot state: {forbidden}"
        )

for forbidden in (
    "kzt_lazy_slot_bridge_table_init(",
    "kzt_lazy_slot_bridge_table_destroy(",
):
    if forbidden in context:
        raise AssertionError(
            f"context retains superseded lazy slot work: {forbidden}"
        )

if "'kzt_lazy_slot_bridge.c'" in meson:
    raise AssertionError("superseded lazy slot implementation is still built")

print("WI-1009 lazy slot bridge removal contract: PASS")
