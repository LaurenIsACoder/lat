#!/usr/bin/env python3

import pathlib
import sys


root = pathlib.Path(sys.argv[1]).resolve()
for removed_path in (
    "target/i386/latx/context/kzt_lazy_slot_bridge.c",
    "target/i386/latx/include/kzt_lazy_slot_bridge.h",
):
    if (root / removed_path).exists():
        raise AssertionError(f"superseded lazy slot module exists: {removed_path}")

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

for path in (root / "target/i386/latx").rglob("*"):
    if not path.is_file() or path.suffix not in {".c", ".h", ".build"}:
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for forbidden in (
        "kzt_lazy_slot_bridge",
        "kzt_lazy_slot_bridges",
        "KZT_LAZY_SLOT_BRIDGE",
    ):
        if forbidden in text:
            raise AssertionError(
                f"production tree retains superseded lazy slot state: "
                f"{path.relative_to(root)}: {forbidden}"
            )

print("WI-1009 lazy slot bridge removal contract: PASS")
