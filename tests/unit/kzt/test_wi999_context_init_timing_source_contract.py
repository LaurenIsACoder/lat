#!/usr/bin/env python3

import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1]).resolve()
source = (
    root / "target/i386/latx/context/box64context.c"
).read_text(encoding="utf-8")

if "kzt_context_init_timing schema=1" not in source:
    raise AssertionError("KZT context initialization does not emit stage timing")

for field in (
    "base_ns=",
    "library_access_ns=",
    "patch_guard_ns=",
    "total_ns=",
):
    if field not in source:
        raise AssertionError(f"context timing is missing {field}")

if not re.search(
    r"timing_enabled\s*=\s*kzt_registry_diagnostics_enabled\s*\(\s*\)",
    source,
):
    raise AssertionError("context timing is not Registry-diagnostics-gated")

print("WI-999 context initialization timing source contract: PASS")
