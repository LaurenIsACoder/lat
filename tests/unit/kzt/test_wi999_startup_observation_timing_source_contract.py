#!/usr/bin/env python3
import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1]).resolve()
source = (
    root / "target/i386/latx/context/kzt_observation_adapter.c"
).read_text(encoding="utf-8")

if "kzt_observation_timing schema=1" not in source:
    raise AssertionError("startup observation does not emit stage timing")

for field in (
    "access_ns=",
    "observe_ns=",
    "legacy_ns=",
    "supplement_ns=",
    "total_ns=",
):
    if field not in source:
        raise AssertionError(f"startup observation timing is missing {field}")

if not re.search(
    r"timing_enabled\s*=\s*request\s*&&\s*request->diagnostics_enabled",
    source,
):
    raise AssertionError("startup timing is not Registry-diagnostics-gated")

if not re.search(
    r"if\s*\(\s*timing_enabled\s*\)\s*\{\s*"
    r"timing_start\s*=\s*kzt_observation_timing_now\s*\(\s*\)",
    source,
    re.DOTALL,
):
    raise AssertionError("normal observation path still reads the timing clock")

print("WI-999 startup observation timing source contract: PASS")
