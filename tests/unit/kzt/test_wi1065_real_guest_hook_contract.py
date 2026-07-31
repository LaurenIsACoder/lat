#!/usr/bin/env python3
"""WI-1065 fixture and runner contract for hook timing evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_BUILD = ROOT / "tests/unit/kzt/guest_loader/build_guest_loader_fixture.sh"
RUNNER = ROOT / "tests/unit/kzt/test_wi1065_real_guest_hook.py"


build = FIXTURE_BUILD.read_text(encoding="utf-8")
runner = RUNNER.read_text(encoding="utf-8")

for required in (
    "wi1065_constructor.c",
    "wi1065_relro.c",
    "wi1065_loader_events.c",
    "libwi1065_constructor.so",
    "libwi1065_partial_relro.so",
    "libwi1065_full_relro.so",
    "wi1065-loader-events",
    "-Wl,-z,relro,-z,now",
):
    if required not in build:
        raise AssertionError(f"WI-1065 fixture build misses {required}")

for required in (
    'event_records(output, "published")',
    'event_records(output, "consumed")',
    "WI1065_CONSTRUCTOR",
    "WI1065_RELRO partial",
    "WI1065_RELRO full",
    "WI1065_THREADS_PASS",
    "LATX_KZT_LOADER_EVENT_HOOK",
    "LATX_KZT_LOADER_EVENT_FORCE_PATTERN_MISMATCH",
    '"LATX_AOT": "0"',
    "UNKNOWN_BUILD_ID",
    "PATTERN_MISMATCH",
    "rollback=disabled",
):
    if required not in runner:
        raise AssertionError(f"WI-1065 runner misses {required}")

print("WI-1065 real guest hook fixture contract: PASS")
