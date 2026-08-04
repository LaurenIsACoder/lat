#!/usr/bin/env python3
"""WI-601 contract for the isolated real-guest performance fixture."""

import pathlib
import sys


root = pathlib.Path(sys.argv[1]).resolve()
script = (root / "tests/unit/kzt/guest_e2e/build_guest_probe.sh").read_text(
    encoding="utf-8"
)
perf_main = (root / "tests/unit/kzt/guest_e2e/kzt_guest_perf_main.c").read_text(
    encoding="utf-8"
)
perf_probe = (root / "tests/unit/kzt/guest_e2e/kzt_guest_perf_probe.c").read_text(
    encoding="utf-8"
)

perf_main_start = script.rfind(
    "run_cc", 0, script.index('"$script_dir/kzt_guest_perf_start.S"')
)
perf_main_command = script[perf_main_start:script.index(
    "-o \"$build_dir/kzt_guest_perf_main\"", perf_main_start
)]
if "-fno-plt" not in perf_main_command:
    raise AssertionError("performance main must use -fno-plt")

for required in (
    "perf_jump_slot_count=$(grep -Ec",
    "if [[ $perf_jump_slot_count -ne 1 ]]; then",
    "perf_versioned_dlerror_jump_slots=$(grep -Ec",
    "${e2e_symbol}@GLIBC_",
    "if [[ $perf_versioned_dlerror_jump_slots -ne 1 ]]; then",
    "perf_main_jump_slots=$(grep -Ec",
    "if [[ $perf_main_jump_slots -ne 0 ]]; then",
):
    if required not in script:
        raise AssertionError(f"missing performance fixture check: {required}")

for mode in ("startup", "first", "steady"):
    if f'"{mode}"' not in perf_main:
        raise AssertionError(f"performance main does not expose {mode} mode")
for required in (
    "kzt_guest_perf_first",
    "kzt_guest_perf_steady",
    "dlerror() != NULL",
):
    if required not in perf_probe:
        raise AssertionError(f"performance probe is missing {required}")
if "checksum += index + 1" in perf_probe:
    raise AssertionError("performance checksum must derive from dlerror result")

print("WI-601 performance fixture contract: PASS")
