#!/usr/bin/env python3
"""WI-1082: steady dlerror diagnostics are aggregated once per process."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
cpu_exec = (root / "accel/tcg/cpu-exec.c").read_text(encoding="utf-8")
process_exit = (root / "linux-user/exit.c").read_text(encoding="utf-8")
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")

for required in (
    "LATX_KZT_STEADY_DIAGNOSTICS",
    "kzt_steady_tb_summary schema=1",
    "pin_replace=",
    "pinned_hit=",
    "pinned_miss=",
    "collision_miss=",
    "flags_miss=",
    "invalid_miss=",
    "bridge_translate=",
    "guest_prepared=",
    "guest_hit=",
    "guest_retranslate=",
    "flush_generation=",
    "tb_flush_count=",
    "tb_invalidate_count=",
    "fast_cache_hash=",
    "fast_cache_pc=",
    "fast_cache_matches_pin=",
    "pinned_restore=",
):
    if required not in cpu_exec:
        raise AssertionError(f"steady diagnostic lacks {required}")

if "kzt_tb_steady_diagnostics_report(" not in process_exit:
    raise AssertionError("process exit does not emit one summary")

if "kzt_tb_steady_diagnostics_note_guest_prepare(" not in elfloader:
    raise AssertionError("guest continuation preparation is not tracked")

if 'fprintf(stderr,\n            "kzt_pinned_bridge schema=1 event=%s' not in cpu_exec:
    raise AssertionError("existing event diagnostics were removed")

for required in (
    "static void kzt_pinned_bridge_restore_jmp_cache(",
    "latx_fast_jmp_cache_add(cpu, hash, tb)",
    "qatomic_set(&cpu->tb_jmp_cache[hash], tb)",
    "kzt_pinned_bridge_restore_jmp_cache(cpu, tb)",
):
    if required not in cpu_exec:
        raise AssertionError(f"pinned bridge recovery lacks {required}")

print("WI-1082 steady diagnostics source contract: PASS")
