#!/usr/bin/env python3
"""WI-1081: lifecycle refresh work is coalesced and flush-safe."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
cpu_header = (root / "include/hw/core/cpu.h").read_text(encoding="utf-8")
cpu_exec = (root / "accel/tcg/cpu-exec.c").read_text(encoding="utf-8")
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
scope_header = (
    root / "target/i386/latx/include/kzt_loader_callback_scope.h"
).read_text(encoding="utf-8")
adapter = (
    root / "target/i386/latx/context/kzt_guest_library_adapter.c"
).read_text(encoding="utf-8")
dl_api = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
callback = (
    root / "target/i386/latx/context/myalign.c"
).read_text(encoding="utf-8")
diagnostics = (
    root / "target/i386/latx/context/kzt_lifecycle_diagnostics.c"
).read_text(encoding="utf-8")
process_exit = (root / "linux-user/exit.c").read_text(encoding="utf-8")

for required in (
    "kzt_prebind_prepared_guest[8]",
    "flush_generation",
    "cpu->kzt_prebind_prepared_guest[i].pc = 0",
):
    if required not in cpu_header:
        raise AssertionError(f"CPU flush-safe target cache lacks {required}")

for required in (
    "bool kzt_tb_prebind_target_is_prepared(",
    "cpu->kzt_pinned_bridge_cache[index].pc == pc",
    "tb && !(tb->cflags & CF_INVALID)",
    "cpu->kzt_prebind_prepared_guest[index].flush_generation ==",
    "cpu->kzt_pinned_bridge_flush_generation",
):
    if required not in cpu_exec:
        raise AssertionError(f"prepared target validation lacks {required}")

if "kzt_tb_prebind_target_is_prepared(cpu, target)" not in elfloader:
    raise AssertionError("target preparation does not reuse valid work")
if "kzt_tb_prebind_guest_note_prepared(cpu, target)" not in elfloader:
    raise AssertionError("guest continuation preparation is not cached")

if "int prebind_refresh_pending;" not in scope_header:
    raise AssertionError("loader scope cannot carry pending refresh state")
for required in (
    "call_scope->prebind_refresh_pending =",
    "previous.prebind_refresh_pending = 1",
    "call_scope->prebind_refresh_pending = 0",
):
    if required not in adapter:
        raise AssertionError(f"nested scope coalescing lacks {required}")

if "env->kzt_guest_library_loader_scope.prebind_refresh_pending = 1" not in callback:
    raise AssertionError("loader event does not defer scoped refresh")
if "if (call_scope && call_scope->prebind_refresh_pending)" not in dl_api:
    raise AssertionError("outer scope completion does not consume refresh")
if "call_scope->prebind_refresh_pending = 0" not in dl_api:
    raise AssertionError("completed refresh remains pending")

for required in (
    "LATX_KZT_LIFECYCLE_DIAGNOSTICS",
    "kzt_lifecycle_summary schema=1",
    "target_prepare_ns=",
    "scoped_prebind_refresh_ns=",
):
    if required not in diagnostics:
        raise AssertionError(f"lifecycle summary lacks {required}")
if "kzt_lifecycle_diagnostics_report();" not in process_exit:
    raise AssertionError("lifecycle diagnostics are not reported at exit")

print("WI-1081 lifecycle performance source contract: PASS")
