#!/usr/bin/env python3

from pathlib import Path
import sys


def fail(message):
    raise SystemExit(f"WI-1100 atfork bridge gate contract: FAIL: {message}")


def function_body(source, marker, end_marker):
    start = source.find(marker)
    end = source.find(end_marker, start)
    if start < 0 or end < 0:
        fail(f"cannot delimit {marker}")
    return source[start:end]


root = Path(sys.argv[1])
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
runtime_bridge = (
    root / "target/i386/latx/context/kzt_rela_runtime_bridge.c"
).read_text(encoding="utf-8")

runtime_prepare = function_body(
    runtime_bridge,
    "static int kzt_rela_runtime_wrapper_provider_prepare_mode(",
    "\nint kzt_rela_runtime_wrapper_provider_prepare(",
)
runtime_gate = runtime_prepare.find("if (!BridgeForkProtectionAvailable())")
runtime_bridge_access = runtime_prepare.find(
    "kzt_wrapper_bridge_provider_prepare_with_version_evidence("
)
if not (0 <= runtime_gate < runtime_bridge_access):
    fail("runtime provider can access a bridge before the atfork gate")
if "memset(provider, 0, sizeof(*provider));" not in runtime_prepare[
    runtime_gate:runtime_bridge_access
]:
    fail("runtime provider fallback does not clear its output")

per_object = function_body(
    elfloader,
    "int KztPerObjectGotPltWrite(",
    "\nstatic int kzt_elfloader_read_guest_memory(",
)
per_object_gate = per_object.find("if (!BridgeForkProtectionAvailable())")
per_object_add = per_object.find("AddBridge(")
if not (0 <= per_object_gate < per_object_add):
    fail("per-object resolver can create a bridge before the atfork gate")

relocate = function_body(elfloader, "int RelocateElfPlt(", "\n#if 0")
need_resolver = relocate.find("if(need_resolver)")
relocate_gate = relocate.find(
    "if (!BridgeForkProtectionAvailable())", need_resolver
)
first_add = relocate.find("AddBridge(", need_resolver)
if not (0 <= need_resolver < relocate_gate < first_add):
    fail("loader resolver can create a bridge before the atfork gate")
gate_block_end = relocate.find("}", relocate_gate)
if "return 0;" not in relocate[relocate_gate:gate_block_end]:
    fail("loader fallback does not preserve the guest resolver")

print("WI-1100 atfork bridge gate source contract: PASS")
