#!/usr/bin/env python3
from pathlib import Path
import sys


def fail(message):
    raise SystemExit(f"WI-1007 context resolver contract: FAIL: {message}")


root = Path(sys.argv[1])
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
context = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")
cpu_exec = (
    root / "accel/tcg/cpu-exec.c"
).read_text(encoding="utf-8")

start = elfloader.find("int RelocateElfPlt(")
end = elfloader.find("\n#if 0", start)
if start < 0 or end < 0:
    fail("cannot locate RelocateElfPlt")
relocate = elfloader[start:end]
compact_relocate = " ".join(relocate.split())

if "uintptr_t kzt_plt_resolver_bridge;" not in context:
    fail("resolver bridge is not owned by box64context_t")
if "my_context->kzt_plt_resolver_bridge = AddBridge(" not in relocate:
    fail("RelocateElfPlt does not create the context-owned resolver bridge")
if "resolver_bridge = my_context->kzt_plt_resolver_bridge;" not in relocate:
    fail("GOT injection does not use the context-owned resolver bridge")
if "kzt_guest_registry_find_by_link_map(" in relocate:
    fail("resolver publication still allocates a full Registry snapshot")
if "kzt_guest_registry_find_live_object(" not in relocate:
    fail("resolver publication does not use the allocation-free live query")
if ("resolver_match.namespace_id_status == KZT_GUEST_FIELD_OK"
        not in compact_relocate):
    fail("resolver publication does not require known namespace evidence")
if "resolver_match.namespace_id == 0" not in relocate:
    fail("resolver publication does not reject non-main namespaces")
if ("guest_link_map, resolver_match.generation, 0,"
        not in compact_relocate):
    fail("resolver publication does not use the exact live generation")

dispatch_start = elfloader.find("int KztPltResolverDispatch(")
dispatch_end = elfloader.find("\nvoid PltResolver(", dispatch_start)
if dispatch_start < 0 or dispatch_end < 0:
    fail("missing context resolver dispatcher")
dispatch = elfloader[dispatch_start:dispatch_end]
for required in (
    "bridge->CC == 0xCC",
    "bridge->S == 'S'",
    "bridge->C == 'C'",
    "(uintptr_t)bridge->w == (uintptr_t)vFE",
    "bridge->f == (uintptr_t)PltResolver",
    "PltResolver();",
    "cpu->eip = Pop64(cpu);",
):
    if required not in dispatch:
        fail(f"resolver dispatcher is missing exact check: {required}")

tb_find_start = cpu_exec.find("static inline TranslationBlock *tb_find(")
tb_find_end = cpu_exec.find("static inline bool cpu_handle_halt(", tb_find_start)
if tb_find_start < 0 or tb_find_end < 0:
    fail("cannot locate tb_find")
tb_find = cpu_exec[tb_find_start:tb_find_end]
dispatch_call = tb_find.find("KztPltResolverDispatch(")
lookup_call = tb_find.find("tb = tb_lookup(")
if dispatch_call < 0:
    fail("tb_find does not dispatch the context resolver directly")
if lookup_call < 0 or dispatch_call > lookup_call:
    fail("resolver dispatch must occur before resolver TB lookup/generation")
if tb_find.count("cpu_get_tb_cpu_state(") < 2:
    fail("tb_find does not refresh the PC after direct resolver dispatch")

print("KZT WI-1007 context resolver source contract: PASS")
