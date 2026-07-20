#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start + len(signature))
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text()
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text()
adapter = (
    root / "target/i386/latx/context/kzt_observation_adapter.c"
).read_text()
registry_context = (
    root / "target/i386/latx/context/kzt_guest_registry_context.c"
).read_text()
context_header = (
    root / "target/i386/latx/include/box64context.h"
).read_text()
production_meson = (
    root / "target/i386/latx/context/meson.build"
).read_text()
production_route = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text()

# The old callback must reject NULL identity and path before dereferencing.
legacy = function_body(myalign, "static int kzt_tb_callback_legacy(")
identity_guard = legacy.index("if (!my_lm)")
first_dereference = legacy.index("my_lm->")
path_guard = legacy.index("if (!my_lm->l_name)")
assert identity_guard < first_dereference
assert path_guard == legacy.index("my_lm->l_name") - len("if (!")

# Public link_map evidence plus ELF PT_LOAD ranges replace glibc-private
# l_ns/l_map_start/l_map_end offsets. Startup publishes the exact pair while
# the callback gate is still held; dlopen keeps its scoped publish path.
assert "l_map_start" not in legacy
assert "l_map_end" not in legacy
assert "->l_ns" not in legacy
assert "GetElfLoadRange(" in legacy
assert "if (lib && !loader_scope_active &&" in legacy
assert "kzt_guest_library_note_loader_pair(" in legacy

# A malformed ELF or either relocation failure must leave the startup pair
# unpublished.  The final publish is reached only through the shared success
# condition after both failure-returning calls.
header_load = legacy.index("h = LoadAndCheckElfHeader(")
header_guard = legacy.index("if (!h)", header_load)
header_use = legacy.index("ElfHeadReFix(h", header_load)
assert header_load < header_guard < header_use
relocate = legacy.index("RelocateElf(", header_use)
relocate_plt = legacy.index("RelocateElfPlt(", relocate)
publish = legacy.index("kzt_guest_library_note_loader_pair(", relocate_plt)
assert "relocate_result" in legacy[relocate:publish]
assert "relocate_plt_result" in legacy[relocate:publish]
success_condition = legacy.rfind("if (", relocate_plt, publish)
assert success_condition >= 0
condition = legacy[success_condition:publish]
assert "relocate_result == 0" in condition
assert "relocate_plt_result == 0" in condition

plt_observation = function_body(elfloader, "static void kzt_observe_plt_source(")
assert "kzt_elfloader_head_identity(elf_header" in plt_observation
assert "info1.pt_dynamic_addr" not in plt_observation
assert "kzt_guest_link_map_classify_namespace(" in plt_observation
assert "kzt_guest_registry_context_get_main_namespace_head(" in plt_observation
assert "kzt_guest_registry_context_has_main_namespace_evidence(" in plt_observation
assert "kzt_guest_link_map_read_predecessor(" in plt_observation
assert "GetElfLoadRange(" in plt_observation
assert ".namespace_id_present = main_namespace == 1" in plt_observation
assert ".map_range_present = range_available" in plt_observation
relocate_plt = function_body(elfloader, "int RelocateElfPlt(")
assert "uintptr_t kzt_evidence_got = head->pltgot" in relocate_plt
assert "kzt_evidence_got_runtime + 8" in relocate_plt
assert "kzt_guest_link_map_identity_matches(" in relocate_plt
assert "head->pltgot ? head->pltgot : head->got" in relocate_plt
assert relocate_plt.index("kzt_observe_plt_source(") < relocate_plt.index(
    "head->had_RelocateElfPlt = 1"
)

# Production diagnostics are linked, opt-in, and avoid a configure lock when off.
assert "'kzt_guest_dynamic_diagnostics.c'" in production_meson
callback = function_body(myalign, "static void kzt_tb_callback(")
assert "kzt_main_elf_identity(elf_header" in callback
assert "info1.pt_dynamic_addr" not in callback
assert "kzt_guest_link_map_read_predecessor(" in callback
assert "kzt_guest_registry_context_confirm_main_namespace_head(" in callback
assert "int diagnostics_enabled = kzt_registry_diagnostics_enabled();" in callback
assert ".enabled = diagnostics_enabled" in callback
assert ".diagnostics_enabled = diagnostics_enabled" in callback
assert "if (registry && diagnostics_enabled)" in callback

compare = function_body(adapter, "static void kzt_adapter_compare_dynamic_views(")
assert compare.index("!request->diagnostics_enabled") < compare.index(
    "kzt_guest_registry_find_dynamic_view("
)
assert "existing_result.unknown_tag_count = existing_view.unknown_tag_count;" in compare

# Context ownership is represented as one state object with an atomic hot path.
assert "kzt_guest_registry_context_t kzt_guest_registry_context;" in context_header
assert "__atomic_load_n(&context->state" in registry_context
assert "kzt_guest_registry_context_destroy(" in registry_context
assert "registry->" not in registry_context

# Early fail-open remains observable when enrichment stops before a full
# planner/writer diagnostic can be built, but only under the diagnostics gate.
emit = function_body(production_route, "static void production_emit_diagnostic(")
assert "kzt_registry_diagnostics_enabled()" in emit
assert "kzt_rela_fail_open stage=%s" in emit
assert "ROUTE_PRECONDITIONS" in production_route
assert "BASE_EVIDENCE" in production_route
assert "EXACT_LIBRARY_BINDING" in production_route
assert "BRIDGE_EVIDENCE" in production_route
assert "SOURCE_IDENTITY" in production_route
assert "WRITER" in production_route

print("WI-382 registry observation source contract: PASS")
