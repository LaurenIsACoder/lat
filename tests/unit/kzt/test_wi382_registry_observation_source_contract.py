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

# The KZT callback materializes only the wrapper binding under the callback
# gate.  It does not reconstruct an ELF object or derive private glibc data.
materialize = function_body(
    myalign, "static int kzt_tb_callback_materialize_binding("
)
identity_guard = materialize.index("if (!link_map")
first_dereference = materialize.index("link_map->")
assert identity_guard < first_dereference
assert "l_map_start" not in materialize
assert "l_map_end" not in materialize
assert "->l_ns" not in materialize
assert "AddNeededLibWithLibrary(" in materialize
assert "kzt_guest_library_note_loader_pair_pending(" in materialize
assert "kzt_guest_library_note_loader_pair(" in materialize
for forbidden in ("LoadAndCheckElfHeader", "LoadNeededLibs", "RelocateElf"):
    assert forbidden not in materialize

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
assert "request.reuse_complete_dynamic_view = 1" in plt_observation
relocate_plt = function_body(elfloader, "int RelocateElfPlt(")
assert "uintptr_t kzt_evidence_got = head->pltgot" in relocate_plt
assert "kzt_evidence_got_runtime + 8" in relocate_plt
assert "kzt_guest_link_map_identity_matches(" in relocate_plt
assert "head->pltgot ? head->pltgot : head->got" in relocate_plt
assert relocate_plt.index("kzt_observe_plt_source(") < relocate_plt.index(
    "head->had_RelocateElfPlt = 1"
)

# The event hook publishes only the exact link_map event.  The consumer owns
# identity/namespace validation before it enters the observation adapter.
assert "'kzt_guest_dynamic_diagnostics.c'" in production_meson
consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
assert "kzt_main_elf_identity(elf_header" in consumer
assert "info1.pt_dynamic_addr" not in consumer
assert "kzt_guest_link_map_read_predecessor(" in consumer
assert "kzt_guest_registry_context_confirm_main_namespace_head(" in consumer
assert "int diagnostics_enabled = kzt_registry_diagnostics_enabled();" in consumer
assert ".enabled = diagnostics_enabled" in consumer
assert ".diagnostics_enabled = diagnostics_enabled" in consumer
assert ".reuse_complete_dynamic_view = 1" in consumer
assert ".legacy_flow = NULL" in consumer
assert "if (registry && diagnostics_enabled)" in consumer

callback = function_body(myalign, "static void kzt_tb_callback(")
assert "kzt_loader_event_hook_publish(" in callback
assert "kzt_tb_callback_consume(env, &event);" in callback
for forbidden in (
    "LoadAndCheckElfHeader", "LoadNeededLibs", "RelocateElf",
    "kzt_main_elf_identity", "kzt_observe_guest_object",
    "kzt_production_jump_slot_route",
):
    assert forbidden not in callback

compare = function_body(adapter, "static void kzt_adapter_compare_dynamic_views(")
assert compare.index("!request->diagnostics_enabled") < compare.index(
    "kzt_guest_registry_find_dynamic_view("
)
assert "existing_result.unknown_tag_count = existing_view.unknown_tag_count;" in compare
callback_adapter = function_body(
    adapter, "int kzt_observe_guest_object_from_callback("
)
assert "kzt_guest_registry_supplement_map_range(" in callback_adapter
assert callback_adapter.count("kzt_observe_guest_object(") == 1
assert "supplemental" not in callback_adapter

# Context ownership is represented as one state object with an atomic hot path.
assert "kzt_guest_registry_context_t kzt_guest_registry_context;" in context_header
assert "__atomic_load_n(&context->state" in registry_context
assert "kzt_guest_registry_context_destroy(" in registry_context
assert "registry->" not in registry_context
main_namespace_evidence = function_body(
    registry_context,
    "int kzt_guest_registry_context_has_main_namespace_evidence(",
)
assert "kzt_guest_registry_matches_live_identity(" in main_namespace_evidence
assert "kzt_guest_registry_find_by_link_map(" not in main_namespace_evidence
assert "kzt_guest_object_snapshot_free(" not in main_namespace_evidence

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
