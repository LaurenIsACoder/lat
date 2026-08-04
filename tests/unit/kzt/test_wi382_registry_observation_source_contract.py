#!/usr/bin/env python3
import pathlib
import re
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


def if_condition(text: str, marker: str) -> str:
    start = text.index(marker)
    opening = text.index("(", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "(":
            depth += 1
        elif text[pos] == ")":
            depth -= 1
            if depth == 0:
                return " ".join(text[opening + 1:pos].split())
    raise AssertionError(f"unterminated if condition: {marker}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text()
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text()
registry = (
    root / "target/i386/latx/context/kzt_guest_registry.c"
).read_text()
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

# Registry observation materializes the exact observed link_map address as the
# object identity.  Invalid identity input must fail before registry lookup.
snapshot = function_body(
    registry, "static int kzt_snapshot_from_observation("
)
assert "snapshot->link_map_addr = observation->link_map_addr;" in snapshot
observe = function_body(
    registry, "kzt_guest_registry_result_t kzt_guest_registry_observe_with_diagnostic("
)
invalid_identity = if_condition(observe, "if (!observation")
assert invalid_identity == "!observation || observation->link_map_addr == 0"
assert observe.index("if (!observation") < observe.index(
    "kzt_find_object_index(registry, observation->link_map_addr)"
)

# The KZT callback consumes that exact identity through a Registry-owned copy.
# No guest link_map pointer escapes the reader/observation boundary.
materialize = function_body(
    myalign, "static int kzt_tb_callback_materialize_binding("
)
assert "struct link_map_x64" not in materialize
assert "link_map->" not in materialize
assert "kzt_guest_registry_address_match_t match = { 0 };" in materialize
assert "kzt_guest_registry_find_live_object(" in materialize
identity_guard = if_condition(materialize, "if (!context")
guard_terms = (
    "!context",
    "!link_map_addr",
    "kzt_guest_registry_find_live_object(",
    "match.match_count != 1",
    "match.path_status != KZT_GUEST_FIELD_OK",
)
assert all(term in identity_guard for term in guard_terms)
assert [identity_guard.index(term) for term in guard_terms] == sorted(
    identity_guard.index(term) for term in guard_terms
)
assert "name = match.path;" in materialize
assert re.search(
    r"kzt_guest_library_wrapper_source_acquire\(\s*"
    r"context,\s*link_map_addr,\s*name,\s*basename,\s*&source_proof\)",
    materialize,
)
for note_call in (
    "kzt_guest_library_note_loader_pair_pending",
    "kzt_guest_library_note_loader_pair",
):
    assert re.search(
        rf"{note_call}\(\s*context,.*?\blink_map_addr\b",
        materialize,
        re.DOTALL,
    )
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
assert "box64context_t *context = my_context;" in callback
assert "context ? &context->kzt_loader_event_hook : NULL" in callback
assert "kzt_loader_event_hook_publish(" in callback
assert "kzt_tb_callback_consume(context, env, &event);" in callback
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
