#!/usr/bin/env python3
import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1])
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text()
route = (root / "target/i386/latx/context/kzt_jump_slot_route.c").read_text()
production = (root / "target/i386/latx/context/kzt_jump_slot_production.c").read_text()


def body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(signature)


eager = body(elfloader, "int RelocateElfRELA(")
lazy = body(elfloader, "void PltResolver(void)")
shared = "kzt_production_jump_slot_route("

assert shared in eager
assert eager.count("uintptr_t slot_observation = (uintptr_t)(*p);") == 1
assert "kzt_rela_jump_slot_defer_input_t defer_input" in eager
assert "kzt_rela_jump_slot_defer_plan(&defer_input)" in eager
assert not re.search(
    r"kzt_rela_slot_current_is_unresolved_stub\s*\(\s*"
    r"slot_observation\s*,",
    eager,
)
assert "uintptr_t expected_guest_target = slot_observation;" in eager
assert re.search(
    r"kzt_production_jump_slot_route\s*\(\s*"
    r"my_context\s*,\s*NULL\s*,\s*slot_observation\s*,",
    eager,
)
assert re.search(r"&rela\[i\]\s*,\s*p\s*,\s*slot_observation\s*,", eager)
assert "expected_guest_target = legacy_target" not in eager

eager_final_coordinates = re.findall(
    r"kzt_rela_slot_current_is_unresolved_stub\s*\(\s*"
    r"route_result\.final_value\s*,\s*"
    r"(KZT_RELA_STUB_COORDINATE_\w+)",
    eager,
)
assert eager_final_coordinates == [
    "KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW",
    "KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED",
]

# Eager keeps the normal relocation write in its caller.  Lazy first tries the
# Registry-backed direct route, then hands off to the current object's guest
# resolver without reviving the removed host lookup/write path.
assert "option_kzt || wine_option_kzt" in eager
assert "if (option_kzt || wine_option_kzt)" in lazy
assert lazy.count("kzt_production_lazy_direct_route(") == 1
assert lazy.count("kzt_plt_resolver_enter(") == 1
assert "plt_resolver_handoff_guest(" not in lazy
assert lazy.count("plt_resolver_handoff_guest_or_abort(") == 3
assert "plt_resolver_lookup_host_symbol(" not in lazy
assert "getAlternate(" not in lazy
assert not re.search(r"\*p\s*=\s*(?:offs|legacy_target)\s*;", lazy)
assert "__atomic_compare_exchange_n" in production
assert "kzt_guest_registry_find_live_object(" in production
assert "match.namespace_id_status != KZT_GUEST_FIELD_OK" in production
assert "match.namespace_id != 0" in production
assert "resolved_target_matches_legacy" not in production
assert "state->resolved_provider = handle->library;" in production
assert "production_request_is_main_namespace" in production
assert "production_shadow_runtime_candidate" in production
assert "kzt_runtime_candidate_shadow_run" in production
assert ".only_entry = 1" in production
assert "production_emit_diagnostic(&state, route_result);" in production

# Enrichment can leave request string pointers referring into its result text
# buffers.  Both callback results therefore belong to the route-wide state;
# neither callback may create result storage on its own stack.
state = body(production, "typedef struct kzt_production_jump_slot_state")
enrich = body(production, "static int production_enrich(")
base_enrich = body(production, "static int production_enrich_base(")
bridge_enrich = body(production, "static int production_enrich_bridge(")
assert "kzt_rela_request_enricher_result_t base_enrich_result;" in state
assert "kzt_rela_request_enricher_result_t bridge_enrich_result;" in state
assert "kzt_rela_request_enricher_result_t" not in enrich
assert "&state->base_enrich_result" in base_enrich
assert "&state->bridge_enrich_result" in bridge_enrich

# The eager helper retains the exact handle across bridge enrichment/writing,
# releases it before declining, and never performs a direct slot store.
acquire = route.index("ops->acquire_exact_provider")
bridge = route.index("ops->enrich_bridge", acquire)
writer = route.index("ops->try_native_writer", bridge)
release = route.index("ops->release_exact_provider", writer)
decline = route.index("route_decline_without_write", release)
assert acquire < bridge < writer < release < decline
assert "route_legacy_fallback" not in route
assert "*(uintptr_t *)" not in route
assert "compare_exchange_slot" in route

print("WI-237 eager route and lazy guest-handoff contract: PASS")
