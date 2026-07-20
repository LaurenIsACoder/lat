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
assert shared in lazy
assert eager.count("uintptr_t slot_observation = (uintptr_t)(*p);") == 1
assert re.search(
    r"kzt_rela_slot_current_is_unresolved_stub\(\s*slot_observation\s*,",
    eager,
)
assert "uintptr_t expected_guest_target = slot_observation;" in eager
assert "(void *)slot_observation, (void*)legacy_target" in eager
assert "p,\n                                    slot_observation," in eager
assert "expected_guest_target = legacy_target" not in eager

assert lazy.count("uintptr_t slot_observation = (uintptr_t)(*p);") == 1
assert "(void *)slot_observation, (void*)legacy_target" in lazy
assert "rel, p,\n                    slot_observation, 1," in lazy

# Runtime-disabled KZT retains the historical direct stores.  Runtime-enabled
# eager and lazy branches do not add an unchecked store after entering Step5.
assert "if (option_kzt || wine_option_kzt)" in eager
assert "if (option_kzt || wine_option_kzt)" in lazy
assert "__atomic_compare_exchange_n" in production
assert "snapshot->namespace_id.status != KZT_GUEST_FIELD_OK" in production
assert "snapshot->namespace_id.value != 0" in production
assert "input.resolved_target_matches_legacy =\n        resolved_target == legacy_target;" in production
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

# The shared helper retains the exact handle across bridge enrichment/writing,
# releases it before fallback, and never performs a direct slot store.
acquire = route.index("ops->acquire_exact_provider")
bridge = route.index("ops->enrich_bridge", acquire)
writer = route.index("ops->try_native_writer", bridge)
release = route.index("ops->release_exact_provider", writer)
fallback = route.index("route_legacy_fallback", release)
assert acquire < bridge < writer < release < fallback
assert "*(uintptr_t *)" not in route
assert "compare_exchange_slot" in route

# Lazy currently has no raw expected guest target/owner proof and explicitly
# enters the route with expected_guest_target_present == 0.
assert "vername, 0, 0, legacy_target, &route_result" in lazy

print("WI-237 eager/lazy shared jump-slot route contract: PASS")
