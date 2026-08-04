#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[opening:pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text()
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text()
myalign = (root / "target/i386/latx/context/myalign.c").read_text()
translator = (
    root / "target/i386/latx/translator/tr-misc.c"
).read_text()
planner = (
    root / "target/i386/latx/include/kzt_patch_planner.h"
).read_text()
wrappers = (
    root / "target/i386/latx/context/wrappedlibc.c",
    root / "target/i386/latx/context/wrappedlibdl.c",
)

policy = function_body(
    planner, "static inline int kzt_patch_symbol_requires_dlerror_prebind("
)
for symbol in (
    "dlopen", "dlmopen", "dlsym", "dlvsym", "dlinfo", "dladdr", "dladdr1"
):
    assert f'strcmp(symbol_name, "{symbol}") == 0' in policy
assert 'strcmp(symbol_name, "dlerror")' not in policy

prebind = function_body(
    production, "static int production_lazy_prebind_object_prepare("
)
find_symbol = function_body(
    production, "static size_t production_lazy_prebind_find_symbol_index("
)
assert "kzt_runtime_got_plt_candidates_collect(" in find_symbol
assert "strcmp(candidate.symbol_name, symbol_name) == 0" in find_symbol
assert "production_lazy_prebind_find_symbol_index(" in prebind
assert 'relocation_count, "dlerror")' in prebind
assert "SymName(" not in prebind
assert "index = dlerror_index;" in prebind
assert prebind.index("index = dlerror_index;") < prebind.index(
    "kzt_patch_symbol_requires_dlerror_prebind("
)
assert "!source_dlerror_native" in prebind
assert 'strcmp(record.symbol, "dlerror") == 0' in prebind
assert "source_dlerror_native = 1;" in prebind
assert "record.loader_mutation_invariant =" in prebind
invariant = prebind[prebind.index("record.loader_mutation_invariant ="):]
assert "kzt_patch_symbol_is_loader_route_family(record.symbol)" in invariant
assert "record.source.link_map_addr == namespace_head" in invariant

direct = function_body(production, "int kzt_production_lazy_direct_route(")
assert "kzt_patch_symbol_is_loader_route_family(symbol_name)" in direct
assert "kzt_lazy_prebind_scope_has_native_dlerror(" in direct
assert "kzt_lazy_prebind_scope_lease_published(" in direct
assert "KZT_LAZY_DIRECT_ROUTE_REASON_DLERROR_PREBIND_REQUIRED" in direct
assert ".allow_budget_transient_native = loader_write_enabled" in direct
assert "KZT_LAZY_DIRECT_ROUTE_CAS_BUDGET_EXHAUSTED" in production

assert "kzt_production_lazy_route_guest_target" not in production
assert "kzt_production_lazy_complete" not in production

resolver = function_body(elfloader, "void PltResolver(void)\n{")
guest_fallback = resolver[resolver.index(
    "kzt_patch_symbol_requires_dlerror_prebind(symname)"
):]
assert "&my_context->kzt_guest_loader_route_present" in guest_fallback
assert "__ATOMIC_RELEASE" in guest_fallback
assert "kzt_guest_dl_api_set_slow_required(" in guest_fallback
assert guest_fallback.index("kzt_guest_dl_api_set_slow_required(") < (
    guest_fallback.index("kzt_plt_resolver_enter(")
)

dlerror_tb = function_body(
    translator, "static void do_translate_dlerror_brick_tb(onebridge_t *bridge)"
)
assert "offsetof(CPUX86State, kzt_runtime_context)" in dlerror_tb
assert "offsetof(" in dlerror_tb
assert "box64context_t, kzt_guest_loader_route_present" in dlerror_tb
assert "la_bne(guest_route, zero_ir2_opnd, slow_path);" in dlerror_tb

writer = function_body(elfloader, "int KztPerObjectGotPltWrite(")
assert "kzt_production_lazy_prebind_object(" not in writer

relocate = function_body(elfloader, "int RelocateElfPlt(")
assert "kzt_production_lazy_prebind_object(" not in relocate
assert "kzt_production_lazy_prebind_refresh(" not in relocate

consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
assert "!kzt_loader_lifecycle_runtime_healthy(context)" in consumer
assert "&context->kzt_lazy_prebind_refresh_pending" in consumer

lifecycle = function_body(myalign, "static void kzt_tb_debug_state_callback(")
consistent = lifecycle.index("snapshot.state == KZT_LOADER_DEBUG_CONSISTENT")
pending = lifecycle.index("&context->kzt_lazy_prebind_refresh_pending")
refresh = lifecycle.index("kzt_production_lazy_prebind_refresh(", pending)
assert consistent < pending < refresh

for wrapper_path in wrappers:
    wrapper = wrapper_path.read_text()
    slow = function_body(wrapper, "static char *kzt_guest_dlerror_slow_path(")
    assert "Push64(cpu, guest_dlerror)" in slow
    entry = function_body(wrapper, "\nchar* my_dlerror(void)\n")
    assert "kzt_guest_loader_route_present" in entry
    assert "__ATOMIC_ACQUIRE" in entry
    assert "kzt_guest_dl_api_set_slow_required(error_state, 1)" in entry
    assert "guest_loader_route);" in entry
    assert "guest_route_may_have_pending_error" in slow

print("KZT WI-1574 dlerror route coherence source contract: PASS")
