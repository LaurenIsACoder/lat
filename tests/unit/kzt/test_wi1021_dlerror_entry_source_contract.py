#!/usr/bin/env python3
from pathlib import Path
import sys


def fail(message):
    raise SystemExit(f"WI-1021 dlerror entry contract: FAIL: {message}")


root = Path(sys.argv[1])
scope_header = (
    root / "target/i386/latx/include/kzt_guest_symbol_scope.h"
).read_text(encoding="utf-8")
scope_source = (
    root / "target/i386/latx/context/kzt_guest_symbol_scope.c"
).read_text(encoding="utf-8")
dl_api = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
dl_api_header = (
    root / "target/i386/latx/include/kzt_guest_dl_api.h"
).read_text(encoding="utf-8")
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
wrapped_dl = (
    root / "target/i386/latx/context/wrappedlibdl.c"
).read_text(encoding="utf-8")
wrapped_c = (
    root / "target/i386/latx/context/wrappedlibc.c"
).read_text(encoding="utf-8")

if "uintptr_t selected_provider_address;" not in scope_header:
    fail("scope proof does not retain the unique guest symbol address")
if "lookup_result.runtime_address" not in scope_source:
    fail("scope discovery does not publish the dynsym runtime address")
if "uintptr_t kzt_guest_dl_api_load_dlerror_entry" not in dl_api_header:
    fail("shared dlerror entry loader is not declared")
load_start = dl_api.find("uintptr_t kzt_guest_dl_api_load_dlerror_entry(")
load_end = dl_api.find("\n}", load_start)
if load_start < 0 or load_end < 0:
    fail("missing shared dlerror entry loader")
load = dl_api[load_start:load_end]
for required in (
    "kzt_guest_dl_api_load_entries(dl)",
    "entries->dlerror",
    "observed_dlerror",
    "__atomic_load_n(",
    "__ATOMIC_RELAXED",
):
    if required not in load:
        fail(f"hot-path dlerror load is missing {required}")
hint_load = load.find("__atomic_load_n(")
table_load = load.find("kzt_guest_dl_api_load_entries(dl)")
if hint_load < 0 or table_load < 0 or hint_load > table_load:
    fail("hot-path dlerror hint does not precede the acquire table fallback")

publish_start = dl_api.find("int kzt_guest_dl_api_publish_dlerror_entry(")
publish_end = dl_api.find("\n}", publish_start)
if publish_start < 0 or publish_end < 0:
    fail("missing atomic dlerror entry publisher")
publish = dl_api[publish_start:publish_end]
for required in (
    'strcmp(symbol, "dlerror")',
    "__atomic_compare_exchange_n(",
    "observed_dlerror",
    "__ATOMIC_ACQ_REL",
    "__ATOMIC_ACQUIRE",
):
    if required not in publish:
        fail(f"publisher is missing {required}")

cas_start = production.find(
    "production_lazy_direct_cas_slot("
)
cas_end = production.find(
    "\n}", cas_start
)
if cas_start < 0 or cas_end < 0:
    fail("cannot locate production lazy CAS")
cas = production[cas_start:cas_end]
publish_call = cas.find("kzt_guest_dl_api_publish_dlerror_entry(")
slot_cas = cas.find("__atomic_compare_exchange_n(")
if publish_call < 0 or slot_cas < 0 or publish_call > slot_cas:
    fail("guest dlerror entry must be published before the final slot CAS")
for required in (
    "state->preemption_proof.selected_provider_address",
    "state->wrapper_provider.match.custom_wrapper",
):
    if required not in cas:
        fail(f"production publication is missing {required}")

for name, source in (
    ("wrappedlibdl", wrapped_dl),
    ("wrappedlibc", wrapped_c),
):
    helper_start = source.find(
        "static uintptr_t kzt_guest_dlerror_entry_slow("
    )
    helper_end = source.find("\n}", helper_start)
    if helper_start < 0 or helper_end < 0:
        fail(f"cannot locate {name} dlerror slow helper")
    helper = source[helper_start:helper_end]
    if "kzt_guest_dl_entries_for_call(context" not in helper or \
            "entries ? entries->dlerror : 0" not in helper:
        fail(f"{name} slow helper does not acquire the immutable table")
    state_start = source.find("static char *kzt_guest_dlerror_slow_path(")
    state_end = source.find("\n}", state_start)
    if state_start < 0 or state_end < 0:
        fail(f"cannot locate {name} dlerror state slow path")
    state_slow = source[state_start:state_end]
    for required in (
        "kzt_guest_dl_api_dlerror(error_state, guest_dlerror)",
        "kzt_guest_dl_api_load_dlerror_hint(",
        "kzt_guest_dlerror_entry_slow(context)",
        "error_state->guest_dlerror_entry = guest_dlerror",
        "Push64(cpu, guest_dlerror)",
    ):
        if required not in state_slow:
            fail(f"{name} state slow path is missing {required}")
    function_start = source.find("\nchar* my_dlerror(void)\n")
    function_end = source.find("\n}", function_start)
    if function_start < 0 or function_end < 0:
        fail(f"cannot locate {name} my_dlerror")
    function = source[function_start:function_end]
    state_check = function.find("if (fast_result)")
    slow = function.find("kzt_guest_dlerror_slow_path(")
    fast_return = function.find("return fast_result;")
    if min(state_check, slow, fast_return) < 0 or not (
            state_check < slow < fast_return):
        fail(f"{name} does not isolate the clean dlerror fast path")
    if "char *fast_result" not in function:
        fail(f"{name} materializes the clean dlerror result")
    if "kzt_guest_dl_entries_t fallback" in function:
        fail(f"{name} hot dlerror wrapper retains the cold fallback frame")
    if "kzt_guest_dl_api_dlerror(error_state" in function:
        fail(f"{name} hot dlerror wrapper retains the state machine call")

print("KZT WI-1021 dlerror entry source contract: PASS")
