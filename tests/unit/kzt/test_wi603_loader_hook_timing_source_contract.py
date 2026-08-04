#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    if opening < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated body: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text(
    encoding="utf-8"
)
adapter = (root / "target/i386/latx/context/kzt_observation_adapter.c").read_text(
    encoding="utf-8"
)
hook_source = (
    root / "target/i386/latx/context/kzt_loader_event_hook.c"
).read_text(encoding="utf-8")

locator = function_body(myalign, "static struct x86_ld_info * find_ld_part(")
for required in (
    "_dl_relocate_object_end",
    "searchpopret_part",
    "all_part",
    "ret->addr = (uintptr_t) ld_find;",
    "ret->reg = (*(ld_find+ 2)) & 0xf;",
):
    if required not in locator:
        raise AssertionError(f"loader hook locator misses {required}")

bridge = function_body(myalign, "void init_tb_callback_bridge(")
if "find_ld_bridge(info, build_id)" not in bridge:
    raise AssertionError("bridge does not derive hook metadata from guest loader")
if "kzt_loader_event_hook_install(" not in bridge:
    raise AssertionError("bridge does not version-gate the hook installation")
if "ld_info->addr" not in bridge or "kzt_tb_callback" not in bridge:
    raise AssertionError("loader hook does not install the callback at its locator")

callback = function_body(myalign, "static void kzt_tb_callback(")
if "env->regs[R_EAX + ld_info->reg]" not in callback:
    raise AssertionError("loader hook does not capture link_map from located register")
if "kzt_loader_event_hook_publish(" not in callback:
    raise AssertionError("loader hook does not publish through the event seam")
if "kzt_tb_callback_consume(context, env, &event)" not in callback:
    raise AssertionError("loader hook does not hand events to the consumer")

publish = function_body(hook_source, "int kzt_loader_event_hook_publish(")
for required in (
    "!__atomic_load_n(&hook->installed, __ATOMIC_ACQUIRE)",
    "event->link_map_addr = link_map_addr;",
    "event->sequence = __atomic_add_fetch(&hook->event_sequence",
    "clock_gettime(CLOCK_MONOTONIC_RAW, &timestamp)",
    "event->published_ns =",
):
    if required not in publish:
        raise AssertionError(f"loader event publication misses {required}")

consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
for required in (
    ".context = context,",
    ".loader_scope = &env->kzt_guest_library_loader_scope,",
    ".link_map_addr = link_map_addr,",
    ".registry = registry,",
    ".library_bindings = KztGuestLibraryBindingsForContext(context),",
    ".reuse_complete_dynamic_view = 1,",
    ".per_object_flow = kzt_tb_callback_per_object_got_plt,",
    ".per_object_opaque = &callback_scope,",
    ".legacy_flow = NULL,",
    "kzt_observe_guest_object_from_callback(&request, &observation_result)",
):
    if required not in consumer:
        raise AssertionError(f"loader consumer misses handoff input {required}")

observe = function_body(adapter, "int kzt_observe_guest_object_from_callback(")
observe_call = observe.find("kzt_observe_guest_object(request,")
per_object_call = observe.find("request->per_object_flow(request->link_map_addr,")
if observe_call < 0 or per_object_call < 0 or observe_call >= per_object_call:
    raise AssertionError("per-object injection is not sequenced after observation")
if "kzt_guest_library_callback_access_begin_scoped" not in observe:
    raise AssertionError("loader callback lacks an unload/address gate")

print("WI-603 loader hook timing source contract: PASS")
