#!/usr/bin/env python3
import pathlib
import sys


def function_body(text, signature):
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text()
adapter = (root / "target/i386/latx/context/kzt_observation_adapter.c").read_text()

materialize = function_body(
    myalign, "static int kzt_tb_callback_materialize_binding(")
for forbidden in ("struct link_map_x64", "link_map->"):
    if forbidden in materialize:
        raise AssertionError(
            f"loader binding still directly reads guest link_map: {forbidden}")
for required in (
    "kzt_guest_registry_find_live_object(",
    "match.path_status",
    "match.path",
    "kzt_guest_library_wrapper_source_acquire(",
    "kzt_guest_library_binding_result_t",
):
    if required not in materialize:
        raise AssertionError(f"loader binding misses copied proof: {required}")

per_object = function_body(
    myalign, "static int kzt_tb_callback_per_object_got_plt(")
materialize_call = per_object.find(
    "kzt_tb_callback_materialize_binding(link_map_addr, opaque)")
apply_call = per_object.find("kzt_per_object_got_plt_apply(&request, &result)")
if materialize_call < 0 or apply_call < 0 or materialize_call >= apply_call:
    raise AssertionError("wrapper binding is not checked before native GOT/PLT work")
if "result.status == KZT_PER_OBJECT_GOT_PLT_FAIL_OPEN" not in per_object:
    raise AssertionError("per-object fail-open status is not propagated")
if "kzt_tb_callback_materialize_binding(link_map_addr, opaque) != 0 ||" not in per_object:
    raise AssertionError("binding failure does not stop native GOT/PLT work")

observe = function_body(
    adapter, "int kzt_observe_guest_object_from_callback(")
if "(void)request->per_object_flow(" in observe:
    raise AssertionError("adapter still ignores per-object failure")
if "request->per_object_flow(request->link_map_addr," not in observe or \
        "observation_result = KZT_OBSERVATION_ADAPTER_PER_OBJECT_FAILED" not in observe:
    raise AssertionError("adapter does not expose per-object failure")

consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
refresh = consumer.find("kzt_production_lazy_prebind_refresh(")
failure = consumer.find("KZT_OBSERVATION_ADAPTER_PER_OBJECT_FAILED")
if refresh < 0 or failure >= 0:
    raise AssertionError("loader refresh accepts a failed per-object result")
for required in (
    "observation_result == KZT_OBSERVATION_ADAPTER_ADDED",
    "observation_result == KZT_OBSERVATION_ADAPTER_UPDATED",
):
    if required not in consumer[:refresh]:
        raise AssertionError("loader refresh is not limited to successful updates")

print("WI-1629 loader callback snapshot source contract: PASS")
