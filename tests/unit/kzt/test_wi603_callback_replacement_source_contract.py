#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated function body: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text(
    encoding="utf-8"
)

callback = function_body(myalign, "static void kzt_tb_callback(")
if "kzt_loader_event_hook_publish(" not in callback:
    raise AssertionError("loader event is not published through the hook seam")
consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
if ".per_object_flow = kzt_tb_callback_per_object_got_plt," not in consumer:
    raise AssertionError("loader event does not retain Registry per-object flow")
if ".per_object_opaque = &env->kzt_guest_library_loader_scope," not in consumer:
    raise AssertionError("per-object flow does not receive scoped binding state")
if ".legacy_flow = NULL," not in consumer:
    raise AssertionError("KZT loader event still enables legacy callback flow")
for forbidden in (
    "kzt_observation_legacy_result_t",
    "kzt_tb_callback_" + "legacy_state_t",
):
    if forbidden in consumer:
        raise AssertionError(f"KZT loader event retains legacy state: {forbidden}")

per_object = function_body(
    myalign, "static int kzt_tb_callback_per_object_got_plt("
)
materialize = function_body(
    myalign, "static int kzt_tb_callback_materialize_binding("
)
if "kzt_tb_callback_materialize_binding(link_map_addr, opaque)" not in per_object:
    raise AssertionError("per-object flow does not publish its library binding")
for required in (
    "AddNeededLibWithLibrary(",
    "kzt_guest_library_note_loader_pair_pending(",
    "kzt_guest_library_note_loader_pair(",
):
    if required not in materialize:
        raise AssertionError(f"materialization misses binding publication: {required}")
for forbidden in ("LoadAndCheckElfHeader", "LoadNeededLibs", "RelocateElf"):
    if forbidden in materialize:
        raise AssertionError(f"materialization retains raw ELF work: {forbidden}")

bridge = function_body(myalign, "void init_tb_callback_bridge(")
if "kzt_tb_callback" not in bridge or "ld_info->addr" not in bridge:
    raise AssertionError("versioned loader event hook is missing")
for forbidden in ("exec_entry", "jmpinst_exec", "kzt_exectb_callback"):
    if forbidden in bridge:
        raise AssertionError(f"bridge retains obsolete exec-entry hook: {forbidden}")

for forbidden in (
    "static void kzt_exectb_callback(",
    "static void finiReFlesh(",
    "static void test_x86free(",
):
    if forbidden in myalign:
        raise AssertionError(f"KZT source retains obsolete exec path: {forbidden}")

print("WI-603 callback replacement source contract: PASS")
