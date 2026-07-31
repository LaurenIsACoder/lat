#!/usr/bin/env python3
"""WI-1209: clean dlerror bridge bypasses layout-sensitive host wrapper work."""

from pathlib import Path
import sys


root = Path(sys.argv[1]).resolve()
source = (
    root / "target/i386/latx/translator/tr-misc.c"
).read_text(encoding="utf-8")

start = source.find("static void do_translate_dlerror_brick_tb(")
end = source.find("\n}\n", start)
if start < 0 or end < 0:
    raise AssertionError("translator lacks the dlerror bridge fast path")
body = source[start:end]

for required in (
    "kzt_native_to_wrapper();",
    "kzt_guest_dlerror_state.dlerror_fast_result",
    "la_ld_d(",
    "la_bne(",
    "lsenv_offset_of_gpr(lsenv, R_EAX)",
    "la_st_d(",
    "wrapper_gpr_trans((ADDR)bridge->f);",
    "li_d(ra_ir2_opnd, (ADDR)bridge->w);",
    "la_jirl(ra_ir2_opnd, ra_ir2_opnd, 0);",
    "kzt_wrapper_to_native();",
    "gen_set_next_tb_code(&esp_ir2_opnd);",
    "tr_generate_exit_tb_for_bridge();",
):
    if required not in body:
        raise AssertionError(f"dlerror bridge fast path lacks {required}")

fast_load = body.find("kzt_guest_dlerror_state.dlerror_fast_result")
fast_branch = body.find("la_bne(", fast_load)
guest_result = body.find("lsenv_offset_of_gpr(lsenv, R_EAX)", fast_branch)
slow_wrapper = body.find("wrapper_gpr_trans((ADDR)bridge->f);", guest_result)
if min(fast_load, fast_branch, guest_result, slow_wrapper) < 0 or not (
        fast_load < fast_branch < guest_result < slow_wrapper):
    raise AssertionError("clean result is not separated from the exact slow wrapper")

dispatch = source.find("static void do_translate_brick_tb(")
generic = source.find("kzt_native_to_wrapper();", dispatch)
special = source.find("bridge->f == (uintptr_t)my_dlerror", dispatch)
call = source.find("do_translate_dlerror_brick_tb(bridge);", special)
if min(dispatch, generic, special, call) < 0 or not (
        dispatch < special < call < generic):
    raise AssertionError("dlerror bridge is not selected before the generic bridge")

for forbidden in ("MAP_FIXED", "mmap", "address_bits", ">> 16", "& 3"):
    if forbidden in body:
        raise AssertionError(f"dlerror bridge fast path selects an address via {forbidden}")

print("WI-1209 dlerror bridge fast path source contract: PASS")
