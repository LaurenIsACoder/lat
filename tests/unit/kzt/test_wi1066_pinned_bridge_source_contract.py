#!/usr/bin/env python3
"""WI-1066: a published bridge gets a flush-aware, exact TB pin."""

from pathlib import Path
import sys


root = Path(sys.argv[1])
cpu_exec = (root / "accel/tcg/cpu-exec.c").read_text(encoding="utf-8")
cpu_header = (root / "include/hw/core/cpu.h").read_text(encoding="utf-8")
myalign_header = (root / "target/i386/latx/include/myalign.h").read_text(
    encoding="utf-8"
)
myalign = (root / "target/i386/latx/context/myalign.c").read_text(
    encoding="utf-8"
)
production = (root / "target/i386/latx/context/kzt_jump_slot_production.c").read_text(
    encoding="utf-8"
)
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text(
    encoding="utf-8"
)

for required in (
    "kzt_pinned_bridge_cache",
    "kzt_pinned_bridge_flush_generation",
):
    if required not in cpu_header:
        raise AssertionError(f"CPU state lacks {required}")
for required in (
    "void kzt_tb_pin_prebind_bridge(",
    "kzt_pinned_bridge_lookup(",
    "kzt_pinned_bridge_store(",
    "LATX_KZT_PINNED_BRIDGE_DIAGNOSTICS",
    "kzt_pinned_bridge schema=1 event=%s",
):
    if required not in cpu_exec:
        raise AssertionError(f"CPU execution lacks {required}")
for event in ("pin", "store", "hit", "miss"):
    if f'kzt_pinned_bridge_report("{event}"' not in cpu_exec:
        raise AssertionError(f"CPU execution lacks pinned bridge {event} event")

tb_find_start = cpu_exec.find("static inline TranslationBlock *tb_find(")
if tb_find_start < 0:
    raise AssertionError("CPU execution lacks tb_find")
tb_find = cpu_exec[tb_find_start:]
lookup = tb_find.find("kzt_pinned_bridge_lookup(")
generic = tb_find.find("tb_lookup(cpu, pc, cs_base, flags, cflags)")
store = tb_find.find("kzt_pinned_bridge_store(cpu, tb)")
generate = tb_find.find("tb_gen_code(cpu, pc, cs_base, flags, cflags)")
if lookup < 0 or generic < 0 or lookup > generic:
    raise AssertionError("pinned bridge lookup is not ahead of generic lookup")
if store < 0 or generate < 0 or store < generate:
    raise AssertionError("pinned bridge is not stored after generation")
if "cpu_tb_jmp_cache_clear" not in cpu_header or \
        "kzt_pinned_bridge_flush_generation" not in cpu_header:
    raise AssertionError("TB flush does not clear the pinned bridge generation")
if "kzt_tb_pin_prebind_bridge(" not in myalign_header:
    raise AssertionError("pin API is not exposed to the loader consumer")

callback = myalign.find("static int kzt_tb_callback_pretranslate_target(")
if callback < 0:
    raise AssertionError("loader consumer lacks exact target preparation")
callback_end = myalign.find("\n}\n", callback)
callback_body = myalign[callback:callback_end]
for required in ("KztPrebindTargetTbPrepare(",):
    if required not in callback_body:
        raise AssertionError(f"target preparation lacks {required}")
prepare = elfloader[elfloader.find("int KztPrebindTargetTbPrepare("):]
prepare = prepare[:prepare.find("\n}\n")]
for required in ("kzt_tb_pin_prebind_bridge(", "kzt_tb_find_exp(", "env->eip"):
    if required not in prepare:
        raise AssertionError(f"pinned target implementation lacks {required}")
for required in (
    "KZT_PREBIND_GUEST_TB_BUDGET",
    "target <= reserved_va",
    "tb->canlink",
    "tb->lazypc",
):
    if required not in prepare:
        raise AssertionError(f"guest target continuation lacks {required}")
if "RunFunction" in callback_body or "RunFunction" in prepare:
    raise AssertionError("target preparation executes guest code")
if "target_prepare(record->bridge_target" not in production:
    raise AssertionError("publication never requests exact bridge preparation")
if "target_prepare(record->scope_proof.selected_provider_address" not in production:
    raise AssertionError("publication never prepares the proven dlerror guest entry")
if "record->bridge_custom_wrapper &&" not in production or \
        'strcmp(record->symbol, "dlerror")' not in production:
    raise AssertionError("guest target preparation is not limited to custom dlerror")

print("WI-1066 pinned bridge source contract: PASS")
