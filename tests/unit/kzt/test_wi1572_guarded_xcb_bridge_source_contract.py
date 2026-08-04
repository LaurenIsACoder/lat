#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
bridge_private = (root / "target/i386/latx/include/bridge_private.h").read_text()
bridge_header = (root / "target/i386/latx/include/bridge.h").read_text()
bridge_source = (root / "target/i386/latx/context/bridge.c").read_text()
translator = (root / "target/i386/latx/translator/tr-misc.c").read_text()
align_source = (root / "target/i386/latx/context/myalign.c").read_text()
wrapper_source = (root / "target/i386/latx/context/wrapper.c").read_text()
aot_header = (root / "target/i386/latx/include/aot.h").read_text()
aot_source = (root / "target/i386/latx/sbt/aot.c").read_text()

require("guest_fallback_target" in bridge_private, "bridge must store guest fallback")
require("guard_kind" in bridge_private, "bridge must store guard kind")
require(
    "KZT_BRIDGE_GUARD_XCB_CONNECTION" in bridge_private,
    "the XCB connection guard must have an explicit kind",
)
require("AddGuardedBridge" in bridge_header, "guarded bridge API must be public")
require("AddGuardedBridge" in bridge_source, "guarded bridge API must be implemented")
require(
    "KZT_BRIDGE_GUARD_XCB_CONNECTION" in translator
    and "kzt_xcb_guard_acquire_for_bridge" in translator,
    "translator must guard XCB connections before the native wrapper",
)
require(
    "bridge->guest_fallback_target" in translator
    and "lsenv_offset_of_eip" in translator,
    "unknown connections must return to the proven guest target",
)
guarded_start = translator.index(
    "static void do_translate_xcb_guarded_brick_tb("
)
guarded_end = translator.index(
    "static void do_translate_brick_tb(", guarded_start
)
guarded = translator[guarded_start:guarded_end]
require(
    "li_d(helper, bridge->guest_fallback_target);" in guarded
    and "helper, env_ir2_opnd, lsenv_offset_of_eip(lsenv)" in guarded,
    "guarded fallback must update both the next-PC register and env eip",
)
runtime_start = translator.index(
    "static void kzt_generate_guest_runtime_branch("
)
runtime_end = translator.index("void kzt_native_to_wrapper(", runtime_start)
runtime_branch = translator[runtime_start:runtime_end]
require(
    "la_mov64(helper, a0_ir2_opnd);" in runtime_branch
    and "helper, env_ir2_opnd, lsenv_offset_of_eip(lsenv)" in runtime_branch,
    "guest runtime fallback must update both the next-PC register and env eip",
)
require(
    "kzt_xcb_connection_guard_acquire" in align_source,
    "align must acquire a cancellation-safe lease prepared by the bridge guard",
)
align_start = align_source.index("void *align_xcb_connection(void *guest)")
align_end = align_source.index("void unalign_xcb_connection", align_start)
align_function = align_source[align_start:align_end]
require(
    "calloc" not in align_function and "malloc" not in align_function,
    "the XCB alignment hot path must not allocate a per-call scope",
)
aligned_wrappers = [
    line for line in wrapper_source.splitlines()
    if "aligned_xcb = align_xcb_connection" in line
]
require(aligned_wrappers, "generated XCB wrappers must be present")
for line in aligned_wrappers:
    guard = line.find("if (!aligned_xcb)")
    native_call = line.find("fn(", guard)
    require(
        guard >= 0 and native_call > guard,
        "every XCB wrapper must reject failed alignment before native call",
    )
require(
    "LOAD_HELPER_KZT_XCB_GUARD_ACQUIRE" in aot_header
    and "LOAD_HELPER_KZT_XCB_GUARD_ACQUIRE" in aot_source,
    "AOT and immediate translation must share the XCB guard helper",
)
require(
    "-kzt-runtime-entry-v2" in aot_header,
    "adding an AOT helper must invalidate the previous KZT AOT format",
)

production = "\n".join(
    path.read_text(errors="ignore")
    for path in (root / "target/i386/latx").rglob("*.[ch]")
)
require(
    "kzt_lazy_slot_bridge" not in production,
    "guarded XCB fallback must not restore the removed per-slot bridge table",
)

print("wi1572-guarded-xcb-bridge-source-contract: PASS")
