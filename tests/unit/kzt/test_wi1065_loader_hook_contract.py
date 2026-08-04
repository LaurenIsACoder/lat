#!/usr/bin/env python3
"""WI-1065: the private loader hook must be a version-gated event publisher."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MYALIGN = ROOT / "target/i386/latx/context/myalign.c"
HOOK = ROOT / "target/i386/latx/context/kzt_loader_event_hook.c"
HOOK_HEADER = ROOT / "target/i386/latx/include/kzt_loader_event_hook.h"


def function_body(source, prefix):
    start = source.index(prefix)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function beginning {prefix!r}")


hook = HOOK.read_text(encoding="utf-8")
hook_header = HOOK_HEADER.read_text(encoding="utf-8")
myalign = MYALIGN.read_text(encoding="utf-8")

for required in (
    "kzt_loader_event_hook_read_build_id",
    "kzt_loader_event_hook_install",
    "kzt_loader_event_hook_publish",
    "KZT_LOADER_EVENT_HOOK_FAIL_OPEN_UNKNOWN_BUILD_ID",
    "KZT_LOADER_EVENT_HOOK_FAIL_OPEN_PATTERN_MISMATCH",
):
    if required not in hook:
        raise AssertionError(f"WI-1065 hook misses {required}")
for required in (
    "KZT_LOADER_EVENT_HOOK_GLIBC_2_28_BUILD_ID",
    "KZT_LOADER_EVENT_HOOK_GLIBC_2_39_BUILD_ID",
):
    if required not in hook or required not in hook_header:
        raise AssertionError(f"WI-1065 exact layout table misses {required}")

publish = function_body(hook, "int kzt_loader_event_hook_publish(")
for forbidden in (
    "LoadAndCheckElfHeader",
    "LoadNeededLibs",
    "RelocateElf",
    "FindSymbol",
    "kzt_per_object_got_plt_apply",
    "KztPerObjectGotPltWrite",
):
    if forbidden in publish:
        raise AssertionError(f"event publisher performs forbidden work: {forbidden}")

callback = function_body(myalign, "static void kzt_tb_callback(")
if "kzt_loader_event_hook_publish(" not in callback:
    raise AssertionError("loader callback bypasses the event publisher")
if "kzt_tb_callback_consume(" not in callback:
    raise AssertionError("loader callback does not hand published events to consumer")
for forbidden in (
    "kzt_observe_guest_object_from_callback",
    "kzt_per_object_got_plt_apply",
    "AddNeededLibWithLibrary",
):
    if forbidden in callback:
        raise AssertionError(f"event publisher callback still performs {forbidden}")

installer = function_body(myalign, "void init_tb_callback_bridge(")
if "option_kzt = 0" in installer:
    raise AssertionError("unknown loader disables KZT instead of failing open")
if "kzt_loader_event_hook_install(" not in installer:
    raise AssertionError("bridge installation does not enforce version isolation")

print("WI-1065 loader hook event contract: PASS")
