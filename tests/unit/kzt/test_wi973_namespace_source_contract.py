#!/usr/bin/env python3
import pathlib
import sys


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote = None
    escaped = False
    index = opening

    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char == "/" and following == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char == "/" and following == "*":
            end = text.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated C comment")
            index = end + 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1

    raise AssertionError("unterminated function body")


def function_body(text: str, signature: str) -> str:
    start = 0
    while True:
        start = text.find(signature, start)
        if start < 0:
            raise AssertionError(f"missing function: {signature}")
        opening = text.find("{", start + len(signature))
        semicolon = text.find(";", start + len(signature))
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            return text[opening + 1:matching_brace(text, opening)]
        start += len(signature)


root = pathlib.Path(sys.argv[1]).resolve()
context_header = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")
init_source = (
    root / "target/i386/latx/context/kzt_guest_dl_init.c"
).read_text(encoding="utf-8")
common_source = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
common_dlmopen = function_body(
    common_source, "uint64_t kzt_guest_dl_api_dlmopen(")
common_dlinfo = function_body(
    common_source, "int kzt_guest_dl_api_dlinfo(")

if "kzt_guest_library_run_dlmopen" not in common_dlmopen:
    raise AssertionError("shared non-main dlmopen does not use guest")
if "kzt_guest_dl_api_translate_handle" in common_dlinfo:
    raise AssertionError("shared dlinfo retains removed synthetic-handle mapping")
if "kzt_guest_library_run_dlinfo" not in common_dlinfo:
    raise AssertionError("shared dlinfo does not use guest")

if "kzt_guest_dl_entry_state_t guest_dl_entries;" not in context_header:
    raise AssertionError("dlprivate_t misses immutable guest dl table state")
if '"dlmopen"' not in init_source or ".dlmopen = (uintptr_t)resolved[1]" not in init_source:
    raise AssertionError("shared guest dl init misses dlmopen")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    source = (root / relative).read_text(encoding="utf-8")
    dlmopen = function_body(source, "void* my_dlmopen(")
    dlinfo = function_body(source, "int my_dlinfo(")

    if "init_x86dlfun" in source:
        raise AssertionError(f"{relative}: retains private guest dl init")
    if "kzt_guest_dl_entries_for_call" not in source:
        raise AssertionError(f"{relative}: bypasses shared guest dl init")
    if "if (!lmid)" not in dlmopen or "my_dlopen(filename, flag)" not in dlmopen:
        raise AssertionError(f"{relative}: LM_ID_BASE path is not preserved")
    if "kzt_guest_dl_api_dlmopen" not in dlmopen:
        raise AssertionError(f"{relative}: dlmopen bypasses shared guest API")
    if "kzt_guest_dl_api_dlinfo" not in dlinfo:
        raise AssertionError(f"{relative}: dlinfo bypasses shared guest API")
    if "lsassert(0)" in dlinfo:
        raise AssertionError(f"{relative}: dlinfo retains unsupported assertion")
    if "RunFunctionWithState" in dlinfo:
        raise AssertionError(f"{relative}: dlinfo bypasses shared adapter")

print("WI-973 namespace source contract: PASS")
