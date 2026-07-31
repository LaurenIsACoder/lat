#!/usr/bin/env python3
import pathlib
import sys


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("unterminated function")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    return text[opening + 1:matching_brace(text, opening)]


root = pathlib.Path(sys.argv[1]).resolve()
adapter = (
    root / "target/i386/latx/context/kzt_guest_library_adapter.c"
).read_text(encoding="utf-8")
common = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")

selector = function_body(
    adapter, "uintptr_t kzt_guest_library_select_symbol_result(")
version_guard = selector.find("version && version[0]")
owner_lookup = selector.find("kzt_guest_registry_resolve_address_pair")
if version_guard < 0:
    raise AssertionError("versioned selection is not explicitly fail-open")
if owner_lookup >= 0 and version_guard >= owner_lookup:
    raise AssertionError("versioned lookup reaches unversioned owner selection")

dlsym = function_body(common, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(")
dlvsym = function_body(
    common, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlvsym(")
if "context, (uintptr_t)handle, guest_result" not in dlsym:
    raise AssertionError("dlsym does not declare its unversioned selection")
if "context, (uintptr_t)handle, guest_result" not in dlvsym:
    raise AssertionError("dlvsym does not pass the requested version")

print("WI-982 versioned wrapper selection source contract: PASS")
