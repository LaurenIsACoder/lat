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
wrappedlibc = (
    root / "target/i386/latx/context/wrappedlibc.c"
).read_text(encoding="utf-8")
wrappedlibdl = (
    root / "target/i386/latx/context/wrappedlibdl.c"
).read_text(encoding="utf-8")

selector = function_body(
    adapter, "uintptr_t kzt_guest_library_select_symbol_result_with_identity(")
required_selector_tokens = (
    "kzt_rela_runtime_select_exact_wrapper_bridge_retained(",
    "KZT_SYMBOL_VERSION_VERSIONED",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
)
for token in required_selector_tokens:
    if token not in selector:
        raise AssertionError(f"versioned selector misses exact evidence: {token}")

if "(version && version[0]) ||" in selector:
    raise AssertionError("versioned selection still returns before owner proof")
if "versioned = version != NULL" not in selector or \
        "versioned && !version[0]" not in selector:
    raise AssertionError("NULL and empty versions are not distinguished")

dlsym = function_body(common, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(")
dlvsym = function_body(
    common, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlvsym(")
if "(const char *)symbol, NULL" not in dlsym:
    raise AssertionError("dlsym does not explicitly request unversioned selection")
if "(const char *)symbol, version" not in dlvsym:
    raise AssertionError("dlvsym does not pass the requested version")

for name, source in (("libc", wrappedlibc), ("libdl", wrappedlibdl)):
    if "kzt_guest_dl_api_dlsym(" not in source:
        raise AssertionError(f"{name} dlsym does not use the shared API")
    if "kzt_guest_dl_api_dlvsym(" not in source:
        raise AssertionError(f"{name} dlvsym does not use the shared API")

print("WI-982 versioned wrapper selection source contract: PASS")
