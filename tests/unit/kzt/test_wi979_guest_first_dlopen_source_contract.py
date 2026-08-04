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
common = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
common_dlopen = function_body(common, "uint64_t kzt_guest_dl_api_dlopen(")

guest_call = common_dlopen.find("kzt_guest_library_run_dlopen_scoped")
wrapper_attach = common_dlopen.find("AddNeededLibWithLibrary")
finish = common_dlopen.find("kzt_guest_dl_api_finish_dlopen_scoped")
if guest_call < 0 or wrapper_attach < 0 or finish < 0:
    raise AssertionError("shared dlopen misses guest call or wrapper attachment")
if guest_call >= wrapper_attach:
    raise AssertionError("wrapper attachment happens before guest dlopen")
if "return guest_handle" not in common_dlopen:
    raise AssertionError("shared dlopen does not preserve the guest handle")
if "if (!guest_handle)" not in common_dlopen:
    raise AssertionError("shared dlopen does not stop attachment on guest failure")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    source = (root / relative).read_text(encoding="utf-8")
    dlopen = function_body(
        source, "void* my_dlopen(void *filename, int flag){")
    if "kzt_guest_dl_api_dlopen" not in dlopen:
        raise AssertionError(f"{relative}: dlopen bypasses shared guest API")
    for obsolete in (
        "AddNeededLibWithLibrary",
        "dl->libs",
        "dl->count",
        "dl->dlopened",
        "dlopen_recycle_transaction",
        "callx86dlopen",
        "run_guest_dlopen_scoped",
        "(void*)(i+1)",
    ):
        if obsolete in dlopen:
            raise AssertionError(
                f"{relative}: dlopen retains old state via {obsolete}")

print("WI-979 guest-first dlopen source contract: PASS")
