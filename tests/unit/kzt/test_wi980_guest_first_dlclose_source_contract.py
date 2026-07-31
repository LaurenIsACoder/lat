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
common_dlclose = function_body(common, "int kzt_guest_dl_api_dlclose(")

guest_close = common_dlclose.find("kzt_guest_library_run_dlclose")
presence_probe = common_dlclose.find("kzt_guest_library_run_dlopen_scoped")
inactivate = common_dlclose.find("InactiveLibrary")
if guest_close < 0:
    raise AssertionError("shared dlclose does not call guest dlclose")
if presence_probe >= 0 and guest_close >= presence_probe:
    raise AssertionError("guest object is probed before guest dlclose")
if inactivate >= 0 and guest_close >= inactivate:
    raise AssertionError("native wrapper is inactivated before guest dlclose")
if "return guest_result" not in common_dlclose:
    raise AssertionError("shared dlclose does not preserve guest result")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    source = (root / relative).read_text(encoding="utf-8")
    dlclose = function_body(source, "int my_dlclose(void *handle)\n{")
    if "kzt_guest_dl_api_dlclose" not in dlclose:
        raise AssertionError(f"{relative}: dlclose bypasses shared guest API")
    for obsolete in (
        "dl->libs",
        "dl->count",
        "dl->dlopened",
        "Push64",
        "InactiveLibrary",
        "GetElfIndex",
    ):
        if obsolete in dlclose:
            raise AssertionError(
                f"{relative}: dlclose retains old state via {obsolete}")

print("WI-980 guest-first dlclose source contract: PASS")
