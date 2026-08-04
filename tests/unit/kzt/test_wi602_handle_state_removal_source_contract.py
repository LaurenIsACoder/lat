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
header = (root / "target/i386/latx/include/box64context.h").read_text(
    encoding="utf-8"
)
api = (root / "target/i386/latx/context/kzt_guest_dl_api.c").read_text(
    encoding="utf-8"
)
production_meson = (
    root / "target/i386/latx/context/meson.build"
).read_text(encoding="utf-8")
test_meson = (root / "tests/unit/meson.build").read_text(encoding="utf-8")

for removed_path in (
    "target/i386/latx/context/dlopen_recycle_transaction.c",
    "target/i386/latx/include/dlopen_recycle_transaction.h",
    "tests/unit/kzt/test_dlopen_recycle_transaction.c",
):
    if (root / removed_path).exists():
        raise AssertionError(f"removed recycle helper still exists: {removed_path}")

for meson_text in (production_meson, test_meson):
    if "dlopen_recycle_transaction" in meson_text:
        raise AssertionError("build graph still references removed recycle helper")

dlprivate_start = header.find("typedef struct dlprivate_s {")
dlprivate_end = header.find("} dlprivate_t;", dlprivate_start)
if dlprivate_start < 0 or dlprivate_end < 0:
    raise AssertionError("dlprivate_t declaration is missing")
dlprivate = header[dlprivate_start:dlprivate_end]

for legacy_field in ("libs;", "count;", "dlopened;", "dlx86handle;", "lib_sz;", "lib_cap;"):
    if legacy_field in dlprivate:
        raise AssertionError(f"dlprivate_t retains legacy state: {legacy_field}")

if "kzt_guest_dl_api_translate_handle" in api:
    raise AssertionError("shared guest dl API retains old handle translation")

for signature, guest_call in (
    ("kzt_guest_dl_api_dlsym(", "kzt_guest_library_run_dlsym"),
    ("kzt_guest_dl_api_dlvsym(", "kzt_guest_library_run_dlvsym"),
    ("kzt_guest_dl_api_dlinfo(", "kzt_guest_library_run_dlinfo"),
):
    body = function_body(api, signature)
    if guest_call not in body:
        raise AssertionError(f"{signature} does not call guest loader")
    if "guest_handle" in body:
        raise AssertionError(f"{signature} retains a translated handle")

print("WI-602 legacy handle state removal source contract: PASS")
