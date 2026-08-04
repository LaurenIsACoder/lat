#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    if opening < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
myalign = (root / "target/i386/latx/context/myalign.c").read_text(
    encoding="utf-8"
)
materialize = function_body(
    myalign, "static int kzt_tb_callback_materialize_binding("
)
library_source = (root / "target/i386/latx/context/library.c").read_text(
    encoding="utf-8"
)
reload_body = function_body(library_source, "int ReloadLibrary(")

manifest = materialize.find("FindLibIsWrapped")
proof = materialize.find("kzt_guest_library_wrapper_source_acquire")
add = materialize.find("AddNeededLibWithLibrary")
release = materialize.rfind("kzt_guest_library_wrapper_source_release")
if min(manifest, proof, add, release) < 0:
    raise AssertionError("callback materialization lacks manifest/proof lifecycle")
if not (manifest < proof < add < release):
    raise AssertionError("callback wrapper is materialized before exact source proof")
if "&source_proof" not in materialize[add:release]:
    raise AssertionError("callback wrapped publication does not consume proof")
for forbidden in (
    "GetLibInternal",
    "GetGlobalSymbolStartEnd",
    "soname,",
):
    if forbidden in materialize:
        raise AssertionError(f"callback retains ambiguous wrapper source: {forbidden}")

reload_proof = reload_body.find("kzt_guest_library_wrapper_source_acquire")
reload_reactivate = reload_body.find("kzt_guest_library_reactivate")
reload_pair = reload_body.find("kzt_guest_library_note_loader_pair")
reload_release = reload_body.rfind("kzt_guest_library_wrapper_source_release")
reload_active = reload_body.find("lib->active = 1", reload_pair)
if min(reload_proof, reload_reactivate, reload_pair, reload_release,
       reload_active) < 0:
    raise AssertionError("wrapped reload lacks exact source proof lifecycle")
if not (reload_proof < reload_reactivate < reload_pair < reload_active <
        reload_release):
    raise AssertionError("wrapped reload activates before proof-aware publication")
if "&source_proof" not in reload_body[reload_pair:reload_release]:
    raise AssertionError("wrapped reload publication does not consume proof")

print("WI-1099 wrapper provenance source contract: PASS")
