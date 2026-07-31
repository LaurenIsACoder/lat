#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
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
adapter = (
    root / "target/i386/latx/context/kzt_guest_library_adapter.c"
).read_text(encoding="utf-8")
library_source = (
    root / "target/i386/latx/context/library.c"
).read_text(encoding="utf-8")
selector = function_body(
    adapter, "uintptr_t kzt_guest_library_select_symbol_result("
)

ordered = (
    "kzt_guest_registry_loader_symbol_source_acquire",
    "kzt_guest_library_access_lookup",
    "kzt_guest_library_symbol_evidence_lookup",
    "kzt_guest_dynsym_lookup(",
    "kzt_guest_library_symbol_evidence_store",
    "proven_symbol_type == STT_FUNC",
    "GetLibFunctionSymbolStartEnd",
)
positions = [selector.find(token) for token in ordered]
if min(positions) < 0 or positions != sorted(positions):
    raise AssertionError(f"symbol evidence order is incomplete: {positions}")
cleanup = (
    selector.rfind("kzt_guest_registry_source_lease_release"),
    selector.rfind("kzt_guest_library_handle_release"),
)
if (min(cleanup) < 0 or cleanup != tuple(sorted(cleanup)) or
        cleanup[0] < positions[-1]):
    raise AssertionError(f"symbol evidence cleanup is incomplete: {cleanup}")

version_guard = selector.find("version && version[0]")
if version_guard < 0 or version_guard > positions[0]:
    raise AssertionError("versioned lookup reaches unversioned wrapper selection")

for forbidden in (
    "GetGlobalSymbolStartEnd",
    "GetLibInternal",
    "FindLibIsWrapped",
    "AddNeededLib",
    "dlsym(",
    "dlvsym(",
    "basename(",
    "soname",
    "kzt_guest_registry_resolve_address_pair",
    "kzt_guest_registry_find_loader_identity",
    "kzt_guest_registry_find_dynamic_view",
):
    if forbidden in selector:
        raise AssertionError(f"selector retains ambiguous bypass: {forbidden}")

function_lookup = function_body(
    library_source, "int GetLibFunctionSymbolStartEnd(")
if "wrapper_manifest_symbol_is_function" not in function_lookup:
    raise AssertionError("wrapper result lacks function-only manifest proof")
for forbidden in ("getSymbolInMaps(", "getSymbolInDataMaps(", "lib->get("):
    if forbidden in function_lookup:
        raise AssertionError(f"function-only wrapper lookup uses data path: {forbidden}")

print("WI-1099 symbol type source contract: PASS")
