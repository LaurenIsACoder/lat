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

evidence = {
    token: selector.find(token)
    for token in (
        "kzt_guest_registry_loader_symbol_source_acquire",
        "kzt_guest_library_access_lookup",
        "kzt_guest_library_symbol_evidence_lookup",
        "kzt_guest_dynsym_lookup(",
        "kzt_guest_library_symbol_evidence_store",
        "proven_runtime_address == guest_result",
        "proven_symbol_type == STT_FUNC",
        "kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence",
        "GetLibFunctionSymbolStartEnd",
    )
}
if min(evidence.values()) < 0:
    raise AssertionError(f"symbol evidence is incomplete: {evidence}")
owner = evidence["kzt_guest_registry_loader_symbol_source_acquire"]
binding = evidence["kzt_guest_library_access_lookup"]
address = evidence["proven_runtime_address == guest_result"]
symbol_type = evidence["proven_symbol_type == STT_FUNC"]
versioned_bridge = evidence[
    "kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence"
]
unversioned_bridge = evidence["GetLibFunctionSymbolStartEnd"]
if not (owner < binding < address <= symbol_type < versioned_bridge and
        symbol_type < unversioned_bridge):
    raise AssertionError(f"symbol proof does not guard both bridges: {evidence}")
cleanup = (
    selector.rfind("kzt_guest_registry_source_lease_release"),
    selector.rfind("kzt_guest_library_handle_release"),
)
if (min(cleanup) < 0 or cleanup != tuple(sorted(cleanup)) or
        cleanup[0] < max(versioned_bridge, unversioned_bridge)):
    raise AssertionError(f"symbol evidence cleanup is incomplete: {cleanup}")

for token in (
    "KZT_SYMBOL_VERSION_VERSIONED, version",
    "KZT_PATCH_WRAPPER_VERSION_MATCH",
    "kzt_symbol_version_evidence_matches(",
):
    if token not in selector:
        raise AssertionError(f"versioned symbol proof is incomplete: {token}")

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
