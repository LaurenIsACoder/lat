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
runtime_bridge = (
    root / "target/i386/latx/context/kzt_rela_runtime_bridge.c"
).read_text(encoding="utf-8")
selector = function_body(
    adapter, "uintptr_t kzt_guest_library_select_symbol_result_with_identity("
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
        "kzt_rela_runtime_select_exact_wrapper_bridge_retained",
    )
}
if min(evidence.values()) < 0:
    raise AssertionError(f"symbol evidence is incomplete: {evidence}")
owner = evidence["kzt_guest_registry_loader_symbol_source_acquire"]
binding = evidence["kzt_guest_library_access_lookup"]
address = evidence["proven_runtime_address == guest_result"]
symbol_type = evidence["proven_symbol_type == STT_FUNC"]
exact_bridge = evidence["kzt_rela_runtime_select_exact_wrapper_bridge_retained"]
if not owner < binding < address <= symbol_type < exact_bridge:
    raise AssertionError(f"symbol proof does not guard exact bridge: {evidence}")
cleanup = (
    selector.rfind("kzt_guest_registry_source_lease_release"),
    selector.rfind("kzt_guest_library_handle_release"),
)
if (min(cleanup) < 0 or cleanup != tuple(sorted(cleanup)) or
        cleanup[0] < exact_bridge):
    raise AssertionError(f"symbol evidence cleanup is incomplete: {cleanup}")

shared_selector = function_body(
    runtime_bridge,
    "uintptr_t kzt_rela_runtime_select_exact_wrapper_bridge_retained(")
for token in (
    "kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(",
    "kzt_wrapper_probe_minimal_manifest(",
    "KZT_PATCH_WRAPPER_VERSION_MATCH",
    "KZT_PATCH_WRAPPER_UNVERSIONED_MATCH",
    "kzt_symbol_version_evidence_matches(",
):
    if token not in shared_selector:
        raise AssertionError(f"shared symbol proof is incomplete: {token}")

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

provider_inspect = function_body(
    runtime_bridge, "static int kzt_rela_runtime_provider_inspect(")
for forbidden in ("datamap", "getSymbolInDataMaps(", "lib->get("):
    if forbidden in provider_inspect:
        raise AssertionError(f"wrapper provider uses a data-symbol path: {forbidden}")

print("WI-1099 symbol type source contract: PASS")
