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
    raise AssertionError("unterminated C function")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    return text[opening + 1:matching_brace(text, opening)]


root = pathlib.Path(sys.argv[1]).resolve()
bridge_header = (
    root / "target/i386/latx/include/kzt_rela_runtime_bridge.h"
).read_text(encoding="utf-8")
bridge_source = (
    root / "target/i386/latx/context/kzt_rela_runtime_bridge.c"
).read_text(encoding="utf-8")
adapter = (
    root / "target/i386/latx/context/kzt_guest_library_adapter.c"
).read_text(encoding="utf-8")
glob_dat_source = (
    root / "target/i386/latx/context/kzt_guest_glob_dat_target.c"
).read_text(encoding="utf-8")

selector_name = "kzt_rela_runtime_select_exact_wrapper_bridge_retained("
if selector_name not in bridge_header:
    raise AssertionError("shared retained-handle bridge selector is not declared")

shared = function_body(bridge_source, selector_name)
for token in (
    "kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(",
    "kzt_wrapper_probe_minimal_manifest(",
    "KZT_PATCH_WRAPPER_UNVERSIONED_MATCH",
    "KZT_PATCH_WRAPPER_VERSION_MATCH",
    "kzt_symbol_version_evidence_matches(",
    "probe.bridge_target",
):
    if token not in shared:
        raise AssertionError(f"shared selector lacks exact wrapper proof: {token}")

dlsym_selector = function_body(
    adapter, "uintptr_t kzt_guest_library_select_symbol_result_with_identity(")
if "GetLibFunctionSymbolStartEnd(" in dlsym_selector:
    raise AssertionError("dlsym selector still uses the generic name-keyed lookup")
if selector_name not in dlsym_selector:
    raise AssertionError("dlsym selector does not use the shared exact selector")
if dlsym_selector.count("kzt_guest_library_symbol_evidence_lookup(") != 1:
    raise AssertionError("dlsym selector must read symbol and bridge evidence once")
if "kzt_guest_library_symbol_bridge_lookup(" in dlsym_selector:
    raise AssertionError("dlsym selector takes a second binding lock for bridge evidence")
for token in (
    "KZT_SYMBOL_VERSION_VERSIONED",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
    "kzt_guest_library_symbol_evidence_lookup(",
    "kzt_guest_library_symbol_bridge_store(",
):
    if token not in dlsym_selector:
        raise AssertionError(f"dlsym selector lacks version evidence: {token}")

glob_dat = function_body(
    glob_dat_source, "kzt_guest_glob_dat_target_resolve(")
glob_dat_route = function_body(
    glob_dat_source, "int kzt_guest_glob_dat_route(")
if "GetLibSymbolStartEnd(" in glob_dat:
    raise AssertionError("GLOB_DAT still uses the generic name-keyed lookup")
if selector_name not in glob_dat:
    raise AssertionError("GLOB_DAT does not use the shared exact selector")
for token in (
    "KZT_GUEST_LIBRARY_OBJECT_WRAPPED",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
    "version >= 2",
    ".version = NULL",
):
    if token not in glob_dat:
        raise AssertionError(f"GLOB_DAT lacks exact version/owner proof: {token}")
if "target->selected_target = guest_target" not in glob_dat:
    raise AssertionError("GLOB_DAT lost its fail-open guest target")
if "KZT_SYMBOL_VERSION_VERSIONED" in glob_dat:
    raise AssertionError("GLOB_DAT widened beyond confirmed unversioned symbols")
for token in (
    "kzt_guest_symbol_scope_revalidate(",
    "kzt_production_eager_relocation_write(",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
    "kzt_guest_glob_dat_target_release(",
):
    if token not in glob_dat_route:
        raise AssertionError(f"GLOB_DAT route lacks executable fail-open flow: {token}")
if "KZT_SYMBOL_VERSION_VERSIONED" in glob_dat_route:
    raise AssertionError("GLOB_DAT writer widened beyond confirmed unversioned symbols")

print("WI-1633 exact wrapper selection source contract: PASS")
