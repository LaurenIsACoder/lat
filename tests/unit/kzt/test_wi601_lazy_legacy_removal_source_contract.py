#!/usr/bin/env python3
import pathlib
import re
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

    raise AssertionError("unterminated function body")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    return text[opening + 1:matching_brace(text, opening)]


root = pathlib.Path(sys.argv[1]).resolve()
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
production_header = (
    root / "target/i386/latx/include/kzt_jump_slot_production.h"
).read_text(encoding="utf-8")

resolver = function_body(elfloader, "void PltResolver(void)")
direct_route = function_body(
    production, "int kzt_production_lazy_direct_route("
)
declaration_start = production_header.find(
    "int kzt_production_lazy_direct_route("
)
declaration_end = production_header.find(");", declaration_start)
if declaration_start < 0 or declaration_end < 0:
    raise AssertionError("missing lazy direct production declaration")
declaration = production_header[declaration_start:declaration_end + 2]

violations = {
    "legacy_host_lookup_calls": resolver.count(
        "plt_resolver_lookup_host_symbol("
    ),
    "legacy_get_alternate_calls": resolver.count("getAlternate("),
    "legacy_got_write_count": len(
        re.findall(r"\*p\s*=\s*(?:offs|legacy_target)\s*;", resolver)
    ),
    "legacy_write_action_mentions": resolver.count(
        "KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE"
    ),
    "global_guest_resolver_fallbacks": resolver.count(
        "Push64(cpu, dl_runtime_resolver)"
    ),
    "direct_route_legacy_binding_lookups": direct_route.count(
        "kzt_guest_library_access_lookup_by_library("
    ),
    "direct_route_external_provider_inputs": int(
        "library_t *resolved_provider" in declaration
    ),
    "direct_route_external_target_inputs": int(
        "uintptr_t resolved_target" in declaration
    ),
}

remaining = {name: count for name, count in violations.items() if count}
if remaining:
    details = " ".join(
        f"{name}={count}" for name, count in remaining.items()
    )
    raise AssertionError(
        "WI-601 lazy legacy removal contract RED: " + details
    )

if "kzt_guest_library_access_lookup(" not in direct_route:
    raise AssertionError(
        "lazy direct route must acquire the provider by exact guest key"
    )
if "kzt_guest_symbol_scope_discover(" not in direct_route:
    raise AssertionError(
        "lazy direct route must discover its provider from guest scope"
    )
if "symbol_index >= head->numDynSym" not in direct_route:
    raise AssertionError(
        "lazy direct route must reject out-of-range dynamic symbols"
    )

print("WI-601 lazy legacy removal source contract: PASS")
