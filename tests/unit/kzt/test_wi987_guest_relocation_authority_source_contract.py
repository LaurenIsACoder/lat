#!/usr/bin/env python3
import pathlib
import re
import sys


def fail(message: str) -> None:
    raise AssertionError(message)


def matching_brace(text: str, start: int) -> int:
    depth = 0
    quote = None
    escaped = False
    index = start

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
                fail("unterminated C comment")
            index = end + 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    fail("unterminated C function")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        fail(f"missing function: {signature}")
    brace = text.find("{", start + len(signature))
    if brace < 0:
        fail(f"missing function body: {signature}")
    return text[brace + 1:matching_brace(text, brace)]


root = pathlib.Path(sys.argv[1]).resolve()
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
route = (
    root / "target/i386/latx/context/kzt_jump_slot_route.c"
).read_text(encoding="utf-8")
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")

rela = function_body(elfloader, "int RelocateElfRELA(")
legacy = function_body(elfloader, "kzt_resolve_legacy_rela_target(")
glob_dat = function_body(
    elfloader, "kzt_guest_glob_dat_target_resolve("
)
route_apply = function_body(route, "int kzt_jump_slot_route_apply(")
acquire = function_body(production, "static int production_acquire_exact(")

if "GetGlobalSymbolStartEndWithProvider(" in rela:
    fail("RelocateElfRELA must not perform eager host symbol arbitration")
if rela.count("kzt_resolve_legacy_rela_target(") != 2:
    fail("RelocateElfRELA must have one fallback for each supported type")
if "GetGlobalSymbolStartEndWithProvider(" not in legacy:
    fail("legacy compatibility helper lost the historical host lookup")

required_glob_dat = (
    "kzt_owner_resolver_resolve_current(",
    "KZT_OWNER_RESOLVER_RESOLVED",
    "KZT_PATCH_OWNER_MATCH",
    "current_owner.known",
    "KztGuestLibraryLookupForContext(",
    "GetLibSymbolStartEnd(",
    "STT_FUNC",
    "version >= 2",
)
for required in required_glob_dat:
    if required not in glob_dat:
        fail(f"GLOB_DAT authority lacks Registry owner proof: {required}")

guest_route = re.search(
    r"kzt_production_jump_slot_route\s*\(\s*"
    r"my_context\s*,\s*NULL\s*,\s*slot_observation\s*,",
    rela,
    re.DOTALL,
)
if not guest_route:
    fail("eager JUMP_SLOT must enter the route without a host provider")
if not re.search(
    r"if\s*\(\s*\(option_kzt\s*\|\|\s*wine_option_kzt\)\s*&&\s*"
    r"head->self_link_map\s*&&\s*bind\s*!=\s*STB_LOCAL",
    rela,
    re.DOTALL,
):
    fail("eager JUMP_SLOT must skip the new route before source identity exists")
fallback = rela.rfind("kzt_resolve_legacy_rela_target(")
if fallback < 0 or guest_route.start() > fallback:
    fail("host compatibility lookup must happen after the guest-first route")
if not re.search(
    r"kzt_guest_glob_dat_target_resolve\s*\([\s\S]*?\)\s*\)\s*\{"
    r"[\s\S]*?continue\s*;",
    rela,
):
    fail("authoritative GLOB_DAT guest targets must bypass host lookup")
if not re.search(
    r"if\s*\(\s*bind\s*!=\s*STB_LOCAL\s*\)\s*\{[\s\S]*?"
    r"route=GUEST_PRESERVED[\s\S]*?host_lookup=0[\s\S]*?continue\s*;",
    rela,
):
    fail("KZT GLOB_DAT evidence failure can reach host lookup")
if not re.search(
    r"if\s*\(\s*\(option_kzt\s*\|\|\s*wine_option_kzt\)\s*&&\s*"
    r"bind\s*!=\s*STB_LOCAL\s*\)\s*\{[\s\S]*?"
    r"route=GUEST_PRESERVED[\s\S]*?host_lookup=0[\s\S]*?break\s*;",
    rela,
):
    fail("KZT JUMP_SLOT evidence failure can reach host lookup")
if "__atomic_compare_exchange_n(" not in rela:
    fail("GLOB_DAT exact-owner bridge must not overwrite a competitor")

for forbidden in ("input->resolved_target_matches_legacy",):
    if forbidden in route_apply:
        fail(f"route still depends on host arbitration: {forbidden}")
if "input->resolved_provider &&" in route_apply:
    fail("route still requires a host-selected provider")

if "!resolved_provider" in acquire:
    fail("exact provider acquisition rejects Registry-only lookup")
for required in (
    "KztGuestLibraryLookupForContext(",
    "state->resolved_provider = handle->library;",
):
    if required not in acquire:
        fail(f"exact provider acquisition lacks Registry binding: {required}")

print("WI-987 guest relocation authority source contract: PASS")
