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

    raise AssertionError("unterminated function body")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    return text[opening + 1:matching_brace(text, opening)]


def assert_before(body: str, first: str, second: str, label: str) -> None:
    first_index = body.find(first)
    second_index = body.find(second)
    if first_index < 0:
        raise AssertionError(f"{label}: missing {first}")
    if second_index < 0:
        raise AssertionError(f"{label}: missing {second}")
    if first_index >= second_index:
        raise AssertionError(
            f"{label}: {first} must appear before {second}"
        )


root = pathlib.Path(sys.argv[1]).resolve()
planner_header = (
    root / "target/i386/latx/include/kzt_patch_planner.h"
).read_text(encoding="utf-8")
planner = (
    root / "target/i386/latx/context/kzt_patch_planner.c"
).read_text(encoding="utf-8")
direct_route = (
    root / "target/i386/latx/context/kzt_lazy_direct_route.c"
).read_text(encoding="utf-8")
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")

policy = function_body(
    planner_header, "static inline int kzt_patch_symbol_must_stay_guest("
)
if 'strcmp(symbol_name, "dlclose") == 0' not in policy:
    raise AssertionError("guest-owned policy must preserve dlclose")

planner_decide = function_body(planner, "int kzt_patch_planner_decide(")
assert_before(
    planner_decide,
    "kzt_patch_symbol_must_stay_guest",
    "kzt_symbol_version_evidence_valid",
    "patch planner",
)
if "KZT_PATCH_REASON_POLICY_KEEP_GUEST" not in planner_decide:
    raise AssertionError("patch planner must report keep-guest policy")

route_apply = function_body(
    direct_route, "kzt_lazy_direct_route_status_t kzt_lazy_direct_route_apply("
)
assert_before(
    route_apply,
    "kzt_patch_symbol_must_stay_guest",
    "ops->validate_source",
    "lazy direct route",
)
if "KZT_LAZY_DIRECT_ROUTE_REASON_GUEST_OWNED_SYMBOL" not in route_apply:
    raise AssertionError("lazy route must report guest-owned symbol")

production_route = function_body(
    production, "int kzt_production_lazy_direct_route("
)
assert_before(
    production_route,
    "kzt_patch_symbol_must_stay_guest",
    "KztGuestRegistryForContext",
    "production lazy route",
)

print("WI-962 guest lifecycle source contract: PASS")
