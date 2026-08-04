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
    raise AssertionError("unterminated function")


def function_body(text: str, signature: str) -> str:
    start = 0
    while True:
        start = text.find(signature, start)
        if start < 0:
            raise AssertionError(f"missing function: {signature}")
        opening = text.find("{", start + len(signature))
        semicolon = text.find(";", start + len(signature))
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            return text[opening + 1:matching_brace(text, opening)]
        start += len(signature)


root = pathlib.Path(sys.argv[1]).resolve()
header = (
    root / "target/i386/latx/include/kzt_guest_dl_api.h"
).read_text(encoding="utf-8")
source = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")

if "kzt_guest_dlerror_result_t" not in header:
    raise AssertionError("shared dlerror result does not expose tail forwarding")

shared = function_body(
    source,
    "kzt_guest_dlerror_result_t kzt_guest_dl_api_dlerror(",
)
if "forward_to_guest_caller = 1" not in shared:
    raise AssertionError("empty local error does not tail-forward to guest")
if "kzt_guest_library_run_dlerror" not in shared:
    raise AssertionError("local synthetic error no longer consumes stale guest error")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    wrapper = (root / relative).read_text(encoding="utf-8")
    helper = function_body(
        wrapper, "static uintptr_t kzt_guest_dlerror_entry_slow("
    )
    if "kzt_guest_dl_entries_for_call(context" not in helper or \
            "entries ? entries->dlerror : 0" not in helper:
        raise AssertionError(f"{relative}: dlerror slow fallback is incomplete")
    state_slow = function_body(
        wrapper, "static char *kzt_guest_dlerror_slow_path("
    )
    for required in (
        "kzt_guest_dl_api_dlerror(",
        "guest_route_may_have_pending_error",
        "kzt_guest_dl_api_load_dlerror_hint(",
        "kzt_guest_dlerror_entry_slow(context)",
        "error_state->guest_dlerror_entry = guest_dlerror",
        "Push64(cpu, guest_dlerror)",
    ):
        if required not in state_slow:
            raise AssertionError(
                f"{relative}: dlerror state slow path misses {required}"
            )
    body = function_body(wrapper, "char* my_dlerror(void)")
    if "kzt_guest_dlerror_result_t" not in state_slow:
        raise AssertionError(f"{relative}: dlerror does not use shared result")
    if "forward_to_guest_caller" not in state_slow:
        raise AssertionError(f"{relative}: dlerror does not check tail forwarding")
    state_check = body.find("if (fast_result || guest_loader_route)")
    slow = body.find("kzt_guest_dlerror_slow_path(")
    fast_return = body.find("return fast_result;")
    if min(state_check, slow, fast_return) < 0 or not (
            state_check < slow < fast_return):
        raise AssertionError(
            f"{relative}: dlerror does not isolate its clean fast path"
        )
    if "char *fast_result" not in body:
        raise AssertionError(f"{relative}: clean dlerror result is materialized")
    if "kzt_guest_loader_route_present" not in body:
        raise AssertionError(f"{relative}: guest loader route is not preserved")
    if "guest_loader_route);" not in body:
        raise AssertionError(
            f"{relative}: guest loader route is not passed to the slow path"
        )
    if "kzt_guest_dl_entries_t fallback" in body:
        raise AssertionError(f"{relative}: hot dlerror retains cold stack state")
    if "RunFunctionWithState" in body:
        raise AssertionError(f"{relative}: dlerror retains nested guest execution")

print("WI-994 dlerror tail-forward source contract: PASS")
