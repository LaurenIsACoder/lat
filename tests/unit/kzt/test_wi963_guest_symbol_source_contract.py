#!/usr/bin/env python3
import pathlib
import sys


def strip_if_zero(text: str) -> str:
    output = []
    disabled_depth = 0
    for line in text.splitlines(keepends=True):
        directive = line.strip()
        if disabled_depth:
            if directive.startswith(("#if ", "#ifdef ", "#ifndef ")):
                disabled_depth += 1
            elif directive == "#endif":
                disabled_depth -= 1
            continue
        if directive == "#if 0":
            disabled_depth = 1
            continue
        output.append(line)
    if disabled_depth:
        raise AssertionError("unterminated #if 0 block")
    return "".join(output)


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


def assert_before(body: str, first: str, second: str, label: str) -> None:
    first_index = body.find(first)
    second_index = body.find(second)
    if first_index < 0 or second_index < 0 or first_index >= second_index:
        raise AssertionError(f"{label}: {first} must precede {second}")


root = pathlib.Path(sys.argv[1]).resolve()
context_header = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")
state_header = (
    root / "target/i386/latx/include/kzt_guest_dl_state.h"
).read_text(encoding="utf-8")
cpu_header = (root / "target/i386/cpu.h").read_text(encoding="utf-8")
common_source = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
init_source = (
    root / "target/i386/latx/context/kzt_guest_dl_init.c"
).read_text(encoding="utf-8")
common_dlsym = function_body(
    common_source, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(")
common_dlvsym = function_body(
    common_source, "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlvsym(")
common_dlerror = function_body(
    common_source, "kzt_guest_dlerror_result_t kzt_guest_dl_api_dlerror(")

assert_before(
    common_dlsym,
    "kzt_guest_library_run_dlsym",
    "kzt_guest_library_select_symbol_result",
    "shared guest dlsym",
)
assert_before(
    common_dlvsym,
    "kzt_guest_library_run_dlvsym",
    "kzt_guest_library_select_symbol_result",
    "shared guest dlvsym",
)
if "version" not in common_dlvsym:
    raise AssertionError("shared guest dlvsym drops the version")
if "kzt_guest_library_run_dlerror" not in common_dlerror:
    raise AssertionError("shared guest dlerror does not consume guest state")
if "last_error_returned" not in common_dlerror:
    raise AssertionError("shared local dlerror is not one-shot")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    source = strip_if_zero((root / relative).read_text(encoding="utf-8"))
    dlsym = function_body(source, "void* my_dlsym(")
    dlvsym = function_body(source, "void* my_dlvsym(")
    dlerror = function_body(source, "char* my_dlerror(void)")
    dlerror_slow = function_body(
        source, "static char *kzt_guest_dlerror_slow_path("
    )

    if "init_x86dlfun" in source:
        raise AssertionError(f"{relative}: retains private guest dl init")
    if "kzt_guest_dl_entries_for_call" not in source:
        raise AssertionError(f"{relative}: bypasses shared guest dl init")

    if "kzt_guest_dl_api_dlsym" not in dlsym:
        raise AssertionError(f"{relative}: dlsym bypasses shared guest API")
    if "kzt_guest_dl_api_dlvsym" not in dlvsym:
        raise AssertionError(f"{relative}: dlvsym bypasses shared guest API")
    if "my_dlsym(handle, symbol)" in dlvsym:
        raise AssertionError(f"{relative}: dlvsym drops the version")
    if "entries->dlvsym" not in dlvsym:
        raise AssertionError(f"{relative}: RTLD_NEXT does not keep dlvsym")
    if "vername" not in dlvsym:
        raise AssertionError(f"{relative}: dlvsym does not pass vername")
    if (
        "kzt_guest_dl_api_dlerror" not in dlerror
        and "kzt_guest_dlerror_slow_path" not in dlerror
    ):
        raise AssertionError(f"{relative}: dlerror bypasses shared guest API")
    if "kzt_guest_dl_api_dlerror" not in dlerror_slow:
        raise AssertionError(
            f"{relative}: dlerror slow path bypasses shared guest API"
        )

for symbol in ('"dlvsym"', '"dlerror"'):
    if symbol not in init_source:
        raise AssertionError(f"shared guest dl init misses {symbol}")
for assignment in (".dlvsym = (uintptr_t)resolved[7]", ".dlerror = (uintptr_t)resolved[8]"):
    if assignment not in init_source:
        raise AssertionError(f"shared guest dl init misses {assignment}")
if "kzt_guest_dl_entry_state_t guest_dl_entries;" not in context_header:
    raise AssertionError("dlprivate_t misses immutable guest dl table state")
if "kzt_guest_dlerror_state_t kzt_guest_dlerror_state;" not in cpu_header:
    raise AssertionError("guest thread state misses dlerror ownership")
if "last_error_returned" not in state_header:
    raise AssertionError("thread-local dlerror state is not one-shot")

print("WI-963 guest symbol source contract: PASS")
