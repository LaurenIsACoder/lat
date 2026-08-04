#!/usr/bin/env python3
import pathlib
import sys


root = pathlib.Path(sys.argv[1]).resolve()
common_header = root / "target/i386/latx/include/kzt_guest_dl_api.h"
common_source = root / "target/i386/latx/context/kzt_guest_dl_api.c"

if not common_header.is_file() or not common_source.is_file():
    raise AssertionError("shared guest dl API is missing")

source = common_source.read_text(encoding="utf-8")
header = common_header.read_text(encoding="utf-8")
required_common_operations = (
    "kzt_guest_dl_api_clear_error",
    "kzt_guest_dl_api_dlmopen",
    "kzt_guest_dl_api_dlsym",
    "kzt_guest_dl_api_dlvsym",
    "kzt_guest_dl_api_dlerror",
    "kzt_guest_dl_api_dlinfo",
)
for operation in required_common_operations:
    if operation not in source:
        raise AssertionError(f"shared guest dl API misses {operation}")

begin_start = header.find("static inline int kzt_guest_dl_api_begin_call(")
begin_end = header.find("\n}", begin_start)
if begin_start < 0 or begin_end < 0 or \
        "kzt_guest_dl_api_clear_error(state)" not in header[begin_start:begin_end]:
    raise AssertionError("guest DL call entry no longer clears the shared error state")

for operation in (
    "kzt_guest_library_run_dlmopen",
    "kzt_guest_library_run_dlsym",
    "kzt_guest_library_run_dlvsym",
    "kzt_guest_library_run_dlerror",
    "kzt_guest_library_run_dlinfo",
    "kzt_guest_library_select_symbol_result",
):
    if operation not in source:
        raise AssertionError(f"shared guest dl API bypasses {operation}")

for relative in (
    "target/i386/latx/context/wrappedlibc.c",
    "target/i386/latx/context/wrappedlibdl.c",
):
    wrapper = (root / relative).read_text(encoding="utf-8")
    if '#include "kzt_guest_dl_api.h"' not in wrapper:
        raise AssertionError(f"{relative}: shared guest dl API is not included")
    for operation in required_common_operations[1:]:
        if operation not in wrapper:
            raise AssertionError(f"{relative}: does not call {operation}")
    if "kzt_guest_dl_api_begin_call(error_state)" not in wrapper:
        raise AssertionError(f"{relative}: does not enter the shared error state machine")
    for obsolete in (
        "recursive_dlsym_lib",
        "my_dlsym_lib",
        "kzt_symbol_set_bad_handle",
        "kzt_symbol_guest_handle",
    ):
        if obsolete in wrapper:
            raise AssertionError(f"{relative}: retains duplicated {obsolete}")
    if "\n#if 0\nvoid* my_dlsym(" in wrapper:
        raise AssertionError(f"{relative}: retains disabled legacy dlsym")
    for low_level in (
        "kzt_guest_library_run_dlmopen",
        "kzt_guest_library_run_dlsym",
        "kzt_guest_library_run_dlvsym",
        "kzt_guest_library_run_dlerror",
        "kzt_guest_library_run_dlinfo",
        "kzt_guest_library_select_symbol_result",
    ):
        if low_level in wrapper:
            raise AssertionError(
                f"{relative}: duplicates shared state machine via {low_level}"
            )

cpu_source = (root / "target/i386/cpu.c").read_text(encoding="utf-8")
context_source = (
    root / "target/i386/latx/context/box64context.c"
).read_text(encoding="utf-8")
if "kzt_guest_dl_api_free_errors(&cpu->env.kzt_guest_dlerror_state)" not in cpu_source:
    raise AssertionError("guest thread destruction does not free dlerror state")
if "kzt_guest_dl_api_free_errors(&(*dl)->legacy_error)" not in context_source:
    raise AssertionError("legacy context destruction does not free dlerror state")

print("WI-964 shared guest dl API source contract: PASS")
