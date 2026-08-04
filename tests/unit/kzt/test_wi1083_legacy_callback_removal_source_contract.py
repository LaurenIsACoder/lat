#!/usr/bin/env python3
import pathlib
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
myalign = (
    root / "target/i386/latx/context/myalign.c"
).read_text(encoding="utf-8")
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
elfloader_header = (
    root / "target/i386/latx/include/elfloader.h"
).read_text(encoding="utf-8")

legacy_callback = "kzt_tb_callback_" + "legacy"
if legacy_callback in myalign:
    fail("legacy raw-ELF callback definition or call still exists")

consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
if "#ifdef CONFIG_LATX_KZT" not in consumer:
    fail("callback consumer lost its explicit KZT compile boundary")
non_kzt = consumer.split("#else", 1)[1].split("#endif", 1)[0]
non_kzt_lines = [line.strip() for line in non_kzt.splitlines() if line.strip()]
if non_kzt_lines != ["(void)context;", "(void)env;", "(void)event;"]:
    fail(f"non-KZT callback consumer is not a clear no-op: {non_kzt_lines}")

runtime_header = (
    root / "target/i386/latx/include/kzt_guest_runtime_entry.h"
).read_text(encoding="utf-8")
runtime_source = (
    root / "target/i386/latx/context/kzt_guest_runtime_entry.c"
).read_text(encoding="utf-8")
runtime_state_header = (
    root / "target/i386/latx/include/kzt_guest_runtime_entry_state.h"
).read_text(encoding="utf-8")
runtime_state_source = (
    root / "target/i386/latx/context/kzt_guest_runtime_entry_state.c"
).read_text(encoding="utf-8")
cancel_scope_source = (
    root / "target/i386/latx/context/kzt_guest_cancel_scope.c"
).read_text(encoding="utf-8")
wrappedlibc = (
    root / "target/i386/latx/context/wrappedlibc.c"
).read_text(encoding="utf-8")
tr_misc = (
    root / "target/i386/latx/translator/tr-misc.c"
).read_text(encoding="utf-8")
wrappedlibx11 = (
    root / "target/i386/latx/context/wrappedlibx11.c"
).read_text(encoding="utf-8")
wrappedlibxcb = (
    root / "target/i386/latx/context/wrappedlibxcb.c"
).read_text(encoding="utf-8")
guest_dl_init = (
    root / "target/i386/latx/context/kzt_guest_dl_init.c"
).read_text(encoding="utf-8")
guest_dl_api = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
box64context = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")

for symbol in ("free", "realloc", "pthread_setcanceltype"):
    if f'"{symbol}"' not in guest_dl_init:
        fail(f"guest ELF initialization misses exact symbol name: {symbol}")
for forbidden in (
    "kzt_guest_library_run_dlsym",
    "kzt_guest_library_run_dlerror",
    "dlsym(RTLD_DEFAULT",
    "ResetSpecialCaseElf(",
):
    if forbidden in runtime_source:
        fail(f"runtime entry resolver retains forbidden lookup: {forbidden}")
for required in (
    "kzt_guest_runtime_entry_load(",
    "kzt_guest_runtime_entry_for_guest_branch(",
    "kzt_guest_runtime_entry_acquire(",
):
    if required not in runtime_header:
        fail(f"runtime entry fast path is incomplete: {required}")
if "__atomic_load_n(" not in runtime_state_header:
    fail("runtime entry fast path is not an atomic load")

production = "\n".join(
    (myalign, wrappedlibc, tr_misc, wrappedlibx11, wrappedlibxcb, box64context)
)
for forbidden in (
    "x86" + "free",
    "x86" + "realloc",
    "x86" + "pthread_setcanceltype",
    "collect" + "X86free",
    "kzt_" + "wine_init_x86",
    "malloc_" + "map",
    "mallocmaps",
):
    if forbidden in production:
        fail(f"obsolete runtime-entry state remains: {forbidden}")

for signature in (
    "static void do_translate_free_brick_tb(",
    "static void do_translate_realloc_brick_tb(",
):
    translation = function_body(tr_misc, signature)
    if "kzt_generate_guest_runtime_branch(" not in translation:
        fail(f"{signature} has no emitted runtime slow path")
    if "kzt_guest_runtime_entry_for_guest_branch(" in translation or \
            "kzt_guest_runtime_entry_resolve(" in translation:
        fail(f"{signature} still executes guest lookup while translating")
runtime_branch = function_body(
    tr_misc, "static void kzt_generate_guest_runtime_branch(")
for required in (
    "kzt_runtime_guest_entry_or_abort",
    "tr_set_running_of_cs(false)",
    "tr_set_running_of_cs(true)",
    "la_jirl(",
    "la_store_addrx(",
):
    if required not in runtime_branch:
        fail(f"runtime guest branch misses {required}")
if "kzt_guest_runtime_entry_acquire(" not in cancel_scope_source or \
        "kzt_guest_runtime_entry_release(" not in cancel_scope_source:
    fail("blocking consumers do not hold a runtime-entry lifecycle lease")
for consumer_source, label in ((wrappedlibx11, "X11"),
                               (wrappedlibxcb, "XCB")):
    if "kzt_guest_cancel_scope_begin(" not in consumer_source or \
            "kzt_guest_cancel_scope_end(" not in consumer_source:
        fail(f"{label} does not use the pinned cancel scope")
if "if (!scope || !scope->switched)" not in cancel_scope_source:
    fail("wait consumers can restore cancel type without a successful switch")
x_destroy = function_body(wrappedlibx11, "EXPORT void my_XDestroyImage(")
for required in ("abort();", "len ? len : 1", "if (len)"):
    if required not in x_destroy:
        fail(f"XDestroyImage failure/zero-length handling misses {required}")

for required in (
    "tryLoadElfFromFileForContext(context, \"libc.so.6\")",
    "tryLoadElfFromFileForContext(context, \"libdl.so.2\")",
):
    if required not in guest_dl_init:
        fail(f"guest runtime table lookup is not context-explicit: {required}")
if "kzt_guest_runtime_entry_state_begin_teardown(state)" not in guest_dl_api:
    fail("guest runtime entries are not closed before context storage teardown")
if "kzt_guest_runtime_entry_state_publish(" not in guest_dl_init:
    fail("guest ELF initialization does not publish runtime entries")

for required in (
    "elfheader_t* LoadAndCheckElfHeader(",
    "int RelocateElf(",
    "int RelocateElfPlt(",
    "int LoadNeededLibs(",
):
    if required not in elfloader_header:
        fail(f"generic ELF loader declaration was removed: {required}")
    if required not in elfloader:
        fail(f"generic ELF loader implementation was removed: {required}")

if myalign.count("LoadAndCheckElfHeader(") < 2:
    fail("unrelated myalign ELF header loading calls were removed")
if "LoadNeededLibs(" not in myalign:
    fail("unrelated main ELF dependency loading call was removed")

print("WI-1083 legacy callback removal source contract: PASS")
