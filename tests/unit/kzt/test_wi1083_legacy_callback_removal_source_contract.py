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
if non_kzt_lines != ["(void)env;", "(void)event;"]:
    fail(f"non-KZT callback consumer is not a clear no-op: {non_kzt_lines}")

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
