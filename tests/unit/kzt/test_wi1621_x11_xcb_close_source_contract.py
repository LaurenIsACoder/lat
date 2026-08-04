#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1])
x11 = (root / "target/i386/latx/context/wrappedlibx11.c").read_text()
x11_private = (
    root / "target/i386/latx/include/wrappedlibx11_private.h"
).read_text()
context = (root / "target/i386/latx/context/box64context.c").read_text()

close = function_body(x11, "EXPORT int32_t my_XCloseDisplay(")
for required in (
    "PTHREAD_CANCEL_DISABLE",
    "begin_xcb_connection_disconnect_native(",
    "my->XCloseDisplay(",
    "finish_xcb_connection_disconnect(",
):
    require(required in close, f"XCloseDisplay lifecycle misses {required}")
require(
    close.index("begin_xcb_connection_disconnect_native(")
    < close.index("my->XCloseDisplay(")
    < close.index("finish_xcb_connection_disconnect("),
    "XCloseDisplay must drain leases before native close and remove afterward",
)
active_x11_entries = {
    line.strip() for line in x11_private.splitlines()
    if not line.lstrip().startswith("//")
}
require(
    "GOM(XCloseDisplay, iFp)" in active_x11_entries
    and "GO(XCloseDisplay, iFp)" not in active_x11_entries,
    "XCloseDisplay must use the lifecycle-aware custom wrapper",
)

free_context = function_body(context, "void FreeBox64Context(")
map_destroy = free_context.index("kzt_xcb_connection_map_destroy(")
require(
    map_destroy < free_context.index("FreeLibrarian(&ctx->local_maplib)")
    and map_destroy < free_context.index("FreeLibrarian(&ctx->maplib)"),
    "XCB leases must drain before wrapped X11/XCB libraries are unloaded",
)

print("wi1621-x11-xcb-close-source-contract: PASS")
