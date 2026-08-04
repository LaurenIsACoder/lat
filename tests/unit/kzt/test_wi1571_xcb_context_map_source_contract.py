#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
context_header = (root / "target/i386/latx/include/box64context.h").read_text()
context_source = (root / "target/i386/latx/context/box64context.c").read_text()
align_source = (root / "target/i386/latx/context/myalign.c").read_text()
vulkan_source = (root / "target/i386/latx/context/wrappedvulkan.c").read_text()

require(
    "kzt_xcb_connection_map_t *kzt_xcb_connection_map" in context_header,
    "XCB connection ownership must live in box64context_t",
)
require(
    "kzt_xcb_connection_map_init" in context_source
    and "kzt_xcb_connection_map_destroy" in context_source,
    "the context must initialize and destroy its XCB connection map",
)
require("#define NXCB" not in align_source, "the fixed eight-slot map must stay removed")
require("my_xcb_connects" not in align_source, "the process-global native map must stay removed")
require("x64_xcb_connects" not in align_source, "the process-global guest map must stay removed")
require(
    "kzt_xcb_connection_guard_acquire" in align_source,
    "aligning an XCB connection must acquire a tracked context-owned lease",
)
require(
    "dest = add_xcb_connection" not in align_source,
    "an unknown guest connection must not be registered implicitly",
)
require(
    "begin_xcb_connection_disconnect" in align_source
    and "finish_xcb_connection_disconnect" in align_source,
    "disconnect must use the exclusive removal protocol",
)
require(
    "if (!native_conn)" in vulkan_source and "return -3;" in vulkan_source,
    "Vulkan must reject an unknown XCB connection instead of passing NULL native-side",
)

print("wi1571-xcb-context-map-source-contract: PASS")
