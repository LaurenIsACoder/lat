#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
guard = (root / "target/i386/latx/context/kzt_xcb_connection_guard.c").read_text()
mapping = (root / "target/i386/latx/context/kzt_xcb_connection_map.c").read_text()
wrapped = (root / "target/i386/latx/context/wrappedlibxcb.c").read_text()
private = (root / "target/i386/latx/include/wrappedlibxcb_private.h").read_text()

require(
    "pthread_key_create" in guard
    and "kzt_xcb_thread_leases_destroy" in guard
    and "active_count" in guard,
    "thread exit must release both pending and active XCB leases",
)
require(
    "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE" in guard,
    "guard lease transfers must close asynchronous cancellation windows",
)
require(
    "pthread_cleanup_push(kzt_xcb_remove_wait_cancel" in mapping
    and "entry->removal_pending = 0" in mapping
    and "entry->closing = 0" in mapping,
    "cancelled removal waits must roll back closing state and unlock the map",
)
require(
    mapping.count("kzt_xcb_cancel_disable()") >= 6,
    "map mutation and teardown critical sections must reject async cancellation",
)

for symbol in (
    "xcb_wait_for_event",
    "xcb_wait_for_reply",
    "xcb_wait_for_reply64",
    "xcb_wait_for_special_event",
):
    require(
        f"GOM({symbol}," in private,
        f"{symbol} must use its cancellation-aware custom wrapper",
    )
    start = wrapped.index(f"my_{symbol}(")
    end = wrapped.index("\n}", start)
    body = wrapped[start:end]
    require(
        "align_xcb_connection" in body
        and "unalign_xcb_connection" in body,
        f"{symbol} must hold and release a tracked native connection lease",
    )

disconnect_start = wrapped.index("my_xcb_disconnect(")
disconnect_end = wrapped.index("\n}", disconnect_start)
disconnect = wrapped[disconnect_start:disconnect_end]
require(
    "PTHREAD_CANCEL_DISABLE" in disconnect
    and "finish_xcb_connection_disconnect" in disconnect,
    "disconnect must not be cancelled between removal begin and finish",
)

print("wi1611-xcb-cancellation-source-contract: PASS")
