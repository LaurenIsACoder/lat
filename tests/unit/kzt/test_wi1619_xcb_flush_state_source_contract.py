#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
align = (root / "target/i386/latx/context/myalign.c").read_text()

guard_start = align.index("uintptr_t kzt_xcb_guard_acquire_for_bridge(")
guard_end = align.index("static void kzt_xcb_copy_guest_to_native(", guard_start)
guard = align[guard_start:guard_end]
require(
    "kzt_xcb_flush_state_is_supported(" in guard
    and "reason=unsupported_flush_state" in guard
    and "kzt_xcb_connection_guard_cancel();" in guard
    and guard.index("kzt_xcb_connection_guard_prepare(")
    < guard.index("kzt_xcb_flush_state_is_supported("),
    "guard must keep unsupported guest socket/queue state on the guest path",
)

start = align.index("static void kzt_xcb_copy_guest_to_native(")
end = align.index("static void kzt_xcb_copy_native_to_guest(", start)
guest_to_native = align[start:end]

for required in (
    "kzt_xcb_queue_copy(",
    "dest->out.queue",
    "source->out.queue",
    "&dest->out.queue_len",
    "dest->out.request = source->out.request",
    "dest->out.request_written = source->out.request_written",
    "dest->out.out_fd = source->out.out_fd",
):
    require(
        required in guest_to_native,
        f"guest-to-native XCB flush state misses {required}",
    )
for forbidden in (
    "dest->out.cond =",
    "dest->out.socket_cond =",
    "dest->out.return_socket =",
    "dest->out.socket_closure =",
    "dest->out.reqlenlock =",
):
    require(
        forbidden not in guest_to_native,
        f"guest-to-native mirror must not overwrite native synchronization state: {forbidden}",
    )

print("wi1619-xcb-flush-state-source-contract: PASS")
