#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
mapping = (root / "target/i386/latx/context/kzt_xcb_connection_map.c").read_text()
align = (root / "target/i386/latx/context/myalign.c").read_text()
tests = (root / "tests/unit/kzt/test_xcb_connection_map.c").read_text()

require(
    "pthread_mutex_t operation_lock" in mapping
    and "PTHREAD_MUTEX_RECURSIVE" in mapping,
    "each XCB connection must own a recursive operation lock",
)
require(
    "kzt_xcb_connection_lease_lock_mirror" in mapping
    and "pthread_mutex_lock(&entry->operation_lock)" in mapping,
    "guest/native mirror copies must lock the connection entry",
)
acquire_start = mapping.index("static int kzt_xcb_connection_acquire(")
acquire_end = mapping.index(
    "int kzt_xcb_connection_map_acquire_by_guest", acquire_start
)
require(
    "operation_lock" not in mapping[acquire_start:acquire_end],
    "lifetime acquisition must not hold the mirror lock across blocking libxcb calls",
)
require(
    "kzt_xcb_connection_lease_unlock_mirror" in mapping
    and "pthread_mutex_unlock(&entry->operation_lock)" in mapping,
    "mirror copies must release the connection entry lock",
)
require(
    "kzt_xcb_mirror_guest_to_native" in align
    and "kzt_xcb_mirror_native_to_guest" in align,
    "alignment must serialize only mirror copies around the native call",
)
require(
    "kzt_xcb_queue_copy(" in align
    and "memcpy(dest->out.queue, source->out.queue, sizeof(dest->out.queue))"
    not in align
    and "dest->in = source->in" not in align,
    "hot mirror updates must copy only live queue bytes, not fixed 20 KiB buffers",
)
require(
    "test_same_connection_serializes_and_different_connections_run" in tests
    and "test_mirror_lock_is_recursive" in tests
    and "run_operation_benchmark" in tests,
    "whitebox tests must cover recursive locking, serialization, parallelism and lock overhead",
)

print("wi1612-xcb-serialization-source-contract: PASS")
