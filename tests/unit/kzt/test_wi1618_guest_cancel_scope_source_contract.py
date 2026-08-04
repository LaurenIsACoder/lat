#!/usr/bin/env python3

import pathlib
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


root = pathlib.Path(sys.argv[1])
helper = (root / "target/i386/latx/context/kzt_guest_cancel_scope.c").read_text()
x11 = (root / "target/i386/latx/context/wrappedlibx11.c").read_text()
xcb = (root / "target/i386/latx/context/wrappedlibxcb.c").read_text()

require(
    helper.count("kzt_guest_runtime_entry_acquire(") == 1,
    "cancel restoration must reuse the entry acquired before the blocking call",
)
require(
    "scope->runtime.address, 2, scope->oldtype, NULL" in helper,
    "normal return must restore through the pinned guest entry",
)
require(
    "kzt_guest_cancel_scope_cleanup" in helper
    and "kzt_guest_runtime_entry_release(&scope->runtime)" in helper,
    "thread cancellation must release the pinned runtime entry",
)
for name, source in (("X11", x11), ("XCB", xcb)):
    require(
        "pthread_cleanup_push(kzt_guest_cancel_scope_cleanup" in source
        and "kzt_guest_cancel_scope_begin(my_context" in source
        and "kzt_guest_cancel_scope_end(&cancel)" in source
        and "pthread_cleanup_pop(0)" in source,
        f"{name} blocking wrappers must protect the whole cancel scope",
    )

print("wi1618-guest-cancel-scope-source-contract: PASS")
