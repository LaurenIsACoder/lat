#!/usr/bin/env python3

import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1]).resolve()
source = (
    root / "target/i386/latx/translator/translate.c"
).read_text(encoding="utf-8")
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
translate_all = (
    root / "accel/tcg/translate-all.c"
).read_text(encoding="utf-8")

if "kzt_lazy_bridge_translation_timing schema=1" not in source:
    raise AssertionError("lazy resolver bridge translation is not timed")

for field in ("pc=", "code_size=", "total_ns="):
    if field not in source:
        raise AssertionError(f"bridge translation timing is missing {field}")

if "KztPltResolverBridge()" not in source:
    raise AssertionError(
        "lazy resolver timing does not use the context-owned bridge"
    )

if not re.search(
    r"kzt_lazy_bridge_timing_enabled\s*=\s*"
    r"kzt_lazy_diagnostics_enabled\s*&&\s*"
    r"kzt_plt_resolver_bridge\s*&&\s*"
    r"tb->pc\s*==\s*kzt_plt_resolver_bridge",
    source,
):
    raise AssertionError(
        "bridge translation timing is not limited to the lazy resolver"
    )

if "kzt_lazy_bridge_translation_ready_ns" not in source:
    raise AssertionError("translation completion is not handed to resolver")

if "kzt_lazy_resolver_timing schema=1" not in elfloader:
    raise AssertionError("lazy resolver entry timing is not emitted")

for field in (
    "translation_to_entry_ns=",
    "entry_minflt=",
    "prepare_ns=",
    "prepare_minflt=",
    "route_ns=",
    "route_minflt=",
    "finish_ns=",
    "finish_minflt=",
    "done_minflt=",
    "total_ns=",
):
    if field not in elfloader:
        raise AssertionError(f"lazy resolver timing is missing {field}")

if "kzt_lazy_target_bridge_pc" not in source:
    raise AssertionError("resolved target bridge is not handed to translator")

if "kzt_lazy_target_bridge_translation_timing schema=1" not in source:
    raise AssertionError("resolved target bridge translation is not timed")

for field in ("resolver_to_translation_ns=", "total_ns="):
    if field not in source:
        raise AssertionError(f"target bridge timing is missing {field}")

if "kzt_lazy_bridge_tb_gen_timing schema=1" not in translate_all:
    raise AssertionError("full lazy bridge TB generation is not timed")

for field in ("role=", "pc=", "total_ns="):
    if field not in translate_all:
        raise AssertionError(f"full bridge TB timing is missing {field}")

print("WI-995 lazy bridge translation timing source contract: PASS")
