#!/usr/bin/env python3
import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1]).resolve()
source = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
runtime_bridge = (
    root / "target/i386/latx/context/kzt_rela_runtime_bridge.c"
).read_text(encoding="utf-8")

if "kzt_lazy_timing schema=1" not in source:
    raise AssertionError("lazy direct route does not emit stage timing evidence")

required_fields = (
    "source_ns=",
    "candidate_ns=",
    "quiescence_ns=",
    "scope_ns=",
    "provider_ns=",
    "route_ns=",
    "route_prepare_ns=",
    "bridge_ns=",
    "bridge_discover_ns=",
    "bridge_probe_ns=",
    "decision_ns=",
    "final_ns=",
    "cas_ns=",
    "cleanup_ns=",
    "total_ns=",
)
for field in required_fields:
    if field not in source:
        raise AssertionError(f"lazy direct timing is missing {field}")

gate = re.search(
    r"timing_enabled\s*=\s*unlikely\s*\(\s*"
    r"option_kzt_lazy_diagnostics\s*\)",
    source,
)
if not gate:
    raise AssertionError("lazy direct timing is not lazy-diagnostics-gated")
if re.search(
    r"timing_enabled\s*=\s*kzt_registry_diagnostics_enabled",
    source,
):
    raise AssertionError("Registry diagnostics unexpectedly enable timing")

if not re.search(
    r"if\s*\(\s*timing_enabled\s*\)\s*\{\s*"
    r"timing\.start\s*=\s*production_lazy_direct_timing_now\s*\(\s*\)",
    source,
    re.DOTALL,
):
    raise AssertionError("normal lazy route still reads the timing clock")

if "kzt_bridge_discovery_timing schema=1" not in runtime_bridge:
    raise AssertionError("wrapper bridge discovery has no stage timing")
for field in (
    "wrapper_map_ns=",
    "native_lookup_ns=",
    "bridge_cache_ns=",
    "handle_owner_ns=",
    "total_ns=",
):
    if field not in runtime_bridge:
        raise AssertionError(f"wrapper bridge timing is missing {field}")
if "option_kzt_lazy_diagnostics" not in runtime_bridge:
    raise AssertionError("wrapper bridge timing is not lazy-diagnostics-gated")

print("WI-995 lazy direct timing source contract: PASS")
