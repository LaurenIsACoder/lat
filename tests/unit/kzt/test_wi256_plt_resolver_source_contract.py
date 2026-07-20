#!/usr/bin/env python3
import pathlib
import sys


def fail(message: str) -> None:
    raise AssertionError(message)


root = pathlib.Path(sys.argv[1]).resolve()
adapter = root / "target/i386/latx/context/kzt_plt_resolver_adapter.c"
elfloader = root / "target/i386/latx/context/elfloader.c"

if not adapter.is_file():
    fail(f"missing production adapter: {adapter}")

adapter_text = adapter.read_text(encoding="utf-8")
elfloader_text = elfloader.read_text(encoding="utf-8")
lazy_header = (root / "target/i386/latx/include/kzt_lazy_binding.h").read_text(
    encoding="utf-8"
)
lazy_core = (root / "target/i386/latx/context/kzt_lazy_binding.c").read_text(
    encoding="utf-8"
)

if not any(
    call in adapter_text
    for call in ("kzt_lazy_binding_begin(", "->begin_lazy_binding(")
):
    fail("resolver adapter must delegate pending decisions to Contract 1")

for forbidden in (
    "getAlternate(",
    "GetGlobalSymbolStartEnd",
    "kzt_owner_resolver",
    "kzt_wrapper_probe",
    "kzt_bridge_exact",
):
    if forbidden in adapter_text:
        fail(f"resolver adapter duplicates native resolution: {forbidden}")

if "dl_runtime_resolver" in adapter_text:
    fail("resolver adapter must never substitute a process-global resolver")

entry = "kzt_plt_resolver_enter("
resolver_start = elfloader_text.find("void PltResolver(void)")
if resolver_start < 0:
    fail("missing production PltResolver slow path")
body_start = elfloader_text.find("{", resolver_start)
depth = 0
resolver_end = -1
for offset, char in enumerate(elfloader_text[body_start:], start=body_start):
    if char == "{":
        depth += 1
    elif char == "}":
        depth -= 1
        if depth == 0:
            resolver_end = offset + 1
            break
if resolver_end < 0:
    fail("could not delimit production PltResolver")
if entry not in elfloader_text[resolver_start:resolver_end]:
    fail("PltResolver slow path does not call kzt_plt_resolver_enter")

relocate_start = elfloader_text.find("int RelocateElfPlt(")
relocate_end = elfloader_text.find("\n#if 0", relocate_start)
if relocate_start < 0 or relocate_end < 0:
    fail("could not delimit RelocateElfPlt cold path")
relocate_body = elfloader_text[relocate_start:relocate_end]
if "kzt_lazy_completion_bridge = AddBridge(" not in relocate_body:
    fail("completion bridge must be created in RelocateElfPlt cold path")

for forbidden_seam in ("resolve_native_bridge", "compare_exchange_slot"):
    if forbidden_seam in lazy_header or forbidden_seam in lazy_core:
        fail(f"lazy core retains test-only fallback seam: {forbidden_seam}")

production_route = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
resolver_complete_start = elfloader_text.find(
    "static void KztLazyBindingCompleteResolver(void)"
)
resolver_complete_end = elfloader_text.find(
    "typedef struct kzt_plt_resolver_production_state", resolver_complete_start
)
if resolver_complete_start < 0 or resolver_complete_end < 0:
    fail("could not delimit lazy completion resolver")
if "kzt_production_lazy_complete(" not in elfloader_text[
    resolver_complete_start:resolver_complete_end
]:
    fail("completion resolver must call the testable production orchestration")
if "kzt_lazy_binding_complete(" in elfloader_text[
    resolver_complete_start:resolver_complete_end
]:
    fail("completion resolver bypasses production lease orchestration")
lazy_production_start = production_route.find(
    "int kzt_production_lazy_route_guest_target("
)
if lazy_production_start < 0:
    fail("missing lazy production route")
lazy_production = production_route[lazy_production_start:]
for forbidden_lookup in (
    "GetGlobalSymbolStartEndWithProvider",
    "GetGlobalSymbolStartEnd",
    "GetMaplib",
):
    if forbidden_lookup in lazy_production:
        fail(f"lazy completion repeats legacy symbol lookup: {forbidden_lookup}")
if "validate_source_identity" not in production_route:
    fail("production route lacks write-adjacent source generation recheck")
for required in (
    "kzt_production_lazy_load_slot_with_lease(",
    "kzt_lazy_binding_complete(",
    "kzt_guest_registry_source_lease_release(",
):
    if required not in production_route:
        fail(f"production completion orchestration missing: {required}")

production_hits = []
for path in (root / "target/i386").rglob("*.[ch]"):
    if path == adapter or path.name == "kzt_plt_resolver_adapter.h":
        continue
    if entry in path.read_text(encoding="utf-8", errors="ignore"):
        production_hits.append(path.relative_to(root).as_posix())

if production_hits != ["target/i386/latx/context/elfloader.c"]:
    fail(f"resolver enter escaped the one-shot PltResolver path: {production_hits}")

for hot_root in (
    root / "target/i386/tcg",
    root / "target/i386/latx/translator",
):
    if not hot_root.exists():
        continue
    for path in hot_root.rglob("*.[ch]"):
        if entry in path.read_text(encoding="utf-8", errors="ignore"):
            fail(f"per-TB resolver check introduced in {path.relative_to(root)}")

print("WI-256 PLT resolver one-shot source contract: PASS")
