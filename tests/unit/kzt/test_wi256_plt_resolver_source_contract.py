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
elfloader_private_text = (
    root / "target/i386/latx/include/elfloader_private.h"
).read_text(encoding="utf-8")
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

production_state_start = elfloader_text.find(
    "typedef struct kzt_plt_resolver_production_state"
)
production_lookup_start = elfloader_text.find(
    "static int kzt_plt_resolver_lookup_source(", production_state_start
)
resolver_start = elfloader_text.find("void PltResolver(void)")
if min(production_state_start, production_lookup_start, resolver_start) < 0:
    fail("missing production PLT resolver evidence path")
production_state = elfloader_text[
    production_state_start:production_lookup_start
]
production_lookup = elfloader_text[production_lookup_start:resolver_start]
if "kzt_symbol_version_evidence_t version_evidence;" not in production_state:
    fail("production resolver state must retain explicit version evidence")
if ".version_evidence = state->version_evidence," not in production_lookup:
    fail("production lookup must forward explicit version evidence")
if "kzt_guest_registry_find_lazy_source(" not in production_lookup:
    fail("production lookup must use the single-lock, allocation-free Registry source query")
if "state->head->kzt_guest_resolver" not in production_lookup:
    fail("production lookup must retain a per-object guest resolver fallback")
if ".enabled = 0," not in production_lookup:
    fail("per-object resolver fallback must disable native completion")
if ".guest_resolver = state->head->kzt_guest_resolver," not in production_lookup:
    fail("per-object fallback must select the current object's guest resolver")
for forbidden_lookup_step in (
    "kzt_guest_registry_find_by_link_map(",
    "kzt_guest_registry_find_lazy_resolver(",
    "kzt_guest_object_snapshot_free(",
):
    if forbidden_lookup_step in production_lookup:
        fail(
            "production lookup retains the allocating or double-lock Registry path: "
            f"{forbidden_lookup_step}"
        )

entry = "kzt_plt_resolver_enter("
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
resolver_body = elfloader_text[resolver_start:resolver_end]
for required_version_mapping in (
    "version == -1 || version < 2",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
    "vername && vername[0]",
    "KZT_SYMBOL_VERSION_VERSIONED",
    "KZT_SYMBOL_VERSION_ERROR",
    ".version_evidence = version_evidence,",
):
    if required_version_mapping not in resolver_body:
        fail(
            "PltResolver must explicitly classify versioned, unversioned, "
            f"and malformed version evidence: {required_version_mapping}"
        )
if entry not in resolver_body:
    fail("PltResolver slow path does not call kzt_plt_resolver_enter")

direct_entry = "kzt_production_lazy_direct_route("
if direct_entry not in resolver_body:
    fail("PltResolver must try the WI-837 evidence-backed direct route")
direct_call = resolver_body.find(direct_entry)
adapter_call = resolver_body.find(entry)
guest_handoff_call = resolver_body.rfind(
    "plt_resolver_handoff_guest_or_abort("
)
if not (direct_call < adapter_call < guest_handoff_call):
    fail("PltResolver must try direct route, then adapter, then guest handoff")

for forbidden_lazy_step in (
    "plt_resolver_lookup_host_symbol(",
    "getAlternate(",
    "KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE",
    "dl_runtime_resolver",
):
    if forbidden_lazy_step in resolver_body:
        fail(f"PltResolver retains removed lazy legacy logic: {forbidden_lazy_step}")
if "*p = offs" in resolver_body or "*p = legacy_target" in resolver_body:
    fail("PltResolver must not perform the historical direct GOT write")

for required_read in (
    "uintptr_t *intercepted_frame = (uintptr_t *)cpu->regs[R_ESP];",
    "uintptr_t addr = intercepted_frame[0];",
    "uint64_t relocation_slot = intercepted_frame[1];",
    "uintptr_t return_address = intercepted_frame[2];",
):
    if required_read not in resolver_body[:direct_call]:
        fail(f"PltResolver must read, not consume, the adapter frame: {required_read}")

slot_check = resolver_body.find(
    "kzt_plt_resolver_relocation_index_valid("
)
relocation_access = resolver_body.find("Elf64_Rela * rel")
symbol_index_read = resolver_body.find(
    "symbol_index = ELF64_R_SYM(rel->r_info);"
)
symbol_check = resolver_body.find(
    "kzt_plt_resolver_symbol_index_valid("
)
symbol_access = resolver_body.find("Elf64_Sym *sym = &h->DynSym[symbol_index];")
if not (
    0 <= slot_check < relocation_access < symbol_index_read <
    symbol_check < symbol_access < direct_call
):
    fail(
        "PltResolver must validate relocation and symbol indexes before "
        "accessing their tables"
    )

direct_prefix = resolver_body[direct_call:adapter_call]
if direct_prefix.count("Pop64(cpu)") != 2:
    fail("direct route must consume exactly object_head and relocation_slot")
if (
    "direct_result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED"
    not in direct_prefix
    or "Push64(cpu, direct_result.selected_target);" not in direct_prefix
    or "return;" not in direct_prefix
):
    fail("direct route success must return its selected bridge")

if "Return=%p" not in resolver_body or "(void*)return_address" not in resolver_body:
    fail("PltResolver Return diagnostic must report intercepted_frame[2]")
if "*(void**)(cpu->regs[R_ESP])" in resolver_body:
    fail("PltResolver Return diagnostic must not report intercepted_frame[0]")

guest_prefix = resolver_body[adapter_call:guest_handoff_call]
if (
    "enter_result.status != KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED"
    not in guest_prefix
    or "return;" not in guest_prefix
):
    fail("adapter-handled PltResolver paths must return before direct guest handoff")
guest_suffix = resolver_body[guest_handoff_call:]
if "return;" not in guest_suffix:
    fail("per-object guest handoff must return without legacy host resolution")
handoff_helper_start = elfloader_text.find(
    "static void plt_resolver_handoff_guest_or_abort("
)
if handoff_helper_start < 0:
    fail("missing checked guest resolver handoff")
handoff_helper_end = elfloader_text.find(
    "\nvoid PltResolver(void)", handoff_helper_start
)
handoff_helper = elfloader_text[handoff_helper_start:handoff_helper_end]
if "abort();" not in handoff_helper:
    fail("missing guest resolver must not return with an intercepted frame")

relocate_start = elfloader_text.find("int RelocateElfPlt(")
relocate_end = elfloader_text.find("\n#if 0", relocate_start)
if relocate_start < 0 or relocate_end < 0:
    fail("could not delimit RelocateElfPlt cold path")
relocate_body = elfloader_text[relocate_start:relocate_end]
if "kzt_lazy_completion_bridge = AddBridge(" not in relocate_body:
    fail("completion bridge must be created in RelocateElfPlt cold path")
if "uintptr_t kzt_guest_resolver;" not in elfloader_private_text:
    fail("elfheader must retain its own guest PLT resolver")
if "head->kzt_guest_resolver = guest_resolver;" not in relocate_body:
    fail("RelocateElfPlt must retain the current object's guest resolver")
injection_check = relocate_body.find(
    "kzt_plt_resolver_injection_allowed("
)
resolver_save = relocate_body.find(
    "head->kzt_guest_resolver = guest_resolver;"
)
resolver_install = relocate_body.find(
    "*(uintptr_t*)(resolver_got_runtime+16) = resolver_bridge;"
)
if not (0 <= injection_check < resolver_save < resolver_install):
    fail(
        "RelocateElfPlt must validate and retain the guest resolver before "
        "injecting KZT"
    )
if "dl_runtime_resolver" in relocate_body:
    fail("RelocateElfPlt must not retain a process-global guest resolver")
if "*(uintptr_t*)(head->got+head->delta+16)" in relocate_body:
    fail("RelocateElfPlt must not derive the guest resolver from head->got")

for forbidden_seam in ("resolve_native_bridge", "compare_exchange_slot"):
    if forbidden_seam in lazy_header or forbidden_seam in lazy_core:
        fail(f"lazy core retains test-only fallback seam: {forbidden_seam}")

production_route = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
runtime_bridge = (
    root / "target/i386/latx/context/kzt_rela_runtime_bridge.c"
).read_text(encoding="utf-8")
if "production_probe_prepared_wrapper_cache" in production_route:
    fail("production route retains an unused cache-only wrapper probe")

mutex_cursor = 0
while True:
    mutex_start = runtime_bridge.find("pthread_mutex_lock", mutex_cursor)
    if mutex_start < 0:
        break
    mutex_end = runtime_bridge.find("pthread_mutex_unlock", mutex_start)
    if mutex_end < 0:
        fail("bridge mutex critical section has no matching unlock")
    critical_section = runtime_bridge[mutex_start:mutex_end]
    for loader_call in ("dlsym(", "dlvsym(", "dlinfo(", "dladdr(",
                        "dladdr1("):
        if loader_call in critical_section:
            fail(f"bridge mutex encloses loader inspection: {loader_call}")
    mutex_cursor = mutex_end + 1
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
