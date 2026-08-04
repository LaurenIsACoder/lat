#!/usr/bin/env python3
import pathlib
import sys


def fail(message: str) -> None:
    raise AssertionError(message)


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        fail(f"missing function: {signature}")
    body_start = text.find("{", start)
    depth = 0
    for offset, char in enumerate(text[body_start:], start=body_start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:offset + 1]
    fail(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
adapter_path = root / "target/i386/latx/context/kzt_plt_resolver_adapter.c"
elfloader_path = root / "target/i386/latx/context/elfloader.c"
production_path = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
)
elf_private_path = root / "target/i386/latx/include/elfloader_private.h"

for path in (adapter_path, elfloader_path, production_path, elf_private_path):
    if not path.is_file():
        fail(f"missing production source: {path}")

adapter = adapter_path.read_text(encoding="utf-8")
elfloader = elfloader_path.read_text(encoding="utf-8")
production = production_path.read_text(encoding="utf-8")
elf_private = elf_private_path.read_text(encoding="utf-8")

for removed_path in (
    root / "target/i386/latx/context/kzt_lazy_binding.c",
    root / "target/i386/latx/include/kzt_lazy_binding.h",
    root / "target/i386/latx/context/kzt_lazy_diagnostics.c",
    root / "target/i386/latx/include/kzt_lazy_diagnostics.h",
):
    if removed_path.exists():
        fail(f"post-bind completion source still exists: {removed_path}")

for forbidden in (
    "completion_bridge",
    "original_return",
    "begin_lazy_binding",
    "kzt_lazy_binding_pending",
):
    if forbidden in adapter:
        fail(f"resolver adapter rewrites the guest return frame: {forbidden}")

for forbidden in (
    "getAlternate(",
    "GetGlobalSymbolStartEnd",
    "kzt_owner_resolver",
    "kzt_wrapper_probe",
    "kzt_bridge_exact",
    "dl_runtime_resolver",
):
    if forbidden in adapter:
        fail(f"resolver adapter duplicates native resolution: {forbidden}")

lookup = function_body(
    elfloader, "static int kzt_plt_resolver_lookup_source("
)
if "kzt_guest_registry_find_lazy_source(" not in lookup:
    fail("production lookup must use the allocation-free Registry query")
if "state->head->kzt_guest_resolver" not in lookup:
    fail("production lookup must retain the per-object guest resolver")
for forbidden in (
    "kzt_guest_registry_find_by_link_map(",
    "kzt_guest_registry_find_lazy_resolver(",
    "kzt_guest_object_snapshot_free(",
):
    if forbidden in lookup:
        fail(f"production lookup uses stale Registry path: {forbidden}")

resolver = function_body(elfloader, "void PltResolver(void)")
for required in (
    "version == -1 || version < 2",
    "KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED",
    "KZT_SYMBOL_VERSION_VERSIONED",
    "KZT_SYMBOL_VERSION_ERROR",
):
    if required not in resolver:
        fail(f"resolver misses version evidence mapping: {required}")

direct_call = resolver.find("kzt_production_lazy_direct_route(")
adapter_call = resolver.find("kzt_plt_resolver_enter(")
guest_call = resolver.rfind("plt_resolver_handoff_guest_or_abort(")
if not (0 <= direct_call < adapter_call < guest_call):
    fail("resolver must try direct route, then adapter, then guest handoff")

for forbidden in (
    "plt_resolver_lookup_host_symbol(",
    "getAlternate(",
    "KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE",
    "dl_runtime_resolver",
    "KztLazyBindingCompleteResolver",
    "kzt_production_lazy_complete(",
):
    if forbidden in resolver:
        fail(f"resolver retains removed post-bind logic: {forbidden}")
if "*p = offs" in resolver or "*p = legacy_target" in resolver:
    fail("resolver must not perform the historical direct GOT write")

for required in (
    "uintptr_t *intercepted_frame = (uintptr_t *)cpu->regs[R_ESP];",
    "uintptr_t addr = intercepted_frame[0];",
    "uint64_t relocation_slot = intercepted_frame[1];",
    "uintptr_t return_address = intercepted_frame[2];",
):
    if required not in resolver[:direct_call]:
        fail(f"resolver must read the original frame: {required}")

direct_prefix = resolver[direct_call:adapter_call]
if direct_prefix.count("Pop64(cpu)") != 2:
    fail("direct route must consume exactly object_head and relocation_slot")
for required in (
    "KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED",
    "KZT_LAZY_DIRECT_ROUTE_NATIVE_TRANSIENT",
    "Push64(cpu, direct_result.selected_target);",
    "return;",
):
    if required not in direct_prefix:
        fail(f"direct route success contract missing: {required}")
if "plt_resolver_abort_unrecoverable(" not in direct_prefix:
    fail("unrecoverable direct writer failure can reach guest handoff")

adapter_prefix = resolver[adapter_call:guest_call]
if "KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED" not in adapter_prefix:
    fail("adapter result is not checked before guest handoff")
if "return;" not in resolver[guest_call:]:
    fail("guest handoff must return without post-bind completion")
if "Return=%p" not in resolver or "(void*)return_address" not in resolver:
    fail("resolver diagnostic must report the original return address")

relocate = function_body(elfloader, "int RelocateElfPlt(")
if "uintptr_t kzt_guest_resolver;" not in elf_private:
    fail("elfheader must retain its own guest PLT resolver")
for required in (
    "head->kzt_guest_resolver = guest_resolver;",
    ".object_head = (uintptr_t)head,",
):
    if required not in relocate:
        fail(f"RelocateElfPlt misses per-object resolver evidence: {required}")
for forbidden in (
    "KztLazyBindingCompleteResolver",
    "kzt_lazy_completion_bridge",
    "dl_runtime_resolver",
):
    if forbidden in elfloader:
        fail(f"guest fallback retains synthetic completion state: {forbidden}")

direct = function_body(production, "int kzt_production_lazy_direct_route(")
if "kzt_lazy_direct_route_apply(" not in direct:
    fail("production direct route does not use the verified direct core")
for removed_api in (
    "kzt_lazy_binding_",
    "kzt_production_lazy_complete(",
    "kzt_production_lazy_route_guest_target(",
    "kzt_production_lazy_source_lease_acquire(",
    "kzt_production_lazy_load_slot_with_lease(",
):
    if removed_api in production:
        fail(f"production retains post-bind completion API: {removed_api}")

entry = "kzt_plt_resolver_enter("
production_hits = []
for path in (root / "target/i386").rglob("*.[ch]"):
    if path == adapter_path or path.name == "kzt_plt_resolver_adapter.h":
        continue
    if entry in path.read_text(encoding="utf-8", errors="ignore"):
        production_hits.append(path.relative_to(root).as_posix())
if production_hits != ["target/i386/latx/context/elfloader.c"]:
    fail(f"resolver enter escaped the one-shot path: {production_hits}")

print("WI-256 PLT resolver direct-route source contract: PASS")
