#!/usr/bin/env python3
"""WI-1066: lazy prebind remains a bounded, fail-open fast path."""

from pathlib import Path
import sys


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


root = Path(sys.argv[1])
header = (root / "target/i386/latx/include/kzt_jump_slot_production.h").read_text(
    encoding="utf-8"
)
production = (root / "target/i386/latx/context/kzt_jump_slot_production.c").read_text(
    encoding="utf-8"
)
adapter = (root / "target/i386/latx/context/kzt_observation_adapter.c").read_text(
    encoding="utf-8"
)
myalign = (root / "target/i386/latx/context/myalign.c").read_text(
    encoding="utf-8"
)
guest_dl_api = (root / "target/i386/latx/context/kzt_guest_dl_api.c").read_text(
    encoding="utf-8"
)

if "int kzt_production_lazy_prebind_object(" not in header:
    raise AssertionError("missing loader-consumer prebind declaration")
if "void kzt_production_lazy_prebind_refresh(" not in header:
    raise AssertionError("missing epoch refresh declaration")
if "typedef int (*kzt_lazy_prebind_target_prepare_fn)" not in header:
    raise AssertionError("missing exact pinned-bridge preparation callback")

prepare = function_body(
    production, "static int production_lazy_prebind_object_prepare("
)
find_symbol = function_body(
    production, "static size_t production_lazy_prebind_find_symbol_index("
)
for required in (
    "kzt_runtime_got_plt_candidates_collect(",
    "KZT_PATCH_TABLE_PLT_RELA",
    "candidate.symbol_name",
):
    if required not in find_symbol:
        raise AssertionError(f"structured prebind symbol scan lacks {required}")
for required in (
    "kzt_runtime_got_plt_candidates_collect(",
    "production_lazy_prebind_find_symbol_index(",
    "production_symbol_scope_request(",
    "kzt_guest_symbol_scope_discover(",
    "kzt_guest_library_access_lookup(",
    "kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(",
    "kzt_lazy_prebind_scope_claim(",
):
    if required not in prepare:
        raise AssertionError(f"prebind preparation lacks {required}")
for forbidden in (
    "head->VerSym",
    "GetSymbolVersion(",
    "SymName(",
    "head->DynSym",
    "kzt_elfloader_write_guest_word(",
    "RelocateElf",
    "LoadNeededLibs",
):
    if forbidden in prepare:
        raise AssertionError(f"prebind preparation performs forbidden work: {forbidden}")
if "production_lazy_prebind_publish_record(" not in prepare:
    raise AssertionError("prebind preparation never invokes publication")
publish = function_body(
    production, "static int production_lazy_prebind_publish_record(")
for required in (
    "kzt_lazy_prebind_scope_publish_acquire(",
    "kzt_lazy_prebind_scope_publish_finish(",
    "production_lazy_prebind_slot_cas(",
    "writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED",
):
    if required not in publish:
        raise AssertionError(f"prebind publication lacks {required}")

route = function_body(production, "int kzt_production_lazy_direct_route(")
acquire = route.find("kzt_lazy_prebind_scope_acquire(")
candidate = route.find("production_collect_runtime_candidate(")
scope = route.find("kzt_guest_symbol_scope_discover(")
if acquire < 0:
    raise AssertionError("lazy direct route never attempts a prebind lease")
if candidate < 0 or acquire > candidate:
    raise AssertionError("prebind lease is not attempted before candidate rebuild")
if scope < 0 or acquire > scope:
    raise AssertionError("prebind lease is not attempted before scope discovery")
if "kzt_lazy_prebind_scope_release(&state.prebind_lease)" not in route:
    raise AssertionError("lazy direct route does not release the prebind lease")

bridge = function_body(production, "static int production_lazy_direct_find_bridge(")
if "state->prebind_lease.active" not in bridge:
    raise AssertionError("bridge path has no exact prebind fast path")

refresh = function_body(production, "void kzt_production_lazy_prebind_refresh(")
for required in (
    "kzt_guest_registry_dump_snapshot(",
    "kzt_guest_registry_source_lease_acquire(",
    "production_lazy_prebind_object_prepare(",
    "kzt_guest_registry_dump_free(",
):
    if required not in refresh:
        raise AssertionError(f"epoch refresh lacks {required}")
if "target_prepare, target_prepare_opaque" not in refresh:
    raise AssertionError("scope refresh does not forward bridge preparation")

invalidate = function_body(
    production, "int kzt_production_lazy_prebind_invalidate(")
for required in (
    "kzt_lazy_prebind_scope_mutate(",
    "production_lazy_prebind_revoke_closed(",
):
    if required not in invalidate:
        raise AssertionError(f"scope invalidation lacks {required}")
for forbidden in ("RelocateElf", "LoadNeededLibs", "kzt_elfloader_write_guest_word("):
    if forbidden in invalidate:
        raise AssertionError(f"scope invalidation performs forbidden work: {forbidden}")
revoke = function_body(
    production, "static int production_lazy_prebind_revoke_closed(")
for required in (
    "kzt_lazy_prebind_scope_revoke_acquire(",
    "kzt_lazy_prebind_scope_revoke_finish(",
    "production_mandatory_slot_transaction(",
    "writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED",
    "writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH",
):
    if required not in revoke:
        raise AssertionError(f"scope revoke lacks {required}")

consumer = function_body(myalign, "static void kzt_tb_callback_consume(")
refresh = consumer.find("kzt_production_lazy_prebind_refresh(")
if refresh < 0:
    raise AssertionError("loader consumer does not refresh records after an epoch event")
added = consumer.rfind("observation_result == KZT_OBSERVATION_ADAPTER_ADDED",
                       0, refresh)
updated = consumer.rfind("observation_result == KZT_OBSERVATION_ADAPTER_UPDATED",
                         0, refresh)
if added < 0 or updated < 0:
    raise AssertionError("loader refresh is not limited to committed objects")
if "kzt_tb_callback_pretranslate_target" not in consumer:
    raise AssertionError("loader consumer omits exact target preparation")

mutation = adapter.find("request->prebind_invalidate(")
per_object_flow = adapter.find("request->per_object_flow(")
if mutation < 0 or per_object_flow < 0 or mutation > per_object_flow:
    raise AssertionError("loader scope epoch is not advanced before prebind work")

for signature, guest_loader_call in (
    ("uint64_t kzt_guest_dl_api_dlopen(",
     "kzt_guest_library_run_dlopen_scoped("),
    ("int kzt_guest_dl_api_dlclose(", "kzt_guest_library_run_dlclose("),
    ("uint64_t kzt_guest_dl_api_dlmopen(",
     "kzt_guest_library_run_dlmopen("),
):
    body = function_body(guest_dl_api, signature)
    invalidate_at = body.find("kzt_production_lazy_prebind_invalidate(")
    loader_at = body.find(guest_loader_call)
    if invalidate_at < 0 or loader_at < 0 or invalidate_at > loader_at:
        raise AssertionError(f"{signature} invalidates scope after guest loader entry")

print("WI-1066 lazy prebind source contract: PASS")
