#!/usr/bin/env python3
import pathlib
import sys


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
elfloader = (
    root / "target/i386/latx/context/elfloader.c"
).read_text(encoding="utf-8")
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
glob_dat_source = (
    root / "target/i386/latx/context/kzt_guest_glob_dat_target.c"
).read_text(encoding="utf-8")

rela = function_body(elfloader, "int RelocateElfRELA(")
glob_dat_route = function_body(glob_dat_source, "int kzt_guest_glob_dat_route(")
transaction = function_body(
    production, "kzt_production_eager_relocation_write("
)
guest_transaction = function_body(
    production, "kzt_production_guest_relocation_write("
)
mandatory_transaction = function_body(
    production, "production_mandatory_slot_transaction("
)
prebind_transaction = function_body(
    production, "production_lazy_prebind_slot_cas("
)

if "__atomic_compare_exchange_n(" in rela:
    raise AssertionError("eager relocation still performs a direct slot CAS")
if glob_dat_route.count("kzt_production_eager_relocation_write(") != 1:
    raise AssertionError(
        "native GLOB_DAT bridge must retain the optional transactional writer"
    )
if rela.count("kzt_production_guest_relocation_write(") < 3:
    raise AssertionError(
        "local GLOB_DAT, deferred stub, and local eager JUMP_SLOT must use "
        "the mandatory guest transaction"
    )
for required in (
    "kzt_patch_spike_writer_try_apply_with_slot_ops(",
    "KztPatchSpikeGuardForContext(",
    ".begin_write = production_slot_begin_write",
    ".end_write = production_slot_end_write",
    "kzt_guest_registry_patch_decision_lease_acquire(",
):
    if required not in transaction:
        raise AssertionError(f"eager transaction misses {required}")
for forbidden in (
    "KztPatchSpikeGuardForContext(",
    "kzt_patch_spike_writer_try_apply_with_slot_ops(",
):
    if forbidden in guest_transaction or forbidden in mandatory_transaction:
        raise AssertionError(
            f"mandatory guest relocation incorrectly depends on {forbidden}"
        )
for required in (
    "kzt_guest_registry_source_lease_acquire(",
    "production_mandatory_slot_transaction(",
):
    if required not in guest_transaction:
        raise AssertionError(f"guest transaction misses {required}")
for required in (
    "production_slot_begin_write(",
    "production_slot_cas(",
    "production_mandatory_finish_slot(",
):
    if required not in mandatory_transaction:
        raise AssertionError(f"mandatory slot transaction misses {required}")
for required in (
    "kzt_patch_spike_writer_try_apply_with_slot_ops(",
    "KztPatchSpikeGuardForContext(",
    ".begin_write = production_slot_begin_write",
    ".end_write = production_slot_end_write",
):
    if required not in prebind_transaction:
        raise AssertionError(f"lazy prebind bypasses {required}")
if "__atomic_compare_exchange_n(" in prebind_transaction:
    raise AssertionError("lazy prebind performs a direct slot CAS")

revoke = function_body(production, "production_lazy_prebind_revoke_closed(")
if "production_mandatory_slot_transaction(" not in revoke:
    raise AssertionError("lazy prebind revoke is still blocked by optional budget")

print("WI-1095 eager relocation transaction source contract: PASS")
