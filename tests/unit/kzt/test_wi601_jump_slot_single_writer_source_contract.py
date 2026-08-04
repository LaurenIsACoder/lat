#!/usr/bin/env python3
import pathlib
import re
import sys


def fail(message: str) -> None:
    raise AssertionError(message)


def matching_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    quote = None
    escaped = False
    index = start

    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char == "/" and following == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char == "/" and following == "*":
            end = text.find("*/", index + 2)
            if end < 0:
                fail("unterminated C comment")
            index = end + 2
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
        index += 1

    fail(f"unterminated delimiter beginning at offset {start}")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        fail(f"missing function: {signature}")
    brace = text.find("{", start + len(signature))
    if brace < 0:
        fail(f"missing function body: {signature}")
    end = matching_delimiter(text, brace, "{", "}")
    return text[brace + 1:end]


def decision_name(body: str, caller_name: str) -> str:
    match = re.search(
        r"\bkzt_jump_slot_route_caller_decision_t\s+(\w+)\s*=", body
    )
    if not match:
        fail(f"{caller_name}: missing caller decision")
    name = match.group(1)
    if not re.search(
        rf"\b{re.escape(name)}\s*=\s*"
        r"kzt_jump_slot_route_caller_decide\s*\(",
        body,
    ):
        fail(f"{caller_name}: caller decision is not populated by shared policy")
    return name


def guarded_blocks(body: str, condition_pattern: str):
    blocks = []
    for match in re.finditer(r"\bif\s*\(", body):
        condition_start = body.find("(", match.start())
        condition_end = matching_delimiter(body, condition_start, "(", ")")
        condition = body[condition_start + 1:condition_end]
        if not re.search(condition_pattern, condition, re.DOTALL):
            continue
        brace = condition_end + 1
        while brace < len(body) and body[brace].isspace():
            brace += 1
        if brace < len(body) and body[brace] == "{":
            end = matching_delimiter(body, brace, "{", "}")
            blocks.append((brace + 1, end, body[brace + 1:end]))
    return blocks


def decision_switch(body: str, decision: str) -> str:
    for match in re.finditer(r"\bswitch\s*\(", body):
        start = body.find("(", match.start())
        end = matching_delimiter(body, start, "(", ")")
        condition = body[start + 1:end]
        if not re.search(
            rf"\b{re.escape(decision)}\.slot_action\b", condition
        ):
            continue
        brace = end + 1
        while brace < len(body) and body[brace].isspace():
            brace += 1
        if brace < len(body) and body[brace] == "{":
            switch_end = matching_delimiter(body, brace, "{", "}")
            return body[brace + 1:switch_end]
    fail("missing switch over caller decision slot_action")


def assert_legacy_store_guard(
    caller_name: str, body: str, decision: str, store_pattern: str
) -> None:
    stores = list(re.finditer(store_pattern, body))
    if len(stores) != 1:
        fail(
            f"{caller_name}: expected exactly one historical direct store, "
            f"found {len(stores)}"
        )
    condition = (
        rf"\b{re.escape(decision)}\.slot_action\s*==\s*"
        r"KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE\b"
    )
    for start, end, _ in guarded_blocks(body, condition):
        if start < stores[0].start() < end:
            return
    fail(f"{caller_name}: historical direct store is not LEGACY_WRITE-only")


root = pathlib.Path(sys.argv[1]).resolve()
header = (root / "target/i386/latx/include/kzt_jump_slot_route.h").read_text(
    encoding="utf-8"
)
route = (root / "target/i386/latx/context/kzt_jump_slot_route.c").read_text(
    encoding="utf-8"
)
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text(
    encoding="utf-8"
)
production = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text(encoding="utf-8")
writer_header = (
    root / "target/i386/latx/include/kzt_patch_spike_writer.h"
).read_text(encoding="utf-8")
defer_header = (
    root / "target/i386/latx/include/kzt_rela_stub_detector.h"
).read_text(encoding="utf-8")
defer_module = (
    root / "target/i386/latx/context/kzt_rela_stub_detector.c"
).read_text(encoding="utf-8")

for required in (
    "kzt_jump_slot_route_caller_decision_t",
    "KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE",
    "KZT_JUMP_SLOT_ROUTE_SLOT_ROUTE_APPLIED",
    "KZT_JUMP_SLOT_ROUTE_SLOT_PRESERVE",
    "slot_value_usable",
):
    if required not in header:
        fail(f"missing caller-decision public contract: {required}")

signature = re.compile(
    r"kzt_jump_slot_route_caller_decide\s*\(\s*"
    r"int\s+route_call_succeeded\s*,\s*"
    r"const\s+kzt_jump_slot_route_result_t\s*\*\s*result\s*,\s*"
    r"uintptr_t\s+legacy_target\s*,\s*"
    r"int\s+final_value_usable\s*\)",
    re.DOTALL,
)
if not signature.search(header):
    fail("caller-decision public contract has an incompatible signature")

decision_body = function_body(route, "kzt_jump_slot_route_caller_decide(")
for required in (
    "!route_call_succeeded", "!result", "legacy_target", "result->final_value",
    "final_value_usable", "KZT_JUMP_SLOT_ROUTE_BYPASS",
    "KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED",
    "KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED", "KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH",
    "KZT_JUMP_SLOT_ROUTE_WRITE_ERROR",
):
    if required not in decision_body:
        fail(f"caller decision lacks mapping input: {required}")
if "ops->" in decision_body or "compare_exchange" in decision_body:
    fail("caller decision must not access route operations")


def decision_arguments(caller_name: str, caller_body: str) -> str:
    calls = list(re.finditer(r"kzt_jump_slot_route_caller_decide\s*\(", caller_body))
    if len(calls) != 1:
        fail(f"{caller_name}: expected exactly one caller decision")
    start = caller_body.find("(", calls[0].start())
    end = matching_delimiter(caller_body, start, "(", ")")
    return re.sub(r"\s+", "", caller_body[start + 1:end])


def assert_route_success_is_production_result(
    caller_name: str, caller_body: str
) -> None:
    if not re.search(
        r"\bint\s+route_call_succeeded\s*=\s*"
        r"kzt_production_jump_slot_route\s*\([\s\S]*?\)\s*"
        r"==\s*0\s*;",
        caller_body,
    ):
        fail(
            f"{caller_name}: route success must be the production route == 0 "
            "result"
        )


def detector_coordinates(body: str, value: str) -> list[str]:
    coordinates = []
    pattern = re.compile(
        r"kzt_rela_slot_current_is_unresolved_stub\s*\(\s*"
        rf"{re.escape(value)}\s*,\s*"
        r"(KZT_RELA_STUB_COORDINATE_\w+)",
        re.DOTALL,
    )
    return pattern.findall(body)


eager = function_body(elfloader, "int RelocateElfRELA(")
glob_dat_source = (
    root / "target/i386/latx/context/kzt_guest_glob_dat_target.c"
).read_text(encoding="utf-8")
glob_dat_route = function_body(
    glob_dat_source, "int kzt_guest_glob_dat_route("
)
compatibility_writer = function_body(
    elfloader, "static int kzt_eager_compatibility_write("
)
lazy = function_body(elfloader, "void PltResolver(void)")
glob_dat_start = eager.find("case R_X86_64_GLOB_DAT:")
jump_slot_start = eager.find("case R_X86_64_JUMP_SLOT:")
if glob_dat_start < 0 or jump_slot_start < 0 or glob_dat_start >= jump_slot_start:
    fail("RelocateElfRELA: missing ordered GLOB_DAT/JUMP_SLOT cases")
glob_dat = eager[glob_dat_start:jump_slot_start]
jump_slot = eager[jump_slot_start:]
eager_decision = decision_name(eager, "RelocateElfRELA")
arguments = decision_arguments("RelocateElfRELA", eager)
if arguments != "route_call_succeeded,&route_result,0,final_value_usable":
    fail("RelocateElfRELA: caller decision argument order is incompatible")
assert_route_success_is_production_result("RelocateElfRELA", eager)

legacy_stores = list(re.finditer(
    r"(?m)^\s*\*p\s*(?:=|\+=)\s*", eager
))
if legacy_stores:
    fail("RelocateElfRELA: KZT-aware eager path retains a direct slot store")
fallback = eager.rfind("kzt_resolve_legacy_rela_target(")
route_call = eager.find("kzt_production_jump_slot_route(")
if route_call < 0 or fallback < route_call:
    fail("RelocateElfRELA: compatibility write must follow guest-first route")
for required in (
    "if (!slot)",
    "*slot = replacement;",
    "*final_value = replacement;",
    "return KZT_EAGER_COMPATIBILITY_WRITE_APPLIED;",
):
    if required not in compatibility_writer:
        fail(f"compatibility writer lacks {required}")
for forbidden in (
    "option_kzt",
    "wine_option_kzt",
    "__atomic_compare_exchange_n(",
    "kzt_patch_spike_guard_",
    "kzt_production_",
):
    if forbidden in compatibility_writer:
        fail(f"compatibility writer must remain policy-free: {forbidden}")
if compatibility_writer.count("*slot = replacement;") != 1:
    fail("compatibility writer must contain exactly one simple slot store")
if glob_dat.count("kzt_eager_compatibility_write(") != 1 or \
        jump_slot.count("kzt_eager_compatibility_write(") != 2:
    fail("non-KZT GLOB_DAT/JUMP_SLOT writes must share the compatibility writer")

# KZT owns eager relocation writes.  Native GLOB_DAT bridges use the guarded
# writer transaction, while guest/local writes use the mandatory transaction.
if glob_dat_route.count("kzt_production_eager_relocation_write(") != 1:
    fail("KZT GLOB_DAT native bridge must use one guarded transaction")
if glob_dat.count("kzt_production_guest_relocation_write(") != 1:
    fail("KZT local GLOB_DAT must use one mandatory transaction")
if not re.search(
    rf"{re.escape('kzt_production_eager_relocation_write(')}"
    r"[\s\S]*?KZT_PATCH_RELOCATION_GLOB_DAT",
    glob_dat_route,
):
    fail("KZT native GLOB_DAT transaction has the wrong relocation type")
if not re.search(
    rf"{re.escape('kzt_production_guest_relocation_write(')}"
    r"[\s\S]*?KZT_PATCH_RELOCATION_GLOB_DAT",
    glob_dat,
):
    fail("KZT local GLOB_DAT transaction has the wrong relocation type")
glob_legacy = glob_dat.find("kzt_resolve_legacy_rela_target(")
if glob_legacy < 0 or glob_dat.find("kzt_guest_glob_dat_route(") > glob_legacy or \
        glob_dat.find("kzt_production_guest_relocation_write(") > glob_legacy:
    fail("KZT GLOB_DAT transactions must precede the compatibility path")

# KZT JUMP_SLOT writes have three controlled routes: deferred/local guest
# relocations use the mandatory transaction, and non-local eager binding uses
# the shared Registry-backed route.  The simple writer is only the KZT-off arm.
if jump_slot.count("kzt_production_guest_relocation_write(") != 2:
    fail("KZT deferred/local JUMP_SLOT writes must use mandatory transactions")
if jump_slot.count("kzt_production_jump_slot_route(") != 1:
    fail("KZT non-local JUMP_SLOT must use the shared transactional route")
if not re.search(
    r"if\s*\(\s*option_kzt\s*\|\|\s*wine_option_kzt\s*\)\s*\{"
    r"[\s\S]*?kzt_production_guest_relocation_write\s*\("
    r"[\s\S]*?KZT_PATCH_RELOCATION_JUMP_SLOT[\s\S]*?\}\s*else"
    r"[\s\S]*?kzt_eager_compatibility_write\s*\(",
    jump_slot,
):
    fail("deferred JUMP_SLOT does not separate KZT transaction from compatibility")
preserve_blocks = [
    (start, end)
    for start, end, block in guarded_blocks(
        jump_slot, r"\boption_kzt\s*\|\|\s*wine_option_kzt\b"
    )
    if 'route=GUEST_PRESERVED' in block and 'host_lookup=0' in block and
    re.search(r"\bbreak\s*;", block)
]
jump_legacy = jump_slot.find("kzt_resolve_legacy_rela_target(")
if jump_legacy < 0 or not any(end < jump_legacy for _, end in preserve_blocks):
    fail("RelocateElfRELA: KZT evidence failure can reach host lookup")

for forbidden_lazy_writer in (
    "kzt_jump_slot_route_caller_decide(",
    "kzt_production_jump_slot_route(",
    "KZT_JUMP_SLOT_ROUTE_SLOT_LEGACY_WRITE",
):
    if forbidden_lazy_writer in lazy:
        fail(
            "PltResolver: removed lazy legacy writer remains: "
            f"{forbidden_lazy_writer}"
        )
if re.search(r"\*p\s*=\s*(?:offs|legacy_target)\s*;", lazy):
    fail("PltResolver: historical lazy GOT direct store must be absent")
if "kzt_production_lazy_direct_route(" not in lazy:
    fail("PltResolver: missing Registry-backed lazy direct route")
if "kzt_plt_resolver_enter(" not in lazy:
    fail("PltResolver: missing per-object guest resolver handoff")

# Eager deferral is shared policy: a slot can still be link-time raw or already
# runtime-rebased.  The production caller must not duplicate raw-only bounds
# checks; the plan controls whether its local delta adjustment is needed.
for required in (
    "kzt_rela_jump_slot_defer_input_t",
    "kzt_rela_jump_slot_defer_plan_t",
    "slot_is_unresolved_stub",
    "should_defer",
    "should_add_delta",
):
    if required not in defer_header:
        fail(f"missing shared defer-plan contract: {required}")
for required in (
    "KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW",
    "KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED",
):
    if required not in defer_module:
        fail(f"shared defer plan does not recognize both coordinates: {required}")
if eager.count("kzt_rela_jump_slot_defer_plan(&defer_input)") != 1:
    fail("RelocateElfRELA: expected one shared defer plan call")
if "kzt_rela_jump_slot_defer_input_t defer_input" not in eager:
    fail("RelocateElfRELA: missing shared defer plan input")
if not re.search(
    r"\bslot_is_unresolved_stub\s*=\s*"
    r"defer_plan\.slot_is_unresolved_stub\s*;",
    eager,
):
    fail("RelocateElfRELA: route must receive the observed stub fact")
if not re.search(
    r"kzt_production_jump_slot_route\s*\([\s\S]*?"
    r"slot_observation\s*,\s*slot_is_unresolved_stub\s*,",
    eager,
):
    fail("RelocateElfRELA: production route does not receive observed stub fact")
route_blocks = [
    block
    for _, _, block in guarded_blocks(
        jump_slot,
        r"\boption_kzt\s*\|\|\s*wine_option_kzt\b[\s\S]*?"
        r"\bbind\s*!=\s*STB_LOCAL\b",
    )
    if "kzt_production_jump_slot_route(" in block
]
if len(route_blocks) != 1:
    fail("RelocateElfRELA: expected one KZT non-local route block")
if "return -1;" in route_blocks[0]:
    fail("RelocateElfRELA: route-owned unusable slot must fail open")
if re.search(
    r"kzt_rela_slot_current_is_unresolved_stub\s*\(\s*"
    r"slot_observation\s*,",
    eager,
):
    fail("RelocateElfRELA: duplicated raw-only deferred-slot detection")
if "if (defer_plan.should_defer)" not in eager:
    fail("RelocateElfRELA: shared defer plan must choose the deferred branch")
if not re.search(
    r"if\s*\(\s*defer_plan\.should_add_delta\s*\)\s*\{[\s\S]*?"
    r"kzt_eager_compatibility_write\s*\(",
    eager,
):
    fail("RelocateElfRELA: raw deferred slot rebasing bypasses the CAS helper")
if "*need_resolv = 1;" not in eager:
    fail("RelocateElfRELA: deferred slots must request the resolver")
if detector_coordinates(eager, "route_result.final_value") != [
    "KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW",
    "KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED",
]:
    fail("RelocateElfRELA: final value must reject raw and rebased stubs")
if '"GUEST_PRESERVED"' not in eager:
    fail("RelocateElfRELA: route-owned preserve result lacks diagnostics")

if "mmap_lock_held" not in writer_header:
    fail("permission lease must track the QEMU mapping transaction lock")

mapping_lock = function_body(production, "production_slot_mapping_lock(")
mapping_unlock = function_body(production, "production_slot_mapping_unlock(")
permission_begin = function_body(production, "production_slot_begin_write(")
permission_end = function_body(production, "production_slot_end_write(")

for required in ("mmap_lock();", "lease->mmap_lock_held = 1;"):
    if required not in mapping_lock:
        fail(f"mapping lock helper lacks required operation: {required}")
for required in ("mmap_unlock();", "lease->mmap_lock_held = 0;"):
    if required not in mapping_unlock:
        fail(f"mapping unlock helper lacks required operation: {required}")
if "production_slot_mapping_lock(lease)" not in permission_begin:
    fail("permission transaction does not acquire the mapping lock")
if permission_begin.find("production_slot_mapping_lock(lease)") > \
        permission_begin.find("page_get_flags(guest_addr)"):
    fail("permission transaction reads page flags before locking mappings")
if "production_slot_mapping_unlock(lease)" not in permission_end:
    fail("permission transaction does not release the mapping lock")
if "lease->restore_attempts >= 2" not in permission_end:
    fail("permission transaction cannot retain the mapping lock for one recovery")
if permission_end.find("production_slot_mapping_unlock(lease)") < \
        permission_end.find("target_mprotect("):
    fail("permission transaction releases mappings before restoring permissions")

print("WI-601 eager/lazy jump-slot single-writer source contract: PASS")
