#!/usr/bin/env python3

import pathlib
import re
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, name: str, next_name: str) -> str:
    start = source.index(f"static int {name}(")
    end = source.index(f"static int {next_name}(", start)
    return source[start:end]


root = pathlib.Path(sys.argv[1])
source = (
    root / "target/i386/latx/context/kzt_jump_slot_production.c"
).read_text()

selector = function_body(
    source,
    "production_symbol_uses_guarded_xcb_bridge",
    "production_exact_provider_handle_matches",
)
require(
    "return kzt_xcb_route_is_guarded_consumer(symbol_name);" in selector,
    "production bridge selection must reuse the central XCB route policy",
)

prebind = function_body(
    source,
    "production_lazy_prebind_object_prepare",
    "production_lazy_prebind_revoke_closed",
)
require(
    prebind.index("kzt_patch_symbol_must_stay_guest(candidate.symbol_name)")
    < prebind.index(
        "kzt_rela_runtime_wrapper_provider_discover_guarded_retained_with_version_evidence"
    ),
    "lazy prebind must apply planner guest policy before bridge discovery",
)
require(
    re.search(
        r"discover_guarded_retained_with_version_evidence\(.*?"
        r"scope_proof\.selected_provider_address,\s*"
        r"KZT_BRIDGE_GUARD_XCB_CONNECTION",
        prebind,
        re.S,
    ),
    "lazy prebind fallback must be the proven scope provider address",
)

lazy_first_call = function_body(
    source,
    "production_lazy_direct_find_bridge",
    "production_lazy_direct_acquire_decision_lease",
)
require(
    re.search(
        r"discover_guarded_retained_with_version_evidence\(.*?"
        r"state->preemption_proof\.selected_provider_address,\s*"
        r"KZT_BRIDGE_GUARD_XCB_CONNECTION",
        lazy_first_call,
        re.S,
    ),
    "lazy first-call fallback must be the proven preemption provider address",
)

eager = function_body(
    source,
    "production_enrich_bridge",
    "production_validate_source_identity",
)
require(
    eager.index("kzt_patch_symbol_must_stay_guest(request->symbol_name)")
    < eager.index("discover_guarded_with_version_evidence"),
    "eager production must apply planner guest policy before discovery",
)
require(
    re.search(
        r"discover_guarded_with_version_evidence\(.*?"
        r"request->slot_current_value,\s*"
        r"KZT_BRIDGE_GUARD_XCB_CONNECTION",
        eager,
        re.S,
    ),
    "completion/eager fallback must be the revalidated current guest slot target",
)

for path_name, body in (
    ("lazy prebind", prebind),
    ("lazy first-call", lazy_first_call),
    ("eager", eager),
):
    require(
        "expected_guest_target" not in body[
            body.index("discover_guarded") : body.index("&wrapper_provider")
            if "&wrapper_provider" in body[body.index("discover_guarded") :]
            else len(body)
        ],
        f"{path_name} must not use the expected slot target as fallback",
    )

lazy_route = source[source.index("int kzt_production_lazy_direct_route(") :]
require(
    lazy_route.index("kzt_patch_symbol_must_stay_guest(symbol_name)")
    < lazy_route.index(".find_wrapper_bridge = production_lazy_direct_find_bridge"),
    "lazy first-call route must apply planner guest policy before discovery",
)

glob_dat = (
    root / "target/i386/latx/context/kzt_guest_glob_dat_target.c"
).read_text()
require(
    "kzt_xcb_route_classify(symbol_name) != KZT_XCB_ROUTE_NOT_XCB" in glob_dat,
    "GLOB_DAT must preserve every XCB symbol until it has an equivalent guarded route",
)

bridge = (root / "target/i386/latx/context/bridge.c").read_text()
native_start = bridge.index("void* GetNativeFnc(")
native_or_start = bridge.index("void* GetNativeFncOrFnc(", native_start)
native = bridge[native_start:native_or_start]
native_or = bridge[
    native_or_start : bridge.index("// Alternate address handling", native_or_start)
]
require(
    "b->guard_kind != KZT_BRIDGE_GUARD_NONE" in native and
    "return NULL;" in native,
    "GetNativeFnc must not unwrap a guarded bridge",
)
require(
    "b->guard_kind != KZT_BRIDGE_GUARD_NONE" in native_or and
    "return (void*)fnc;" in native_or,
    "GetNativeFncOrFnc must preserve a guarded bridge target",
)

print("wi1573-guarded-xcb-production-source-contract: PASS")
