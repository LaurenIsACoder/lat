#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/kzt_owner_resolver.h"
#include "target/i386/latx/include/kzt_patch_planner.h"
#include "target/i386/latx/include/kzt_rela_immediate_candidate.h"

static int failures;

typedef struct wi236_contract_input {
    kzt_guest_registry_t *registry;
    uintptr_t slot_current_value;
    uintptr_t expected_guest_target;
    uintptr_t native_bridge_target;
    kzt_patch_wrapper_match_t wrapper_match;
} wi236_contract_input_t;

typedef struct wi236_contract_result {
    kzt_rela_immediate_candidate_request_t request;
    kzt_owner_resolution_t owner_resolution;
    kzt_rela_immediate_candidate_result_t plan;
} wi236_contract_result_t;

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static kzt_guest_object_observation_t observation(
    uintptr_t link_map_addr,
    uintptr_t map_start,
    uintptr_t map_end,
    const char *soname)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { soname, KZT_GUEST_FIELD_OK },
        .soname = { soname, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_patch_object_ref_t source_ref(void)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = 0x1110,
        .map_start = 0x69000000,
        .map_end = 0x69010000,
        .generation = 1,
        .soname = "librequester.so",
        .path = "/guest/librequester.so",
    };
}

static void request_base(kzt_rela_immediate_candidate_request_t *request)
{
    memset(request, 0, sizeof(*request));
    request->relocation_type = R_X86_64_JUMP_SLOT;
    request->table_kind = KZT_PATCH_TABLE_PLT_RELA;
    request->entry_index = 7;
    request->entry_addr = 0x69002000;
    request->source = source_ref();
    request->dynamic_addr = 0x69001000;
    request->load_bias = 0x69000000;
    request->dynamic_view_generation = 3;
    request->dynamic_view_available = 1;
    request->slot_addr = 0x69003000;
    request->slot_current_value_present = 1;
    request->symbol_index = 44;
    request->symbol_name = "gtk_widget_show";
    request->version = "GTK_3.0";
    request->wrapper_name = "wrappedgtk3";
    request->wrapper_symbol_version = "GTK_3.0";
}

static void apply_wi236_contract(const wi236_contract_input_t *input,
                                 wi236_contract_result_t *result)
{
    memset(result, 0, sizeof(*result));
    request_base(&result->request);

    result->request.slot_current_value = input->slot_current_value;
    result->request.expected_guest_target = input->expected_guest_target;
    result->request.native_bridge_target = input->native_bridge_target;
    result->request.legacy_target = input->expected_guest_target;
    result->request.wrapper_match = input->wrapper_match;

    kzt_owner_resolver_init(&result->owner_resolution);
    check_int("contract.owner.resolve",
              kzt_owner_resolver_resolve_current(
                  input->registry,
                  input->slot_current_value,
                  input->expected_guest_target,
                  &result->owner_resolution),
              0);
    result->request.current_owner = result->owner_resolution.current_owner;
    result->request.owner_match = result->owner_resolution.owner_match;

    check_int("contract.plan",
              kzt_rela_immediate_jump_slot_plan(&result->request,
                                                &result->plan),
              0);
}

static kzt_guest_registry_t *registry_with_two_objects(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t lib_a =
        observation(0x2000, 0x72000000, 0x72001000, "libcollision.so");
    kzt_guest_object_observation_t lib_b =
        observation(0x3000, 0x76000000, 0x76001000, "libgtk-3.so");

    check_int("registry.observe.a",
              kzt_guest_registry_observe(registry, &lib_a),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("registry.observe.b",
              kzt_guest_registry_observe(registry, &lib_b),
              KZT_GUEST_REGISTRY_ADDED);
    return registry;
}

static void test_bridge_address_is_not_expected_guest_target(void)
{
    kzt_guest_registry_t *registry = registry_with_two_objects();
    wi236_contract_result_t result;
    kzt_owner_resolution_t unsafe_resolution;
    wi236_contract_input_t input = {
        .registry = registry,
        .slot_current_value = 0x72000040,
        .expected_guest_target = 0x76000080,
        .native_bridge_target = 0x72000088,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
    };

    apply_wi236_contract(&input, &result);
    check_int("bridge-not-expected.owner",
              result.request.owner_match, KZT_PATCH_OWNER_MISMATCH);
    check_int("bridge-not-expected.decision",
              result.plan.decision.kind, KZT_PATCH_DECISION_REJECTED);
    check_int("bridge-not-expected.reason",
              result.plan.decision.reason,
              KZT_PATCH_REASON_POLICY_OWNER_MISMATCH);

    check_int("unsafe.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, input.slot_current_value,
                  input.native_bridge_target, &unsafe_resolution),
              0);
    check_int("unsafe.bridge-as-expected-would-match",
              unsafe_resolution.owner_match, KZT_PATCH_OWNER_MATCH);

    kzt_guest_registry_destroy(&registry);
}

static void test_only_full_evidence_can_be_approved(void)
{
    kzt_guest_registry_t *registry = registry_with_two_objects();
    wi236_contract_result_t result;
    wi236_contract_input_t input = {
        .registry = registry,
        .slot_current_value = 0x76000040,
        .expected_guest_target = 0x76000080,
        .native_bridge_target = 0x73000080,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
    };

    apply_wi236_contract(&input, &result);
    check_int("approved.owner",
              result.request.owner_match, KZT_PATCH_OWNER_MATCH);
    check_int("approved.wrapper",
              result.request.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("approved.candidate.bridge",
                result.plan.candidate.bridge_target, 0x73000080);
    check_ulong("approved.decision.bridge",
                result.plan.decision.bridge_target, 0x73000080);
    check_int("approved.decision",
              result.plan.decision.kind, KZT_PATCH_DECISION_APPROVED);
    check_int("approved.reason",
              result.plan.decision.reason,
              KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);

    kzt_guest_registry_destroy(&registry);
}

static void test_owner_unknown_and_mismatch_fail_open_or_reject(void)
{
    kzt_guest_registry_t *registry = registry_with_two_objects();
    wi236_contract_result_t result;
    wi236_contract_input_t input = {
        .registry = NULL,
        .slot_current_value = 0x76000040,
        .expected_guest_target = 0x76000080,
        .native_bridge_target = 0x73000080,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
    };

    apply_wi236_contract(&input, &result);
    check_int("owner-unknown.decision",
              result.plan.decision.kind, KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("owner-unknown.reason",
              result.plan.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);

    input.registry = registry;
    input.slot_current_value = 0x72000040;
    input.expected_guest_target = 0x76000080;
    apply_wi236_contract(&input, &result);
    check_int("owner-mismatch.decision",
              result.plan.decision.kind, KZT_PATCH_DECISION_REJECTED);
    check_int("owner-mismatch.reason",
              result.plan.decision.reason,
              KZT_PATCH_REASON_POLICY_OWNER_MISMATCH);

    kzt_guest_registry_destroy(&registry);
}

static void test_wrapper_and_bridge_fail_open_matrix(void)
{
    static const struct {
        kzt_patch_wrapper_match_t wrapper_match;
        uintptr_t bridge_target;
        kzt_patch_decision_kind_t decision;
        kzt_patch_reason_t reason;
        const char *name;
    } cases[] = {
        {
            KZT_PATCH_WRAPPER_NO_MANIFEST,
            0x73000080,
            KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST,
            "no-manifest",
        },
        {
            KZT_PATCH_WRAPPER_NO_WRAPPER,
            0x73000080,
            KZT_PATCH_DECISION_REJECTED,
            KZT_PATCH_REASON_POLICY_NO_WRAPPER,
            "no-wrapper",
        },
        {
            KZT_PATCH_WRAPPER_SYMBOL_ONLY,
            0x73000080,
            KZT_PATCH_DECISION_REJECTED,
            KZT_PATCH_REASON_POLICY_WRAPPER_SYMBOL_ONLY,
            "symbol-only",
        },
        {
            KZT_PATCH_WRAPPER_VERSION_MISMATCH,
            0x73000080,
            KZT_PATCH_DECISION_REJECTED,
            KZT_PATCH_REASON_POLICY_VERSION_MISMATCH,
            "version-mismatch",
        },
        {
            KZT_PATCH_WRAPPER_VERSION_MATCH,
            0,
            KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET,
            "bridge-zero",
        },
    };
    kzt_guest_registry_t *registry = registry_with_two_objects();
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wi236_contract_result_t result;
        wi236_contract_input_t input = {
            .registry = registry,
            .slot_current_value = 0x76000040,
            .expected_guest_target = 0x76000080,
            .native_bridge_target = cases[i].bridge_target,
            .wrapper_match = cases[i].wrapper_match,
        };

        apply_wi236_contract(&input, &result);
        check_int(cases[i].name,
                  result.plan.decision.kind, cases[i].decision);
        check_int(cases[i].name,
                  result.plan.decision.reason, cases[i].reason);
    }

    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_bridge_address_is_not_expected_guest_target();
    test_only_full_evidence_can_be_approved();
    test_owner_unknown_and_mismatch_fail_open_or_reject();
    test_wrapper_and_bridge_fail_open_matrix();

    if (failures) {
        fprintf(stderr, "kzt-wi236-enrichment-matrix: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-wi236-enrichment-matrix: ok");
    return 0;
}
