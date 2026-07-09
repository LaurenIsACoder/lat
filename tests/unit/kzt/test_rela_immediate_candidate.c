#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_patch_spike_writer.h"
#include "target/i386/latx/include/kzt_rela_immediate_candidate.h"

static int failures;

typedef struct wi231_fake_slot {
    uintptr_t slot_addr;
    uintptr_t value;
    uintptr_t replacement_value;
    int read_calls;
    int writer_write_calls;
    int legacy_write_calls;
    int fail_replacement_write;
    int fail_rollback_write;
    int force_verify_mismatch;
} wi231_fake_slot_t;

typedef struct wi231_writer_route {
    int planner_called;
    int writer_called;
    kzt_rela_immediate_candidate_result_t plan;
    kzt_patch_spike_record_t record;
} wi231_writer_route_t;

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

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got,
            expected);
    ++failures;
}

static void check_str(const char *name, const char *got,
                      const char *expected)
{
    if (got && expected && !strcmp(got, expected)) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static int wi231_fake_read_slot(uintptr_t slot_addr, uintptr_t *value,
                                void *opaque)
{
    wi231_fake_slot_t *slot = opaque;

    if (!slot || !value || slot_addr != slot->slot_addr) {
        return -1;
    }

    ++slot->read_calls;
    if (slot->force_verify_mismatch && slot->read_calls > 1) {
        *value = slot->replacement_value + 0x10;
        return 0;
    }

    *value = slot->value;
    return 0;
}

static int wi231_fake_write_slot(uintptr_t slot_addr, uintptr_t value,
                                 void *opaque)
{
    wi231_fake_slot_t *slot = opaque;

    if (!slot || slot_addr != slot->slot_addr) {
        return -1;
    }

    ++slot->writer_write_calls;
    if (value == slot->replacement_value && slot->fail_replacement_write) {
        return -1;
    }
    if (value != slot->replacement_value && slot->fail_rollback_write) {
        return -1;
    }

    slot->value = value;
    return 0;
}

static kzt_patch_spike_slot_ops_t wi231_slot_ops(wi231_fake_slot_t *slot)
{
    return (kzt_patch_spike_slot_ops_t) {
        .read_slot = wi231_fake_read_slot,
        .write_slot = wi231_fake_write_slot,
        .opaque = slot,
    };
}

static kzt_patch_spike_guard_t wi231_enabled_guard(void)
{
    kzt_patch_spike_config_t config = {
        .enabled = 1,
        .write_enabled = 1,
        .budget = 8,
    };
    kzt_patch_spike_guard_t guard;

    kzt_patch_spike_guard_init(&guard, &config);
    return guard;
}

static void wi231_legacy_write(wi231_fake_slot_t *slot,
                               uintptr_t legacy_target)
{
    ++slot->legacy_write_calls;
    slot->value = legacy_target;
}

static int wi231_plan_approved_for_writer(
    const kzt_rela_immediate_candidate_result_t *plan)
{
    return plan && plan->status == KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED &&
           plan->decision_present &&
           plan->decision.kind == KZT_PATCH_DECISION_APPROVED &&
           plan->decision.allow_native_bridge;
}

static void wi231_apply_step4_writer_contract(
    const kzt_rela_immediate_candidate_result_t *plan,
    wi231_fake_slot_t *slot, uintptr_t legacy_target,
    wi231_writer_route_t *route)
{
    kzt_patch_spike_guard_t guard = wi231_enabled_guard();
    kzt_patch_spike_slot_ops_t ops;

    memset(route, 0, sizeof(*route));
    if (plan) {
        route->plan = *plan;
    }

    if (!wi231_plan_approved_for_writer(plan)) {
        wi231_legacy_write(slot, legacy_target);
        return;
    }

    ops = wi231_slot_ops(slot);
    check_int("wi231.writer.apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(
                  &guard, &plan->decision, &ops, &route->record),
              0);
    route->writer_called = route->record.writer_called;
    if (!route->record.skip_legacy_write) {
        wi231_legacy_write(slot, legacy_target);
    }
}

static void wi231_apply_step4_request_contract(
    const kzt_rela_immediate_candidate_request_t *request,
    wi231_fake_slot_t *slot, uintptr_t legacy_target,
    wi231_writer_route_t *route)
{
    kzt_rela_immediate_candidate_result_t plan;

    memset(&plan, 0, sizeof(plan));
    memset(route, 0, sizeof(*route));
    route->planner_called = 1;
    check_int("wi231.plan.call",
              kzt_rela_immediate_jump_slot_plan(request, &plan), 0);
    wi231_apply_step4_writer_contract(&plan, slot, legacy_target, route);
    route->planner_called = 1;
}

static void wi231_trace(const char *tc, const wi231_fake_slot_t *slot,
                        const wi231_writer_route_t *route)
{
    printf("WI231_TC tc=%s plan_status=%d plan_reason=%d "
           "decision=%s writer_called=%d legacy_writes=%d "
           "skip_legacy=%d result=%s failure=%s reads=%d "
           "writer_writes=%d final=0x%lx\n",
           tc, route->plan.status, route->plan.reason,
           route->plan.decision_present ?
               kzt_patch_decision_kind_name(route->plan.decision.kind) :
               "(none)",
           route->writer_called, slot->legacy_write_calls,
           route->record.skip_legacy_write,
           kzt_patch_spike_result_name(route->record.result),
           kzt_patch_spike_failure_name(route->record.failure),
           slot->read_calls, slot->writer_write_calls,
           (unsigned long)slot->value);
}

static kzt_patch_object_ref_t object_ref(uintptr_t link_map_addr,
                                         unsigned long generation,
                                         const char *soname)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = link_map_addr,
        .map_start = 0x7000000000 + generation * 0x100000,
        .map_end = 0x7000009000 + generation * 0x100000,
        .generation = generation,
        .soname = soname,
        .path = soname,
    };
}

static kzt_rela_immediate_candidate_request_t base_request(void)
{
    return (kzt_rela_immediate_candidate_request_t) {
        .relocation_type = R_X86_64_JUMP_SLOT,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 4,
        .entry_addr = 0x7000100200,
        .source = object_ref(0x1110, 5, "librequester.so"),
        .dynamic_addr = 0x7000100000,
        .load_bias = 0x7000000000,
        .dynamic_view_generation = 18,
        .dynamic_view_available = 1,
        .slot_addr = 0x7000200088,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7100001234,
        .lazy_binding_deferred = 0,
        .symbol_index = 33,
        .symbol_name = "gtk_widget_show",
        .version = "GTK_3.0",
        .current_owner = object_ref(0x2220, 9, "libgtk-3.so"),
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
        .wrapper_name = "wrappedgtk3",
        .wrapper_symbol_version = "GTK_3.0",
        .bridge_target = 0x7200004560,
    };
}

static wi231_fake_slot_t wi231_slot_from_request(
    const kzt_rela_immediate_candidate_request_t *request)
{
    return (wi231_fake_slot_t) {
        .slot_addr = request->slot_addr,
        .value = request->slot_current_value,
        .replacement_value = request->bridge_target,
    };
}

static kzt_rela_immediate_candidate_result_t wi231_planned_decision(
    kzt_patch_decision_kind_t kind, kzt_patch_reason_t reason)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    check_int("wi231.template.plan",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    result.status = KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED;
    result.reason = KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE;
    result.candidate_present = 1;
    result.decision_present = 1;
    result.decision.kind = kind;
    result.decision.reason = reason;
    result.decision.allow_native_bridge =
        kind == KZT_PATCH_DECISION_APPROVED;
    return result;
}

static kzt_rela_immediate_candidate_result_t wi231_error_plan(void)
{
    kzt_rela_immediate_candidate_result_t result =
        wi231_planned_decision(KZT_PATCH_DECISION_ERROR,
                               KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT);

    result.status = KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN;
    result.reason = KZT_RELA_IMMEDIATE_CANDIDATE_REASON_PLANNER_ERROR;
    result.candidate_present = 0;
    return result;
}

static void test_immediate_jump_slot_builds_candidate_fields(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;
    const kzt_patch_candidate_t *candidate;

    check_int("jump_slot.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("jump_slot.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED);
    check_int("jump_slot.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE);
    check_int("jump_slot.candidate_present", result.candidate_present, 1);
    check_int("jump_slot.decision_present", result.decision_present, 1);

    candidate = &result.candidate;
    check_int("jump_slot.table", candidate->table_kind,
              KZT_PATCH_TABLE_PLT_RELA);
    check_ulong("jump_slot.entry_index", candidate->entry_index, 4);
    check_ulong("jump_slot.entry_addr", candidate->entry_addr,
                request.entry_addr);
    check_int("jump_slot.reloc", candidate->reloc_type,
              KZT_PATCH_RELOCATION_JUMP_SLOT);
    check_ulong("jump_slot.slot", candidate->slot_addr, request.slot_addr);
    check_int("jump_slot.current_present",
              candidate->slot_current_value_present, 1);
    check_ulong("jump_slot.current", candidate->slot_current_value,
                request.slot_current_value);
    check_int("jump_slot.lazy", candidate->lazy_binding_deferred, 0);
    check_ulong("jump_slot.symbol_index", candidate->symbol_index, 33);
    check_str("jump_slot.symbol", candidate->symbol_name,
              "gtk_widget_show");
    check_str("jump_slot.version", candidate->version, "GTK_3.0");
    check_int("jump_slot.owner", candidate->owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_int("jump_slot.wrapper", candidate->wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("jump_slot.bridge", candidate->bridge_target,
                request.bridge_target);
    check_int("jump_slot.decision", result.decision.kind,
              KZT_PATCH_DECISION_APPROVED);
}

static void test_non_target_relocation_does_not_build_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.relocation_type = R_X86_64_RELATIVE;
    check_int("relative.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("relative.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("relative.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION);
    check_int("relative.candidate_present", result.candidate_present, 0);
    check_int("relative.decision_present", result.decision_present, 0);
}

static void test_glob_dat_keeps_legacy_path_without_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.relocation_type = R_X86_64_GLOB_DAT;
    request.table_kind = KZT_PATCH_TABLE_RELA;
    check_int("glob_dat.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("glob_dat.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("glob_dat.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION);
    check_int("glob_dat.candidate_present", result.candidate_present, 0);
}

static void test_deferred_lazy_binding_does_not_build_writable_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.lazy_binding_deferred = 1;
    check_int("lazy.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("lazy.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("lazy.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING);
    check_int("lazy.candidate_present", result.candidate_present, 0);
}

static void test_missing_symbol_information_fails_open(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.symbol_name = NULL;
    check_int("missing_symbol.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("missing_symbol.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN);
    check_int("missing_symbol.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_NAME);
    check_int("missing_symbol.candidate_present", result.candidate_present, 0);
    check_int("missing_symbol.decision_present", result.decision_present, 0);
}

static void test_missing_owner_still_plans_but_keeps_legacy_decision(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    memset(&request.current_owner, 0, sizeof(request.current_owner));
    request.owner_match = KZT_PATCH_OWNER_UNKNOWN;
    request.wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    request.bridge_target = 0;

    check_int("owner_unknown.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("owner_unknown.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED);
    check_int("owner_unknown.candidate_present", result.candidate_present, 1);
    check_int("owner_unknown.decision_present", result.decision_present, 1);
    check_int("owner_unknown.decision", result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("owner_unknown.reason", result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);
}

static void test_wi231_approved_writer_success_skips_legacy_duplicate_write(
    void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    uintptr_t legacy_target = 0x7300002222;
    wi231_fake_slot_t slot = wi231_slot_from_request(&request);
    wi231_writer_route_t route;

    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.success.planner", route.planner_called, 1);
    check_int("wi231.success.decision", route.plan.decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_int("wi231.success.writer", route.writer_called, 1);
    check_int("wi231.success.skip_legacy",
              route.record.skip_legacy_write, 1);
    check_int("wi231.success.legacy", slot.legacy_write_calls, 0);
    check_ulong("wi231.success.final", slot.value, request.bridge_target);
    wi231_trace("approved-writer-success-skips-legacy", &slot, &route);
}

static void test_wi231_planner_non_approved_results_keep_legacy(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    uintptr_t legacy_target = 0x7300003333;
    wi231_fake_slot_t slot;
    wi231_writer_route_t route;
    kzt_rela_immediate_candidate_result_t plan;

    memset(&request.current_owner, 0, sizeof(request.current_owner));
    request.owner_match = KZT_PATCH_OWNER_UNKNOWN;
    request.wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    request.bridge_target = 0;
    slot = wi231_slot_from_request(&request);
    slot.replacement_value = 0x7200004560;
    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.unsupported.decision", route.plan.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("wi231.unsupported.writer", route.writer_called, 0);
    check_int("wi231.unsupported.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.unsupported.final", slot.value, legacy_target);
    wi231_trace("planner-unsupported-keeps-legacy", &slot, &route);

    request = base_request();
    request.owner_match = KZT_PATCH_OWNER_MISMATCH;
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.rejected.decision", route.plan.decision.kind,
              KZT_PATCH_DECISION_REJECTED);
    check_int("wi231.rejected.writer", route.writer_called, 0);
    check_int("wi231.rejected.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.rejected.final", slot.value, legacy_target);
    wi231_trace("planner-rejected-keeps-legacy", &slot, &route);

    plan = wi231_planned_decision(KZT_PATCH_DECISION_DEFERRED,
                                  KZT_PATCH_REASON_DEFERRED_LAZY_BINDING);
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.deferred.writer", route.writer_called, 0);
    check_int("wi231.deferred.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.deferred.final", slot.value, legacy_target);
    wi231_trace("planner-deferred-keeps-legacy", &slot, &route);

    plan = wi231_error_plan();
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.error.writer", route.writer_called, 0);
    check_int("wi231.error.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.error.final", slot.value, legacy_target);
    wi231_trace("planner-error-keeps-legacy", &slot, &route);
}

static void test_wi231_writer_failures_fail_open_to_legacy(void)
{
    kzt_rela_immediate_candidate_result_t plan =
        wi231_planned_decision(KZT_PATCH_DECISION_APPROVED,
                               KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);
    uintptr_t legacy_target = 0x7300004444;
    wi231_fake_slot_t slot;
    wi231_writer_route_t route;

    slot = wi231_slot_from_request(&(kzt_rela_immediate_candidate_request_t) {
        .slot_addr = plan.decision.slot_addr,
        .slot_current_value = plan.decision.slot_current_value + 4,
        .bridge_target = plan.decision.bridge_target,
    });
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.mismatch.writer", route.writer_called, 1);
    check_int("wi231.mismatch.failure", route.record.failure,
              KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH);
    check_int("wi231.mismatch.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.mismatch.final", slot.value, legacy_target);
    wi231_trace("writer-expected-mismatch-fail-open", &slot, &route);

    slot = wi231_slot_from_request(&(kzt_rela_immediate_candidate_request_t) {
        .slot_addr = plan.decision.slot_addr,
        .slot_current_value = plan.decision.slot_current_value,
        .bridge_target = plan.decision.bridge_target,
    });
    slot.fail_replacement_write = 1;
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.write_fail.failure", route.record.failure,
              KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED);
    check_int("wi231.write_fail.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.write_fail.final", slot.value, legacy_target);
    wi231_trace("writer-write-fail-fail-open", &slot, &route);

    slot = wi231_slot_from_request(&(kzt_rela_immediate_candidate_request_t) {
        .slot_addr = plan.decision.slot_addr,
        .slot_current_value = plan.decision.slot_current_value,
        .bridge_target = plan.decision.bridge_target,
    });
    slot.force_verify_mismatch = 1;
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.verify_fail.failure", route.record.failure,
              KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED);
    check_int("wi231.verify_fail.rollback",
              route.record.rollback_called, 1);
    check_int("wi231.verify_fail.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.verify_fail.final", slot.value, legacy_target);
    wi231_trace("writer-verify-fail-fail-open", &slot, &route);

    slot = wi231_slot_from_request(&(kzt_rela_immediate_candidate_request_t) {
        .slot_addr = plan.decision.slot_addr,
        .slot_current_value = plan.decision.slot_current_value,
        .bridge_target = plan.decision.bridge_target,
    });
    slot.force_verify_mismatch = 1;
    slot.fail_rollback_write = 1;
    wi231_apply_step4_writer_contract(&plan, &slot, legacy_target, &route);
    check_int("wi231.rollback_fail.failure", route.record.failure,
              KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED);
    check_int("wi231.rollback_fail.rollback",
              route.record.rollback_called, 1);
    check_int("wi231.rollback_fail.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.rollback_fail.final", slot.value, legacy_target);
    wi231_trace("writer-rollback-fail-fail-open", &slot, &route);
}

static void test_wi231_non_target_glob_dat_and_lazy_skip_writer(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    uintptr_t legacy_target = 0x7300005555;
    wi231_fake_slot_t slot;
    wi231_writer_route_t route;

    request.relocation_type = R_X86_64_RELATIVE;
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.relative.writer", route.writer_called, 0);
    check_int("wi231.relative.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.relative.final", slot.value, legacy_target);
    wi231_trace("non-target-relocation-skips-writer", &slot, &route);

    request = base_request();
    request.relocation_type = R_X86_64_GLOB_DAT;
    request.table_kind = KZT_PATCH_TABLE_RELA;
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.glob_dat.writer", route.writer_called, 0);
    check_int("wi231.glob_dat.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.glob_dat.final", slot.value, legacy_target);
    wi231_trace("glob-dat-skips-writer", &slot, &route);

    request = base_request();
    request.lazy_binding_deferred = 1;
    slot = wi231_slot_from_request(&request);
    wi231_apply_step4_request_contract(&request, &slot, legacy_target,
                                       &route);
    check_int("wi231.lazy.writer", route.writer_called, 0);
    check_int("wi231.lazy.legacy", slot.legacy_write_calls, 1);
    check_ulong("wi231.lazy.final", slot.value, legacy_target);
    wi231_trace("lazy-deferred-skips-writer", &slot, &route);
}

int main(void)
{
    test_immediate_jump_slot_builds_candidate_fields();
    test_non_target_relocation_does_not_build_candidate();
    test_glob_dat_keeps_legacy_path_without_candidate();
    test_deferred_lazy_binding_does_not_build_writable_candidate();
    test_missing_symbol_information_fails_open();
    test_missing_owner_still_plans_but_keeps_legacy_decision();
    test_wi231_approved_writer_success_skips_legacy_duplicate_write();
    test_wi231_planner_non_approved_results_keep_legacy();
    test_wi231_writer_failures_fail_open_to_legacy();
    test_wi231_non_target_glob_dat_and_lazy_skip_writer();

    if (failures) {
        fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
