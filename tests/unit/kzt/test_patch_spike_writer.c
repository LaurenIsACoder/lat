#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "target/i386/latx/include/kzt_patch_spike_writer.h"

int option_kzt_patch_spike;
int option_kzt_patch_spike_write;
unsigned long option_kzt_patch_spike_budget;

static int failures;

typedef struct fake_slot {
    uintptr_t slot_addr;
    uintptr_t value;
    uintptr_t replacement_value;
    uintptr_t previous_value;
    int read_calls;
    int write_calls;
    int fail_replacement_write;
    int fail_rollback_write;
    int force_verify_mismatch;
} fake_slot_t;

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

    fprintf(stderr, "%s: got %lu expected %lu\n", name, got, expected);
    ++failures;
}

static void check_uintptr(const char *name, uintptr_t got, uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_ptr(const char *name, const void *got, const void *expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %p expected %p\n", name, got, expected);
    ++failures;
}

static kzt_patch_decision_t approved_decision(uintptr_t slot_addr)
{
    return (kzt_patch_decision_t) {
        .kind = KZT_PATCH_DECISION_APPROVED,
        .reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
        .allow_native_bridge = 1,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 3,
        .entry_addr = 0x7100000040,
        .reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT,
        .slot_addr = slot_addr,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7200001000,
        .symbol_name = "puts",
        .wrapper_name = "wrapped_puts",
        .bridge_target = 0x7300002000,
    };
}

static kzt_patch_candidate_t approved_candidate(uintptr_t slot_addr)
{
    return (kzt_patch_candidate_t) {
        .source = {
            .known = 1,
            .link_map_addr = 0x7000001000,
            .map_start = 0x7000000000,
            .map_end = 0x7000008000,
            .generation = 42,
            .soname = "librequester.so",
            .path = "/guest/lib/librequester.so",
        },
        .dynamic_addr = 0x7000004000,
        .load_bias = 0x7000000000,
        .dynamic_view_generation = 43,
        .dynamic_view_available = 1,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 3,
        .entry_addr = 0x7000004180,
        .reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT,
        .slot_addr = slot_addr,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7200001000,
        .symbol_index = 77,
        .symbol_name = "gtk_widget_show",
        .version = "GTK_3.0",
        .current_owner = {
            .known = 1,
            .link_map_addr = 0x7200000000,
            .map_start = 0x7200000000,
            .map_end = 0x7200010000,
            .generation = 44,
            .soname = "libgtk-3.so",
            .path = "/guest/lib/libgtk-3.so",
        },
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
        .wrapper_name = "wrappedgtk3",
        .wrapper_symbol_version = "GTK_3.0",
        .bridge_target = 0x7300002000,
    };
}

static kzt_patch_spike_guard_t init_guard(int enabled, int write_enabled,
                                          unsigned long budget)
{
    kzt_patch_spike_config_t config = {
        .enabled = enabled,
        .write_enabled = write_enabled,
        .budget = budget,
    };
    kzt_patch_spike_guard_t guard;

    kzt_patch_spike_guard_init(&guard, &config);
    return guard;
}

static int fake_read_slot(uintptr_t slot_addr, uintptr_t *value, void *opaque)
{
    fake_slot_t *slot = opaque;

    if (!slot || !value || slot_addr != slot->slot_addr) {
        return -1;
    }

    ++slot->read_calls;
    if (slot->force_verify_mismatch && slot->read_calls > 1) {
        *value = slot->replacement_value + 8;
        return 0;
    }

    *value = slot->value;
    return 0;
}

static int fake_write_slot(uintptr_t slot_addr, uintptr_t value, void *opaque)
{
    fake_slot_t *slot = opaque;

    if (!slot || slot_addr != slot->slot_addr) {
        return -1;
    }
    ++slot->write_calls;
    if (value == slot->replacement_value && slot->fail_replacement_write) {
        return -1;
    }
    if (value == slot->previous_value && slot->fail_rollback_write) {
        return -1;
    }

    slot->value = value;
    return 0;
}

static kzt_patch_spike_slot_ops_t fake_slot_ops(fake_slot_t *slot)
{
    return (kzt_patch_spike_slot_ops_t) {
        .read_slot = fake_read_slot,
        .write_slot = fake_write_slot,
        .opaque = slot,
    };
}

static int trace_enabled(void)
{
    const char *value = getenv("KZT_PATCH_SPIKE_WRITER_TEST_TRACE");

    return value && value[0] && strcmp(value, "0") != 0;
}

static void trace_record(const char *tc,
                         const char *target,
                         const kzt_patch_decision_t *decision,
                         const kzt_patch_spike_record_t *record,
                         const fake_slot_t *slot)
{
    uintptr_t final_value = slot ? slot->value : 0;

    if (!trace_enabled() || !decision || !record) {
        return;
    }

    printf("KZT_SPIKE_TC tc=%s target=%s decision=%s reason=%s "
           "table=%s reloc=%s symbol=%s wrapper=%s result=%s failure=%s "
           "skip_legacy=%d writer_called=%d slot_addr=0x%lx "
           "expected=0x%lx replacement=0x%lx observed=0x%lx "
           "verified=0x%lx final=0x%lx rollback_called=%d "
           "writes_remaining=%lu\n",
           tc, target,
           kzt_patch_decision_kind_name(decision->kind),
           kzt_patch_reason_name(decision->reason),
           kzt_patch_table_kind_name(decision->table_kind),
           kzt_patch_relocation_type_name(decision->reloc_type),
           decision->symbol_name ? decision->symbol_name : "(none)",
           decision->wrapper_name ? decision->wrapper_name : "(none)",
           kzt_patch_spike_result_name(record->result),
           kzt_patch_spike_failure_name(record->failure),
           record->skip_legacy_write, record->writer_called,
           (unsigned long)decision->slot_addr,
           (unsigned long)decision->slot_current_value,
           (unsigned long)decision->bridge_target,
           (unsigned long)record->observed_value,
           (unsigned long)record->verified_value,
           (unsigned long)final_value,
           record->rollback_called,
           record->writes_remaining);
}

static void check_no_slot_calls(const char *name, const fake_slot_t *slot)
{
    char field[128];

    snprintf(field, sizeof(field), "%s.read", name);
    check_int(field, slot->read_calls, 0);
    snprintf(field, sizeof(field), "%s.write", name);
    check_int(field, slot->write_calls, 0);
}

static void test_planner_approved_jump_slot_drives_writer(void)
{
    kzt_patch_candidate_t candidate = approved_candidate(0x7100000018);
    kzt_patch_decision_t decision;
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 2);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = candidate.slot_addr,
        .value = candidate.slot_current_value,
        .replacement_value = candidate.bridge_target,
        .previous_value = candidate.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("planner-writer.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    check_int("planner-writer.kind", decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_int("planner-writer.reason", decision.reason,
              KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);
    check_int("planner-writer.allow", decision.allow_native_bridge, 1);
    check_int("planner-writer.reloc", decision.reloc_type,
              KZT_PATCH_RELOCATION_JUMP_SLOT);

    check_int("planner-writer.apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("planner-writer.result", record.result,
              KZT_PATCH_SPIKE_RESULT_APPLIED);
    check_int("planner-writer.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_NONE);
    check_int("planner-writer.skip", record.skip_legacy_write, 1);
    check_int("planner-writer.writer-called", record.writer_called, 1);
    check_uintptr("planner-writer.final", slot.value,
                  candidate.bridge_target);
    trace_record("TC1", "planner-approved-jump-slot", &decision, &record,
                 &slot);
}

static void test_success_write_and_verify_with_direct_slot_ops(void)
{
    uintptr_t slot = 0x7200001000;
    kzt_patch_decision_t decision = approved_decision((uintptr_t)&slot);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 1);
    kzt_patch_spike_record_t record;

    check_int("success.try-apply",
              kzt_patch_spike_writer_try_apply(&guard, &decision,
                                               &record), 0);
    check_uintptr("success.slot", slot, decision.bridge_target);
    check_int("success.result", record.result, KZT_PATCH_SPIKE_RESULT_APPLIED);
    check_int("success.failure", record.failure, KZT_PATCH_SPIKE_FAILURE_NONE);
    check_int("success.action", record.action,
              KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE);
    check_int("success.skip-legacy", record.skip_legacy_write, 1);
    check_ulong("success.remaining", record.writes_remaining, 0);
    check_int("success.writer-called", record.writer_called, 1);
    check_int("success.read", record.read_attempted, 1);
    check_int("success.expected-match", record.expected_current_matched, 1);
    check_int("success.write-attempt", record.write_attempted, 1);
    check_int("success.write-success", record.write_succeeded, 1);
    check_int("success.verify-attempt", record.verify_attempted, 1);
    check_int("success.verify-success", record.verify_succeeded, 1);
    check_int("success.rollback", record.rollback_called, 0);
    check_uintptr("success.previous", record.previous_value,
                  decision.slot_current_value);
    check_uintptr("success.observed", record.observed_value,
                  decision.slot_current_value);
    check_uintptr("success.verified", record.verified_value,
                  decision.bridge_target);
}

static void test_expected_current_mismatch_does_not_write(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value + 4,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value + 4,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("mismatch.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("mismatch.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("mismatch.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH);
    check_int("mismatch.read-calls", slot.read_calls, 1);
    check_int("mismatch.write-calls", slot.write_calls, 0);
    check_int("mismatch.write-attempt", record.write_attempted, 0);
    check_int("mismatch.expected-match", record.expected_current_matched, 0);
    check_uintptr("mismatch.observed", record.observed_value,
                  decision.slot_current_value + 4);
    trace_record("TC2", "expected-current-mismatch-fail-open", &decision,
                 &record, &slot);
}

static void test_guard_diagnostics_only_does_not_call_writer(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 0, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("diagnostics.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("diagnostics.result", record.result,
              KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY);
    check_int("diagnostics.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED);
    check_int("diagnostics.writer-called", record.writer_called, 0);
    check_no_slot_calls("diagnostics.slot", &slot);
    trace_record("TC3", "diagnostics-only-keeps-legacy", &decision, &record,
                 &slot);
}

static void test_write_failure_is_recorded(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
        .fail_replacement_write = 1,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("write-fail.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("write-fail.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("write-fail.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED);
    check_int("write-fail.read-calls", slot.read_calls, 1);
    check_int("write-fail.write-calls", slot.write_calls, 1);
    check_int("write-fail.write-attempt", record.write_attempted, 1);
    check_int("write-fail.write-success", record.write_succeeded, 0);
    check_uintptr("write-fail.slot", slot.value, decision.slot_current_value);
    trace_record("TC4", "write-failure-fail-open", &decision, &record,
                 &slot);
}

static void test_verify_failure_rolls_back_successfully(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
        .force_verify_mismatch = 1,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("verify-fail.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("verify-fail.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("verify-fail.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED);
    check_int("verify-fail.read-calls", slot.read_calls, 2);
    check_int("verify-fail.write-calls", slot.write_calls, 2);
    check_int("verify-fail.verify-attempt", record.verify_attempted, 1);
    check_int("verify-fail.verify-success", record.verify_succeeded, 0);
    check_int("verify-fail.rollback-called", record.rollback_called, 1);
    check_int("verify-fail.rollback-success", record.rollback_succeeded, 1);
    check_uintptr("verify-fail.rollback-value", record.rollback_value,
                  decision.slot_current_value);
    check_uintptr("verify-fail.slot", slot.value, decision.slot_current_value);
    trace_record("TC5", "verify-failure-rolls-back", &decision, &record,
                 &slot);
}

static void test_rollback_failure_is_observable(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
        .force_verify_mismatch = 1,
        .fail_rollback_write = 1,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    check_int("rollback-fail.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("rollback-fail.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("rollback-fail.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED);
    check_int("rollback-fail.rollback-called", record.rollback_called, 1);
    check_int("rollback-fail.rollback-success", record.rollback_succeeded, 0);
    check_int("rollback-fail.circuit",
              kzt_patch_spike_guard_circuit_open(&guard), 1);
    check_uintptr("rollback-fail.slot", slot.value, decision.bridge_target);
    trace_record("TC6", "rollback-failure-opens-circuit", &decision,
                 &record, &slot);
}

static void test_non_approved_decision_does_not_write(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    decision.kind = KZT_PATCH_DECISION_REJECTED;
    decision.reason = KZT_PATCH_REASON_POLICY_KEEP_GUEST;
    decision.allow_native_bridge = 0;
    check_int("rejected.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("rejected.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("rejected.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED);
    check_int("rejected.writer-called", record.writer_called, 0);
    check_no_slot_calls("rejected.slot", &slot);
}

static void test_approved_non_jump_slot_does_not_consume_guard_budget(void)
{
    kzt_patch_decision_t decision = approved_decision(0x7100000018);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_record_t record;
    fake_slot_t slot = {
        .slot_addr = decision.slot_addr,
        .value = decision.slot_current_value,
        .replacement_value = decision.bridge_target,
        .previous_value = decision.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t ops = fake_slot_ops(&slot);

    decision.table_kind = KZT_PATCH_TABLE_RELA;
    decision.reloc_type = KZT_PATCH_RELOCATION_GLOB_DAT;
    check_int("glob-dat.try-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &decision,
                                                             &ops,
                                                             &record), 0);
    check_int("glob-dat.result", record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("glob-dat.failure", record.failure,
              KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT);
    check_int("glob-dat.writer-called", record.writer_called, 0);
    check_ulong("glob-dat.remaining", record.writes_remaining, 8);
    check_no_slot_calls("glob-dat.slot", &slot);
}

static void test_persistent_guard_budget_blocks_second_write(void)
{
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 1);
    kzt_patch_decision_t first_decision = approved_decision(0x7100000018);
    kzt_patch_decision_t second_decision = approved_decision(0x7100000020);
    kzt_patch_spike_record_t first_record;
    kzt_patch_spike_record_t second_record;
    fake_slot_t first_slot = {
        .slot_addr = first_decision.slot_addr,
        .value = first_decision.slot_current_value,
        .replacement_value = first_decision.bridge_target,
        .previous_value = first_decision.slot_current_value,
    };
    fake_slot_t second_slot = {
        .slot_addr = second_decision.slot_addr,
        .value = second_decision.slot_current_value,
        .replacement_value = second_decision.bridge_target,
        .previous_value = second_decision.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t first_ops = fake_slot_ops(&first_slot);
    kzt_patch_spike_slot_ops_t second_ops = fake_slot_ops(&second_slot);

    check_int("persistent-budget.first-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &first_decision,
                                                             &first_ops,
                                                             &first_record), 0);
    check_int("persistent-budget.first-result", first_record.result,
              KZT_PATCH_SPIKE_RESULT_APPLIED);
    check_int("persistent-budget.first-skip", first_record.skip_legacy_write,
              1);
    check_uintptr("persistent-budget.first-slot", first_slot.value,
                  first_decision.bridge_target);

    check_int("persistent-budget.second-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &second_decision,
                                                             &second_ops,
                                                             &second_record), 0);
    check_int("persistent-budget.second-result", second_record.result,
              KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED);
    check_int("persistent-budget.second-failure", second_record.failure,
              KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED);
    check_int("persistent-budget.second-writer", second_record.writer_called,
              0);
    check_int("persistent-budget.second-skip", second_record.skip_legacy_write,
              0);
    check_ulong("persistent-budget.second-remaining",
                second_record.writes_remaining, 0);
    check_uintptr("persistent-budget.second-slot", second_slot.value,
                  second_decision.slot_current_value);
    check_no_slot_calls("persistent-budget.second-slot-calls", &second_slot);
    check_ulong("persistent-budget.attempts", guard.write_attempts, 1);
    check_ulong("persistent-budget.successes", guard.write_successes, 1);
    trace_record("TC7", "persistent-guard-budget-exhausted",
                 &second_decision, &second_record, &second_slot);
}

static void test_persistent_guard_circuit_blocks_second_write(void)
{
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_decision_t first_decision = approved_decision(0x7100000018);
    kzt_patch_decision_t second_decision = approved_decision(0x7100000020);
    kzt_patch_spike_record_t first_record;
    kzt_patch_spike_record_t second_record;
    fake_slot_t first_slot = {
        .slot_addr = first_decision.slot_addr,
        .value = first_decision.slot_current_value,
        .replacement_value = first_decision.bridge_target,
        .previous_value = first_decision.slot_current_value,
        .force_verify_mismatch = 1,
        .fail_rollback_write = 1,
    };
    fake_slot_t second_slot = {
        .slot_addr = second_decision.slot_addr,
        .value = second_decision.slot_current_value,
        .replacement_value = second_decision.bridge_target,
        .previous_value = second_decision.slot_current_value,
    };
    kzt_patch_spike_slot_ops_t first_ops = fake_slot_ops(&first_slot);
    kzt_patch_spike_slot_ops_t second_ops = fake_slot_ops(&second_slot);

    check_int("persistent-circuit.first-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &first_decision,
                                                             &first_ops,
                                                             &first_record), 0);
    check_int("persistent-circuit.first-result", first_record.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("persistent-circuit.first-failure", first_record.failure,
              KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED);
    check_int("persistent-circuit.first-rollback", first_record.rollback_called,
              1);
    check_int("persistent-circuit.open",
              kzt_patch_spike_guard_circuit_open(&guard), 1);
    check_uintptr("persistent-circuit.first-slot", first_slot.value,
                  first_decision.bridge_target);

    check_int("persistent-circuit.second-apply",
              kzt_patch_spike_writer_try_apply_with_slot_ops(&guard,
                                                             &second_decision,
                                                             &second_ops,
                                                             &second_record), 0);
    check_int("persistent-circuit.second-result", second_record.result,
              KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN);
    check_int("persistent-circuit.second-failure", second_record.failure,
              KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN);
    check_int("persistent-circuit.second-writer", second_record.writer_called,
              0);
    check_int("persistent-circuit.second-skip", second_record.skip_legacy_write,
              0);
    check_uintptr("persistent-circuit.second-slot", second_slot.value,
                  second_decision.slot_current_value);
    check_no_slot_calls("persistent-circuit.second-slot-calls", &second_slot);
    check_ulong("persistent-circuit.attempts", guard.write_attempts, 1);
    check_ulong("persistent-circuit.successes", guard.write_successes, 0);
}

static void test_record_fields_are_complete(void)
{
    uintptr_t slot = 0x7200001000;
    kzt_patch_decision_t decision = approved_decision((uintptr_t)&slot);
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 2);
    kzt_patch_spike_record_t record;

    check_int("record.try-apply",
              kzt_patch_spike_writer_try_apply(&guard, &decision,
                                               &record), 0);
    check_int("record.valid", record.valid, 1);
    check_int("record.kind", record.decision_kind, decision.kind);
    check_int("record.reason", record.decision_reason, decision.reason);
    check_int("record.allow", record.allow_native_bridge,
              decision.allow_native_bridge);
    check_int("record.table", record.table_kind, decision.table_kind);
    check_int("record.reloc", record.reloc_type, decision.reloc_type);
    check_ulong("record.entry-index", record.entry_index,
                decision.entry_index);
    check_uintptr("record.entry", record.entry_addr, decision.entry_addr);
    check_uintptr("record.slot", record.slot_addr, decision.slot_addr);
    check_int("record.expected-present", record.expected_value_present, 1);
    check_uintptr("record.expected", record.expected_value,
                  decision.slot_current_value);
    check_uintptr("record.replacement", record.replacement_value,
                  decision.bridge_target);
    check_ptr("record.symbol", record.symbol_name, decision.symbol_name);
    check_ptr("record.wrapper", record.wrapper_name, decision.wrapper_name);
    check_int("record.result", record.result, KZT_PATCH_SPIKE_RESULT_APPLIED);
    check_int("record.failure", record.failure, KZT_PATCH_SPIKE_FAILURE_NONE);
    check_int("record.action", record.action,
              KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE);
    check_ulong("record.remaining", record.writes_remaining, 1);
}

int main(void)
{
    test_planner_approved_jump_slot_drives_writer();
    test_success_write_and_verify_with_direct_slot_ops();
    test_expected_current_mismatch_does_not_write();
    test_guard_diagnostics_only_does_not_call_writer();
    test_write_failure_is_recorded();
    test_verify_failure_rolls_back_successfully();
    test_rollback_failure_is_observable();
    test_non_approved_decision_does_not_write();
    test_approved_non_jump_slot_does_not_consume_guard_budget();
    test_persistent_guard_budget_blocks_second_write();
    test_persistent_guard_circuit_blocks_second_write();
    test_record_fields_are_complete();

    if (failures) {
        fprintf(stderr, "kzt-patch-spike-writer: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-patch-spike-writer: all tests passed");
    return 0;
}
