#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_patch_spike_guard.h"

int option_kzt_patch_spike;
int option_kzt_patch_spike_write;
unsigned long option_kzt_patch_spike_budget;

typedef struct fake_writer {
    int read_calls;
    int write_calls;
    int verify_calls;
    int rollback_calls;
    int fail_read;
    int fail_write;
    int fail_verify;
    int fail_rollback;
    uintptr_t current_value;
    uintptr_t last_written_value;
} fake_writer_t;

static int failures;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

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

static void check_uintptr(const char *name, uintptr_t got,
                          uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static kzt_patch_decision_t approved_decision(void)
{
    return (kzt_patch_decision_t) {
        .kind = KZT_PATCH_DECISION_APPROVED,
        .reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
        .allow_native_bridge = 1,
        .slot_addr = 0x7100000018,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7200001000,
        .bridge_target = 0x7300002000,
    };
}

static kzt_patch_spike_writer_status_t fake_write_slot(
    const kzt_patch_decision_t *decision,
    uintptr_t expected_value,
    uintptr_t replacement_value,
    uintptr_t *previous_value,
    void *opaque)
{
    fake_writer_t *writer = opaque;

    (void)decision;
    ++writer->read_calls;
    if (writer->fail_read) {
        return KZT_PATCH_SPIKE_WRITER_READ_FAILED;
    }

    if (previous_value) {
        *previous_value = writer->current_value;
    }
    if (writer->current_value != expected_value) {
        return KZT_PATCH_SPIKE_WRITER_EXPECTED_MISMATCH;
    }

    ++writer->write_calls;
    writer->last_written_value = replacement_value;
    if (writer->fail_write) {
        return KZT_PATCH_SPIKE_WRITER_WRITE_FAILED;
    }

    writer->current_value = replacement_value;
    return KZT_PATCH_SPIKE_WRITER_OK;
}

static int fake_verify_slot(const kzt_patch_decision_t *decision,
                            uintptr_t expected_value,
                            void *opaque)
{
    fake_writer_t *writer = opaque;

    (void)decision;
    ++writer->verify_calls;
    if (writer->fail_verify) {
        return -1;
    }

    return writer->current_value == expected_value ? 0 : -1;
}

static int fake_rollback_slot(const kzt_patch_decision_t *decision,
                              uintptr_t previous_value,
                              void *opaque)
{
    fake_writer_t *writer = opaque;

    (void)decision;
    ++writer->rollback_calls;
    if (writer->fail_rollback) {
        return -1;
    }

    writer->current_value = previous_value;
    return 0;
}

static kzt_patch_spike_writer_ops_t writer_ops(fake_writer_t *writer)
{
    return (kzt_patch_spike_writer_ops_t) {
        .write_slot = fake_write_slot,
        .verify_slot = fake_verify_slot,
        .rollback_slot = fake_rollback_slot,
        .opaque = writer,
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

static void assert_no_writer_calls(const char *name,
                                   const fake_writer_t *writer)
{
    char field[128];

    snprintf(field, sizeof(field), "%s.read", name);
    check_int(field, writer->read_calls, 0);
    snprintf(field, sizeof(field), "%s.write", name);
    check_int(field, writer->write_calls, 0);
    snprintf(field, sizeof(field), "%s.verify", name);
    check_int(field, writer->verify_calls, 0);
    snprintf(field, sizeof(field), "%s.rollback", name);
    check_int(field, writer->rollback_calls, 0);
}

static void test_default_config_is_closed_and_noop(void)
{
    kzt_patch_spike_config_t config = { 1, 1, 1 };
    kzt_patch_spike_guard_t guard;
    kzt_patch_spike_outcome_t outcome;
    fake_writer_t writer = { 0 };
    int fake_planner_calls = 0;

    option_kzt_patch_spike = 0;
    option_kzt_patch_spike_write = 0;
    option_kzt_patch_spike_budget = 0;

    kzt_patch_spike_config_from_options(&config);
    check_int("default.enabled", config.enabled, 0);
    check_int("default.write-enabled", config.write_enabled, 0);
    check_ulong("default.budget", config.budget, 0);

    kzt_patch_spike_guard_init(&guard, &config);
    if (kzt_patch_spike_guard_should_plan(&guard)) {
        ++fake_planner_calls;
    }

    check_int("default.should-plan", fake_planner_calls, 0);
    check_int("default.try-write",
              kzt_patch_spike_guard_try_write(&guard, NULL, NULL,
                                              &outcome), 0);
    check_int("default.result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_DISABLED);
    check_int("default.action", outcome.action,
              KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY);
    check_int("default.skip-legacy", outcome.skip_legacy_write, 0);
    assert_no_writer_calls("default.writer", &writer);
}

static void test_diagnostics_only_never_writes(void)
{
    kzt_patch_decision_t decision = approved_decision();
    kzt_patch_spike_guard_t guard = init_guard(1, 0, 4);
    kzt_patch_spike_outcome_t outcome;
    fake_writer_t writer = {
        .current_value = decision.slot_current_value,
    };
    kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);

    check_int("diagnostics.should-plan",
              kzt_patch_spike_guard_should_plan(&guard), 1);
    check_int("diagnostics.try-write",
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    check_int("diagnostics.result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY);
    check_int("diagnostics.failure", outcome.failure,
              KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED);
    check_int("diagnostics.action", outcome.action,
              KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY);
    check_int("diagnostics.skip-legacy", outcome.skip_legacy_write, 0);
    assert_no_writer_calls("diagnostics.writer", &writer);
}

static void test_spike_on_without_write_or_budget_is_noop(void)
{
    kzt_patch_decision_t decision = approved_decision();
    kzt_patch_spike_outcome_t outcome;
    fake_writer_t writer = {
        .current_value = decision.slot_current_value,
    };
    kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);
    kzt_patch_spike_guard_t no_write = init_guard(1, 0, 1);
    kzt_patch_spike_guard_t no_budget = init_guard(1, 1, 0);

    check_int("no-write.try-write",
              kzt_patch_spike_guard_try_write(&no_write, &decision, &ops,
                                              &outcome), 0);
    check_int("no-write.result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY);
    check_int("no-write.skip-legacy", outcome.skip_legacy_write, 0);
    assert_no_writer_calls("no-write.writer", &writer);

    check_int("no-budget.try-write",
              kzt_patch_spike_guard_try_write(&no_budget, &decision, &ops,
                                              &outcome), 0);
    check_int("no-budget.result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED);
    check_int("no-budget.failure", outcome.failure,
              KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED);
    check_int("no-budget.skip-legacy", outcome.skip_legacy_write, 0);
    assert_no_writer_calls("no-budget.writer", &writer);
}

static void test_approved_budget_one_allows_one_write(void)
{
    kzt_patch_decision_t decision = approved_decision();
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 1);
    kzt_patch_spike_outcome_t outcome;
    fake_writer_t writer = {
        .current_value = decision.slot_current_value,
    };
    kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);

    check_int("budget-one.first",
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    check_int("budget-one.first-result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_APPLIED);
    check_int("budget-one.first-action", outcome.action,
              KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE);
    check_int("budget-one.skip-legacy", outcome.skip_legacy_write, 1);
    check_ulong("budget-one.remaining", outcome.writes_remaining, 0);
    check_int("budget-one.reads", writer.read_calls, 1);
    check_int("budget-one.writes", writer.write_calls, 1);
    check_int("budget-one.verifies", writer.verify_calls, 1);
    check_uintptr("budget-one.value", writer.current_value,
                  decision.bridge_target);
    check_uintptr("budget-one.previous", outcome.previous_value,
                  decision.slot_current_value);

    writer.current_value = decision.slot_current_value;
    check_int("budget-one.second",
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    check_int("budget-one.second-result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED);
    check_int("budget-one.second-skip-legacy", outcome.skip_legacy_write, 0);
    check_int("budget-one.reads-after", writer.read_calls, 1);
    check_int("budget-one.writes-after", writer.write_calls, 1);
}

static void test_non_approved_decisions_fail_open_without_writes(void)
{
    kzt_patch_decision_kind_t kinds[] = {
        KZT_PATCH_DECISION_REJECTED,
        KZT_PATCH_DECISION_UNSUPPORTED,
        KZT_PATCH_DECISION_DEFERRED,
        KZT_PATCH_DECISION_ERROR,
    };
    size_t i;

    for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
        kzt_patch_decision_t decision = approved_decision();
        kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
        kzt_patch_spike_outcome_t outcome;
        fake_writer_t writer = {
            .current_value = decision.slot_current_value,
        };
        kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);

        decision.kind = kinds[i];
        decision.allow_native_bridge = 0;
        check_int("blocked.try-write",
                  kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                                  &outcome), 0);
        check_int("blocked.result", outcome.result,
                  KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
        check_int("blocked.failure", outcome.failure,
                  KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED);
        check_int("blocked.action", outcome.action,
                  KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY);
        check_int("blocked.skip-legacy", outcome.skip_legacy_write, 0);
        assert_no_writer_calls("blocked.writer", &writer);
    }
}

static void run_fail_open_case(const char *name,
                               fake_writer_t writer,
                               kzt_patch_spike_failure_t expected_failure,
                               int expected_reads,
                               int expected_writes,
                               int expected_verifies,
                               int expected_rollbacks)
{
    kzt_patch_decision_t decision = approved_decision();
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_outcome_t outcome;
    kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);
    char field[128];

    check_int(name,
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    snprintf(field, sizeof(field), "%s.result", name);
    check_int(field, outcome.result, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    snprintf(field, sizeof(field), "%s.failure", name);
    check_int(field, outcome.failure, expected_failure);
    snprintf(field, sizeof(field), "%s.action", name);
    check_int(field, outcome.action, KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY);
    snprintf(field, sizeof(field), "%s.skip-legacy", name);
    check_int(field, outcome.skip_legacy_write, 0);
    snprintf(field, sizeof(field), "%s.reads", name);
    check_int(field, writer.read_calls, expected_reads);
    snprintf(field, sizeof(field), "%s.writes", name);
    check_int(field, writer.write_calls, expected_writes);
    snprintf(field, sizeof(field), "%s.verifies", name);
    check_int(field, writer.verify_calls, expected_verifies);
    snprintf(field, sizeof(field), "%s.rollbacks", name);
    check_int(field, writer.rollback_calls, expected_rollbacks);
    snprintf(field, sizeof(field), "%s.circuit", name);
    check_int(field, kzt_patch_spike_guard_circuit_open(&guard), 0);
}

static void test_writer_failures_fail_open(void)
{
    kzt_patch_decision_t decision = approved_decision();

    run_fail_open_case("read-failure", (fake_writer_t) {
        .current_value = decision.slot_current_value,
        .fail_read = 1,
    }, KZT_PATCH_SPIKE_FAILURE_READ_FAILED, 1, 0, 0, 0);

    run_fail_open_case("expected-mismatch", (fake_writer_t) {
        .current_value = decision.slot_current_value + 8,
    }, KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH, 1, 0, 0, 0);

    run_fail_open_case("write-failure", (fake_writer_t) {
        .current_value = decision.slot_current_value,
        .fail_write = 1,
    }, KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED, 1, 1, 0, 0);

    run_fail_open_case("verify-failure", (fake_writer_t) {
        .current_value = decision.slot_current_value,
        .fail_verify = 1,
    }, KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED, 1, 1, 1, 1);
}

static void test_rollback_failure_opens_circuit_breaker(void)
{
    kzt_patch_decision_t decision = approved_decision();
    kzt_patch_spike_guard_t guard = init_guard(1, 1, 8);
    kzt_patch_spike_outcome_t outcome;
    fake_writer_t writer = {
        .current_value = decision.slot_current_value,
        .fail_verify = 1,
        .fail_rollback = 1,
    };
    kzt_patch_spike_writer_ops_t ops = writer_ops(&writer);

    check_int("rollback-failure.first",
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    check_int("rollback-failure.result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_FAIL_OPEN);
    check_int("rollback-failure.failure", outcome.failure,
              KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED);
    check_int("rollback-failure.rollback-called", outcome.rollback_called, 1);
    check_int("rollback-failure.skip-legacy", outcome.skip_legacy_write, 0);
    check_int("rollback-failure.circuit-open",
              kzt_patch_spike_guard_circuit_open(&guard), 1);

    writer.fail_verify = 0;
    writer.fail_rollback = 0;
    writer.current_value = decision.slot_current_value;
    check_int("rollback-failure.second",
              kzt_patch_spike_guard_try_write(&guard, &decision, &ops,
                                              &outcome), 0);
    check_int("rollback-failure.second-result", outcome.result,
              KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN);
    check_int("rollback-failure.second-failure", outcome.failure,
              KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN);
    check_int("rollback-failure.second-skip-legacy",
              outcome.skip_legacy_write, 0);
    check_int("rollback-failure.reads-after", writer.read_calls, 1);
    check_int("rollback-failure.writes-after", writer.write_calls, 1);
}

int main(void)
{
    test_default_config_is_closed_and_noop();
    test_diagnostics_only_never_writes();
    test_spike_on_without_write_or_budget_is_noop();
    test_approved_budget_one_allows_one_write();
    test_non_approved_decisions_fail_open_without_writes();
    test_writer_failures_fail_open();
    test_rollback_failure_opens_circuit_breaker();

    check_true("name.result", strcmp(kzt_patch_spike_result_name(
                   KZT_PATCH_SPIKE_RESULT_APPLIED), "APPLIED") == 0);
    check_true("name.failure", strcmp(kzt_patch_spike_failure_name(
                   KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED),
                   "ROLLBACK_FAILED") == 0);

    if (failures) {
        fprintf(stderr, "kzt-patch-spike-guard: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-patch-spike-guard: all tests passed");
    return 0;
}
