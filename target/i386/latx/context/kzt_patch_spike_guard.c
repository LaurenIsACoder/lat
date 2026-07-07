#include "kzt_patch_spike_guard.h"

#include <string.h>

#if defined(CONFIG_LATX_KZT)
extern int option_kzt_patch_spike;
extern int option_kzt_patch_spike_write;
extern unsigned long option_kzt_patch_spike_budget;
#endif

static void kzt_patch_spike_outcome_set(
    kzt_patch_spike_outcome_t *outcome,
    kzt_patch_spike_result_t result,
    kzt_patch_spike_failure_t failure,
    kzt_patch_spike_action_t action,
    const kzt_patch_spike_guard_t *guard)
{
    outcome->result = result;
    outcome->failure = failure;
    outcome->action = action;
    outcome->skip_legacy_write =
        action == KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE;
    outcome->writes_remaining =
        kzt_patch_spike_guard_budget_remaining(guard);
}

static int kzt_patch_spike_writer_ready(
    const kzt_patch_spike_writer_ops_t *writer)
{
    return writer && writer->write_slot && writer->verify_slot &&
           writer->rollback_slot;
}

static kzt_patch_spike_failure_t kzt_patch_spike_writer_failure(
    kzt_patch_spike_writer_status_t status)
{
    switch (status) {
    case KZT_PATCH_SPIKE_WRITER_READ_FAILED:
        return KZT_PATCH_SPIKE_FAILURE_READ_FAILED;
    case KZT_PATCH_SPIKE_WRITER_EXPECTED_MISMATCH:
        return KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH;
    case KZT_PATCH_SPIKE_WRITER_WRITE_FAILED:
        return KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED;
    case KZT_PATCH_SPIKE_WRITER_OK:
        return KZT_PATCH_SPIKE_FAILURE_NONE;
    }

    return KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED;
}

void kzt_patch_spike_config_from_options(kzt_patch_spike_config_t *config)
{
    if (!config) {
        return;
    }

#if defined(CONFIG_LATX_KZT)
    config->enabled = option_kzt_patch_spike > 0;
    config->write_enabled = option_kzt_patch_spike_write > 0;
    config->budget = option_kzt_patch_spike_budget;
#else
    config->enabled = 0;
    config->write_enabled = 0;
    config->budget = 0;
#endif
}

void kzt_patch_spike_guard_init(kzt_patch_spike_guard_t *guard,
                                const kzt_patch_spike_config_t *config)
{
    if (!guard) {
        return;
    }

    memset(guard, 0, sizeof(*guard));
    if (config) {
        guard->config = *config;
    }
}

int kzt_patch_spike_guard_should_plan(
    const kzt_patch_spike_guard_t *guard)
{
    return guard && guard->config.enabled && !guard->circuit_open;
}

int kzt_patch_spike_guard_circuit_open(
    const kzt_patch_spike_guard_t *guard)
{
    return guard && guard->circuit_open;
}

unsigned long kzt_patch_spike_guard_budget_remaining(
    const kzt_patch_spike_guard_t *guard)
{
    if (!guard || guard->config.budget <= guard->write_attempts) {
        return 0;
    }

    return guard->config.budget - guard->write_attempts;
}

static int kzt_patch_spike_decision_allows_write(
    const kzt_patch_decision_t *decision)
{
    return decision && decision->kind == KZT_PATCH_DECISION_APPROVED &&
           decision->allow_native_bridge;
}

int kzt_patch_spike_guard_try_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome)
{
    kzt_patch_spike_writer_status_t writer_status;
    uintptr_t previous_value = 0;

    if (!guard || !outcome) {
        return -1;
    }

    memset(outcome, 0, sizeof(*outcome));
    outcome->action = KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY;
    outcome->writes_remaining =
        kzt_patch_spike_guard_budget_remaining(guard);

    if (guard->circuit_open) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN,
            KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (!guard->config.enabled) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_DISABLED,
            KZT_PATCH_SPIKE_FAILURE_NONE,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (!kzt_patch_spike_decision_allows_write(decision)) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (!guard->config.write_enabled) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY,
            KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (kzt_patch_spike_guard_budget_remaining(guard) == 0) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED,
            KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (!kzt_patch_spike_writer_ready(writer) ||
        !decision->slot_current_value_present) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    ++guard->write_attempts;
    outcome->writer_called = 1;
    outcome->writes_remaining =
        kzt_patch_spike_guard_budget_remaining(guard);

    writer_status = writer->write_slot(decision,
                                       decision->slot_current_value,
                                       decision->bridge_target,
                                       &previous_value,
                                       writer->opaque);
    outcome->previous_value = previous_value;
    if (writer_status != KZT_PATCH_SPIKE_WRITER_OK) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            kzt_patch_spike_writer_failure(writer_status),
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    if (writer->verify_slot(decision, decision->bridge_target,
                            writer->opaque) != 0) {
        outcome->rollback_called = 1;
        if (writer->rollback_slot(decision, previous_value,
                                  writer->opaque) != 0) {
            guard->circuit_open = 1;
            kzt_patch_spike_outcome_set(
                outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
                KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED,
                KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
            return 0;
        }

        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        return 0;
    }

    ++guard->write_successes;
    kzt_patch_spike_outcome_set(
        outcome, KZT_PATCH_SPIKE_RESULT_APPLIED,
        KZT_PATCH_SPIKE_FAILURE_NONE,
        KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE, guard);
    return 0;
}

const char *kzt_patch_spike_result_name(kzt_patch_spike_result_t result)
{
    switch (result) {
    case KZT_PATCH_SPIKE_RESULT_DISABLED:
        return "DISABLED";
    case KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY:
        return "DIAGNOSTICS_ONLY";
    case KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED:
        return "BUDGET_EXHAUSTED";
    case KZT_PATCH_SPIKE_RESULT_APPLIED:
        return "APPLIED";
    case KZT_PATCH_SPIKE_RESULT_FAIL_OPEN:
        return "FAIL_OPEN";
    case KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN:
        return "CIRCUIT_OPEN";
    }

    return "UNKNOWN";
}

const char *kzt_patch_spike_failure_name(kzt_patch_spike_failure_t failure)
{
    switch (failure) {
    case KZT_PATCH_SPIKE_FAILURE_NONE:
        return "NONE";
    case KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED:
        return "DECISION_NOT_APPROVED";
    case KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED:
        return "WRITE_NOT_AUTHORIZED";
    case KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED:
        return "BUDGET_EXHAUSTED";
    case KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH:
        return "EXPECTED_MISMATCH";
    case KZT_PATCH_SPIKE_FAILURE_READ_FAILED:
        return "READ_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED:
        return "WRITE_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED:
        return "VERIFY_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED:
        return "ROLLBACK_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN:
        return "CIRCUIT_BREAKER_OPEN";
    }

    return "UNKNOWN";
}
