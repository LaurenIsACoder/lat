#include "qemu/osdep.h"

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
        action != KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY;
    outcome->writes_remaining =
        kzt_patch_spike_guard_budget_remaining(guard);
}

static int kzt_patch_spike_writer_ready(
    const kzt_patch_spike_writer_ops_t *writer)
{
    return writer && writer->write_slot && writer->verify_slot &&
           writer->rollback_slot;
}

static void kzt_patch_spike_guard_lock(kzt_patch_spike_guard_t *guard)
{
    while (__atomic_exchange_n(&guard->transaction_gate, 1,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&guard->transaction_gate, __ATOMIC_RELAXED)) {
        }
    }
}

static void kzt_patch_spike_guard_unlock(kzt_patch_spike_guard_t *guard)
{
    __atomic_store_n(&guard->transaction_gate, 0, __ATOMIC_RELEASE);
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
    case KZT_PATCH_SPIKE_WRITER_PERMISSION_ENABLE_FAILED:
        return KZT_PATCH_SPIKE_FAILURE_PERMISSION_ENABLE_FAILED;
    case KZT_PATCH_SPIKE_WRITER_PERMISSION_RESTORE_FAILED:
        return KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED;
    case KZT_PATCH_SPIKE_WRITER_GENERATION_MISMATCH:
        return KZT_PATCH_SPIKE_FAILURE_GENERATION_MISMATCH;
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
    return guard && guard->config.enabled &&
           !__atomic_load_n(&guard->circuit_open, __ATOMIC_ACQUIRE);
}

int kzt_patch_spike_guard_circuit_open(
    const kzt_patch_spike_guard_t *guard)
{
    return guard && __atomic_load_n(&guard->circuit_open, __ATOMIC_ACQUIRE);
}

void kzt_patch_spike_guard_trip(kzt_patch_spike_guard_t *guard)
{
    if (guard) {
        __atomic_store_n(&guard->circuit_open, 1, __ATOMIC_RELEASE);
    }
}

unsigned long kzt_patch_spike_guard_budget_remaining(
    const kzt_patch_spike_guard_t *guard)
{
    unsigned long attempts;

    if (!guard) {
        return 0;
    }

    attempts = __atomic_load_n(&guard->write_attempts, __ATOMIC_ACQUIRE);
    if (guard->config.budget <= attempts) {
        return 0;
    }

    return guard->config.budget - attempts;
}

static int kzt_patch_spike_guard_reserve_budget(kzt_patch_spike_guard_t *guard)
{
    unsigned long attempts;
    attempts = __atomic_load_n(&guard->write_attempts, __ATOMIC_ACQUIRE);
    if (attempts >= guard->config.budget) {
        return 0;
    }
    __atomic_store_n(&guard->write_attempts, attempts + 1,
                     __ATOMIC_RELEASE);
    return 1;
}

static int kzt_patch_spike_failure_preserves_guest(
    kzt_patch_spike_failure_t failure)
{
    return failure == KZT_PATCH_SPIKE_FAILURE_PERMISSION_ENABLE_FAILED ||
           failure == KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED ||
           failure == KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED ||
           failure == KZT_PATCH_SPIKE_FAILURE_GENERATION_MISMATCH;
}

static int kzt_patch_spike_decision_allows_write(
    const kzt_patch_decision_t *decision)
{
    return decision && decision->kind == KZT_PATCH_DECISION_APPROVED &&
           decision->allow_native_bridge;
}

static int kzt_patch_spike_guard_try_write_internal(
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
    kzt_patch_spike_guard_lock(guard);
    outcome->writes_remaining =
        kzt_patch_spike_guard_budget_remaining(guard);

    if (__atomic_load_n(&guard->circuit_open, __ATOMIC_ACQUIRE)) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN,
            KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN,
            KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (!guard->config.enabled) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_DISABLED,
            KZT_PATCH_SPIKE_FAILURE_NONE,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (!kzt_patch_spike_decision_allows_write(decision)) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (!guard->config.write_enabled) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY,
            KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (!kzt_patch_spike_writer_ready(writer) ||
        !decision->slot_current_value_present) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (!kzt_patch_spike_guard_reserve_budget(guard)) {
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED,
            KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

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
        kzt_patch_spike_failure_t failure =
            kzt_patch_spike_writer_failure(writer_status);
        int preserve_guest = kzt_patch_spike_failure_preserves_guest(failure);

        if (failure == KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED) {
            if (writer->finish_slot &&
                writer->finish_slot(decision, writer->opaque) ==
                    KZT_PATCH_SPIKE_WRITER_OK) {
                kzt_patch_spike_outcome_set(
                    outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
                    KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED,
                    KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST, guard);
                kzt_patch_spike_guard_unlock(guard);
                return 0;
            }
            __atomic_store_n(&guard->circuit_open, 1, __ATOMIC_RELEASE);
            kzt_patch_spike_outcome_set(
                outcome, KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE,
                KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE,
                KZT_PATCH_SPIKE_ACTION_TRANSACTION_UNRECOVERABLE, guard);
            kzt_patch_spike_guard_unlock(guard);
            return 0;
        }
        kzt_patch_spike_outcome_set(
            outcome, preserve_guest ? KZT_PATCH_SPIKE_RESULT_GUEST_PRESERVED :
                                      KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            failure, preserve_guest ?
                     KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST :
                     KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (writer->verify_slot(decision, decision->bridge_target,
                            writer->opaque) != 0) {
        outcome->rollback_called = 1;
        if (writer->rollback_slot(decision, previous_value,
                                  writer->opaque) != 0) {
            if (writer->finish_slot &&
                writer->finish_slot(decision, writer->opaque) !=
                    KZT_PATCH_SPIKE_WRITER_OK) {
                (void)writer->finish_slot(decision, writer->opaque);
            }
            __atomic_store_n(&guard->circuit_open, 1, __ATOMIC_RELEASE);
            kzt_patch_spike_outcome_set(
                outcome, KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE,
                KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE,
                KZT_PATCH_SPIKE_ACTION_TRANSACTION_UNRECOVERABLE, guard);
            kzt_patch_spike_guard_unlock(guard);
            return 0;
        }

        if (writer->finish_slot &&
            writer->finish_slot(decision, writer->opaque) !=
                KZT_PATCH_SPIKE_WRITER_OK) {
            if (writer->finish_slot(decision, writer->opaque) !=
                KZT_PATCH_SPIKE_WRITER_OK) {
                __atomic_store_n(&guard->circuit_open, 1, __ATOMIC_RELEASE);
                kzt_patch_spike_outcome_set(
                    outcome, KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE,
                    KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE,
                    KZT_PATCH_SPIKE_ACTION_TRANSACTION_UNRECOVERABLE, guard);
                kzt_patch_spike_guard_unlock(guard);
                return 0;
            }
        }

        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
            KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED,
            KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    if (writer->finish_slot &&
        writer->finish_slot(decision, writer->opaque) !=
            KZT_PATCH_SPIKE_WRITER_OK) {
        int rollback_succeeded;
        int restore_succeeded;

        outcome->rollback_called = 1;
        rollback_succeeded = writer->rollback_slot(
            decision, previous_value, writer->opaque) == 0;
        restore_succeeded = writer->finish_slot(
            decision, writer->opaque) == KZT_PATCH_SPIKE_WRITER_OK;
        if (rollback_succeeded && restore_succeeded) {
            kzt_patch_spike_outcome_set(
                outcome, KZT_PATCH_SPIKE_RESULT_ROLLED_BACK,
                KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED,
                KZT_PATCH_SPIKE_ACTION_ROLLBACK_COMPLETE, guard);
            kzt_patch_spike_guard_unlock(guard);
            return 0;
        }
        __atomic_store_n(&guard->circuit_open, 1, __ATOMIC_RELEASE);
        kzt_patch_spike_outcome_set(
            outcome, KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE,
            KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE,
            KZT_PATCH_SPIKE_ACTION_TRANSACTION_UNRECOVERABLE, guard);
        kzt_patch_spike_guard_unlock(guard);
        return 0;
    }

    __atomic_add_fetch(&guard->write_successes, 1, __ATOMIC_ACQ_REL);
    kzt_patch_spike_outcome_set(
        outcome, KZT_PATCH_SPIKE_RESULT_APPLIED,
        KZT_PATCH_SPIKE_FAILURE_NONE,
        KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE, guard);
    kzt_patch_spike_guard_unlock(guard);
    return 0;
}

int kzt_patch_spike_guard_try_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome)
{
    return kzt_patch_spike_guard_try_write_internal(
        guard, decision, writer, outcome);
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
    case KZT_PATCH_SPIKE_RESULT_GUEST_PRESERVED:
        return "GUEST_PRESERVED";
    case KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN:
        return "CIRCUIT_OPEN";
    case KZT_PATCH_SPIKE_RESULT_ROLLED_BACK:
        return "ROLLED_BACK";
    case KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE:
        return "UNRECOVERABLE";
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
    case KZT_PATCH_SPIKE_FAILURE_PERMISSION_ENABLE_FAILED:
        return "PERMISSION_ENABLE_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED:
        return "PERMISSION_RESTORE_FAILED";
    case KZT_PATCH_SPIKE_FAILURE_GENERATION_MISMATCH:
        return "GENERATION_MISMATCH";
    case KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN:
        return "CIRCUIT_BREAKER_OPEN";
    case KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE:
        return "TRANSACTION_UNRECOVERABLE";
    }

    return "UNKNOWN";
}
