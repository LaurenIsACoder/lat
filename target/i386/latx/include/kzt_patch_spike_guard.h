#ifndef KZT_PATCH_SPIKE_GUARD_H
#define KZT_PATCH_SPIKE_GUARD_H

#include <stdint.h>

#include "kzt_patch_planner.h"

typedef enum kzt_patch_spike_action {
    KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY = 0,
    KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE,
    KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST,
} kzt_patch_spike_action_t;

typedef enum kzt_patch_spike_result {
    KZT_PATCH_SPIKE_RESULT_DISABLED = 0,
    KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY,
    KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED,
    KZT_PATCH_SPIKE_RESULT_APPLIED,
    KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
    KZT_PATCH_SPIKE_RESULT_GUEST_PRESERVED,
    KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN,
} kzt_patch_spike_result_t;

typedef enum kzt_patch_spike_failure {
    KZT_PATCH_SPIKE_FAILURE_NONE = 0,
    KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT,
    KZT_PATCH_SPIKE_FAILURE_DECISION_NOT_APPROVED,
    KZT_PATCH_SPIKE_FAILURE_WRITE_NOT_AUTHORIZED,
    KZT_PATCH_SPIKE_FAILURE_BUDGET_EXHAUSTED,
    KZT_PATCH_SPIKE_FAILURE_EXPECTED_MISMATCH,
    KZT_PATCH_SPIKE_FAILURE_READ_FAILED,
    KZT_PATCH_SPIKE_FAILURE_WRITE_FAILED,
    KZT_PATCH_SPIKE_FAILURE_VERIFY_FAILED,
    KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED,
    KZT_PATCH_SPIKE_FAILURE_PERMISSION_ENABLE_FAILED,
    KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED,
    KZT_PATCH_SPIKE_FAILURE_GENERATION_MISMATCH,
    KZT_PATCH_SPIKE_FAILURE_CIRCUIT_BREAKER_OPEN,
} kzt_patch_spike_failure_t;

typedef enum kzt_patch_spike_writer_status {
    KZT_PATCH_SPIKE_WRITER_OK = 0,
    KZT_PATCH_SPIKE_WRITER_READ_FAILED,
    KZT_PATCH_SPIKE_WRITER_EXPECTED_MISMATCH,
    KZT_PATCH_SPIKE_WRITER_WRITE_FAILED,
    KZT_PATCH_SPIKE_WRITER_PERMISSION_ENABLE_FAILED,
    KZT_PATCH_SPIKE_WRITER_PERMISSION_RESTORE_FAILED,
    KZT_PATCH_SPIKE_WRITER_GENERATION_MISMATCH,
} kzt_patch_spike_writer_status_t;

typedef struct kzt_patch_spike_config {
    int enabled;
    int write_enabled;
    unsigned long budget;
} kzt_patch_spike_config_t;

typedef struct kzt_patch_spike_guard {
    kzt_patch_spike_config_t config;
    unsigned long write_attempts;
    unsigned long write_successes;
    int circuit_open;
    int transaction_gate;
} kzt_patch_spike_guard_t;

typedef struct kzt_patch_spike_outcome {
    kzt_patch_spike_result_t result;
    kzt_patch_spike_failure_t failure;
    kzt_patch_spike_action_t action;
    int skip_legacy_write;
    unsigned long writes_remaining;
    int writer_called;
    int rollback_called;
    uintptr_t previous_value;
} kzt_patch_spike_outcome_t;

typedef struct kzt_patch_spike_writer_ops {
    kzt_patch_spike_writer_status_t (*write_slot)(
        const kzt_patch_decision_t *decision,
        uintptr_t expected_value,
        uintptr_t replacement_value,
        uintptr_t *previous_value,
        void *opaque);
    int (*verify_slot)(const kzt_patch_decision_t *decision,
                       uintptr_t expected_value,
                       void *opaque);
    int (*rollback_slot)(const kzt_patch_decision_t *decision,
                         uintptr_t previous_value,
                         void *opaque);
    kzt_patch_spike_writer_status_t (*finish_slot)(
        const kzt_patch_decision_t *decision, void *opaque);
    void *opaque;
} kzt_patch_spike_writer_ops_t;

void kzt_patch_spike_config_from_options(kzt_patch_spike_config_t *config);
void kzt_patch_spike_guard_init(kzt_patch_spike_guard_t *guard,
                                const kzt_patch_spike_config_t *config);

int kzt_patch_spike_guard_should_plan(
    const kzt_patch_spike_guard_t *guard);
int kzt_patch_spike_guard_circuit_open(
    const kzt_patch_spike_guard_t *guard);
unsigned long kzt_patch_spike_guard_budget_remaining(
    const kzt_patch_spike_guard_t *guard);

int kzt_patch_spike_guard_try_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome);

const char *kzt_patch_spike_result_name(kzt_patch_spike_result_t result);
const char *kzt_patch_spike_failure_name(kzt_patch_spike_failure_t failure);

#endif
