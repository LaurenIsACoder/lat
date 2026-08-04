#ifndef KZT_PATCH_SPIKE_GUARD_H
#define KZT_PATCH_SPIKE_GUARD_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_patch_planner.h"

typedef enum kzt_patch_spike_action {
    KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY = 0,
    KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE,
    KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST,
    KZT_PATCH_SPIKE_ACTION_ROLLBACK_COMPLETE,
    KZT_PATCH_SPIKE_ACTION_TRANSACTION_UNRECOVERABLE,
} kzt_patch_spike_action_t;

typedef enum kzt_patch_spike_result {
    KZT_PATCH_SPIKE_RESULT_DISABLED = 0,
    KZT_PATCH_SPIKE_RESULT_DIAGNOSTICS_ONLY,
    KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED,
    KZT_PATCH_SPIKE_RESULT_APPLIED,
    KZT_PATCH_SPIKE_RESULT_FAIL_OPEN,
    KZT_PATCH_SPIKE_RESULT_GUEST_PRESERVED,
    KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN,
    KZT_PATCH_SPIKE_RESULT_ROLLED_BACK,
    KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE,
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
    KZT_PATCH_SPIKE_FAILURE_TRANSACTION_UNRECOVERABLE,
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

typedef enum kzt_patch_spike_cohort_kind {
    KZT_PATCH_SPIKE_COHORT_NONE = 0,
    KZT_PATCH_SPIKE_COHORT_X11_DISPLAY,
} kzt_patch_spike_cohort_kind_t;

typedef enum kzt_patch_spike_cohort_origin {
    KZT_PATCH_SPIKE_COHORT_ORIGIN_UNKNOWN = 0,
    KZT_PATCH_SPIKE_COHORT_ORIGIN_PLT_RELA,
    KZT_PATCH_SPIKE_COHORT_ORIGIN_DLSYM,
} kzt_patch_spike_cohort_origin_t;

typedef struct kzt_patch_spike_cohort_context {
    kzt_patch_spike_cohort_kind_t kind;
    kzt_patch_spike_cohort_origin_t origin;
    uintptr_t source_namespace_id;
    uintptr_t provider_namespace_id;
    int provider_wrapped;
} kzt_patch_spike_cohort_context_t;

typedef struct kzt_patch_spike_cohort_entry
    kzt_patch_spike_cohort_entry_t;

typedef struct kzt_patch_spike_guard {
    kzt_patch_spike_config_t config;
    unsigned long write_attempts;
    unsigned long write_successes;
    unsigned long reserved_writes;
    int circuit_open;
    int transaction_gate;
    int cohort_gate;
    kzt_patch_spike_cohort_entry_t *cohort_entries;
    size_t cohort_entry_count;
    size_t cohort_entry_capacity;
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
void kzt_patch_spike_guard_destroy(kzt_patch_spike_guard_t *guard);

int kzt_patch_spike_guard_should_plan(
    const kzt_patch_spike_guard_t *guard);
int kzt_patch_spike_guard_circuit_open(
    const kzt_patch_spike_guard_t *guard);
void kzt_patch_spike_guard_trip(kzt_patch_spike_guard_t *guard);
unsigned long kzt_patch_spike_guard_budget_remaining(
    const kzt_patch_spike_guard_t *guard);
int kzt_patch_spike_guard_reserve_writes(
    kzt_patch_spike_guard_t *guard, unsigned long count);
void kzt_patch_spike_guard_release_reserved_writes(
    kzt_patch_spike_guard_t *guard, unsigned long count);

int kzt_patch_spike_guard_try_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome);
int kzt_patch_spike_guard_try_reserved_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome);
int kzt_patch_spike_guard_try_cohort_write(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_cohort_context_t *cohort,
    const kzt_patch_spike_writer_ops_t *writer,
    kzt_patch_spike_outcome_t *outcome);
void kzt_patch_spike_guard_retire_identity(
    kzt_patch_spike_guard_t *guard, uintptr_t link_map_addr,
    unsigned long generation, uintptr_t namespace_id);

const char *kzt_patch_spike_result_name(kzt_patch_spike_result_t result);
const char *kzt_patch_spike_failure_name(kzt_patch_spike_failure_t failure);

#endif
