#ifndef KZT_RUNTIME_CANDIDATE_SHADOW_H
#define KZT_RUNTIME_CANDIDATE_SHADOW_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_registry.h"
#include "kzt_owner_resolver.h"
#include "kzt_runtime_got_plt_candidate.h"
#include "kzt_wrapper_probe.h"

#define KZT_RUNTIME_CANDIDATE_SHADOW_DECISION_BUCKETS \
    ((size_t)KZT_PATCH_DECISION_APPROVED + 1)
#define KZT_RUNTIME_CANDIDATE_SHADOW_REASON_BUCKETS \
    ((size_t)KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE + 1)

typedef enum kzt_runtime_candidate_shadow_status {
    KZT_RUNTIME_CANDIDATE_SHADOW_OK = 0,
    KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN,
    KZT_RUNTIME_CANDIDATE_SHADOW_ERROR,
} kzt_runtime_candidate_shadow_status_t;

typedef enum kzt_runtime_candidate_shadow_reason {
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_NONE = 0,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_INVALID_ARGUMENT,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_FAIL_OPEN,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_ERROR,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_RECORD_CAPACITY_EXCEEDED,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_OBJECT_GENERATION_CHANGED,
    KZT_RUNTIME_CANDIDATE_SHADOW_REASON_PLANNER_ERROR,
} kzt_runtime_candidate_shadow_reason_t;

typedef int (*kzt_runtime_candidate_shadow_expected_target_fn)(
    const kzt_patch_candidate_t *candidate,
    uintptr_t *expected_guest_target,
    void *opaque);

typedef enum kzt_runtime_candidate_shadow_stub_classification {
    KZT_RUNTIME_CANDIDATE_SHADOW_STUB_NO_MATCH = 0,
    KZT_RUNTIME_CANDIDATE_SHADOW_STUB_MATCH,
    KZT_RUNTIME_CANDIDATE_SHADOW_STUB_UNKNOWN,
} kzt_runtime_candidate_shadow_stub_classification_t;

typedef kzt_runtime_candidate_shadow_stub_classification_t
(*kzt_runtime_candidate_shadow_stub_classifier_fn)(
    const kzt_patch_candidate_t *candidate,
    void *opaque);

/* Return zero only for one live object with one non-zero generation. */
typedef int (*kzt_runtime_candidate_shadow_generation_query_fn)(
    uintptr_t link_map_addr,
    unsigned long *generation,
    void *opaque);

typedef struct kzt_runtime_candidate_shadow_record {
    size_t candidate_index;
    kzt_owner_resolution_t owner_resolution;
    kzt_wrapper_probe_result_t wrapper_probe;
    kzt_patch_decision_t decision;
    /* Shadow records are audit-only and never consume a legacy target. */
    int audit_only;
    int legacy_target_consumed;
    int observe_only;
    /* Eligibility is audit output only; it never authorizes a write. */
    int eligible;
} kzt_runtime_candidate_shadow_record_t;

/*
 * Contract: E is used only for owner resolution, B only comes from a
 * side-effect-free bridge cache query, and the observed current slot is not
 * legacy target L.  This shadow API has no legacy_target input.
 */
typedef struct kzt_runtime_candidate_shadow_input {
    const kzt_runtime_got_plt_candidate_request_t *collector_request;
    kzt_guest_registry_t *registry;
    const kzt_wrapper_probe_manifest_t *wrapper_manifest;
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops;
    kzt_runtime_candidate_shadow_expected_target_fn
        resolve_expected_guest_target;
    void *expected_target_opaque;
    /* Missing or UNKNOWN stub evidence is always treated as non-stub. */
    kzt_runtime_candidate_shadow_stub_classifier_fn classify_stub;
    void *stub_classifier_opaque;
    kzt_runtime_candidate_shadow_generation_query_fn query_generation;
    void *generation_query_opaque;
    kzt_runtime_candidate_shadow_record_t *records;
    size_t record_capacity;
} kzt_runtime_candidate_shadow_input_t;

typedef struct kzt_runtime_candidate_shadow_result {
    kzt_runtime_candidate_shadow_status_t status;
    kzt_runtime_candidate_shadow_reason_t reason;
    kzt_runtime_got_plt_candidate_result_t collector_result;
    size_t candidate_count;
    size_t record_count;
    size_t eligible_count;
    size_t observe_only_count;
    size_t decision_histogram[
        KZT_RUNTIME_CANDIDATE_SHADOW_DECISION_BUCKETS];
    size_t reason_histogram[
        KZT_RUNTIME_CANDIDATE_SHADOW_REASON_BUCKETS];
} kzt_runtime_candidate_shadow_result_t;

int kzt_runtime_candidate_shadow_run(
    const kzt_runtime_candidate_shadow_input_t *input,
    kzt_runtime_candidate_shadow_result_t *result);

#endif
