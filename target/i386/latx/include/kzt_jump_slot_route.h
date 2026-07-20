#ifndef KZT_JUMP_SLOT_ROUTE_H
#define KZT_JUMP_SLOT_ROUTE_H

#include <stdint.h>

#include "kzt_guest_library_binding.h"
#include "kzt_patch_spike_writer.h"
#include "kzt_rela_immediate_candidate.h"

typedef enum kzt_jump_slot_route_writer_status {
    KZT_JUMP_SLOT_ROUTE_WRITER_DECLINED = 0,
    KZT_JUMP_SLOT_ROUTE_WRITER_APPLIED,
    KZT_JUMP_SLOT_ROUTE_WRITER_ERROR,
    KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE,
} kzt_jump_slot_route_writer_status_t;

typedef enum kzt_jump_slot_route_status {
    KZT_JUMP_SLOT_ROUTE_BYPASS = 0,
    KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED,
    KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED,
    KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED,
    KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH,
    KZT_JUMP_SLOT_ROUTE_WRITE_ERROR,
} kzt_jump_slot_route_status_t;

typedef int (*kzt_jump_slot_route_load_fn)(uintptr_t slot_addr,
                                            uintptr_t *value,
                                            void *opaque);
typedef int (*kzt_jump_slot_route_cas_fn)(uintptr_t slot_addr,
                                           uintptr_t *expected,
                                           uintptr_t replacement,
                                           void *opaque);

typedef struct kzt_jump_slot_route_ops {
    int (*enrich_base)(kzt_rela_immediate_candidate_request_t *request,
                       void *opaque);
    int (*acquire_exact_provider)(
        const kzt_patch_object_ref_t *owner, library_t *resolved_provider,
        kzt_guest_library_handle_t *handle, void *opaque);
    void (*release_exact_provider)(kzt_guest_library_handle_t *handle,
                                   void *opaque);
    int (*enrich_bridge)(kzt_rela_immediate_candidate_request_t *request,
                         library_t *held_provider, void *opaque);
    int (*validate_source_identity)(
        const kzt_rela_immediate_candidate_request_t *request,
        void *opaque);
    kzt_jump_slot_route_writer_status_t (*try_native_writer)(
        const kzt_rela_immediate_candidate_request_t *request,
        const kzt_patch_spike_slot_ops_t *slot_ops, void *opaque);
    kzt_jump_slot_route_load_fn load_slot;
    kzt_jump_slot_route_cas_fn compare_exchange_slot;
    kzt_patch_spike_slot_permission_begin_fn begin_slot_write;
    kzt_patch_spike_slot_permission_end_fn end_slot_write;
    kzt_patch_spike_slot_generation_validate_fn validate_write_generation;
    void *opaque;
} kzt_jump_slot_route_ops_t;

typedef struct kzt_jump_slot_route_input {
    int enabled;
    int preserve_observed_on_failure;
    int expected_guest_target_present;
    int resolved_target_matches_legacy;
    library_t *resolved_provider;
    kzt_rela_immediate_candidate_request_t request;
} kzt_jump_slot_route_input_t;

typedef struct kzt_jump_slot_route_result {
    kzt_jump_slot_route_status_t status;
    kzt_jump_slot_route_writer_status_t writer_status;
    uintptr_t observed_value;
    uintptr_t expected_guest_target;
    uintptr_t selected_target;
    uintptr_t final_value;
    int exact_provider_acquired;
    int exact_provider_matched;
    int native_writer_called;
    int source_identity_rechecked;
    int legacy_fallback_attempted;
} kzt_jump_slot_route_result_t;

int kzt_jump_slot_route_apply(const kzt_jump_slot_route_input_t *input,
                              const kzt_jump_slot_route_ops_t *ops,
                              kzt_jump_slot_route_result_t *result);

#endif
