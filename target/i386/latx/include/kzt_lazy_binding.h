#ifndef KZT_LAZY_BINDING_H
#define KZT_LAZY_BINDING_H

#include <stdint.h>

#include "kzt_guest_library_binding.h"
#include "kzt_patch_planner.h"

#define KZT_LAZY_BINDING_SYMBOL_MAX 128
#define KZT_LAZY_BINDING_VERSION_MAX 128

typedef enum kzt_lazy_binding_status {
    KZT_LAZY_BINDING_BYPASS = 0,
    KZT_LAZY_BINDING_HANDOFF_GUEST,
    KZT_LAZY_BINDING_WAITING_GUEST_TARGET,
    KZT_LAZY_BINDING_GUEST_PRESERVED,
    KZT_LAZY_BINDING_NATIVE_APPLIED,
    KZT_LAZY_BINDING_CAS_MISMATCH,
    KZT_LAZY_BINDING_ERROR,
} kzt_lazy_binding_status_t;

typedef enum kzt_lazy_binding_reason {
    KZT_LAZY_BINDING_REASON_NONE = 0,
    KZT_LAZY_BINDING_REASON_DISABLED,
    KZT_LAZY_BINDING_REASON_INVALID_REQUEST,
    KZT_LAZY_BINDING_REASON_PENDING_OCCUPIED,
    KZT_LAZY_BINDING_REASON_GENERATION_CHANGED,
    KZT_LAZY_BINDING_REASON_NON_MAIN_NAMESPACE,
    KZT_LAZY_BINDING_REASON_RESOLVER_MISSING,
    KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED,
    KZT_LAZY_BINDING_REASON_MISSING_VERSION,
    KZT_LAZY_BINDING_REASON_POST_BIND_INVALID,
    KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE,
    KZT_LAZY_BINDING_REASON_NATIVE_APPLIED,
    KZT_LAZY_BINDING_REASON_CAS_MISMATCH,
    KZT_LAZY_BINDING_REASON_SLOT_READ_ERROR,
    KZT_LAZY_BINDING_REASON_CAS_ERROR,
} kzt_lazy_binding_reason_t;

#define KZT_LAZY_BINDING_REASON_PENDING_BUSY \
    KZT_LAZY_BINDING_REASON_PENDING_OCCUPIED

typedef struct kzt_lazy_binding_begin_request {
    int enabled;
    uintptr_t context_id;
    uintptr_t source_link_map;
    unsigned long source_generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
    unsigned long relocation_index;
    uintptr_t slot_addr;
    uintptr_t unresolved_stub;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    long addend;
    uintptr_t guest_resolver;
} kzt_lazy_binding_begin_request_t;

typedef struct kzt_lazy_binding_pending {
    int armed;
    uintptr_t context_id;
    uintptr_t source_link_map;
    unsigned long source_generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
    unsigned long relocation_index;
    uintptr_t slot_addr;
    uintptr_t unresolved_stub;
    uintptr_t guest_resolver;
    long addend;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    char symbol_storage[KZT_LAZY_BINDING_SYMBOL_MAX];
    char version_storage[KZT_LAZY_BINDING_VERSION_MAX];
} kzt_lazy_binding_pending_t;

typedef enum kzt_lazy_binding_route_status {
    KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED = 0,
    KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED,
    KZT_LAZY_BINDING_ROUTE_CAS_MISMATCH,
    KZT_LAZY_BINDING_ROUTE_ERROR,
} kzt_lazy_binding_route_status_t;

typedef struct kzt_lazy_binding_route_result {
    kzt_lazy_binding_route_status_t status;
    uintptr_t selected_target;
    uintptr_t final_value;
} kzt_lazy_binding_route_result_t;

typedef struct kzt_lazy_binding_ops {
    int (*load_slot)(uintptr_t slot_addr, uintptr_t *value, void *opaque);
    int (*validate_post_bind)(const kzt_lazy_binding_pending_t *pending,
                              uintptr_t guest_target, void *opaque);
    int (*route_guest_target)(const kzt_lazy_binding_pending_t *pending,
                              uintptr_t guest_target,
                              kzt_lazy_binding_route_result_t *result,
                              void *opaque);
    void *opaque;
} kzt_lazy_binding_ops_t;

typedef struct kzt_lazy_binding_result {
    kzt_lazy_binding_status_t status;
    kzt_lazy_binding_reason_t reason;
    uintptr_t slot_before;
    uintptr_t slot_after;
    uintptr_t selected_target;
    int pending_armed;
    int pending_cleared;
} kzt_lazy_binding_result_t;

int kzt_lazy_binding_begin(
    const kzt_lazy_binding_begin_request_t *request,
    kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result);

int kzt_lazy_binding_complete(
    kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_ops_t *ops,
    kzt_lazy_binding_result_t *result);

void kzt_lazy_binding_cancel(kzt_lazy_binding_pending_t *pending);

#endif
