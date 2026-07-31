#ifndef KZT_LAZY_DIRECT_ROUTE_H
#define KZT_LAZY_DIRECT_ROUTE_H

#include <stdint.h>

#include "kzt_guest_dynamic_view.h"
#include "kzt_guest_library_binding.h"
#include "kzt_patch_planner.h"

typedef enum kzt_lazy_direct_route_status {
    KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED = 0,
    KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED,
} kzt_lazy_direct_route_status_t;

typedef enum kzt_lazy_direct_route_reason {
    KZT_LAZY_DIRECT_ROUTE_REASON_NONE = 0,
    KZT_LAZY_DIRECT_ROUTE_REASON_DISABLED,
    KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_INPUT,
    KZT_LAZY_DIRECT_ROUTE_REASON_NON_MAIN_NAMESPACE,
    KZT_LAZY_DIRECT_ROUTE_REASON_INCOMPLETE_DYNAMIC_VIEW,
    KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_VERSION,
    KZT_LAZY_DIRECT_ROUTE_REASON_UNSUPPORTED_SYMBOL_BINDING,
    KZT_LAZY_DIRECT_ROUTE_REASON_GUEST_OWNED_SYMBOL,
    KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN,
    KZT_LAZY_DIRECT_ROUTE_REASON_SOURCE_REJECTED,
    KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE,
    KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_MISMATCH,
    KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_UNAVAILABLE,
    KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_VERSION_MISMATCH,
    KZT_LAZY_DIRECT_ROUTE_REASON_LEASE_UNAVAILABLE,
    KZT_LAZY_DIRECT_ROUTE_REASON_FINAL_VALIDATION_FAILED,
    KZT_LAZY_DIRECT_ROUTE_REASON_CAS_MISMATCH,
    KZT_LAZY_DIRECT_ROUTE_REASON_CAS_ERROR,
    KZT_LAZY_DIRECT_ROUTE_REASON_NATIVE_APPLIED,
} kzt_lazy_direct_route_reason_t;

typedef enum kzt_lazy_direct_route_cas_status {
    KZT_LAZY_DIRECT_ROUTE_CAS_ERROR = -1,
    KZT_LAZY_DIRECT_ROUTE_CAS_MISMATCH = 0,
    KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED = 1,
} kzt_lazy_direct_route_cas_status_t;

typedef struct kzt_lazy_direct_route_object {
    uintptr_t link_map_addr;
    unsigned long generation;
} kzt_lazy_direct_route_object_t;

typedef struct kzt_lazy_direct_route_input {
    int enabled;
    int preemption_safe;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
    kzt_lazy_direct_route_object_t source;
    kzt_lazy_direct_route_object_t provider;
    const kzt_guest_dynamic_view_t *source_dynamic_view;
    unsigned long source_dynamic_view_generation;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    uintptr_t slot_addr;
    uintptr_t guest_unresolved_slot;
    uintptr_t expected_current_slot;
} kzt_lazy_direct_route_input_t;

typedef struct kzt_lazy_direct_route_provider {
    void *handle;
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
} kzt_lazy_direct_route_provider_t;

typedef struct kzt_lazy_direct_route_bridge {
    uintptr_t target;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
} kzt_lazy_direct_route_bridge_t;

typedef struct kzt_lazy_direct_route_lease {
    void *handle;
    int active;
} kzt_lazy_direct_route_lease_t;

typedef struct kzt_lazy_direct_route_ops {
    int (*validate_source)(const kzt_lazy_direct_route_input_t *input,
                           void *opaque);
    int (*acquire_provider)(const kzt_lazy_direct_route_input_t *input,
                            kzt_lazy_direct_route_provider_t *provider,
                            void *opaque);
    void (*release_provider)(kzt_lazy_direct_route_provider_t *provider,
                             void *opaque);
    int (*find_wrapper_bridge)(
        const kzt_lazy_direct_route_input_t *input,
        const kzt_lazy_direct_route_provider_t *provider,
        kzt_lazy_direct_route_bridge_t *bridge,
        void *opaque);
    int (*acquire_decision_lease)(
        const kzt_lazy_direct_route_input_t *input,
        const kzt_lazy_direct_route_provider_t *provider,
        kzt_lazy_direct_route_lease_t *lease,
        void *opaque);
    void (*release_decision_lease)(kzt_lazy_direct_route_lease_t *lease,
                                   void *opaque);
    int (*validate_final)(
        const kzt_lazy_direct_route_input_t *input,
        const kzt_lazy_direct_route_provider_t *provider,
        const kzt_lazy_direct_route_bridge_t *bridge,
        const kzt_lazy_direct_route_lease_t *lease,
        void *opaque);
    kzt_lazy_direct_route_cas_status_t (*cas_slot)(
        uintptr_t slot_addr,
        uintptr_t expected,
        uintptr_t replacement,
        const kzt_lazy_direct_route_lease_t *lease,
        void *opaque);
    void *opaque;
} kzt_lazy_direct_route_ops_t;

typedef struct kzt_lazy_direct_route_result {
    kzt_lazy_direct_route_status_t status;
    kzt_lazy_direct_route_reason_t reason;
    uintptr_t selected_target;
} kzt_lazy_direct_route_result_t;

int kzt_lazy_direct_symbol_binding_supported(unsigned char st_info);

kzt_lazy_direct_route_status_t kzt_lazy_direct_route_apply(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_ops_t *ops,
    kzt_lazy_direct_route_result_t *result);

#endif
