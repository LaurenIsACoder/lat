#ifndef KZT_PLT_RESOLVER_ADAPTER_H
#define KZT_PLT_RESOLVER_ADAPTER_H

#include <stdint.h>

#include "kzt_lazy_binding.h"

#ifdef KZT_PLT_RESOLVER_ADAPTER_TEST
typedef struct CPUX86State {
    uint64_t regs[16];
} CPUX86State;
#define R_ESP 4
#else
typedef struct CPUX86State CPUX86State;
#endif

typedef struct kzt_plt_resolver_source {
    int enabled;
    uintptr_t context_id;
    uintptr_t object_head;
    uintptr_t source_link_map;
    unsigned long source_generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
    uintptr_t slot_addr;
    uintptr_t unresolved_stub;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    long addend;
    uintptr_t guest_resolver;
} kzt_plt_resolver_source_t;

typedef struct kzt_plt_resolver_runtime_ops {
    int (*lookup_source)(uintptr_t object_head,
                         kzt_plt_resolver_source_t *source, void *opaque);
    int (*begin_lazy_binding)(
        const kzt_lazy_binding_begin_request_t *request,
        kzt_lazy_binding_pending_t *pending,
        kzt_lazy_binding_result_t *result, void *opaque);
    kzt_lazy_binding_pending_t *pending;
    uintptr_t completion_bridge;
    uintptr_t *original_return;
    void *opaque;
} kzt_plt_resolver_runtime_ops_t;

typedef enum kzt_plt_resolver_enter_status {
    KZT_PLT_RESOLVER_ERROR = 0,
    KZT_PLT_RESOLVER_HANDOFF_GUEST,
    KZT_PLT_RESOLVER_GUEST_PRESERVED,
    KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED,
} kzt_plt_resolver_enter_status_t;

typedef struct kzt_plt_resolver_enter_result {
    kzt_plt_resolver_enter_status_t status;
    uintptr_t object_head;
    unsigned long relocation_slot;
    uintptr_t return_address;
    uintptr_t selected_resolver;
    int pending_armed;
} kzt_plt_resolver_enter_result_t;

int kzt_plt_resolver_enter(
    CPUX86State *cpu, const kzt_plt_resolver_runtime_ops_t *ops,
    kzt_plt_resolver_enter_result_t *result);

#endif
