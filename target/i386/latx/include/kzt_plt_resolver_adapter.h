#ifndef KZT_PLT_RESOLVER_ADAPTER_H
#define KZT_PLT_RESOLVER_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef KZT_PLT_RESOLVER_ADAPTER_TEST
typedef struct CPUX86State {
    uint64_t regs[16];
} CPUX86State;
#define R_ESP 4
#else
typedef struct CPUX86State CPUX86State;
#endif

typedef struct kzt_plt_resolver_source {
    uintptr_t source_link_map;
    uintptr_t guest_resolver;
} kzt_plt_resolver_source_t;

typedef struct kzt_plt_resolver_runtime_ops {
    int (*lookup_source)(uintptr_t object_head,
                         kzt_plt_resolver_source_t *source, void *opaque);
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
} kzt_plt_resolver_enter_result_t;

int kzt_plt_resolver_injection_allowed(
    uintptr_t guest_resolver, uintptr_t resolver_bridge);

int kzt_plt_resolver_relocation_index_valid(
    uint64_t relocation_index, uintptr_t relocation_table,
    size_t relocation_table_size, size_t relocation_entry_size);

int kzt_plt_resolver_symbol_index_valid(
    unsigned long symbol_index, uintptr_t symbol_table,
    size_t symbol_count);

int kzt_plt_resolver_enter(
    CPUX86State *cpu, const kzt_plt_resolver_runtime_ops_t *ops,
    kzt_plt_resolver_enter_result_t *result);

#endif
