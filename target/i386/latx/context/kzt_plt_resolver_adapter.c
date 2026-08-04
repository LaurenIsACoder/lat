#ifndef KZT_PLT_RESOLVER_ADAPTER_TEST
#include "qemu/osdep.h"
#endif

#include "kzt_plt_resolver_adapter.h"

#include <limits.h>
#include <string.h>

#ifndef KZT_PLT_RESOLVER_ADAPTER_TEST
#include "target/i386/cpu.h"
#endif

static void resolver_push64(CPUX86State *cpu, uintptr_t value)
{
    cpu->regs[R_ESP] -= sizeof(uint64_t);
    *(uint64_t *)cpu->regs[R_ESP] = value;
}

int kzt_plt_resolver_injection_allowed(
    uintptr_t guest_resolver, uintptr_t resolver_bridge)
{
    return guest_resolver && resolver_bridge &&
           guest_resolver != resolver_bridge;
}

int kzt_plt_resolver_relocation_index_valid(
    uint64_t relocation_index, uintptr_t relocation_table,
    size_t relocation_table_size, size_t relocation_entry_size)
{
    return relocation_table && relocation_entry_size &&
           relocation_table_size >= relocation_entry_size &&
           relocation_table_size % relocation_entry_size == 0 &&
           relocation_index <= INT_MAX &&
           relocation_index <
               relocation_table_size / relocation_entry_size;
}

int kzt_plt_resolver_symbol_index_valid(
    unsigned long symbol_index, uintptr_t symbol_table,
    size_t symbol_count)
{
    return symbol_table && symbol_count && symbol_index < symbol_count;
}

int kzt_plt_resolver_enter(
    CPUX86State *cpu, const kzt_plt_resolver_runtime_ops_t *ops,
    kzt_plt_resolver_enter_result_t *result)
{
    const uint64_t *frame;
    kzt_plt_resolver_source_t source;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->status = KZT_PLT_RESOLVER_ERROR;
    }
    if (!cpu || !ops || !result || !ops->lookup_source ||
        !cpu->regs[R_ESP]) {
        return -1;
    }

    frame = (const uint64_t *)cpu->regs[R_ESP];
    result->object_head = frame[0];
    result->relocation_slot = frame[1];
    result->return_address = frame[2];
    memset(&source, 0, sizeof(source));
    if (ops->lookup_source(result->object_head, &source, ops->opaque) != 0 ||
        !source.guest_resolver || !source.source_link_map) {
        result->status = KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED;
        return 0;
    }

    cpu->regs[R_ESP] += 2 * sizeof(uint64_t);
    result->selected_resolver = source.guest_resolver;
    result->status = KZT_PLT_RESOLVER_HANDOFF_GUEST;
    resolver_push64(cpu, result->relocation_slot);
    resolver_push64(cpu, source.source_link_map);
    resolver_push64(cpu, source.guest_resolver);
    return 0;
}
