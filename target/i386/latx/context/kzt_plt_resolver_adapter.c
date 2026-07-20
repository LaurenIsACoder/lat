#ifndef KZT_PLT_RESOLVER_ADAPTER_TEST
#include "qemu/osdep.h"
#endif

#include "kzt_plt_resolver_adapter.h"

#include <string.h>

#ifndef KZT_PLT_RESOLVER_ADAPTER_TEST
#include "target/i386/cpu.h"
#endif

static void resolver_push64(CPUX86State *cpu, uintptr_t value)
{
    cpu->regs[R_ESP] -= sizeof(uint64_t);
    *(uint64_t *)cpu->regs[R_ESP] = value;
}

int kzt_plt_resolver_enter(
    CPUX86State *cpu, const kzt_plt_resolver_runtime_ops_t *ops,
    kzt_plt_resolver_enter_result_t *result)
{
    const uint64_t *frame;
    kzt_plt_resolver_source_t source;
    kzt_lazy_binding_begin_request_t request;
    kzt_lazy_binding_result_t begin_result;

    if (result) {
        memset(result, 0, sizeof(*result));
        result->status = KZT_PLT_RESOLVER_ERROR;
    }
    if (!cpu || !ops || !result || !ops->lookup_source ||
        !ops->begin_lazy_binding || !ops->pending || !cpu->regs[R_ESP]) {
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
    memset(&request, 0, sizeof(request));
    request.enabled = source.enabled;
    request.context_id = source.context_id;
    request.source_link_map = source.source_link_map;
    request.source_generation = source.source_generation;
    request.namespace_id = source.namespace_id;
    request.namespace_kind = source.namespace_kind;
    request.relocation_index = result->relocation_slot;
    request.slot_addr = source.slot_addr;
    request.unresolved_stub = source.unresolved_stub;
    request.symbol = source.symbol;
    request.version_evidence = source.version_evidence;
    request.version = source.version;
    request.addend = source.addend;
    request.guest_resolver = source.guest_resolver;
    memset(&begin_result, 0, sizeof(begin_result));
    if (ops->begin_lazy_binding(&request, ops->pending, &begin_result,
                                ops->opaque) != 0) {
        begin_result.status = KZT_LAZY_BINDING_GUEST_PRESERVED;
    }

    result->selected_resolver = source.guest_resolver;
    result->pending_armed = begin_result.pending_armed;
    if (begin_result.status == KZT_LAZY_BINDING_HANDOFF_GUEST) {
        result->status = KZT_PLT_RESOLVER_HANDOFF_GUEST;
        if (ops->completion_bridge && ops->original_return) {
            *ops->original_return = *(uintptr_t *)cpu->regs[R_ESP];
            *(uintptr_t *)cpu->regs[R_ESP] = ops->completion_bridge;
        }
    } else {
        result->status = KZT_PLT_RESOLVER_GUEST_PRESERVED;
    }
    resolver_push64(cpu, result->relocation_slot);
    resolver_push64(cpu, source.source_link_map);
    resolver_push64(cpu, source.guest_resolver);
    return 0;
}
