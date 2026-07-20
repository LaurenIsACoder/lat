#include "kzt_lazy_binding.h"

#include <string.h>

static void lazy_result_init(kzt_lazy_binding_result_t *result)
{
    if (!result) {
        return;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_BINDING_ERROR;
    result->reason = KZT_LAZY_BINDING_REASON_INVALID_REQUEST;
}

static int lazy_copy_text(char *dst, size_t size, const char *src,
                          const char **stored)
{
    size_t length;

    if (stored) {
        *stored = NULL;
    }
    if (!dst || !size || !stored) {
        return -1;
    }
    if (!src || !src[0]) {
        return 0;
    }
    length = strlen(src);
    if (length >= size) {
        return -1;
    }
    memcpy(dst, src, length + 1);
    *stored = dst;
    return 0;
}

static void lazy_consume(kzt_lazy_binding_pending_t *pending,
                         kzt_lazy_binding_result_t *result)
{
    if (pending) {
        memset(pending, 0, sizeof(*pending));
    }
    if (result) {
        result->pending_armed = 0;
        result->pending_cleared = 1;
    }
}

int kzt_lazy_binding_begin(
    const kzt_lazy_binding_begin_request_t *request,
    kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result)
{
    kzt_lazy_binding_pending_t candidate;

    lazy_result_init(result);
    if (!request || !pending || !result) {
        return -1;
    }
    result->selected_target = request->guest_resolver;
    result->slot_before = request->unresolved_stub;
    result->slot_after = request->unresolved_stub;
    if (!request->enabled) {
        result->status = KZT_LAZY_BINDING_BYPASS;
        result->reason = KZT_LAZY_BINDING_REASON_DISABLED;
        return 0;
    }
    /* Nested resolvers share a context.  A pending owned by another context
     * cannot complete this request and must not block its fail-open path. */
    if (pending->armed && pending->context_id == request->context_id) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_PENDING_BUSY;
        return 0;
    }
    if (request->namespace_kind != KZT_GUEST_LIBRARY_NAMESPACE_MAIN ||
        request->namespace_id != 0) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_NON_MAIN_NAMESPACE;
        return 0;
    }
    if (!request->context_id || !request->source_link_map ||
        !request->source_generation || !request->slot_addr ||
        !request->unresolved_stub || !request->guest_resolver) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = request->guest_resolver ?
            KZT_LAZY_BINDING_REASON_INVALID_REQUEST :
            KZT_LAZY_BINDING_REASON_RESOLVER_MISSING;
        return 0;
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.context_id = request->context_id;
    candidate.source_link_map = request->source_link_map;
    candidate.source_generation = request->source_generation;
    candidate.namespace_id = request->namespace_id;
    candidate.namespace_kind = request->namespace_kind;
    candidate.relocation_index = request->relocation_index;
    candidate.slot_addr = request->slot_addr;
    candidate.unresolved_stub = request->unresolved_stub;
    candidate.guest_resolver = request->guest_resolver;
    candidate.addend = request->addend;
    candidate.version_evidence = request->version_evidence;
    if (lazy_copy_text(candidate.symbol_storage,
                       sizeof(candidate.symbol_storage), request->symbol,
                       &candidate.symbol) != 0 ||
        lazy_copy_text(candidate.version_storage,
                       sizeof(candidate.version_storage), request->version,
                       &candidate.version) != 0) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_INVALID_REQUEST;
        return 0;
    }
    candidate.armed = 1;
    *pending = candidate;
    /* Repair the pointers after the structure copy. */
    pending->symbol = candidate.symbol ? pending->symbol_storage : NULL;
    pending->version = candidate.version ? pending->version_storage : NULL;
    result->status = KZT_LAZY_BINDING_HANDOFF_GUEST;
    result->reason = KZT_LAZY_BINDING_REASON_NONE;
    result->pending_armed = 1;
    return 0;
}

int kzt_lazy_binding_complete(
    kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_ops_t *ops,
    kzt_lazy_binding_result_t *result)
{
    uintptr_t guest_target = 0;
    kzt_lazy_binding_route_result_t route_result;

    lazy_result_init(result);
    if (!pending || !ops || !result || !pending->armed || !ops->load_slot) {
        return -1;
    }
    if (ops->load_slot(pending->slot_addr, &guest_target, ops->opaque) != 0) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_SLOT_READ_ERROR;
        lazy_consume(pending, result);
        return 0;
    }
    result->slot_before = guest_target;
    result->slot_after = guest_target;
    result->selected_target = guest_target;
    if (guest_target == pending->unresolved_stub) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED;
        lazy_consume(pending, result);
        return 0;
    }
    if (!kzt_symbol_version_evidence_valid(pending->version_evidence,
                                           pending->version)) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_MISSING_VERSION;
        lazy_consume(pending, result);
        return 0;
    }
    if (!ops->validate_post_bind ||
        ops->validate_post_bind(pending, guest_target, ops->opaque) <= 0) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_POST_BIND_INVALID;
        lazy_consume(pending, result);
        return 0;
    }
    if (!ops->route_guest_target) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE;
        lazy_consume(pending, result);
        return 0;
    }
    memset(&route_result, 0, sizeof(route_result));
    if (ops->route_guest_target(pending, guest_target, &route_result,
                                ops->opaque) != 0 ||
        route_result.status == KZT_LAZY_BINDING_ROUTE_ERROR) {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE;
    } else if (route_result.status == KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED) {
        result->status = KZT_LAZY_BINDING_NATIVE_APPLIED;
        result->reason = KZT_LAZY_BINDING_REASON_NATIVE_APPLIED;
    } else if (route_result.status == KZT_LAZY_BINDING_ROUTE_CAS_MISMATCH) {
        result->status = KZT_LAZY_BINDING_CAS_MISMATCH;
        result->reason = KZT_LAZY_BINDING_REASON_CAS_MISMATCH;
    } else {
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE;
    }
    result->selected_target = route_result.selected_target ?
        route_result.selected_target : guest_target;
    result->slot_after = route_result.final_value ?
        route_result.final_value : guest_target;
    lazy_consume(pending, result);
    return 0;
}

void kzt_lazy_binding_cancel(kzt_lazy_binding_pending_t *pending)
{
    if (pending) {
        memset(pending, 0, sizeof(*pending));
    }
}
