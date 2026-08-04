#include "kzt_per_object_got_plt.h"

#include <string.h>

static void kzt_per_object_got_plt_init_result(
    kzt_per_object_got_plt_result_t *result)
{
    if (result) {
        memset(result, 0, sizeof(*result));
        result->status = KZT_PER_OBJECT_GOT_PLT_FAIL_OPEN;
    }
}

int kzt_per_object_got_plt_apply(
    const kzt_per_object_got_plt_request_t *request,
    kzt_per_object_got_plt_result_t *result)
{
    kzt_guest_registry_address_match_t match = { 0 };
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t view_status;
    unsigned long view_generation = 0;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision_lease = { 0 };
    kzt_guest_got_plt_injection_claim_result_t claim;
    int applied = 0;

    kzt_per_object_got_plt_init_result(result);
    if (!request || !result || !request->registry ||
        !request->link_map_addr || !request->apply ||
        kzt_guest_registry_find_live_object(
            request->registry, request->link_map_addr, &match) != 0 ||
        match.match_count != 1 || !match.generation ||
        match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        match.namespace_id != 0 ||
        kzt_guest_registry_find_dynamic_view(
            request->registry, request->link_map_addr, &view, &view_status,
            &view_generation) != 0 ||
        view_status != KZT_GUEST_FIELD_OK ||
        view_generation != match.generation ||
        kzt_guest_registry_source_lease_acquire(
            request->registry, request->link_map_addr, match.generation, 0,
            &source_lease) != 0 ||
        kzt_guest_registry_patch_decision_lease_acquire(
            &source_lease, &decision_lease) != 0) {
        kzt_guest_registry_source_lease_release(&source_lease);
        return 0;
    }

    result->generation = match.generation;
    claim = kzt_guest_registry_got_plt_injection_claim(&decision_lease, &view);
    if (claim == KZT_GUEST_GOT_PLT_INJECTION_GRANTED) {
        result->write_attempted = 1;
        applied = request->apply(request->link_map_addr, match.generation,
                                 &view, request->opaque) == 0;
        if (kzt_guest_registry_got_plt_injection_finish(
                &decision_lease, applied) == 0 && applied) {
            result->status = KZT_PER_OBJECT_GOT_PLT_APPLIED;
        }
    } else if (claim == KZT_GUEST_GOT_PLT_INJECTION_IN_PROGRESS) {
        result->status = KZT_PER_OBJECT_GOT_PLT_IN_PROGRESS;
    } else if (claim == KZT_GUEST_GOT_PLT_INJECTION_ALREADY_APPLIED) {
        result->status = KZT_PER_OBJECT_GOT_PLT_ALREADY_APPLIED;
    }

    kzt_guest_registry_patch_decision_lease_release(&decision_lease);
    kzt_guest_registry_source_lease_release(&source_lease);
    return 0;
}
