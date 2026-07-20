#include "kzt_jump_slot_route.h"

#include <string.h>

typedef struct kzt_jump_slot_route_slot_state {
    const kzt_jump_slot_route_ops_t *ops;
    uintptr_t last_read;
    uintptr_t committed_value;
    int last_read_present;
    int write_succeeded;
    int cas_mismatch;
} kzt_jump_slot_route_slot_state_t;

static int route_slot_read(uintptr_t slot_addr, uintptr_t *value, void *opaque)
{
    kzt_jump_slot_route_slot_state_t *state = opaque;

    if (!state || !state->ops || !state->ops->load_slot || !value ||
        state->ops->load_slot(slot_addr, value, state->ops->opaque) != 0) {
        return -1;
    }
    state->last_read = *value;
    state->last_read_present = 1;
    return 0;
}

static int route_slot_write(uintptr_t slot_addr, uintptr_t value, void *opaque)
{
    kzt_jump_slot_route_slot_state_t *state = opaque;
    uintptr_t expected;
    int exchanged;

    if (!state || !state->ops || !state->ops->compare_exchange_slot ||
        !state->last_read_present) {
        return -1;
    }
    expected = state->write_succeeded ? state->committed_value :
                                        state->last_read;
    exchanged = state->ops->compare_exchange_slot(
        slot_addr, &expected, value, state->ops->opaque);
    if (exchanged > 0) {
        state->last_read = value;
        state->committed_value = value;
        state->write_succeeded = 1;
    } else {
        state->last_read = expected;
        state->cas_mismatch = exchanged == 0;
    }
    return exchanged > 0 ? 0 : -1;
}

static int route_slot_begin_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease,
    void *opaque)
{
    kzt_jump_slot_route_slot_state_t *state = opaque;

    if (!state || !state->ops || !state->ops->begin_slot_write) {
        return -1;
    }
    return state->ops->begin_slot_write(slot_addr, lease, state->ops->opaque);
}

static int route_slot_end_write(kzt_patch_spike_permission_lease_t *lease,
                                void *opaque)
{
    kzt_jump_slot_route_slot_state_t *state = opaque;

    if (!state || !state->ops || !state->ops->end_slot_write) {
        return -1;
    }
    return state->ops->end_slot_write(lease, state->ops->opaque);
}

static int route_slot_validate_generation(const kzt_patch_decision_t *decision,
                                          void *opaque)
{
    kzt_jump_slot_route_slot_state_t *state = opaque;

    if (!state || !state->ops || !state->ops->validate_write_generation) {
        return -1;
    }
    return state->ops->validate_write_generation(decision, state->ops->opaque);
}

static int route_has_owner_evidence(
    const kzt_rela_immediate_candidate_request_t *request)
{
    return request && request->owner_match == KZT_PATCH_OWNER_MATCH &&
           request->current_owner.known &&
           request->current_owner.link_map_addr &&
           request->current_owner.generation;
}

static int route_owner_identity_matches(
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_patch_object_ref_t *acquired_owner)
{
    return route_has_owner_evidence(request) && acquired_owner &&
           request->current_owner.link_map_addr ==
               acquired_owner->link_map_addr &&
           request->current_owner.generation == acquired_owner->generation;
}

static int route_legacy_fallback(
    const kzt_jump_slot_route_input_t *input,
    const kzt_jump_slot_route_ops_t *ops,
    kzt_jump_slot_route_result_t *result)
{
    uintptr_t expected = result->observed_value;
    int exchanged;

    if (input->preserve_observed_on_failure) {
        result->status = KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED;
        result->selected_target = result->observed_value;
        result->final_value = result->observed_value;
        return 0;
    }

    result->legacy_fallback_attempted = 1;
    result->selected_target = input->request.legacy_target;
    exchanged = ops->compare_exchange_slot(
        input->request.slot_addr, &expected, input->request.legacy_target,
        ops->opaque);
    if (exchanged < 0) {
        result->status = KZT_JUMP_SLOT_ROUTE_WRITE_ERROR;
        result->final_value = expected;
        return 0;
    }
    if (exchanged == 0) {
        result->status = KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH;
        result->final_value = expected;
        return 0;
    }
    result->status = KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED;
    result->final_value = input->request.legacy_target;
    return 0;
}

int kzt_jump_slot_route_apply(const kzt_jump_slot_route_input_t *input,
                              const kzt_jump_slot_route_ops_t *ops,
                              kzt_jump_slot_route_result_t *result)
{
    kzt_rela_immediate_candidate_request_t request;
    kzt_patch_object_ref_t acquired_owner;
    kzt_guest_library_handle_t handle;
    kzt_jump_slot_route_slot_state_t slot_state;
    kzt_patch_spike_slot_ops_t slot_ops;
    int acquired = 0;

    if (!result) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_JUMP_SLOT_ROUTE_WRITE_ERROR;
    if (!input || !ops || !ops->load_slot ||
        !ops->compare_exchange_slot || !input->request.slot_addr) {
        return -1;
    }
    result->expected_guest_target = input->request.expected_guest_target;
    if (!input->enabled) {
        result->status = KZT_JUMP_SLOT_ROUTE_BYPASS;
        return 0;
    }
    if (ops->load_slot(input->request.slot_addr, &result->observed_value,
                       ops->opaque) != 0) {
        return 0;
    }
    if (input->request.slot_current_value_present &&
        result->observed_value != input->request.slot_current_value) {
        result->status = KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH;
        result->final_value = result->observed_value;
        return 0;
    }

    request = input->request;
    request.slot_current_value_present = 1;
    request.slot_current_value = result->observed_value;
    memset(&handle, 0, sizeof(handle));
    memset(&acquired_owner, 0, sizeof(acquired_owner));
    memset(&slot_state, 0, sizeof(slot_state));

    if (input->resolved_target_matches_legacy &&
        input->expected_guest_target_present &&
        request.expected_guest_target && input->resolved_provider &&
        ops->enrich_base && ops->acquire_exact_provider &&
        ops->release_exact_provider && ops->enrich_bridge &&
        ops->try_native_writer &&
        ops->enrich_base(&request, ops->opaque) == 0 &&
        route_has_owner_evidence(&request)) {
        acquired_owner = request.current_owner;
        if (ops->acquire_exact_provider(&acquired_owner,
                                        input->resolved_provider, &handle,
                                        ops->opaque) == 0) {
            acquired = 1;
            result->exact_provider_acquired = 1;
            if (handle.library == input->resolved_provider) {
                result->exact_provider_matched = 1;
                if (ops->enrich_bridge(&request, handle.library,
                                       ops->opaque) == 0 &&
                    route_owner_identity_matches(&request,
                                                 &acquired_owner) &&
                    (!ops->validate_source_identity ||
                     (result->source_identity_rechecked = 1,
                      ops->validate_source_identity(&request,
                                                    ops->opaque) > 0))) {
                    slot_state = (kzt_jump_slot_route_slot_state_t){
                        .ops = ops,
                    };
                    slot_ops = (kzt_patch_spike_slot_ops_t){
                        .read_slot = route_slot_read,
                        .write_slot = route_slot_write,
                        .begin_write = route_slot_begin_write,
                        .end_write = route_slot_end_write,
                        .validate_generation = route_slot_validate_generation,
                        .opaque = &slot_state,
                    };
                    result->native_writer_called = 1;
                    result->writer_status = ops->try_native_writer(
                        &request, &slot_ops, ops->opaque);
                }
            }
        }
    }

    if (acquired) {
        ops->release_exact_provider(&handle, ops->opaque);
    }
    if (result->native_writer_called && slot_state.cas_mismatch) {
        result->status = KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH;
        result->selected_target = slot_state.last_read;
        result->final_value = slot_state.last_read;
        return 0;
    }
    if (result->writer_status == KZT_JUMP_SLOT_ROUTE_WRITER_APPLIED) {
        result->status = KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED;
        result->selected_target = request.native_bridge_target;
        result->final_value = request.native_bridge_target;
        return 0;
    }
    if (result->writer_status == KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE) {
        result->status = KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED;
        result->selected_target = slot_state.last_read_present ?
                                  slot_state.last_read : result->observed_value;
        result->final_value = result->selected_target;
        return 0;
    }

    return route_legacy_fallback(input, ops, result);
}
