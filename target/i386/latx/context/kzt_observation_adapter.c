#include "kzt_observation_adapter.h"

static kzt_observation_adapter_result_t kzt_adapter_result_from_registry(
    kzt_guest_registry_result_t registry_result)
{
    switch (registry_result) {
    case KZT_GUEST_REGISTRY_ADDED:
        return KZT_OBSERVATION_ADAPTER_ADDED;
    case KZT_GUEST_REGISTRY_UNCHANGED:
        return KZT_OBSERVATION_ADAPTER_UNCHANGED;
    case KZT_GUEST_REGISTRY_UPDATED:
        return KZT_OBSERVATION_ADAPTER_UPDATED;
    case KZT_GUEST_REGISTRY_CONFLICT:
        return KZT_OBSERVATION_ADAPTER_CONFLICT;
    case KZT_GUEST_REGISTRY_DISABLED:
    case KZT_GUEST_REGISTRY_ERROR:
        return KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED;
    case KZT_GUEST_REGISTRY_RESULT_COUNT:
        break;
    }

    return KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED;
}

static kzt_observation_adapter_result_t kzt_observe_guest_object(
    const kzt_observation_adapter_request_t *request,
    kzt_guest_registry_observation_diagnostic_t *registry_diagnostic)
{
    kzt_guest_object_observation_t observation;
    kzt_guest_registry_result_t registry_result;

    if (!request || !request->enabled) {
        if (request) {
            kzt_guest_registry_note_diagnostic(
                request->registry, KZT_GUEST_REGISTRY_DISABLED,
                request->link_map_addr, registry_diagnostic);
        }
        return KZT_OBSERVATION_ADAPTER_DISABLED;
    }

    if (kzt_guest_link_map_read_observation(request->link_map_addr,
                                            request->reader_ops,
                                            &observation) != 0) {
        kzt_guest_registry_note_diagnostic(
            request->registry, KZT_GUEST_REGISTRY_ERROR,
            request->link_map_addr, registry_diagnostic);
        return KZT_OBSERVATION_ADAPTER_READER_FAILED;
    }

    if (observation.link_map_addr == 0 ||
        observation.load_bias.status != KZT_GUEST_FIELD_OK) {
        kzt_guest_link_map_observation_clear(&observation);
        kzt_guest_registry_note_diagnostic(
            request->registry, KZT_GUEST_REGISTRY_ERROR,
            request->link_map_addr, registry_diagnostic);
        return KZT_OBSERVATION_ADAPTER_READER_FAILED;
    }

    registry_result = kzt_guest_registry_observe_with_diagnostic(
        request->registry, &observation, registry_diagnostic);
    kzt_guest_link_map_observation_clear(&observation);

    return kzt_adapter_result_from_registry(registry_result);
}

static void kzt_observation_adapter_emit_diagnostic(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t result,
    const kzt_guest_registry_observation_diagnostic_t *registry_diagnostic)
{
    kzt_observation_adapter_diagnostic_t diagnostic = { 0 };

    if (!request || !request->diagnostics_enabled || !request->diagnostic) {
        return;
    }

    diagnostic.enabled = 1;
    diagnostic.result = result;
    diagnostic.link_map_addr = request->link_map_addr;
    diagnostic.emitted = 0;
    if (registry_diagnostic) {
        diagnostic.registry = *registry_diagnostic;
        diagnostic.emitted = registry_diagnostic->enabled &&
                             registry_diagnostic->emitted;
    }

    if (!diagnostic.emitted) {
        return;
    }

    request->diagnostic(&diagnostic, request->diagnostic_opaque);
}

int kzt_observe_guest_object_from_callback(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_result_t observation_result;
    kzt_guest_registry_observation_diagnostic_t registry_diagnostic = { 0 };
    int legacy_ret = 0;

    observation_result = kzt_observe_guest_object(request,
                                                 &registry_diagnostic);
    if (result) {
        *result = observation_result;
    }

    if (request && request->legacy_flow) {
        legacy_ret = request->legacy_flow(request->link_map_addr,
                                          request->legacy_opaque);
    }

    kzt_observation_adapter_emit_diagnostic(request, observation_result,
                                            &registry_diagnostic);
    return legacy_ret;
}
