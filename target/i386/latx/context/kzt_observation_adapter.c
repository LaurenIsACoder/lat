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
    }

    return KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED;
}

static kzt_observation_adapter_result_t kzt_observe_guest_object(
    const kzt_observation_adapter_request_t *request)
{
    kzt_guest_object_observation_t observation;
    kzt_guest_registry_result_t registry_result;

    if (!request || !request->enabled) {
        return KZT_OBSERVATION_ADAPTER_DISABLED;
    }

    if (kzt_guest_link_map_read_observation(request->link_map_addr,
                                            request->reader_ops,
                                            &observation) != 0) {
        return KZT_OBSERVATION_ADAPTER_READER_FAILED;
    }

    if (observation.link_map_addr == 0 ||
        observation.load_bias.status != KZT_GUEST_FIELD_OK) {
        kzt_guest_link_map_observation_clear(&observation);
        return KZT_OBSERVATION_ADAPTER_READER_FAILED;
    }

    registry_result = kzt_guest_registry_observe(request->registry,
                                                &observation);
    kzt_guest_link_map_observation_clear(&observation);

    return kzt_adapter_result_from_registry(registry_result);
}

int kzt_observe_guest_object_from_callback(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_result_t observation_result;

    observation_result = kzt_observe_guest_object(request);
    if (result) {
        *result = observation_result;
    }

    if (!request || !request->legacy_flow) {
        return 0;
    }

    return request->legacy_flow(request->link_map_addr,
                                request->legacy_opaque);
}
