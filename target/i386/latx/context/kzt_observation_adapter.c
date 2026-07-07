#include "kzt_observation_adapter.h"

#include <string.h>

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

static int kzt_adapter_registry_result_allows_dynamic_parse(
    kzt_guest_registry_result_t registry_result)
{
    return registry_result == KZT_GUEST_REGISTRY_ADDED ||
           registry_result == KZT_GUEST_REGISTRY_UNCHANGED ||
           registry_result == KZT_GUEST_REGISTRY_UPDATED;
}

static void kzt_adapter_note_dynamic_failure(
    const kzt_observation_adapter_request_t *request,
    kzt_guest_registry_result_t result,
    kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
{
    kzt_guest_registry_observation_diagnostic_t *registry_diagnostic = NULL;

    if (dynamic_diagnostic) {
        registry_diagnostic = &dynamic_diagnostic->registry;
    }

    (void)kzt_guest_registry_note_diagnostic(
        request ? request->registry : NULL, result,
        request ? request->link_map_addr : 0, registry_diagnostic);
}

static void kzt_observe_guest_dynamic_view(
    const kzt_observation_adapter_request_t *request,
    const kzt_guest_object_observation_t *observation,
    kzt_guest_registry_result_t registry_result,
    kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
{
    kzt_guest_dynamic_parse_result_t parse_result = { 0 };
    kzt_guest_registry_result_t commit_result;
    int parse_return;

    if (dynamic_diagnostic) {
        memset(dynamic_diagnostic, 0, sizeof(*dynamic_diagnostic));
        dynamic_diagnostic->commit_result = KZT_GUEST_REGISTRY_RESULT_COUNT;
    }

    if (!request || !observation ||
        !kzt_adapter_registry_result_allows_dynamic_parse(registry_result)) {
        return;
    }

    if (observation->dynamic_addr.status != KZT_GUEST_FIELD_OK ||
        observation->dynamic_addr.value == 0 ||
        observation->load_bias.status != KZT_GUEST_FIELD_OK) {
        return;
    }

    if (dynamic_diagnostic) {
        dynamic_diagnostic->attempted = 1;
        dynamic_diagnostic->dynamic_addr = observation->dynamic_addr.value;
    }

    parse_return = kzt_guest_dynamic_parse(observation->dynamic_addr.value,
                                           observation->load_bias.value,
                                           request->reader_ops,
                                           &parse_result);
    if (dynamic_diagnostic) {
        dynamic_diagnostic->parse_return = parse_return;
        dynamic_diagnostic->status = parse_result.status;
        dynamic_diagnostic->error = parse_result.error;
        dynamic_diagnostic->entry_count = parse_result.entry_count;
        dynamic_diagnostic->read_error_addr = parse_result.read_error_addr;
    }

    if (parse_return != 0) {
        kzt_adapter_note_dynamic_failure(
            request, KZT_GUEST_REGISTRY_ERROR, dynamic_diagnostic);
        kzt_guest_dynamic_parse_result_clear(&parse_result);
        return;
    }

    if (parse_result.status != KZT_GUEST_DYNAMIC_COMPLETE) {
        kzt_adapter_note_dynamic_failure(
            request, KZT_GUEST_REGISTRY_ERROR, dynamic_diagnostic);
    }

    commit_result = kzt_guest_registry_commit_dynamic_view(
        request->registry, observation->link_map_addr, &parse_result.view);
    if (dynamic_diagnostic) {
        dynamic_diagnostic->commit_attempted = 1;
        dynamic_diagnostic->commit_result = commit_result;
    }
    if (commit_result == KZT_GUEST_REGISTRY_DISABLED ||
        commit_result == KZT_GUEST_REGISTRY_ERROR) {
        kzt_adapter_note_dynamic_failure(request, commit_result,
                                         dynamic_diagnostic);
    }

    kzt_guest_dynamic_parse_result_clear(&parse_result);
}

static kzt_observation_adapter_result_t kzt_observe_guest_object(
    const kzt_observation_adapter_request_t *request,
    kzt_guest_registry_observation_diagnostic_t *registry_diagnostic,
    kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
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
    kzt_observe_guest_dynamic_view(request, &observation, registry_result,
                                   dynamic_diagnostic);
    kzt_guest_link_map_observation_clear(&observation);

    return kzt_adapter_result_from_registry(registry_result);
}

static void kzt_observation_adapter_emit_diagnostic(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t result,
    const kzt_guest_registry_observation_diagnostic_t *registry_diagnostic,
    const kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
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
    if (dynamic_diagnostic) {
        diagnostic.dynamic = *dynamic_diagnostic;
        if (dynamic_diagnostic->registry.enabled &&
            dynamic_diagnostic->registry.emitted) {
            diagnostic.emitted = 1;
        }
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
    kzt_observation_adapter_dynamic_diagnostic_t dynamic_diagnostic = {
        .commit_result = KZT_GUEST_REGISTRY_RESULT_COUNT,
    };
    int legacy_ret = 0;

    observation_result = kzt_observe_guest_object(request,
                                                 &registry_diagnostic,
                                                 &dynamic_diagnostic);
    if (result) {
        *result = observation_result;
    }

    if (request && request->legacy_flow) {
        legacy_ret = request->legacy_flow(request->link_map_addr,
                                          request->legacy_opaque);
    }

    kzt_observation_adapter_emit_diagnostic(request, observation_result,
                                            &registry_diagnostic,
                                            &dynamic_diagnostic);
    return legacy_ret;
}
