#include "kzt_observation_adapter.h"

#include <string.h>

#include "kzt_guest_library_binding.h"

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

static void kzt_adapter_compare_dynamic_views(
    const kzt_observation_adapter_request_t *request,
    const kzt_guest_dynamic_parse_result_t *parse_result,
    unsigned long generation,
    kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
{
    kzt_guest_dynamic_view_t existing_view = { 0 };
    kzt_guest_dynamic_parse_result_t existing_result = { 0 };
    kzt_guest_dynamic_diagnostic_report_t report;
    kzt_guest_field_status_t existing_status = KZT_GUEST_FIELD_NOT_PARSED;
    unsigned long existing_generation = 0;

    if (!request || !request->diagnostics_enabled || !parse_result ||
        !dynamic_diagnostic || generation == 0 ||
        kzt_guest_registry_find_dynamic_view(
            request->registry, request->link_map_addr, &existing_view,
            &existing_status, &existing_generation) != 0 ||
        existing_status != KZT_GUEST_FIELD_OK ||
        existing_generation != generation) {
        return;
    }

    existing_result.status = existing_view.status;
    existing_result.error = KZT_GUEST_DYNAMIC_ERROR_NONE;
    existing_result.entry_count = existing_view.entry_count;
    existing_result.scan_limit = existing_view.scan_limit;
    existing_result.unknown_tag_count = existing_view.unknown_tag_count;
    existing_result.first_unknown_tag = existing_view.first_unknown_tag;
    existing_result.first_unknown_tag_index =
        existing_view.first_unknown_tag_index;
    existing_result.view = existing_view;
    if (kzt_guest_dynamic_diagnostics_compare(&existing_result, parse_result,
                                             &report) != 0 ||
        kzt_guest_dynamic_diagnostics_summarize(
            &report, request->link_map_addr, generation,
            &dynamic_diagnostic->comparison) != 0) {
        return;
    }

    dynamic_diagnostic->comparison_attempted = 1;
}

static int kzt_adapter_reuse_complete_dynamic_view(
    const kzt_observation_adapter_request_t *request,
    const kzt_guest_object_observation_t *observation,
    kzt_guest_registry_result_t registry_result,
    unsigned long generation,
    kzt_observation_adapter_dynamic_diagnostic_t *dynamic_diagnostic)
{
    kzt_guest_dynamic_view_t view = { 0 };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_NOT_PARSED;
    unsigned long existing_generation = 0;

    if (!request || !observation || request->library_bindings ||
        request->dynamic_diagnostics_force_compare ||
        registry_result != KZT_GUEST_REGISTRY_UNCHANGED ||
        generation == 0 ||
        kzt_guest_registry_find_dynamic_view(
            request->registry, observation->link_map_addr, &view, &status,
            &existing_generation) != 0 ||
        status != KZT_GUEST_FIELD_OK ||
        existing_generation != generation ||
        view.status != KZT_GUEST_DYNAMIC_COMPLETE ||
        view.dynamic_addr != observation->dynamic_addr.value ||
        view.load_bias != observation->load_bias.value) {
        return 0;
    }

    if (dynamic_diagnostic) {
        dynamic_diagnostic->cache_hit = 1;
        dynamic_diagnostic->parse_return = 0;
        dynamic_diagnostic->dynamic_addr = view.dynamic_addr;
        dynamic_diagnostic->status = view.status;
        dynamic_diagnostic->error = KZT_GUEST_DYNAMIC_ERROR_NONE;
        dynamic_diagnostic->entry_count = view.entry_count;
        dynamic_diagnostic->commit_result = KZT_GUEST_REGISTRY_UNCHANGED;
    }
    return 1;
}

static void kzt_observe_guest_dynamic_view(
    const kzt_observation_adapter_request_t *request,
    const kzt_guest_object_observation_t *observation,
    kzt_guest_registry_result_t registry_result,
    unsigned long generation,
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

    if (kzt_adapter_reuse_complete_dynamic_view(
            request, observation, registry_result, generation,
            dynamic_diagnostic)) {
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

    kzt_adapter_compare_dynamic_views(request, &parse_result, generation,
                                      dynamic_diagnostic);

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
        request->registry, observation->link_map_addr, generation,
        &parse_result.view);
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

    if (observation.link_map_addr == 0) {
        kzt_guest_link_map_observation_clear(&observation);
        kzt_guest_registry_note_diagnostic(
            request->registry, KZT_GUEST_REGISTRY_ERROR,
            request->link_map_addr, registry_diagnostic);
        return KZT_OBSERVATION_ADAPTER_READER_FAILED;
    }

    if (request->namespace_id_present &&
        observation.namespace_id.status == KZT_GUEST_FIELD_UNKNOWN) {
        observation.namespace_id.value = request->namespace_id;
        observation.namespace_id.status = KZT_GUEST_FIELD_OK;
    }
    if (request->map_range_present && request->map_start < request->map_end &&
        observation.map_start.status == KZT_GUEST_FIELD_UNKNOWN &&
        observation.map_end.status == KZT_GUEST_FIELD_UNKNOWN) {
        observation.map_start.value = request->map_start;
        observation.map_start.status = KZT_GUEST_FIELD_OK;
        observation.map_end.value = request->map_end;
        observation.map_end.status = KZT_GUEST_FIELD_OK;
    }

    registry_result = kzt_guest_registry_observe_with_diagnostic(
        request->registry, &observation, registry_diagnostic);
    if (kzt_adapter_registry_result_allows_dynamic_parse(registry_result) &&
        registry_diagnostic && registry_diagnostic->generation &&
        observation.namespace_id.status == KZT_GUEST_FIELD_OK &&
        observation.namespace_id.value == 0) {
        kzt_guest_library_binding_key_t key = {
            .link_map_addr = observation.link_map_addr,
            .generation = registry_diagnostic->generation,
            .namespace_id = observation.namespace_id.value,
            .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        };
        kzt_guest_library_binding_result_t binding_result =
            kzt_guest_library_note_observation(
                request->library_bindings, &key);
        if (binding_result == KZT_GUEST_LIBRARY_BINDING_CANCELLED) {
            /* A loader pair was canceled by unload before this delayed
             * observation arrived.  Retire this generation so address reuse
             * receives fresh evidence on retry. */
            (void)kzt_guest_registry_retire(
                request->registry, key.link_map_addr, key.generation);
        }
    }
    kzt_observe_guest_dynamic_view(request, &observation, registry_result,
                                   registry_diagnostic
                                       ? registry_diagnostic->generation
                                       : 0,
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
    kzt_guest_library_callback_access_t callback_access = { 0 };
    int legacy_ret = 0;

    if (request && request->library_bindings &&
        kzt_guest_library_callback_access_begin_scoped(
            request->library_bindings, request->link_map_addr,
            request->loader_scope,
            &callback_access) != 0) {
        /* Unload won the address gate.  No reader, parser, diagnostic, or
         * legacy loader flow may touch this guest object after this point. */
        if (result) *result = KZT_OBSERVATION_ADAPTER_DISABLED;
        return 0;
    }

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
    kzt_guest_library_callback_access_end(&callback_access);
    return legacy_ret;
}
