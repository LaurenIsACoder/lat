#include "kzt_rela_request_enricher.h"
#include "kzt_rela_stub_detector.h"

#include <stdio.h>
#include <string.h>

static int kzt_rela_enricher_string_has_value(
    kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK ||
           status == KZT_GUEST_FIELD_TRUNCATED;
}

static void kzt_rela_enricher_copy_text(char *dst, size_t dst_size,
                                        const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

static void kzt_rela_enricher_ref_from_match(
    const kzt_guest_registry_address_match_t *match,
    kzt_rela_request_enricher_text_t *text,
    kzt_patch_object_ref_t *ref)
{
    const char *soname = NULL;
    const char *path = NULL;

    memset(ref, 0, sizeof(*ref));
    if (!match || !text) {
        return;
    }

    if (kzt_rela_enricher_string_has_value(match->soname_status)) {
        soname = match->soname;
    }
    if (kzt_rela_enricher_string_has_value(match->path_status)) {
        path = match->path;
    }
    kzt_rela_enricher_copy_text(text->soname, sizeof(text->soname), soname);
    kzt_rela_enricher_copy_text(text->path, sizeof(text->path), path);

    ref->known = 1;
    ref->link_map_addr = match->link_map_addr;
    ref->map_start = match->map_start;
    ref->map_end = match->map_end;
    ref->generation = match->generation;
    ref->soname = text->soname[0] ? text->soname : NULL;
    ref->path = text->path[0] ? text->path : NULL;
}

static int kzt_rela_enricher_find_unique_source(
    kzt_guest_registry_t *registry, uintptr_t address,
    kzt_rela_request_enricher_result_t *result)
{
    kzt_guest_registry_address_pair_t pair;

    if (!registry || !address || !result) {
        return -1;
    }
    if (kzt_guest_registry_resolve_address_pair(
            registry, address, address, &pair) != 0) {
        return -1;
    }
    if (pair.current.match_count == 1) {
        kzt_rela_enricher_ref_from_match(
            &pair.current, &result->source_text, &result->source);
        result->source_present = result->source.known;
    }
    return result->source_present ? 0 : -1;
}

static void kzt_rela_enricher_apply_source(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_patch_object_ref_t *source)
{
    const char *fallback_soname;
    const char *fallback_path;

    if (!request || !source || !source->known) {
        return;
    }

    fallback_soname = request->source.soname;
    fallback_path = request->source.path;
    request->source = *source;
    if (!request->source.soname) {
        request->source.soname = fallback_soname;
    }
    if (!request->source.path) {
        request->source.path = fallback_path;
    }
}

static void kzt_rela_enricher_apply_dynamic_view(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *result)
{
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t status;
    unsigned long generation;

    request->dynamic_view_available = 0;
    request->dynamic_view_generation = 0;
    if (!input || !input->registry || !request->source.link_map_addr) {
        return;
    }

    if (kzt_guest_registry_find_dynamic_view(
            input->registry, request->source.link_map_addr, &view, &status,
            &generation) != 0) {
        return;
    }
    if (status != KZT_GUEST_FIELD_OK ||
        view.status != KZT_GUEST_DYNAMIC_COMPLETE) {
        return;
    }

    request->dynamic_addr = view.dynamic_addr;
    request->load_bias = view.load_bias;
    request->dynamic_view_available = 1;
    request->dynamic_view_generation = generation;
    if (result) {
        result->dynamic_view_present = 1;
    }
}

static void kzt_rela_enricher_apply_owner(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *result)
{
    if (!request || !input || !result) {
        return;
    }

    request->owner_match = KZT_PATCH_OWNER_UNKNOWN;
    memset(&request->current_owner, 0, sizeof(request->current_owner));
    kzt_owner_resolver_init(&result->owner_resolution);
    if (input->slot_current_value_is_unresolved_stub) {
        request->lazy_binding_deferred = 1;
        return;
    }

    if (kzt_owner_resolver_resolve_current(
            input->registry, request->slot_current_value,
            request->expected_guest_target, &result->owner_resolution) != 0) {
        return;
    }

    request->current_owner = result->owner_resolution.current_owner;
    request->owner_match = result->owner_resolution.owner_match;
    result->owner_present = request->current_owner.known;
}

static int kzt_rela_enricher_has_wrapper_base_evidence(
    const kzt_rela_immediate_candidate_request_t *request)
{
    return request && request->source.known &&
           request->source.link_map_addr && request->source.generation &&
           request->dynamic_view_available &&
           request->dynamic_view_generation &&
           request->owner_match == KZT_PATCH_OWNER_MATCH &&
           request->current_owner.known &&
           request->current_owner.link_map_addr &&
           request->current_owner.generation;
}

int kzt_rela_immediate_request_enrich_wrapper_only(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_wrapper_only_input_t *input,
    kzt_rela_request_enricher_result_t *result)
{
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops;
    kzt_wrapper_probe_bridge_ops_t restricted_bridge_ops;
    kzt_wrapper_probe_request_t probe_request;

    if (!request || !result) {
        return -1;
    }

    request->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    request->wrapper_name = NULL;
    request->wrapper_version_evidence = KZT_SYMBOL_VERSION_UNKNOWN;
    request->wrapper_symbol_version = NULL;
    request->native_bridge_target = 0;

    probe_request.symbol_name = request->symbol_name;
    probe_request.symbol_version_evidence = request->version_evidence;
    probe_request.symbol_version = request->version;
    bridge_ops = input ? input->bridge_ops : NULL;
    if (bridge_ops && !kzt_rela_enricher_has_wrapper_base_evidence(request)) {
        restricted_bridge_ops = *bridge_ops;
        restricted_bridge_ops.add_bridge = NULL;
        bridge_ops = &restricted_bridge_ops;
    }
    if (kzt_wrapper_probe_minimal_manifest(
            input ? input->wrapper_manifest : NULL, &probe_request, bridge_ops,
            &result->wrapper_probe) != 0) {
        return -1;
    }

    kzt_wrapper_probe_apply_to_decision_request(
        &result->wrapper_probe, &request->wrapper_match,
        &request->wrapper_name, &request->wrapper_symbol_version,
        &request->native_bridge_target);
    request->wrapper_version_evidence =
        result->wrapper_probe.wrapper_version_evidence;
    result->wrapper_present = 1;
    return 0;
}

void kzt_rela_request_enricher_result_init(
    kzt_rela_request_enricher_result_t *result)
{
    if (!result) {
        return;
    }

    memset(result, 0, sizeof(*result));
    kzt_owner_resolver_init(&result->owner_resolution);
    result->wrapper_probe.wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
}

int kzt_rela_immediate_request_enrich(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *result)
{
    if (!request || !input || !result) {
        return -1;
    }
    kzt_rela_request_enricher_result_init(result);

    if (request->source.known && request->source.map_start &&
        kzt_rela_enricher_find_unique_source(
            input->registry, request->source.map_start, result) == 0) {
        kzt_rela_enricher_apply_source(request, &result->source);
    }

    kzt_rela_enricher_apply_dynamic_view(request, input, result);
    kzt_rela_enricher_apply_owner(request, input, result);
    /* Wrapper evidence is planner input, not a failure of base enrichment.
     * Keep malformed or missing wrapper data fail-open for the caller. */
    (void)kzt_rela_immediate_request_enrich_wrapper_only(
        request, &(kzt_rela_request_wrapper_only_input_t){
            .wrapper_manifest = input->wrapper_manifest,
            .bridge_ops = input->bridge_ops,
        }, result);
    return 0;
}
