#include "kzt_rela_request_enricher.h"
#include "kzt_rela_stub_detector.h"

#include <stdio.h>
#include <string.h>

static int kzt_rela_add_load_bias(uintptr_t address, intptr_t load_bias,
                                  uintptr_t *runtime_address)
{
    uintptr_t magnitude;

    if (!runtime_address) {
        return 0;
    }
    if (load_bias >= 0) {
        magnitude = (uintptr_t)load_bias;
        if (address > UINTPTR_MAX - magnitude) {
            return 0;
        }
        *runtime_address = address + magnitude;
        return 1;
    }

    magnitude = (uintptr_t)(-(load_bias + 1)) + 1;
    if (address < magnitude) {
        return 0;
    }
    *runtime_address = address - magnitude;
    return 1;
}

static int kzt_rela_value_in_range(uintptr_t value, uintptr_t start,
                                   uintptr_t end)
{
    return start < end && value >= start && value < end;
}

static int kzt_rela_value_in_loaded_range(uintptr_t value,
                                          intptr_t load_bias,
                                          uintptr_t start,
                                          uintptr_t end)
{
    uintptr_t runtime_start;
    uintptr_t runtime_end;

    if (start >= end ||
        !kzt_rela_add_load_bias(start, load_bias, &runtime_start) ||
        !kzt_rela_add_load_bias(end, load_bias, &runtime_end)) {
        return 0;
    }

    return kzt_rela_value_in_range(value, runtime_start, runtime_end);
}

int kzt_rela_slot_current_is_unresolved_stub(
    uintptr_t slot_current_value, kzt_rela_stub_coordinate_t coordinate,
    intptr_t load_bias,
    uintptr_t plt_start, uintptr_t plt_end,
    uintptr_t gotplt_start, uintptr_t gotplt_end)
{
    if (!slot_current_value ||
        coordinate == KZT_RELA_STUB_COORDINATE_UNKNOWN) {
        return 0;
    }

    if (coordinate == KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW) {
        return kzt_rela_value_in_range(slot_current_value,
                                       plt_start, plt_end) ||
               kzt_rela_value_in_range(slot_current_value,
                                       gotplt_start, gotplt_end);
    }
    if (coordinate == KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED) {
        return kzt_rela_value_in_loaded_range(slot_current_value, load_bias,
                                              plt_start, plt_end) ||
               kzt_rela_value_in_loaded_range(slot_current_value, load_bias,
                                              gotplt_start, gotplt_end);
    }

    return 0;
}

static int kzt_rela_enricher_field_ok(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK;
}

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

static int kzt_rela_enricher_snapshot_has_range(
    const kzt_guest_object_snapshot_t *snapshot)
{
    if (!snapshot) {
        return 0;
    }
    if (!kzt_rela_enricher_field_ok(snapshot->map_start.status) ||
        !kzt_rela_enricher_field_ok(snapshot->map_end.status)) {
        return 0;
    }

    return snapshot->map_start.value < snapshot->map_end.value;
}

static int kzt_rela_enricher_snapshot_contains(
    const kzt_guest_object_snapshot_t *snapshot, uintptr_t address)
{
    if (!kzt_rela_enricher_snapshot_has_range(snapshot)) {
        return 0;
    }

    return address >= snapshot->map_start.value &&
           address < snapshot->map_end.value;
}

static const char *kzt_rela_enricher_snapshot_string(
    const kzt_guest_string_field_t *field)
{
    if (!field || !kzt_rela_enricher_string_has_value(field->status)) {
        return NULL;
    }

    return field->value;
}

static void kzt_rela_enricher_ref_from_snapshot(
    const kzt_guest_object_snapshot_t *snapshot,
    kzt_rela_request_enricher_text_t *text,
    kzt_patch_object_ref_t *ref)
{
    const char *soname;
    const char *path;

    memset(ref, 0, sizeof(*ref));
    if (!snapshot || !text) {
        return;
    }

    soname = kzt_rela_enricher_snapshot_string(&snapshot->soname);
    path = kzt_rela_enricher_snapshot_string(&snapshot->path);
    kzt_rela_enricher_copy_text(text->soname, sizeof(text->soname), soname);
    kzt_rela_enricher_copy_text(text->path, sizeof(text->path), path);

    ref->known = 1;
    ref->link_map_addr = snapshot->link_map_addr;
    ref->map_start = snapshot->map_start.value;
    ref->map_end = snapshot->map_end.value;
    ref->generation = snapshot->generation;
    ref->soname = text->soname[0] ? text->soname : NULL;
    ref->path = text->path[0] ? text->path : NULL;
}

static int kzt_rela_enricher_find_unique_source(
    kzt_guest_registry_t *registry, uintptr_t address,
    kzt_rela_request_enricher_result_t *result)
{
    kzt_guest_registry_dump_t dump = { 0 };
    const kzt_guest_object_snapshot_t *match = NULL;
    size_t i;
    size_t count = 0;

    if (!registry || !address || !result) {
        return -1;
    }
    if (kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        return -1;
    }

    for (i = 0; i < dump.count; ++i) {
        if (dump.objects[i].state == KZT_GUEST_OBJECT_UNLOADING ||
            dump.objects[i].state == KZT_GUEST_OBJECT_DEAD) {
            continue;
        }
        if (!kzt_rela_enricher_snapshot_contains(&dump.objects[i], address)) {
            continue;
        }
        ++count;
        if (!match) {
            match = &dump.objects[i];
        }
    }

    if (count == 1 && match) {
        kzt_rela_enricher_ref_from_snapshot(
            match, &result->source_text, &result->source);
        result->source_present = result->source.known;
    }

    kzt_guest_registry_dump_free(&dump);
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

static void kzt_rela_enricher_apply_wrapper(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *result)
{
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops;
    kzt_wrapper_probe_bridge_ops_t restricted_bridge_ops;
    kzt_wrapper_probe_request_t probe_request;

    if (!request || !input || !result) {
        return;
    }

    request->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    request->wrapper_name = NULL;
    request->wrapper_version_evidence = KZT_SYMBOL_VERSION_UNKNOWN;
    request->wrapper_symbol_version = NULL;
    request->native_bridge_target = 0;

    probe_request.symbol_name = request->symbol_name;
    probe_request.symbol_version_evidence = request->version_evidence;
    probe_request.symbol_version = request->version;
    bridge_ops = input->bridge_ops;
    if (bridge_ops &&
        (!request->dynamic_view_available ||
         request->owner_match != KZT_PATCH_OWNER_MATCH)) {
        restricted_bridge_ops = *bridge_ops;
        restricted_bridge_ops.add_bridge = NULL;
        bridge_ops = &restricted_bridge_ops;
    }
    if (kzt_wrapper_probe_minimal_manifest(
            input->wrapper_manifest, &probe_request, bridge_ops,
            &result->wrapper_probe) != 0) {
        return;
    }

    kzt_wrapper_probe_apply_to_decision_request(
        &result->wrapper_probe, &request->wrapper_match,
        &request->wrapper_name, &request->wrapper_symbol_version,
        &request->native_bridge_target);
    request->wrapper_version_evidence =
        result->wrapper_probe.wrapper_version_evidence;
    result->wrapper_present = 1;
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
    kzt_rela_enricher_apply_wrapper(request, input, result);
    return 0;
}
