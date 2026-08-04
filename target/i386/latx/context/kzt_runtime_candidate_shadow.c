#include "kzt_runtime_candidate_shadow.h"

#include <string.h>

static void kzt_runtime_candidate_shadow_result_init(
    kzt_runtime_candidate_shadow_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->status = KZT_RUNTIME_CANDIDATE_SHADOW_OK;
    result->reason = KZT_RUNTIME_CANDIDATE_SHADOW_REASON_NONE;
}

static int kzt_runtime_candidate_shadow_output_sizes_valid(
    const kzt_runtime_candidate_shadow_input_t *input)
{
    const kzt_runtime_got_plt_candidate_request_t *collector;

    if (!input || !input->collector_request) {
        return 0;
    }

    collector = input->collector_request;
    if ((!input->records && input->record_capacity > 0) ||
        input->record_capacity >
            SIZE_MAX / sizeof(kzt_runtime_candidate_shadow_record_t)) {
        return 0;
    }

    if ((!collector->candidates && collector->candidate_capacity > 0) ||
        collector->candidate_capacity >
            SIZE_MAX / sizeof(kzt_patch_candidate_t)) {
        return 0;
    }

    return 1;
}

static void kzt_runtime_candidate_shadow_clear_outputs(
    const kzt_runtime_candidate_shadow_input_t *input)
{
    const kzt_runtime_got_plt_candidate_request_t *collector;

    if (!input || !input->collector_request) {
        return;
    }

    collector = input->collector_request;
    if (collector->candidates && collector->candidate_capacity > 0) {
        memset(collector->candidates, 0,
               collector->candidate_capacity *
                   sizeof(*collector->candidates));
    }
    if (collector->string_storage && collector->string_storage_size > 0) {
        memset(collector->string_storage, 0,
               collector->string_storage_size);
    }
    if (input->records && input->record_capacity > 0) {
        memset(input->records, 0,
               input->record_capacity * sizeof(*input->records));
    }
}

static int kzt_runtime_candidate_shadow_registry_generation(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long *generation)
{
    kzt_guest_registry_dump_t dump = { 0 };
    size_t matches = 0;
    size_t i;

    if (!registry || link_map_addr == 0 || !generation) {
        return -1;
    }

    if (kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        return -1;
    }

    for (i = 0; i < dump.count; ++i) {
        if (dump.objects[i].link_map_addr != link_map_addr) {
            continue;
        }
        if (dump.objects[i].state == KZT_GUEST_OBJECT_UNLOADING ||
            dump.objects[i].state == KZT_GUEST_OBJECT_DEAD) {
            continue;
        }

        *generation = dump.objects[i].generation;
        ++matches;
    }

    kzt_guest_registry_dump_free(&dump);
    return matches == 1 && *generation != 0 ? 0 : -1;
}

static int kzt_runtime_candidate_shadow_query_generation(
    const kzt_runtime_candidate_shadow_input_t *input,
    uintptr_t link_map_addr,
    unsigned long *generation)
{
    *generation = 0;
    if (input->query_generation) {
        return input->query_generation(
            link_map_addr, generation,
            input->generation_query_opaque);
    }

    return kzt_runtime_candidate_shadow_registry_generation(
        input->registry, link_map_addr, generation);
}

static int kzt_runtime_candidate_shadow_generation_valid(
    const kzt_runtime_candidate_shadow_input_t *input,
    const kzt_patch_candidate_t *candidate)
{
    unsigned long current_generation = 0;

    if (!candidate || !candidate->source.known ||
        candidate->source.link_map_addr == 0 ||
        candidate->source.generation == 0 ||
        candidate->dynamic_view_generation == 0) {
        return 0;
    }

    if (kzt_runtime_candidate_shadow_query_generation(
            input, candidate->source.link_map_addr,
            &current_generation) != 0 ||
        current_generation == 0) {
        return 0;
    }

    return candidate->source.generation == current_generation &&
           candidate->dynamic_view_generation == current_generation;
}

static int kzt_runtime_candidate_shadow_batch_generation_valid(
    const kzt_runtime_candidate_shadow_input_t *input,
    size_t candidate_count)
{
    size_t i;

    for (i = 0; i < candidate_count; ++i) {
        if (!kzt_runtime_candidate_shadow_generation_valid(
                input,
                &input->collector_request->candidates[i])) {
            return 0;
        }
    }

    return 1;
}

static int kzt_runtime_candidate_shadow_is_precise_stub(
    const kzt_runtime_candidate_shadow_input_t *input,
    const kzt_patch_candidate_t *candidate)
{
    if (!candidate || !candidate->slot_current_value_present ||
        !input->classify_stub) {
        return 0;
    }

    if (candidate->reloc_type != KZT_PATCH_RELOCATION_JUMP_SLOT &&
        candidate->reloc_type != KZT_PATCH_RELOCATION_GLOB_DAT) {
        return 0;
    }

    return input->classify_stub(
               candidate, input->stub_classifier_opaque) ==
           KZT_RUNTIME_CANDIDATE_SHADOW_STUB_MATCH;
}

static int kzt_runtime_candidate_shadow_decision_valid(
    const kzt_patch_decision_t *decision)
{
    return decision &&
           decision->kind >= KZT_PATCH_DECISION_ERROR &&
           (size_t)decision->kind <
               KZT_RUNTIME_CANDIDATE_SHADOW_DECISION_BUCKETS &&
           decision->reason >= KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT &&
           (size_t)decision->reason <
               KZT_RUNTIME_CANDIDATE_SHADOW_REASON_BUCKETS;
}

static void kzt_runtime_candidate_shadow_enrich_owner(
    const kzt_runtime_candidate_shadow_input_t *input,
    kzt_patch_candidate_t *candidate,
    kzt_runtime_candidate_shadow_record_t *record)
{
    uintptr_t expected_guest_target = 0;

    memset(&candidate->current_owner, 0, sizeof(candidate->current_owner));
    candidate->owner_match = KZT_PATCH_OWNER_UNKNOWN;
    kzt_owner_resolver_init(&record->owner_resolution);

    if (candidate->lazy_binding_deferred || !input->registry ||
        !input->resolve_expected_guest_target) {
        return;
    }

    if (input->resolve_expected_guest_target(
            candidate, &expected_guest_target,
            input->expected_target_opaque) != 0 ||
        expected_guest_target == 0) {
        return;
    }

    if (kzt_owner_resolver_resolve_current(
            input->registry, candidate->slot_current_value,
            expected_guest_target, &record->owner_resolution) != 0) {
        return;
    }

    candidate->current_owner =
        record->owner_resolution.current_owner;
    candidate->owner_match = record->owner_resolution.owner_match;
}

static int kzt_runtime_candidate_shadow_enrich_wrapper(
    const kzt_runtime_candidate_shadow_input_t *input,
    kzt_patch_candidate_t *candidate,
    kzt_runtime_candidate_shadow_record_t *record)
{
    kzt_wrapper_probe_bridge_ops_t readonly_bridge_ops = { 0 };
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops = NULL;
    kzt_wrapper_probe_request_t probe_request = {
        .symbol_name = candidate->symbol_name,
        .symbol_version_evidence = candidate->version_evidence,
        .symbol_version = candidate->version,
    };

    candidate->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    candidate->wrapper_name = NULL;
    candidate->wrapper_version_evidence = KZT_SYMBOL_VERSION_UNKNOWN;
    candidate->wrapper_symbol_version = NULL;
    candidate->bridge_target = 0;

    if (input->bridge_ops) {
        readonly_bridge_ops.check_bridge =
            input->bridge_ops->check_bridge;
        readonly_bridge_ops.add_bridge = NULL;
        readonly_bridge_ops.opaque = input->bridge_ops->opaque;
        bridge_ops = &readonly_bridge_ops;
    }

    if (kzt_wrapper_probe_minimal_manifest(
            input->wrapper_manifest, &probe_request, bridge_ops,
            &record->wrapper_probe) != 0) {
        return -1;
    }

    kzt_wrapper_probe_apply_to_candidate(&record->wrapper_probe,
                                         candidate);
    return 0;
}

static void kzt_runtime_candidate_shadow_fail_open(
    const kzt_runtime_candidate_shadow_input_t *input,
    kzt_runtime_candidate_shadow_result_t *result,
    kzt_runtime_candidate_shadow_reason_t reason)
{
    kzt_runtime_candidate_shadow_clear_outputs(input);
    result->status = KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN;
    result->reason = reason;
    result->collector_result.candidate_count = 0;
    result->candidate_count = 0;
    result->record_count = 0;
    result->eligible_count = 0;
    result->observe_only_count = 0;
    memset(result->decision_histogram, 0,
           sizeof(result->decision_histogram));
    memset(result->reason_histogram, 0,
           sizeof(result->reason_histogram));
}

int kzt_runtime_candidate_shadow_run(
    const kzt_runtime_candidate_shadow_input_t *input,
    kzt_runtime_candidate_shadow_result_t *result)
{
    const kzt_runtime_got_plt_candidate_request_t *collector;
    size_t candidate_count;
    size_t i;
    int collect_status;

    if (!result) {
        return -1;
    }

    kzt_runtime_candidate_shadow_result_init(result);
    if (!kzt_runtime_candidate_shadow_output_sizes_valid(input)) {
        result->status = KZT_RUNTIME_CANDIDATE_SHADOW_ERROR;
        result->reason =
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_INVALID_ARGUMENT;
        return -1;
    }

    collector = input->collector_request;
    kzt_runtime_candidate_shadow_clear_outputs(input);
    collect_status = kzt_runtime_got_plt_candidates_collect(
        collector, &result->collector_result);
    if (collect_status != 0 ||
        result->collector_result.status ==
            KZT_RUNTIME_GOT_PLT_CANDIDATE_ERROR) {
        kzt_runtime_candidate_shadow_clear_outputs(input);
        result->status = KZT_RUNTIME_CANDIDATE_SHADOW_ERROR;
        result->reason =
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_ERROR;
        return -1;
    }

    if (result->collector_result.status ==
        KZT_RUNTIME_GOT_PLT_CANDIDATE_FAIL_OPEN) {
        kzt_runtime_candidate_shadow_fail_open(
            input, result,
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_FAIL_OPEN);
        return 0;
    }

    candidate_count = result->collector_result.candidate_count;
    if (candidate_count > input->record_capacity) {
        kzt_runtime_candidate_shadow_fail_open(
            input, result,
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_RECORD_CAPACITY_EXCEEDED);
        return 0;
    }

    if (!kzt_runtime_candidate_shadow_batch_generation_valid(
            input, candidate_count)) {
        kzt_runtime_candidate_shadow_fail_open(
            input, result,
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_OBJECT_GENERATION_CHANGED);
        return 0;
    }

    for (i = 0; i < candidate_count; ++i) {
        kzt_patch_candidate_t *candidate = &collector->candidates[i];
        kzt_runtime_candidate_shadow_record_t *record =
            &input->records[i];

        record->candidate_index = i;
        candidate->lazy_binding_deferred =
            kzt_runtime_candidate_shadow_is_precise_stub(input,
                                                         candidate);
        kzt_runtime_candidate_shadow_enrich_owner(input, candidate,
                                                  record);
        if (kzt_runtime_candidate_shadow_enrich_wrapper(
                input, candidate, record) != 0 ||
            kzt_patch_planner_decide(candidate,
                                     &record->decision) != 0) {
            kzt_runtime_candidate_shadow_fail_open(
                input, result,
                KZT_RUNTIME_CANDIDATE_SHADOW_REASON_PLANNER_ERROR);
            return 0;
        }

        if (!kzt_runtime_candidate_shadow_decision_valid(
                &record->decision)) {
            kzt_runtime_candidate_shadow_fail_open(
                input, result,
                KZT_RUNTIME_CANDIDATE_SHADOW_REASON_PLANNER_ERROR);
            return 0;
        }

        record->audit_only = 1;
        record->legacy_target_consumed = 0;
        record->observe_only =
            candidate->reloc_type == KZT_PATCH_RELOCATION_GLOB_DAT;
        record->eligible =
            record->decision.kind == KZT_PATCH_DECISION_APPROVED &&
            !record->observe_only;
        result->decision_histogram[record->decision.kind]++;
        result->reason_histogram[record->decision.reason]++;
        result->eligible_count += record->eligible;
        result->observe_only_count += record->observe_only;
    }

    if (!kzt_runtime_candidate_shadow_batch_generation_valid(
            input, candidate_count)) {
        kzt_runtime_candidate_shadow_fail_open(
            input, result,
            KZT_RUNTIME_CANDIDATE_SHADOW_REASON_OBJECT_GENERATION_CHANGED);
        return 0;
    }

    result->candidate_count = candidate_count;
    result->record_count = candidate_count;
    return 0;
}
