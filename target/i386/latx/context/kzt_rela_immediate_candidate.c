#include "kzt_rela_immediate_candidate.h"

#include <string.h>

#include "elf.h"

static int kzt_rela_immediate_string_empty(const char *value)
{
    return !value || !value[0];
}

static void kzt_rela_immediate_result_set(
    kzt_rela_immediate_candidate_result_t *result,
    kzt_rela_immediate_candidate_status_t status,
    kzt_rela_immediate_candidate_reason_t reason)
{
    result->status = status;
    result->reason = reason;
}

static int kzt_rela_immediate_fail_open(
    kzt_rela_immediate_candidate_result_t *result,
    kzt_rela_immediate_candidate_reason_t reason)
{
    kzt_rela_immediate_result_set(
        result, KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN, reason);
    return 0;
}

static void kzt_rela_immediate_copy_request(
    const kzt_rela_immediate_candidate_request_t *request,
    kzt_patch_candidate_t *candidate)
{
    memset(candidate, 0, sizeof(*candidate));
    candidate->source = request->source;
    candidate->dynamic_addr = request->dynamic_addr;
    candidate->load_bias = request->load_bias;
    candidate->dynamic_view_generation = request->dynamic_view_generation;
    candidate->dynamic_view_available = request->dynamic_view_available;
    candidate->table_kind = request->table_kind;
    candidate->entry_index = request->entry_index;
    candidate->entry_addr = request->entry_addr;
    candidate->reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT;
    candidate->slot_addr = request->slot_addr;
    candidate->slot_current_value_present =
        request->slot_current_value_present;
    candidate->slot_current_value = request->slot_current_value;
    candidate->lazy_binding_deferred = request->lazy_binding_deferred;
    candidate->symbol_index = request->symbol_index;
    candidate->symbol_name = request->symbol_name;
    candidate->version_evidence = request->version_evidence;
    candidate->version = request->version;
    candidate->current_owner = request->current_owner;
    candidate->owner_match = request->owner_match;
    candidate->wrapper_match = request->wrapper_match;
    candidate->wrapper_name = request->wrapper_name;
    candidate->wrapper_version_evidence =
        request->wrapper_version_evidence;
    candidate->wrapper_symbol_version = request->wrapper_symbol_version;
    candidate->bridge_target = request->native_bridge_target;
}

int kzt_rela_immediate_jump_slot_plan(
    const kzt_rela_immediate_candidate_request_t *request,
    kzt_rela_immediate_candidate_result_t *result)
{
    kzt_patch_decision_t decision;

    if (!result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    if (!request) {
        return kzt_rela_immediate_fail_open(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_REASON_INVALID_ARGUMENT);
    }

    if (request->relocation_type != R_X86_64_JUMP_SLOT) {
        kzt_rela_immediate_result_set(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED,
            KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION);
        return 0;
    }

    if (request->lazy_binding_deferred) {
        kzt_rela_immediate_result_set(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED,
            KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING);
        return 0;
    }

    if (request->slot_addr == 0) {
        return kzt_rela_immediate_fail_open(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SLOT);
    }

    if (!request->slot_current_value_present) {
        return kzt_rela_immediate_fail_open(
            result,
            KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_CURRENT_VALUE);
    }

    if (kzt_rela_immediate_string_empty(request->symbol_name)) {
        return kzt_rela_immediate_fail_open(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_NAME);
    }

    if (!kzt_symbol_version_evidence_valid(request->version_evidence,
                                           request->version)) {
        return kzt_rela_immediate_fail_open(
            result,
            KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_VERSION);
    }

    kzt_rela_immediate_copy_request(request, &result->candidate);
    result->candidate_present = 1;

    if (kzt_patch_planner_decide(&result->candidate, &decision) != 0) {
        result->candidate_present = 0;
        return kzt_rela_immediate_fail_open(
            result, KZT_RELA_IMMEDIATE_CANDIDATE_REASON_PLANNER_ERROR);
    }

    result->decision = decision;
    result->decision_present = 1;
    kzt_rela_immediate_result_set(
        result, KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED,
        KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE);
    return 0;
}

static int kzt_rela_immediate_decision_allows_writer(
    const kzt_rela_immediate_candidate_result_t *plan)
{
    return plan && plan->status == KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED &&
           plan->decision_present &&
           plan->decision.kind == KZT_PATCH_DECISION_APPROVED &&
           plan->decision.allow_native_bridge;
}

int kzt_rela_immediate_jump_slot_try_write(
    const kzt_rela_immediate_candidate_request_t *request,
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_spike_slot_ops_t *slot_ops,
    kzt_rela_immediate_writer_result_t *result)
{
    kzt_rela_immediate_writer_result_t local_result;

    if (!result) {
        result = &local_result;
    }

    memset(result, 0, sizeof(*result));
    result->planner_called = 1;
    if (kzt_rela_immediate_jump_slot_plan(request, &result->plan) != 0) {
        return 0;
    }

    if (!kzt_rela_immediate_decision_allows_writer(&result->plan)) {
        return 0;
    }

    if (kzt_patch_spike_writer_try_apply_with_slot_ops(
            guard, &result->plan.decision, slot_ops,
            &result->record) != 0) {
        return 0;
    }

    result->writer_called = result->record.writer_called;
    result->skip_legacy_write = result->record.skip_legacy_write;
    return 0;
}
