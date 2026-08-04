#include "kzt_rela_diagnostics.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define KZT_RELA_DIAGNOSTIC_THROTTLE_MAGIC 0x4b5a5444U

static int kzt_rela_diagnostic_mode_enabled(
    kzt_rela_diagnostic_mode_t mode)
{
    return mode == KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS ||
           mode == KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED;
}

static int kzt_rela_diagnostic_mode_records_writer(
    kzt_rela_diagnostic_mode_t mode)
{
    return mode == KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED;
}

kzt_rela_diagnostic_mode_t kzt_rela_diagnostic_mode_from_flags(
    int diagnostics_enabled,
    int write_enabled)
{
    if (diagnostics_enabled && write_enabled) {
        return KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED;
    }
    if (diagnostics_enabled) {
        return KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS;
    }
    if (write_enabled) {
        return KZT_RELA_DIAGNOSTIC_MODE_WRITE_ENABLED_ONLY;
    }

    return KZT_RELA_DIAGNOSTIC_MODE_DEFAULT;
}

const char *kzt_rela_diagnostic_reason_domain_name(
    kzt_rela_diagnostic_reason_domain_t domain)
{
    switch (domain) {
    case KZT_RELA_DIAGNOSTIC_REASON_CANDIDATE:
        return "candidate";
    case KZT_RELA_DIAGNOSTIC_REASON_PLANNER:
        return "planner";
    case KZT_RELA_DIAGNOSTIC_REASON_WRITER:
        return "writer";
    }

    return "unknown";
}

static const char *kzt_rela_candidate_status_name(
    kzt_rela_immediate_candidate_status_t status)
{
    switch (status) {
    case KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED:
        return "SKIPPED";
    case KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED:
        return "PLANNED";
    case KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN:
        return "FAIL_OPEN";
    }

    return "UNKNOWN";
}

static const char *kzt_rela_candidate_reason_name(
    kzt_rela_immediate_candidate_reason_t reason)
{
    switch (reason) {
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE:
        return "NONE";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION:
        return "NON_TARGET_RELOCATION";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING:
        return "DEFERRED_LAZY_BINDING";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SLOT:
        return "MISSING_SLOT";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_CURRENT_VALUE:
        return "MISSING_CURRENT_VALUE";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_NAME:
        return "MISSING_SYMBOL_NAME";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_VERSION:
        return "MISSING_SYMBOL_VERSION";
    case KZT_RELA_IMMEDIATE_CANDIDATE_REASON_PLANNER_ERROR:
        return "PLANNER_ERROR";
    }

    return "UNKNOWN";
}

static void kzt_rela_diagnostic_copy_name(char *dst, size_t dst_size,
                                          const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }

    snprintf(dst, dst_size, "%s", src ? src : "UNKNOWN");
}

static void kzt_rela_diagnostic_copy_source(char *dst, size_t dst_size,
                                            const char *src)
{
    size_t i;

    if (!dst || dst_size == 0) {
        return;
    }
    if (!src || !src[0]) {
        src = "(unknown)";
    }

    for (i = 0; i + 1 < dst_size && src[i]; ++i) {
        unsigned char value = (unsigned char)src[i];

        if (value <= ' ' || value == '"' || value == '\\' || value == '=') {
            dst[i] = '_';
        } else {
            dst[i] = (char)value;
        }
    }
    dst[i] = '\0';
}

static const char *kzt_rela_diagnostic_object_name(
    const kzt_patch_object_ref_t *object)
{
    if (!object) {
        return NULL;
    }
    if (object->path && object->path[0]) {
        return object->path;
    }
    if (object->soname && object->soname[0]) {
        return object->soname;
    }

    return NULL;
}

static void kzt_rela_diagnostic_apply_request(
    const kzt_rela_immediate_candidate_request_t *request,
    kzt_rela_diagnostic_record_t *record)
{
    if (!request || !record) {
        return;
    }

    kzt_rela_diagnostic_copy_source(
        record->source, sizeof(record->source),
        kzt_rela_diagnostic_object_name(&request->source));
    record->source_link_map = request->source.link_map_addr;
    record->current_owner = request->current_owner.link_map_addr;
    record->source_generation = request->source.generation;
    record->current_owner_generation = request->current_owner.generation;
    record->owner_match = request->owner_match;
    record->wrapper_match = request->wrapper_match;
    record->bridge_target = request->native_bridge_target;
    kzt_rela_diagnostic_copy_name(
        record->symbol, sizeof(record->symbol), request->symbol_name);
    kzt_rela_diagnostic_copy_name(
        record->version, sizeof(record->version), request->version);
}

static void kzt_rela_diagnostic_apply_decision(
    const kzt_patch_decision_t *decision,
    kzt_rela_diagnostic_record_t *record)
{
    if (!decision || !record) {
        return;
    }

    kzt_rela_diagnostic_copy_source(
        record->source, sizeof(record->source),
        kzt_rela_diagnostic_object_name(&decision->source));
    record->source_link_map = decision->source.link_map_addr;
    record->current_owner = decision->current_owner.link_map_addr;
    record->source_generation = decision->source.generation;
    record->current_owner_generation = decision->current_owner.generation;
    record->owner_match = decision->owner_match;
    record->wrapper_match = decision->wrapper_match;
    record->bridge_target = decision->bridge_target;
    kzt_rela_diagnostic_copy_name(
        record->symbol, sizeof(record->symbol), decision->symbol_name);
    kzt_rela_diagnostic_copy_name(
        record->version, sizeof(record->version), decision->version);
}

int kzt_rela_immediate_diagnostic_record(
    kzt_rela_diagnostic_mode_t mode,
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_immediate_writer_result_t *result,
    int legacy_fallback,
    kzt_rela_diagnostic_record_t *record)
{
    const kzt_rela_immediate_candidate_result_t *plan = NULL;

    if (!record) {
        return -1;
    }

    memset(record, 0, sizeof(*record));
    kzt_rela_diagnostic_copy_source(record->source, sizeof(record->source),
                                    NULL);
    record->owner_match = KZT_PATCH_OWNER_UNKNOWN;
    record->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    record->reason_domain = KZT_RELA_DIAGNOSTIC_REASON_CANDIDATE;
    kzt_rela_diagnostic_copy_name(record->reason, sizeof(record->reason),
                                  "UNAVAILABLE");
    kzt_rela_diagnostic_copy_name(record->decision,
                                  sizeof(record->decision), "UNAVAILABLE");
    kzt_rela_diagnostic_copy_name(record->writer_result,
                                  sizeof(record->writer_result),
                                  "NOT_RECORDED");
    record->legacy_fallback = legacy_fallback != 0;
    kzt_rela_diagnostic_apply_request(request, record);

    if (result) {
        plan = &result->plan;
        kzt_rela_diagnostic_copy_name(
            record->decision, sizeof(record->decision),
            kzt_rela_candidate_status_name(plan->status));
        kzt_rela_diagnostic_copy_name(
            record->reason, sizeof(record->reason),
            kzt_rela_candidate_reason_name(plan->reason));
    }

    if (plan && plan->decision_present) {
        record->reason_domain = KZT_RELA_DIAGNOSTIC_REASON_PLANNER;
        kzt_rela_diagnostic_apply_decision(&plan->decision, record);
        kzt_rela_diagnostic_copy_name(
            record->decision, sizeof(record->decision),
            kzt_patch_decision_kind_name(plan->decision.kind));
        kzt_rela_diagnostic_copy_name(
            record->reason, sizeof(record->reason),
            kzt_patch_reason_name(plan->decision.reason));
    }

    if (kzt_rela_diagnostic_mode_records_writer(mode) && result &&
        result->record.valid) {
        record->reason_domain = KZT_RELA_DIAGNOSTIC_REASON_WRITER;
        kzt_rela_diagnostic_copy_name(
            record->reason, sizeof(record->reason),
            kzt_patch_spike_failure_name(result->record.failure));
        kzt_rela_diagnostic_copy_name(
            record->writer_result, sizeof(record->writer_result),
            kzt_patch_spike_result_name(result->record.result));
    }

    return 0;
}

kzt_rela_diagnostic_format_status_t kzt_rela_diagnostic_format(
    const kzt_rela_diagnostic_record_t *record,
    char *buffer,
    size_t buffer_size)
{
    int written;

    if (!record || !buffer || buffer_size == 0) {
        return KZT_RELA_DIAGNOSTIC_FORMAT_ERROR;
    }

    written = snprintf(
        buffer, buffer_size,
        "kzt_rela_diagnostic source=%s source_link_map=0x%lx "
        "source_generation=%lu current_owner=0x%lx "
        "current_owner_generation=%lu owner_match=%s "
        "wrapper_match=%s bridge_target=0x%lx symbol=%s version=%s "
        "reason_domain=%s "
        "reason=%s decision=%s writer_result=%s legacy_fallback=%d",
        record->source,
        (unsigned long)record->source_link_map,
        record->source_generation,
        (unsigned long)record->current_owner,
        record->current_owner_generation,
        kzt_patch_owner_match_name(record->owner_match),
        kzt_patch_wrapper_match_name(record->wrapper_match),
        (unsigned long)record->bridge_target,
        record->symbol,
        record->version,
        kzt_rela_diagnostic_reason_domain_name(record->reason_domain),
        record->reason,
        record->decision,
        record->writer_result,
        record->legacy_fallback);
    if (written < 0) {
        return KZT_RELA_DIAGNOSTIC_FORMAT_ERROR;
    }
    if ((size_t)written >= buffer_size) {
        return KZT_RELA_DIAGNOSTIC_FORMAT_TRUNCATED;
    }

    return KZT_RELA_DIAGNOSTIC_FORMAT_OK;
}

static int kzt_rela_diagnostic_throttle_valid(
    const kzt_rela_diagnostic_throttle_t *throttle)
{
    return throttle &&
           __atomic_load_n(&throttle->initialized, __ATOMIC_ACQUIRE) ==
               KZT_RELA_DIAGNOSTIC_THROTTLE_MAGIC;
}

static void kzt_rela_diagnostic_throttle_lock(
    kzt_rela_diagnostic_throttle_t *throttle)
{
    while (__atomic_exchange_n(&throttle->lock, 1U, __ATOMIC_ACQUIRE) != 0U) {
    }
}

static void kzt_rela_diagnostic_throttle_unlock(
    kzt_rela_diagnostic_throttle_t *throttle)
{
    __atomic_store_n(&throttle->lock, 0U, __ATOMIC_RELEASE);
}

int kzt_rela_diagnostic_throttle_init(
    kzt_rela_diagnostic_throttle_t *throttle,
    unsigned long capacity)
{
    if (!throttle) {
        return -1;
    }

    memset(throttle, 0, sizeof(*throttle));
    throttle->capacity = capacity;
    __atomic_store_n(&throttle->initialized,
                     KZT_RELA_DIAGNOSTIC_THROTTLE_MAGIC,
                     __ATOMIC_RELEASE);
    return 0;
}

int kzt_rela_diagnostic_throttle_try_admit(
    kzt_rela_diagnostic_throttle_t *throttle)
{
    int result;

    if (!kzt_rela_diagnostic_throttle_valid(throttle)) {
        return -1;
    }

    kzt_rela_diagnostic_throttle_lock(throttle);
    if (throttle->admitted >= throttle->capacity) {
        if (throttle->suppressed != ULONG_MAX) {
            ++throttle->suppressed;
        }
        result = 0;
    } else {
        ++throttle->admitted;
        result = 1;
    }
    kzt_rela_diagnostic_throttle_unlock(throttle);
    return result;
}

int kzt_rela_diagnostic_throttle_snapshot(
    kzt_rela_diagnostic_throttle_t *throttle,
    kzt_rela_diagnostic_throttle_snapshot_t *snapshot)
{
    if (!snapshot || !kzt_rela_diagnostic_throttle_valid(throttle)) {
        return -1;
    }

    kzt_rela_diagnostic_throttle_lock(throttle);
    snapshot->capacity = throttle->capacity;
    snapshot->admitted = throttle->admitted;
    snapshot->suppressed = throttle->suppressed;
    kzt_rela_diagnostic_throttle_unlock(throttle);
    return 0;
}

int kzt_rela_immediate_diagnostic_emit(
    const kzt_rela_immediate_diagnostic_input_t *input,
    kzt_rela_immediate_diagnostic_result_t *result)
{
    int admitted;

    if (!input || !result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->status = KZT_RELA_DIAGNOSTIC_EMIT_DISABLED;
    result->format_status = KZT_RELA_DIAGNOSTIC_FORMAT_ERROR;
    if (!kzt_rela_diagnostic_mode_enabled(input->mode)) {
        return 0;
    }

    admitted = kzt_rela_diagnostic_throttle_try_admit(input->throttle);
    if (admitted < 0) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_THROTTLE_FAILED;
        return 0;
    }
    if (admitted == 0) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_SUPPRESSED;
        return 0;
    }

    if (kzt_rela_immediate_diagnostic_record(
            input->mode, input->request, input->result,
            input->legacy_fallback, &result->record) != 0) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_FAILED;
        return 0;
    }
    result->record_present = 1;

    result->format_status = kzt_rela_diagnostic_format(
        &result->record, input->buffer, input->buffer_size);
    if (result->format_status == KZT_RELA_DIAGNOSTIC_FORMAT_TRUNCATED) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_TRUNCATED;
        return 0;
    }
    if (result->format_status != KZT_RELA_DIAGNOSTIC_FORMAT_OK) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_FAILED;
        return 0;
    }

    if (!input->sink) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_SINK_FAILED;
        result->sink_status = -1;
        return 0;
    }

    result->sink_status = input->sink(
        input->buffer, strlen(input->buffer), input->sink_opaque);
    if (result->sink_status != 0) {
        result->status = KZT_RELA_DIAGNOSTIC_EMIT_SINK_FAILED;
        return 0;
    }

    result->status = KZT_RELA_DIAGNOSTIC_EMIT_EMITTED;
    return 0;
}
