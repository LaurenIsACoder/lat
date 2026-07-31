#include "kzt_lazy_diagnostics.h"

#include <stdio.h>
#include <string.h>

#define KZT_LAZY_DIAGNOSTIC_SCHEMA 1UL

static void kzt_lazy_diagnostic_copy_token(char *dst, size_t dst_size,
                                           const char *src)
{
    size_t i;

    if (!dst || dst_size == 0) {
        return;
    }
    if (!src || !src[0]) {
        src = "(none)";
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

static const char *kzt_lazy_diagnostic_status_name(
    const kzt_lazy_binding_result_t *binding_result)
{
    if (!binding_result) {
        return "INVALID_RESULT";
    }

    switch (binding_result->status) {
    case KZT_LAZY_BINDING_BYPASS:
        return "BYPASS";
    case KZT_LAZY_BINDING_HANDOFF_GUEST:
        return "HANDOFF_GUEST";
    case KZT_LAZY_BINDING_WAITING_GUEST_TARGET:
        return "WAITING_GUEST_TARGET";
    case KZT_LAZY_BINDING_NATIVE_APPLIED:
        return "NATIVE_APPLIED";
    case KZT_LAZY_BINDING_CAS_MISMATCH:
        return "CAS_MISMATCH";
    case KZT_LAZY_BINDING_WRITE_ROLLED_BACK:
        return "WRITE_ROLLED_BACK";
    case KZT_LAZY_BINDING_UNRECOVERABLE:
        return "UNRECOVERABLE";
    case KZT_LAZY_BINDING_ERROR:
        return "ERROR";
    case KZT_LAZY_BINDING_GUEST_PRESERVED:
        switch (binding_result->reason) {
        case KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED:
            return "SLOT_UNCHANGED";
        case KZT_LAZY_BINDING_REASON_MISSING_VERSION:
            return "MISSING_VERSION";
        default:
            return "GUEST_PRESERVED";
        }
    }

    return "UNKNOWN";
}

static const char *kzt_lazy_diagnostic_reason_name(
    kzt_lazy_binding_reason_t reason)
{
    switch (reason) {
    case KZT_LAZY_BINDING_REASON_NONE:
        return "NONE";
    case KZT_LAZY_BINDING_REASON_DISABLED:
        return "DISABLED";
    case KZT_LAZY_BINDING_REASON_INVALID_REQUEST:
        return "INVALID_REQUEST";
    case KZT_LAZY_BINDING_REASON_PENDING_OCCUPIED:
        return "PENDING_OCCUPIED";
    case KZT_LAZY_BINDING_REASON_GENERATION_CHANGED:
        return "GENERATION_CHANGED";
    case KZT_LAZY_BINDING_REASON_NON_MAIN_NAMESPACE:
        return "NON_MAIN_NAMESPACE";
    case KZT_LAZY_BINDING_REASON_RESOLVER_MISSING:
        return "RESOLVER_MISSING";
    case KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED:
        return "SLOT_UNCHANGED";
    case KZT_LAZY_BINDING_REASON_MISSING_VERSION:
        return "MISSING_VERSION";
    case KZT_LAZY_BINDING_REASON_POST_BIND_INVALID:
        return "POST_BIND_INVALID";
    case KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE:
        return "NATIVE_UNAVAILABLE";
    case KZT_LAZY_BINDING_REASON_NATIVE_APPLIED:
        return "NATIVE_APPLIED";
    case KZT_LAZY_BINDING_REASON_CAS_MISMATCH:
        return "CAS_MISMATCH";
    case KZT_LAZY_BINDING_REASON_SLOT_READ_ERROR:
        return "SLOT_READ_ERROR";
    case KZT_LAZY_BINDING_REASON_CAS_ERROR:
        return "CAS_ERROR";
    case KZT_LAZY_BINDING_REASON_WRITE_ROLLED_BACK:
        return "WRITE_ROLLED_BACK";
    case KZT_LAZY_BINDING_REASON_UNRECOVERABLE:
        return "UNRECOVERABLE";
    }

    return "UNKNOWN";
}

int kzt_lazy_diagnostic_record_build(
    const kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_result_t *binding_result,
    kzt_lazy_diagnostic_record_t *record)
{
    if (!pending || !binding_result || !record) {
        return -1;
    }

    memset(record, 0, sizeof(*record));
    record->schema = KZT_LAZY_DIAGNOSTIC_SCHEMA;
    kzt_lazy_diagnostic_copy_token(record->symbol, sizeof(record->symbol),
                                   pending->symbol);
    kzt_lazy_diagnostic_copy_token(
        record->first_execution_route,
        sizeof(record->first_execution_route), "guest");
    kzt_lazy_diagnostic_copy_token(
        record->completion_route_status,
        sizeof(record->completion_route_status),
        kzt_lazy_diagnostic_status_name(binding_result));
    record->slot_before = pending->unresolved_stub;
    record->slot_after_guest = binding_result->slot_before;
    record->selected_second_target = binding_result->slot_after;
    kzt_lazy_diagnostic_copy_token(record->reason, sizeof(record->reason),
                                   kzt_lazy_diagnostic_reason_name(
                                       binding_result->reason));
    return 0;
}

kzt_lazy_diagnostic_format_status_t kzt_lazy_diagnostic_format(
    const kzt_lazy_diagnostic_record_t *record,
    char *buffer,
    size_t buffer_size)
{
    int written;

    if (!record || !buffer || buffer_size == 0) {
        return KZT_LAZY_DIAGNOSTIC_FORMAT_ERROR;
    }

    written = snprintf(
        buffer, buffer_size,
        "kzt_lazy_diagnostic schema=%lu symbol=%s first_execution_route=%s "
        "completion_route_status=%s slot_before=0x%lx "
        "slot_after_guest=0x%lx selected_second_target=0x%lx reason=%s",
        record->schema, record->symbol, record->first_execution_route,
        record->completion_route_status,
        (unsigned long)record->slot_before,
        (unsigned long)record->slot_after_guest,
        (unsigned long)record->selected_second_target, record->reason);
    if (written < 0) {
        return KZT_LAZY_DIAGNOSTIC_FORMAT_ERROR;
    }
    if ((size_t)written >= buffer_size) {
        return KZT_LAZY_DIAGNOSTIC_FORMAT_TRUNCATED;
    }

    return KZT_LAZY_DIAGNOSTIC_FORMAT_OK;
}

int kzt_lazy_diagnostics_stderr_sink(const char *line,
                                     size_t line_length,
                                     void *opaque)
{
    FILE *stream = opaque ? (FILE *)opaque : stderr;

    if (!line || !stream) {
        return -1;
    }
    if (fwrite(line, 1, line_length, stream) != line_length) {
        return -1;
    }
    if (fputc('\n', stream) == EOF) {
        return -1;
    }
    return fflush(stream);
}

int kzt_lazy_diagnostics_emit(
    const kzt_lazy_diagnostic_input_t *input,
    kzt_lazy_diagnostic_emit_result_t *result)
{
    if (!input || !result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_DIAGNOSTIC_EMIT_DISABLED;
    result->format_status = KZT_LAZY_DIAGNOSTIC_FORMAT_ERROR;
    if (!input->enabled) {
        return 0;
    }
    if (kzt_lazy_diagnostic_record_build(input->pending,
                                         input->binding_result,
                                         &result->record) != 0) {
        result->status = KZT_LAZY_DIAGNOSTIC_EMIT_FORMAT_FAILED;
        return 0;
    }
    result->record_present = 1;
    result->format_status = kzt_lazy_diagnostic_format(
        &result->record, input->buffer, input->buffer_size);
    if (result->format_status == KZT_LAZY_DIAGNOSTIC_FORMAT_TRUNCATED) {
        result->status = KZT_LAZY_DIAGNOSTIC_EMIT_FORMAT_TRUNCATED;
        return 0;
    }
    if (result->format_status != KZT_LAZY_DIAGNOSTIC_FORMAT_OK) {
        result->status = KZT_LAZY_DIAGNOSTIC_EMIT_FORMAT_FAILED;
        return 0;
    }
    if (!input->sink) {
        result->status = KZT_LAZY_DIAGNOSTIC_EMIT_SINK_FAILED;
        result->sink_status = -1;
        return 0;
    }

    result->sink_status = input->sink(input->buffer, strlen(input->buffer),
                                      input->sink_opaque);
    if (result->sink_status != 0) {
        result->status = KZT_LAZY_DIAGNOSTIC_EMIT_SINK_FAILED;
        return 0;
    }

    result->status = KZT_LAZY_DIAGNOSTIC_EMIT_EMITTED;
    return 0;
}

int kzt_lazy_diagnostics_emit_production(
    const kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_result_t *binding_result,
    kzt_lazy_diagnostic_emit_result_t *result)
{
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input;

    memset(&input, 0, sizeof(input));
    input.enabled = 1;
    input.pending = pending;
    input.binding_result = binding_result;
    input.buffer = buffer;
    input.buffer_size = sizeof(buffer);
    input.sink = kzt_lazy_diagnostics_stderr_sink;
    return kzt_lazy_diagnostics_emit(&input, result);
}
