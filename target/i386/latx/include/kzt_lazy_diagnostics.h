#ifndef KZT_LAZY_DIAGNOSTICS_H
#define KZT_LAZY_DIAGNOSTICS_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_lazy_binding.h"

#define KZT_LAZY_DIAGNOSTIC_SYMBOL_LIMIT KZT_LAZY_BINDING_SYMBOL_MAX
#define KZT_LAZY_DIAGNOSTIC_ROUTE_LIMIT 64
#define KZT_LAZY_DIAGNOSTIC_REASON_LIMIT 64
#define KZT_LAZY_DIAGNOSTIC_LINE_LIMIT 1024

typedef enum kzt_lazy_diagnostic_format_status {
    KZT_LAZY_DIAGNOSTIC_FORMAT_ERROR = -1,
    KZT_LAZY_DIAGNOSTIC_FORMAT_OK = 0,
    KZT_LAZY_DIAGNOSTIC_FORMAT_TRUNCATED,
} kzt_lazy_diagnostic_format_status_t;

typedef enum kzt_lazy_diagnostic_emit_status {
    KZT_LAZY_DIAGNOSTIC_EMIT_DISABLED = 0,
    KZT_LAZY_DIAGNOSTIC_EMIT_EMITTED,
    KZT_LAZY_DIAGNOSTIC_EMIT_FORMAT_FAILED,
    KZT_LAZY_DIAGNOSTIC_EMIT_FORMAT_TRUNCATED,
    KZT_LAZY_DIAGNOSTIC_EMIT_SINK_FAILED,
} kzt_lazy_diagnostic_emit_status_t;

typedef struct kzt_lazy_diagnostic_record {
    unsigned long schema;
    char symbol[KZT_LAZY_DIAGNOSTIC_SYMBOL_LIMIT];
    char first_execution_route[KZT_LAZY_DIAGNOSTIC_ROUTE_LIMIT];
    char completion_route_status[KZT_LAZY_DIAGNOSTIC_ROUTE_LIMIT];
    uintptr_t slot_before;
    uintptr_t slot_after_guest;
    uintptr_t selected_second_target;
    char reason[KZT_LAZY_DIAGNOSTIC_REASON_LIMIT];
} kzt_lazy_diagnostic_record_t;

typedef int (*kzt_lazy_diagnostic_sink_fn)(const char *line,
                                           size_t line_length,
                                           void *opaque);

typedef struct kzt_lazy_diagnostic_input {
    int enabled;
    const kzt_lazy_binding_pending_t *pending;
    const kzt_lazy_binding_result_t *binding_result;
    char *buffer;
    size_t buffer_size;
    kzt_lazy_diagnostic_sink_fn sink;
    void *sink_opaque;
} kzt_lazy_diagnostic_input_t;

typedef struct kzt_lazy_diagnostic_emit_result {
    kzt_lazy_diagnostic_emit_status_t status;
    int record_present;
    kzt_lazy_diagnostic_record_t record;
    kzt_lazy_diagnostic_format_status_t format_status;
    int sink_status;
} kzt_lazy_diagnostic_emit_result_t;

int kzt_lazy_diagnostic_record_build(
    const kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_result_t *binding_result,
    kzt_lazy_diagnostic_record_t *record);

kzt_lazy_diagnostic_format_status_t kzt_lazy_diagnostic_format(
    const kzt_lazy_diagnostic_record_t *record,
    char *buffer,
    size_t buffer_size);

int kzt_lazy_diagnostics_stderr_sink(const char *line,
                                     size_t line_length,
                                     void *opaque);

int kzt_lazy_diagnostics_emit(
    const kzt_lazy_diagnostic_input_t *input,
    kzt_lazy_diagnostic_emit_result_t *result);

int kzt_lazy_diagnostics_emit_production(
    const kzt_lazy_binding_pending_t *pending,
    const kzt_lazy_binding_result_t *binding_result,
    kzt_lazy_diagnostic_emit_result_t *result);

#endif
