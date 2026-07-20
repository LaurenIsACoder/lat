#ifndef KZT_RELA_DIAGNOSTICS_H
#define KZT_RELA_DIAGNOSTICS_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_rela_immediate_candidate.h"

#define KZT_RELA_DIAGNOSTIC_SOURCE_LIMIT 256
#define KZT_RELA_DIAGNOSTIC_NAME_LIMIT 64
#define KZT_RELA_DIAGNOSTIC_LINE_LIMIT 1024

typedef enum kzt_rela_diagnostic_mode {
    KZT_RELA_DIAGNOSTIC_MODE_DEFAULT = 0,
    KZT_RELA_DIAGNOSTIC_MODE_WRITE_ENABLED_ONLY,
    KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS,
    KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
} kzt_rela_diagnostic_mode_t;

typedef enum kzt_rela_diagnostic_reason_domain {
    KZT_RELA_DIAGNOSTIC_REASON_CANDIDATE = 0,
    KZT_RELA_DIAGNOSTIC_REASON_PLANNER,
    KZT_RELA_DIAGNOSTIC_REASON_WRITER,
} kzt_rela_diagnostic_reason_domain_t;

typedef enum kzt_rela_diagnostic_format_status {
    KZT_RELA_DIAGNOSTIC_FORMAT_ERROR = -1,
    KZT_RELA_DIAGNOSTIC_FORMAT_OK = 0,
    KZT_RELA_DIAGNOSTIC_FORMAT_TRUNCATED,
} kzt_rela_diagnostic_format_status_t;

typedef enum kzt_rela_diagnostic_emit_status {
    KZT_RELA_DIAGNOSTIC_EMIT_DISABLED = 0,
    KZT_RELA_DIAGNOSTIC_EMIT_EMITTED,
    KZT_RELA_DIAGNOSTIC_EMIT_SUPPRESSED,
    KZT_RELA_DIAGNOSTIC_EMIT_THROTTLE_FAILED,
    KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_FAILED,
    KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_TRUNCATED,
    KZT_RELA_DIAGNOSTIC_EMIT_SINK_FAILED,
} kzt_rela_diagnostic_emit_status_t;

typedef struct kzt_rela_diagnostic_record {
    char source[KZT_RELA_DIAGNOSTIC_SOURCE_LIMIT];
    uintptr_t source_link_map;
    uintptr_t current_owner;
    unsigned long source_generation;
    unsigned long current_owner_generation;
    kzt_patch_owner_match_t owner_match;
    kzt_patch_wrapper_match_t wrapper_match;
    uintptr_t bridge_target;
    char symbol[KZT_RELA_DIAGNOSTIC_NAME_LIMIT];
    char version[KZT_RELA_DIAGNOSTIC_NAME_LIMIT];
    kzt_rela_diagnostic_reason_domain_t reason_domain;
    char reason[KZT_RELA_DIAGNOSTIC_NAME_LIMIT];
    char decision[KZT_RELA_DIAGNOSTIC_NAME_LIMIT];
    char writer_result[KZT_RELA_DIAGNOSTIC_NAME_LIMIT];
    int legacy_fallback;
} kzt_rela_diagnostic_record_t;

/*
 * Initialize before publishing to other threads. Capacity is immutable after
 * initialization. The embedded lock serializes counter updates and snapshots;
 * callers must not mutate the fields directly after publication.
 */
typedef struct kzt_rela_diagnostic_throttle {
    unsigned long capacity;
    unsigned long admitted;
    unsigned long suppressed;
    unsigned int lock;
    unsigned int initialized;
} kzt_rela_diagnostic_throttle_t;

typedef struct kzt_rela_diagnostic_throttle_snapshot {
    unsigned long capacity;
    unsigned long admitted;
    unsigned long suppressed;
} kzt_rela_diagnostic_throttle_snapshot_t;

typedef int (*kzt_rela_diagnostic_sink_fn)(const char *line,
                                          size_t line_length,
                                          void *opaque);

/*
 * The adapter only consumes caller-owned request/result snapshots. It copies
 * text into the record and invokes the sink synchronously; it never probes,
 * plans, creates bridges, writes a slot, or applies legacy fallback.
 */
typedef struct kzt_rela_immediate_diagnostic_input {
    kzt_rela_diagnostic_mode_t mode;
    const kzt_rela_immediate_candidate_request_t *request;
    const kzt_rela_immediate_writer_result_t *result;
    int legacy_fallback;
    kzt_rela_diagnostic_throttle_t *throttle;
    char *buffer;
    size_t buffer_size;
    kzt_rela_diagnostic_sink_fn sink;
    void *sink_opaque;
} kzt_rela_immediate_diagnostic_input_t;

typedef struct kzt_rela_immediate_diagnostic_result {
    kzt_rela_diagnostic_emit_status_t status;
    int record_present;
    kzt_rela_diagnostic_record_t record;
    kzt_rela_diagnostic_format_status_t format_status;
    int sink_status;
} kzt_rela_immediate_diagnostic_result_t;

kzt_rela_diagnostic_mode_t kzt_rela_diagnostic_mode_from_flags(
    int diagnostics_enabled,
    int write_enabled);

const char *kzt_rela_diagnostic_reason_domain_name(
    kzt_rela_diagnostic_reason_domain_t domain);

int kzt_rela_immediate_diagnostic_record(
    kzt_rela_diagnostic_mode_t mode,
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_immediate_writer_result_t *result,
    int legacy_fallback,
    kzt_rela_diagnostic_record_t *record);

kzt_rela_diagnostic_format_status_t kzt_rela_diagnostic_format(
    const kzt_rela_diagnostic_record_t *record,
    char *buffer,
    size_t buffer_size);

int kzt_rela_diagnostic_throttle_init(
    kzt_rela_diagnostic_throttle_t *throttle,
    unsigned long capacity);
int kzt_rela_diagnostic_throttle_try_admit(
    kzt_rela_diagnostic_throttle_t *throttle);
int kzt_rela_diagnostic_throttle_snapshot(
    kzt_rela_diagnostic_throttle_t *throttle,
    kzt_rela_diagnostic_throttle_snapshot_t *snapshot);

int kzt_rela_immediate_diagnostic_emit(
    const kzt_rela_immediate_diagnostic_input_t *input,
    kzt_rela_immediate_diagnostic_result_t *result);

#endif
