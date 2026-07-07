#ifndef KZT_RUNTIME_GOT_PLT_CANDIDATE_H
#define KZT_RUNTIME_GOT_PLT_CANDIDATE_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_dynamic_view.h"
#include "kzt_guest_link_map_reader.h"
#include "kzt_patch_planner.h"

typedef enum kzt_runtime_got_plt_candidate_status {
    KZT_RUNTIME_GOT_PLT_CANDIDATE_OK = 0,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_FAIL_OPEN,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_ERROR,
} kzt_runtime_got_plt_candidate_status_t;

typedef enum kzt_runtime_got_plt_candidate_reason {
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_NONE = 0,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_INVALID_ARGUMENT,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DYNAMIC_VIEW_UNAVAILABLE,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_TABLE_OVERFLOW,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_RELOCATION_READ_FAILED,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_OVERFLOW,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_READ_FAILED,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SYMBOL_READ_FAILED,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_NAME,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_VERSION_READ_FAILED,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION,
    KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_CAPACITY_EXCEEDED,
} kzt_runtime_got_plt_candidate_reason_t;

typedef struct kzt_runtime_got_plt_candidate_request {
    const kzt_guest_dynamic_view_t *view;
    const kzt_guest_link_map_reader_ops_t *reader_ops;
    const kzt_patch_object_ref_t *source;
    unsigned long dynamic_view_generation;
    kzt_patch_candidate_t *candidates;
    size_t candidate_capacity;
    char *string_storage;
    size_t string_storage_size;
} kzt_runtime_got_plt_candidate_request_t;

typedef struct kzt_runtime_got_plt_candidate_result {
    kzt_runtime_got_plt_candidate_status_t status;
    kzt_runtime_got_plt_candidate_reason_t reason;
    int patch_reason_present;
    kzt_patch_reason_t patch_reason;
    size_t candidate_count;
    kzt_patch_table_kind_t table_kind;
    size_t entry_index;
    uintptr_t entry_addr;
    uintptr_t slot_addr;
    uintptr_t read_error_addr;
} kzt_runtime_got_plt_candidate_result_t;

int kzt_runtime_got_plt_candidates_collect(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result);

const char *kzt_runtime_got_plt_candidate_status_name(
    kzt_runtime_got_plt_candidate_status_t status);

const char *kzt_runtime_got_plt_candidate_reason_name(
    kzt_runtime_got_plt_candidate_reason_t reason);

#endif
