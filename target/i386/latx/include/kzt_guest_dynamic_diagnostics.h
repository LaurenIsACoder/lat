#ifndef KZT_GUEST_DYNAMIC_DIAGNOSTICS_H
#define KZT_GUEST_DYNAMIC_DIAGNOSTICS_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_dynamic.h"

#define KZT_GUEST_DYNAMIC_DIAGNOSTIC_FIELD_LIMIT 32

typedef enum kzt_guest_dynamic_diagnostic_match {
    KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED = 0,
    KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_OLD,
    KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_NEW,
    KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH,
} kzt_guest_dynamic_diagnostic_match_t;

typedef struct kzt_guest_dynamic_diagnostic_field {
    const char *name;
    kzt_guest_dynamic_diagnostic_match_t match;
    int old_present;
    uint64_t old_value;
    kzt_guest_dynamic_address_semantics_t old_address_semantics;
    size_t old_count;
    int new_present;
    uint64_t new_value;
    kzt_guest_dynamic_address_semantics_t new_address_semantics;
    size_t new_count;
} kzt_guest_dynamic_diagnostic_field_t;

typedef struct kzt_guest_dynamic_diagnostic_report {
    kzt_guest_dynamic_status_t old_status;
    kzt_guest_dynamic_status_t new_status;
    kzt_guest_dynamic_error_t old_error;
    kzt_guest_dynamic_error_t new_error;
    uintptr_t old_read_error_addr;
    uintptr_t new_read_error_addr;
    size_t old_entry_count;
    size_t new_entry_count;
    size_t old_unknown_tag_count;
    size_t new_unknown_tag_count;
    int64_t old_first_unknown_tag;
    int64_t new_first_unknown_tag;
    size_t old_first_unknown_tag_index;
    size_t new_first_unknown_tag_index;
    int old_truncated;
    int new_truncated;
    int old_read_error;
    int new_read_error;

    kzt_guest_dynamic_diagnostic_match_t status_match;
    kzt_guest_dynamic_diagnostic_match_t entry_count_match;
    kzt_guest_dynamic_diagnostic_match_t unknown_tags_match;

    size_t field_count;
    size_t matched_count;
    size_t missing_old_count;
    size_t missing_new_count;
    size_t mismatch_count;
    size_t difference_count;
    size_t blocking_count;

    kzt_guest_dynamic_diagnostic_field_t
        fields[KZT_GUEST_DYNAMIC_DIAGNOSTIC_FIELD_LIMIT];
} kzt_guest_dynamic_diagnostic_report_t;

int kzt_guest_dynamic_diagnostics_compare(
    const kzt_guest_dynamic_parse_result_t *old_result,
    const kzt_guest_dynamic_parse_result_t *new_result,
    kzt_guest_dynamic_diagnostic_report_t *report);

const kzt_guest_dynamic_diagnostic_field_t *
kzt_guest_dynamic_diagnostic_find_field(
    const kzt_guest_dynamic_diagnostic_report_t *report,
    const char *name);

#endif
