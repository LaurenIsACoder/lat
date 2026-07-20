#ifndef KZT_GUEST_DYNAMIC_H
#define KZT_GUEST_DYNAMIC_H

#include <stddef.h>
#include <stdint.h>

#include "elf.h"
#include "kzt_guest_dynamic_view.h"
#include "kzt_guest_link_map_reader.h"

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif


typedef enum kzt_guest_dynamic_error {
    KZT_GUEST_DYNAMIC_ERROR_NONE = 0,
    KZT_GUEST_DYNAMIC_ERROR_INVALID_ARGUMENT,
    KZT_GUEST_DYNAMIC_ERROR_ALLOCATION_FAILURE,
    KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE,
    KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED,
    KZT_GUEST_DYNAMIC_ERROR_TOO_MANY_NEEDED,
} kzt_guest_dynamic_error_t;

typedef struct kzt_guest_dynamic_parse_result {
    kzt_guest_dynamic_status_t status;
    kzt_guest_dynamic_error_t error;
    size_t entry_count;
    uintptr_t read_error_addr;
    size_t scan_limit;
    size_t unknown_tag_count;
    int64_t first_unknown_tag;
    size_t first_unknown_tag_index;
    kzt_guest_dynamic_view_t view;
} kzt_guest_dynamic_parse_result_t;

int kzt_guest_dynamic_parse(
    uintptr_t dynamic_addr,
    uintptr_t load_bias,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_dynamic_parse_result_t *result);

void kzt_guest_dynamic_view_destroy(kzt_guest_dynamic_view_t *view);
void kzt_guest_dynamic_parse_result_clear(
    kzt_guest_dynamic_parse_result_t *result);

#endif
