#ifndef KZT_GUEST_DYNAMIC_H
#define KZT_GUEST_DYNAMIC_H

#include <stddef.h>
#include <stdint.h>

#include "elf.h"
#include "kzt_guest_link_map_reader.h"

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

#define KZT_GUEST_DYNAMIC_SCAN_LIMIT 512
#define KZT_GUEST_DYNAMIC_NEEDED_LIMIT 32

typedef enum kzt_guest_dynamic_status {
    KZT_GUEST_DYNAMIC_COMPLETE = 0,
    KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL,
    KZT_GUEST_DYNAMIC_READ_ERROR,
    KZT_GUEST_DYNAMIC_ERROR,
} kzt_guest_dynamic_status_t;

typedef enum kzt_guest_dynamic_error {
    KZT_GUEST_DYNAMIC_ERROR_NONE = 0,
    KZT_GUEST_DYNAMIC_ERROR_INVALID_ARGUMENT,
    KZT_GUEST_DYNAMIC_ERROR_ALLOCATION_FAILURE,
    KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE,
    KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED,
    KZT_GUEST_DYNAMIC_ERROR_TOO_MANY_NEEDED,
} kzt_guest_dynamic_error_t;

typedef enum kzt_guest_dynamic_address_semantics {
    KZT_GUEST_DYNAMIC_ADDRESS_UNKNOWN = 0,
    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS,
    KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET,
    KZT_GUEST_DYNAMIC_SCALAR,
} kzt_guest_dynamic_address_semantics_t;

typedef struct kzt_guest_dynamic_field {
    int present;
    uint64_t value;
    kzt_guest_dynamic_address_semantics_t address_semantics;
} kzt_guest_dynamic_field_t;

typedef struct kzt_guest_dynamic_view {
    uintptr_t dynamic_addr;
    uintptr_t load_bias;
    kzt_guest_dynamic_status_t status;
    size_t entry_count;
    int has_null;
    size_t scan_limit;
    size_t unknown_tag_count;
    int64_t first_unknown_tag;
    size_t first_unknown_tag_index;

    kzt_guest_dynamic_field_t symtab;
    kzt_guest_dynamic_field_t strtab;
    kzt_guest_dynamic_field_t syment;
    kzt_guest_dynamic_field_t strsz;
    kzt_guest_dynamic_field_t hash;
    kzt_guest_dynamic_field_t gnu_hash;
    kzt_guest_dynamic_field_t versym;
    kzt_guest_dynamic_field_t verneed;
    kzt_guest_dynamic_field_t verneednum;
    kzt_guest_dynamic_field_t verdef;
    kzt_guest_dynamic_field_t verdefnum;
    kzt_guest_dynamic_field_t rela;
    kzt_guest_dynamic_field_t relasz;
    kzt_guest_dynamic_field_t relaent;
    kzt_guest_dynamic_field_t rel;
    kzt_guest_dynamic_field_t relsz;
    kzt_guest_dynamic_field_t relent;
    kzt_guest_dynamic_field_t jmprel;
    kzt_guest_dynamic_field_t pltrelsz;
    kzt_guest_dynamic_field_t pltrel;
    kzt_guest_dynamic_field_t pltgot;

    uint64_t needed_offsets[KZT_GUEST_DYNAMIC_NEEDED_LIMIT];
    size_t needed_count;
    kzt_guest_dynamic_address_semantics_t needed_address_semantics;
} kzt_guest_dynamic_view_t;

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
