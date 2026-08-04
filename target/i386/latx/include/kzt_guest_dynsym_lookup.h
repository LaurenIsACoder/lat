#ifndef KZT_GUEST_DYNSYM_LOOKUP_H
#define KZT_GUEST_DYNSYM_LOOKUP_H

#include <stdint.h>

#include "kzt_guest_dynamic_view.h"
#include "kzt_guest_link_map_reader.h"
#include "kzt_patch_planner.h"

enum {
    KZT_ELF_STB_GNU_UNIQUE = 10,
    KZT_ELF_STT_GNU_IFUNC = 10,
};

typedef enum kzt_guest_dynsym_lookup_status {
    KZT_GUEST_DYNSYM_LOOKUP_FOUND = 0,
    KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND,
    KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN,
} kzt_guest_dynsym_lookup_status_t;

typedef struct kzt_guest_dynsym_lookup_result {
    kzt_guest_dynsym_lookup_status_t status;
    unsigned char binding;
    unsigned char type;
    unsigned char visibility;
    uint32_t symbol_index;
    uintptr_t runtime_address;
} kzt_guest_dynsym_lookup_result_t;

kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_lookup(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    kzt_guest_dynsym_lookup_result_t *result);

#endif
