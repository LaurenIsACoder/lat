#ifndef KZT_GUEST_LINK_MAP_READER_H
#define KZT_GUEST_LINK_MAP_READER_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_registry.h"

#define KZT_GUEST_LINK_MAP_NAME_LIMIT 4096

typedef int (*kzt_guest_memory_read_fn)(uintptr_t guest_addr,
                                        void *dst,
                                        size_t size,
                                        void *opaque);

typedef struct kzt_guest_link_map_reader_ops {
    kzt_guest_memory_read_fn read_memory;
    void *opaque;
} kzt_guest_link_map_reader_ops_t;

int kzt_guest_link_map_read_name_snapshot(
    uintptr_t guest_name_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    size_t max_len,
    kzt_guest_string_field_t *name);

int kzt_guest_link_map_read_observation(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_object_observation_t *observation);

void kzt_guest_link_map_observation_clear(
    kzt_guest_object_observation_t *observation);

void kzt_guest_link_map_string_clear(kzt_guest_string_field_t *field);

#ifdef KZT_GUEST_LINK_MAP_READER_TEST
void kzt_guest_link_map_reader_test_set_alloc_failure_after(long allocations);
#endif

#endif
