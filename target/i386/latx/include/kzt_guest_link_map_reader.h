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

typedef struct kzt_guest_link_map_identity {
    uintptr_t load_bias;
    uintptr_t dynamic_addr;
} kzt_guest_link_map_identity_t;

int kzt_guest_link_map_read_identity(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_link_map_identity_t *identity);

int kzt_guest_link_map_identity_matches(
    const kzt_guest_link_map_identity_t *identity,
    uintptr_t expected_load_bias,
    uintptr_t expected_dynamic_addr);

int kzt_guest_link_map_read_predecessor(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *predecessor);

/* Walk the public x86_64 link_map l_prev chain to its exact head.  With a
 * previously confirmed main head, classification is based only on head
 * identity.  Otherwise both l_addr and l_ld must match the main executable.
 * Returns 1 for main, 0 for a complete non-main chain, and -1 when unknown. */
int kzt_guest_link_map_classify_namespace(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_identity_t *main_identity,
    uintptr_t confirmed_main_head,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *namespace_head);

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
