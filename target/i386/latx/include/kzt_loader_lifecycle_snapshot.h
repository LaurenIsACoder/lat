#ifndef KZT_LOADER_LIFECYCLE_SNAPSHOT_H
#define KZT_LOADER_LIFECYCLE_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_link_map_reader.h"
#include "kzt_loader_event_hook.h"

#define KZT_LOADER_LIFECYCLE_SNAPSHOT_INLINE_MAPS 64

typedef enum kzt_loader_lifecycle_snapshot_result {
    KZT_LOADER_LIFECYCLE_SNAPSHOT_OK = 0,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_INPUT,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_READ_ERROR,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_STATE,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_CYCLE,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_NAMESPACE,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_ALLOCATION,
    KZT_LOADER_LIFECYCLE_SNAPSHOT_OVERFLOW,
} kzt_loader_lifecycle_snapshot_result_t;

typedef struct kzt_loader_lifecycle_snapshot {
    kzt_loader_debug_state_t state;
    kzt_loader_lifecycle_snapshot_result_t result;
    uintptr_t *live_maps;
    size_t live_map_count;
    size_t live_map_capacity;
    uintptr_t inline_live_maps[
        KZT_LOADER_LIFECYCLE_SNAPSHOT_INLINE_MAPS];
} kzt_loader_lifecycle_snapshot_t;

/* The caller owns the token.  Initialize it before first capture and call
 * release after every successful or failed capture before reusing it. */
int kzt_loader_lifecycle_snapshot_capture(
    kzt_guest_registry_t *registry,
    uintptr_t r_debug_addr,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_loader_lifecycle_snapshot_t *snapshot);

void kzt_loader_lifecycle_snapshot_release(
    kzt_loader_lifecycle_snapshot_t *snapshot);

const char *kzt_loader_lifecycle_snapshot_result_name(
    kzt_loader_lifecycle_snapshot_result_t result);

#ifdef KZT_LOADER_LIFECYCLE_SNAPSHOT_TEST
void kzt_loader_lifecycle_snapshot_test_set_alloc_failure_after(
    long allocations);
#endif

#endif
