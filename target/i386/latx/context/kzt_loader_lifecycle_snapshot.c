#include "kzt_loader_lifecycle_snapshot.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define KZT_LOADER_LIFECYCLE_DEBUG_NODES 16

typedef struct kzt_r_debug_extended_x64 {
    int32_t version;
    int32_t version_padding;
    uintptr_t map;
    uintptr_t brk;
    int32_t state;
    int32_t state_padding;
    uintptr_t loader_base;
    uintptr_t next;
} kzt_r_debug_extended_x64_t;

typedef struct kzt_link_map_chain_x64 {
    uintptr_t load_bias;
    uintptr_t name;
    uintptr_t dynamic_addr;
    uintptr_t next;
    uintptr_t previous;
} kzt_link_map_chain_x64_t;

#ifdef KZT_LOADER_LIFECYCLE_SNAPSHOT_TEST
static long snapshot_fail_after = -1;

void kzt_loader_lifecycle_snapshot_test_set_alloc_failure_after(
    long allocations)
{
    snapshot_fail_after = allocations;
}
#endif

static void *kzt_loader_lifecycle_snapshot_alloc(size_t size)
{
#ifdef KZT_LOADER_LIFECYCLE_SNAPSHOT_TEST
    if (snapshot_fail_after == 0) {
        return NULL;
    }
    if (snapshot_fail_after > 0) {
        --snapshot_fail_after;
    }
#endif
    return malloc(size);
}

static int kzt_loader_lifecycle_snapshot_fail(
    kzt_loader_lifecycle_snapshot_t *snapshot,
    kzt_loader_lifecycle_snapshot_result_t result)
{
    if (snapshot->live_maps &&
        snapshot->live_maps != snapshot->inline_live_maps) {
        free(snapshot->live_maps);
    }
    snapshot->state = KZT_LOADER_DEBUG_CONSISTENT;
    snapshot->result = result;
    snapshot->live_maps = snapshot->inline_live_maps;
    snapshot->live_map_count = 0;
    snapshot->live_map_capacity =
        KZT_LOADER_LIFECYCLE_SNAPSHOT_INLINE_MAPS;
    return -1;
}

static int kzt_loader_lifecycle_snapshot_grow(
    kzt_loader_lifecycle_snapshot_t *snapshot)
{
    uintptr_t *maps;
    size_t capacity;
    size_t bytes;

    if (snapshot->live_map_capacity > SIZE_MAX / 2) {
        return kzt_loader_lifecycle_snapshot_fail(
            snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_OVERFLOW);
    }
    capacity = snapshot->live_map_capacity * 2;
    if (capacity > SIZE_MAX / sizeof(*maps)) {
        return kzt_loader_lifecycle_snapshot_fail(
            snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_OVERFLOW);
    }
    bytes = capacity * sizeof(*maps);
    maps = kzt_loader_lifecycle_snapshot_alloc(bytes);
    if (!maps) {
        return kzt_loader_lifecycle_snapshot_fail(
            snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_ALLOCATION);
    }
    memcpy(maps, snapshot->live_maps,
           snapshot->live_map_count * sizeof(*maps));
    if (snapshot->live_maps != snapshot->inline_live_maps) {
        free(snapshot->live_maps);
    }
    snapshot->live_maps = maps;
    snapshot->live_map_capacity = capacity;
    return 0;
}

static int kzt_loader_lifecycle_snapshot_append(
    kzt_loader_lifecycle_snapshot_t *snapshot,
    uintptr_t link_map_addr)
{
    if (snapshot->live_map_count == snapshot->live_map_capacity &&
        kzt_loader_lifecycle_snapshot_grow(snapshot) != 0) {
        return -1;
    }
    snapshot->live_maps[snapshot->live_map_count++] = link_map_addr;
    return 0;
}

static int kzt_loader_lifecycle_snapshot_supplement_namespaces(
    kzt_guest_registry_t *registry,
    const uintptr_t *live_maps,
    const size_t group_starts[KZT_LOADER_LIFECYCLE_DEBUG_NODES],
    const size_t group_counts[KZT_LOADER_LIFECYCLE_DEBUG_NODES],
    size_t group_count)
{
    size_t group;

    for (group = 0; group < group_count; ++group) {
        uintptr_t namespace_id = 0;
        int namespace_known = group == 0;
        size_t end = group_starts[group] + group_counts[group];
        size_t index;

        for (index = group_starts[group]; index < end; ++index) {
            kzt_guest_registry_address_match_t match = { 0 };

            if (kzt_guest_registry_find_live_object(
                    registry, live_maps[index], &match) != 0 ||
                match.namespace_id_status != KZT_GUEST_FIELD_OK) {
                continue;
            }
            if (namespace_known && namespace_id != match.namespace_id) {
                return -1;
            }
            namespace_id = match.namespace_id;
            namespace_known = 1;
        }
        if (!namespace_known) {
            continue;
        }
        for (index = group_starts[group]; index < end; ++index) {
            kzt_guest_registry_address_match_t match = { 0 };
            kzt_guest_registry_result_t result;

            if (kzt_guest_registry_find_live_object(
                    registry, live_maps[index], &match) != 0) {
                continue;
            }
            if (match.namespace_id_status == KZT_GUEST_FIELD_OK) {
                if (match.namespace_id != namespace_id) {
                    return -1;
                }
                continue;
            }
            result = kzt_guest_registry_supplement_namespace(
                registry, live_maps[index], match.generation,
                namespace_id);
            if (result != KZT_GUEST_REGISTRY_UPDATED &&
                result != KZT_GUEST_REGISTRY_UNCHANGED) {
                return -1;
            }
        }
    }
    return 0;
}

int kzt_loader_lifecycle_snapshot_capture(
    kzt_guest_registry_t *registry,
    uintptr_t r_debug_addr,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_loader_lifecycle_snapshot_t *snapshot)
{
    uintptr_t debug_nodes[KZT_LOADER_LIFECYCLE_DEBUG_NODES] = { 0 };
    size_t group_starts[KZT_LOADER_LIFECYCLE_DEBUG_NODES] = { 0 };
    size_t group_counts[KZT_LOADER_LIFECYCLE_DEBUG_NODES] = { 0 };
    uintptr_t debug_addr;
    size_t debug_count = 0;
    int active_state = KZT_LOADER_DEBUG_CONSISTENT;

    if (!snapshot) {
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->live_maps = snapshot->inline_live_maps;
    snapshot->live_map_capacity =
        KZT_LOADER_LIFECYCLE_SNAPSHOT_INLINE_MAPS;
    snapshot->result = KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_INPUT;
    if (!registry || !r_debug_addr || !reader_ops ||
        !reader_ops->read_memory) {
        return -1;
    }

    debug_addr = r_debug_addr;
    while (debug_addr) {
        kzt_r_debug_extended_x64_t debug;
        uintptr_t map_addr;
        size_t index;

        if (debug_count == KZT_LOADER_LIFECYCLE_DEBUG_NODES) {
            return kzt_loader_lifecycle_snapshot_fail(
                snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_CYCLE);
        }
        if (reader_ops->read_memory(
                debug_addr, &debug, sizeof(debug), reader_ops->opaque) != 0) {
            return kzt_loader_lifecycle_snapshot_fail(
                snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_READ_ERROR);
        }
        if (debug.state < KZT_LOADER_DEBUG_CONSISTENT ||
            debug.state > KZT_LOADER_DEBUG_DELETE) {
            return kzt_loader_lifecycle_snapshot_fail(
                snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_STATE);
        }
        for (index = 0; index < debug_count; ++index) {
            if (debug_nodes[index] == debug_addr) {
                return kzt_loader_lifecycle_snapshot_fail(
                    snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_CYCLE);
            }
        }
        debug_nodes[debug_count] = debug_addr;
        group_starts[debug_count] = snapshot->live_map_count;
        ++debug_count;
        if (debug.state != KZT_LOADER_DEBUG_CONSISTENT) {
            if (active_state != KZT_LOADER_DEBUG_CONSISTENT &&
                active_state != debug.state) {
                return kzt_loader_lifecycle_snapshot_fail(
                    snapshot,
                    KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_STATE);
            }
            active_state = debug.state;
        }

        map_addr = debug.map;
        while (map_addr) {
            kzt_link_map_chain_x64_t map;

            if (reader_ops->read_memory(
                    map_addr, &map, sizeof(map), reader_ops->opaque) != 0) {
                return kzt_loader_lifecycle_snapshot_fail(
                    snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_READ_ERROR);
            }
            for (index = 0; index < snapshot->live_map_count; ++index) {
                if (snapshot->live_maps[index] == map_addr) {
                    return kzt_loader_lifecycle_snapshot_fail(
                        snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_CYCLE);
                }
            }
            if (kzt_loader_lifecycle_snapshot_append(
                    snapshot, map_addr) != 0) {
                return -1;
            }
            map_addr = map.next;
        }
        group_counts[debug_count - 1] =
            snapshot->live_map_count - group_starts[debug_count - 1];
        debug_addr = debug.next;
    }
    if (!debug_count) {
        return kzt_loader_lifecycle_snapshot_fail(
            snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_INPUT);
    }
    if (active_state == KZT_LOADER_DEBUG_DELETE &&
        kzt_loader_lifecycle_snapshot_supplement_namespaces(
            registry, snapshot->live_maps, group_starts, group_counts,
            debug_count) != 0) {
        return kzt_loader_lifecycle_snapshot_fail(
            snapshot, KZT_LOADER_LIFECYCLE_SNAPSHOT_NAMESPACE);
    }
    snapshot->state = active_state;
    snapshot->result = KZT_LOADER_LIFECYCLE_SNAPSHOT_OK;
    return 0;
}

void kzt_loader_lifecycle_snapshot_release(
    kzt_loader_lifecycle_snapshot_t *snapshot)
{
    if (!snapshot) {
        return;
    }
    if (snapshot->live_maps &&
        snapshot->live_maps != snapshot->inline_live_maps) {
        free(snapshot->live_maps);
    }
    memset(snapshot, 0, sizeof(*snapshot));
}

const char *kzt_loader_lifecycle_snapshot_result_name(
    kzt_loader_lifecycle_snapshot_result_t result)
{
    switch (result) {
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_OK:
        return "OK";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_INPUT:
        return "INVALID_INPUT";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_READ_ERROR:
        return "READ_ERROR";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_INVALID_STATE:
        return "INVALID_STATE";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_CYCLE:
        return "CYCLE";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_NAMESPACE:
        return "NAMESPACE";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_ALLOCATION:
        return "ALLOCATION";
    case KZT_LOADER_LIFECYCLE_SNAPSHOT_OVERFLOW:
        return "OVERFLOW";
    }
    return "INVALID";
}
