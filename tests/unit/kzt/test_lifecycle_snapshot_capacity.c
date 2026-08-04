#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kzt_guest_registry.h"
#include "kzt_loader_event_hook.h"
#include "kzt_loader_lifecycle_snapshot.h"

#define LIVE_MAP_COUNT 1025

#define CHECK(name, condition)                                                \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s\n", name);                             \
            exit(EXIT_FAILURE);                                                \
        }                                                                      \
    } while (0)

typedef struct test_r_debug_extended_x64 {
    int32_t version;
    int32_t version_padding;
    uintptr_t map;
    uintptr_t brk;
    int32_t state;
    int32_t state_padding;
    uintptr_t loader_base;
    uintptr_t next;
} test_r_debug_extended_x64_t;

typedef struct test_link_map_chain_x64 {
    uintptr_t load_bias;
    uintptr_t name;
    uintptr_t dynamic_addr;
    uintptr_t next;
    uintptr_t previous;
} test_link_map_chain_x64_t;

typedef struct read_fixture {
    test_link_map_chain_x64_t *maps;
    size_t map_count;
    size_t map_reads;
} read_fixture_t;

typedef struct lifecycle_fixture {
    kzt_guest_registry_t *registry;
    size_t prepare_calls;
    size_t cancel_calls;
    size_t unload_calls;
    kzt_loader_lifecycle_identity_t unloaded;
} lifecycle_fixture_t;

static int read_memory(uintptr_t address, void *dst, size_t size, void *opaque)
{
    read_fixture_t *fixture = opaque;
    uintptr_t first = (uintptr_t)fixture->maps;
    uintptr_t end = first + fixture->map_count * sizeof(*fixture->maps);

    if (!address || !dst || !size) {
        return -1;
    }
    if (address >= first && address < end &&
        size == sizeof(*fixture->maps)) {
        ++fixture->map_reads;
    }
    memcpy(dst, (const void *)address, size);
    return 0;
}

static kzt_guest_object_observation_t observation_for(uintptr_t link_map_addr)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { link_map_addr + 0x1000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { link_map_addr + 0x2000, KZT_GUEST_FIELD_OK },
        .map_start = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libsnapshot.so", KZT_GUEST_FIELD_OK },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static int resolve_identity(
    uintptr_t link_map_addr,
    kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;
    kzt_guest_loader_identity_t resolved = { 0 };

    if (kzt_guest_registry_find_loader_object_identity(
            fixture->registry, link_map_addr, &resolved) != 0) {
        return -1;
    }
    *identity = (kzt_loader_lifecycle_identity_t) {
        .link_map_addr = resolved.link_map_addr,
        .generation = resolved.generation,
        .namespace_id = resolved.namespace_id,
    };
    return 0;
}

static int prepare_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;
    kzt_guest_loader_identity_t unload = {
        .link_map_addr = identity->link_map_addr,
        .generation = identity->generation,
        .namespace_id = identity->namespace_id,
    };

    if (kzt_guest_registry_begin_loader_unload(
            fixture->registry, &unload) != 0) {
        return -1;
    }
    ++fixture->prepare_calls;
    return 0;
}

static int cancel_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;
    kzt_guest_loader_identity_t unload = {
        .link_map_addr = identity->link_map_addr,
        .generation = identity->generation,
        .namespace_id = identity->namespace_id,
    };

    if (kzt_guest_registry_cancel_loader_unload(
            fixture->registry, &unload) != 0) {
        return -1;
    }
    ++fixture->cancel_calls;
    return 0;
}

static int finish_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;
    int status;
    kzt_guest_loader_identity_t unload = {
        .link_map_addr = identity->link_map_addr,
        .generation = identity->generation,
        .namespace_id = identity->namespace_id,
    };

    status = kzt_guest_registry_finish_loader_unload(
        fixture->registry, &unload);
    CHECK("finish loader unload", status == 0);
    if (status != 0) {
        return -1;
    }
    fixture->unloaded = *identity;
    ++fixture->unload_calls;
    return 0;
}

static void link_maps(test_link_map_chain_x64_t *maps, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        maps[index] = (test_link_map_chain_x64_t) {
            .load_bias = 0x100000 + index * 0x10000,
            .dynamic_addr = 0x101000 + index * 0x10000,
            .next = index + 1 < count ? (uintptr_t)&maps[index + 1] : 0,
            .previous = index ? (uintptr_t)&maps[index - 1] : 0,
        };
    }
}

static void test_allocation_failure_is_observable(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    test_link_map_chain_x64_t maps[
        KZT_LOADER_LIFECYCLE_SNAPSHOT_INLINE_MAPS + 1];
    test_r_debug_extended_x64_t debug = {
        .version = 1,
        .state = KZT_LOADER_DEBUG_CONSISTENT,
        .map = (uintptr_t)maps,
    };
    read_fixture_t reads = {
        .maps = maps,
        .map_count = sizeof(maps) / sizeof(maps[0]),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = read_memory,
        .opaque = &reads,
    };
    kzt_loader_lifecycle_snapshot_t snapshot = { 0 };

    CHECK("allocation registry", registry != NULL);
    link_maps(maps, reads.map_count);
    kzt_loader_lifecycle_snapshot_test_set_alloc_failure_after(0);
    CHECK("allocation capture fails",
          kzt_loader_lifecycle_snapshot_capture(
              registry, (uintptr_t)&debug, &reader_ops, &snapshot) != 0);
    CHECK("allocation result observable",
          snapshot.result == KZT_LOADER_LIFECYCLE_SNAPSHOT_ALLOCATION);
    CHECK("allocation count cleared", snapshot.live_map_count == 0);
    kzt_loader_lifecycle_snapshot_test_set_alloc_failure_after(-1);
    kzt_loader_lifecycle_snapshot_release(&snapshot);
    kzt_guest_registry_destroy(&registry);
}

static void test_1025_maps_complete_lifecycle_and_reuse(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    test_link_map_chain_x64_t *maps =
        calloc(LIVE_MAP_COUNT, sizeof(*maps));
    test_r_debug_extended_x64_t debug = {
        .version = 1,
        .state = KZT_LOADER_DEBUG_DELETE,
        .map = (uintptr_t)maps,
    };
    read_fixture_t reads = {
        .maps = maps,
        .map_count = LIVE_MAP_COUNT,
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = read_memory,
        .opaque = &reads,
    };
    kzt_loader_lifecycle_snapshot_t snapshot = { 0 };
    kzt_loader_event_hook_t hook;
    lifecycle_fixture_t lifecycle = { .registry = registry };
    kzt_guest_loader_identity_t old_identity = { 0 };
    kzt_guest_object_snapshot_t *reused = NULL;
    kzt_guest_registry_dump_t dump = { 0 };
    uintptr_t reused_addr;
    size_t index;
    int found_dead = 0;

    CHECK("capacity registry", registry != NULL);
    CHECK("capacity maps", maps != NULL);
    if (!registry || !maps) {
        free(maps);
        kzt_guest_registry_destroy(&registry);
        return;
    }
    link_maps(maps, LIVE_MAP_COUNT);
    for (index = 0; index < LIVE_MAP_COUNT; ++index) {
        kzt_guest_object_observation_t observation =
            observation_for((uintptr_t)&maps[index]);

        CHECK("observe live map",
              kzt_guest_registry_observe(registry, &observation) ==
                  KZT_GUEST_REGISTRY_ADDED);
    }
    reused_addr = (uintptr_t)&maps[LIVE_MAP_COUNT - 1];
    CHECK("old identity",
          kzt_guest_registry_find_loader_object_identity(
              registry, reused_addr, &old_identity) == 0);
    CHECK("install lifecycle hook",
          kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID,
              0x1000, 3, 1) == 0);
    CHECK("enable lifecycle hook",
          kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, (uintptr_t)&debug) == 0);

    CHECK("capture 1025 DELETE maps",
          kzt_loader_lifecycle_snapshot_capture(
              registry, (uintptr_t)&debug, &reader_ops, &snapshot) == 0);
    CHECK("read all 1025 link maps", reads.map_reads == LIVE_MAP_COUNT);
    CHECK("snapshot contains 1025 maps",
          snapshot.live_map_count == LIVE_MAP_COUNT);
    CHECK("snapshot DELETE state",
          snapshot.state == KZT_LOADER_DEBUG_DELETE);
    CHECK("publish 1025 DELETE maps",
          kzt_loader_event_hook_publish_lifecycle(
              &hook, snapshot.state, snapshot.live_maps,
              snapshot.live_map_count, resolve_identity, prepare_unload,
              cancel_unload, finish_unload, &lifecycle) == 0);
    CHECK("prepare all 1025 identities",
          lifecycle.prepare_calls == LIVE_MAP_COUNT);
    kzt_loader_lifecycle_snapshot_release(&snapshot);

    maps[LIVE_MAP_COUNT - 2].next = 0;
    debug.state = KZT_LOADER_DEBUG_CONSISTENT;
    reads.map_reads = 0;
    CHECK("capture 1024 CONSISTENT maps",
          kzt_loader_lifecycle_snapshot_capture(
              registry, (uintptr_t)&debug, &reader_ops, &snapshot) == 0);
    CHECK("read remaining 1024 link maps",
          reads.map_reads == LIVE_MAP_COUNT - 1);
    CHECK("publish CONSISTENT maps",
          kzt_loader_event_hook_publish_lifecycle(
              &hook, snapshot.state, snapshot.live_maps,
              snapshot.live_map_count, resolve_identity, prepare_unload,
              cancel_unload, finish_unload, &lifecycle) == 0);
    CHECK("cancel remaining identities",
          lifecycle.cancel_calls == LIVE_MAP_COUNT - 1);
    CHECK("one identity unloaded", lifecycle.unload_calls == 1);
    CHECK("exact removed identity unloaded",
          lifecycle.unloaded.link_map_addr == reused_addr &&
              lifecycle.unloaded.generation == old_identity.generation);
    kzt_loader_lifecycle_snapshot_release(&snapshot);

    CHECK("dump DEAD generation",
          kzt_guest_registry_dump_snapshot(registry, &dump) == 0);
    for (index = 0; index < dump.count; ++index) {
        if (dump.objects[index].link_map_addr == reused_addr &&
            dump.objects[index].generation == old_identity.generation &&
            dump.objects[index].state == KZT_GUEST_OBJECT_DEAD) {
            found_dead = 1;
        }
    }
    CHECK("removed identity reaches DEAD", found_dead);
    kzt_guest_registry_dump_free(&dump);

    {
        kzt_guest_object_observation_t observation =
            observation_for(reused_addr);

        CHECK("observe reused address",
              kzt_guest_registry_observe(registry, &observation) ==
                  KZT_GUEST_REGISTRY_ADDED);
    }
    CHECK("find reused address",
          kzt_guest_registry_find_by_link_map(
              registry, reused_addr, &reused) == 0 && reused != NULL);
    CHECK("reused address gets new generation",
          reused->generation > old_identity.generation);
    kzt_guest_object_snapshot_free(reused);

    CHECK("destroy lifecycle hook", kzt_loader_event_hook_destroy(&hook) == 0);
    free(maps);
    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_allocation_failure_is_observable();
    test_1025_maps_complete_lifecycle_and_reuse();
    puts("kzt lifecycle snapshot capacity: PASS");
    return EXIT_SUCCESS;
}
