#include "kzt_loader_event_hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "CHECK failed: %s:%d: %s\\n", __FILE__, \
                    __LINE__, #condition); \
            exit(1); \
        } \
    } while (0)

static void test_version_and_pattern_fail_open(void)
{
    kzt_loader_event_hook_t hook;

    CHECK(kzt_loader_event_hook_install(&hook, 0, 0x1000, 3, 1) != 0);
    CHECK(hook.result == KZT_LOADER_EVENT_HOOK_FAIL_OPEN_BUILD_ID_READ);
    CHECK(kzt_loader_event_hook_scope_layout(&hook) ==
          KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED);
    CHECK(kzt_loader_event_hook_install(&hook, "unknown", 0x1000, 3, 1) != 0);
    CHECK(hook.result == KZT_LOADER_EVENT_HOOK_FAIL_OPEN_UNKNOWN_BUILD_ID);
    CHECK(kzt_loader_event_hook_scope_layout(&hook) ==
          KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED);
    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID, 0, 3, 0) != 0);
    CHECK(hook.result == KZT_LOADER_EVENT_HOOK_FAIL_OPEN_PATTERN_MISMATCH);

    CHECK(setenv("LATX_KZT_LOADER_EVENT_FORCE_PATTERN_MISMATCH", "1", 1) == 0);
    CHECK(!kzt_loader_event_hook_pattern_allowed(1));
    CHECK(unsetenv("LATX_KZT_LOADER_EVENT_FORCE_PATTERN_MISMATCH") == 0);
    CHECK(kzt_loader_event_hook_pattern_allowed(1));

    CHECK(setenv("LATX_KZT_LOADER_EVENT_HOOK", "0", 1) == 0);
    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID, 0x1000, 3, 1) != 0);
    CHECK(hook.result == KZT_LOADER_EVENT_HOOK_FAIL_OPEN_DISABLED);
    CHECK(unsetenv("LATX_KZT_LOADER_EVENT_HOOK") == 0);
}

static void test_event_publishes_exact_map_with_monotonic_sequence(void)
{
    kzt_loader_event_hook_t hook;
    kzt_loader_event_t first;
    kzt_loader_event_t second;

    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID, 0x1000, 3, 1) == 0);
    CHECK(kzt_loader_event_hook_scope_layout(&hook) ==
          KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF);
    CHECK(kzt_loader_event_hook_publish(&hook, 0x11110000, &first) == 0);
    CHECK(kzt_loader_event_hook_publish(&hook, 0x22220000, &second) == 0);
    CHECK(first.link_map_addr == 0x11110000);
    CHECK(second.link_map_addr == 0x22220000);
    CHECK(second.sequence == first.sequence + 1);
    CHECK(kzt_loader_event_hook_publish(&hook, 0, &second) != 0);
    kzt_loader_event_hook_destroy(&hook);
}

typedef struct lifecycle_fixture {
    kzt_loader_lifecycle_identity_t identities[2];
    kzt_loader_lifecycle_identity_t unloaded;
    int unload_calls;
    int prepare_calls;
    int cancel_calls;
} lifecycle_fixture_t;

static int resolve_lifecycle_identity(
    uintptr_t link_map_addr,
    kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;

    for (size_t i = 0; i < 2; ++i) {
        if (fixture->identities[i].link_map_addr == link_map_addr) {
            *identity = fixture->identities[i];
            return 0;
        }
    }
    return -1;
}

static void publish_lifecycle_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;

    fixture->unloaded = *identity;
    ++fixture->unload_calls;
}

static int prepare_lifecycle_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;

    CHECK(identity != NULL);
    ++fixture->prepare_calls;
    return 0;
}

static int cancel_lifecycle_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_fixture_t *fixture = opaque;

    CHECK(identity != NULL);
    ++fixture->cancel_calls;
    return 0;
}

static void test_delete_consistent_publishes_exact_removed_identity(void)
{
    kzt_loader_event_hook_t hook;
    lifecycle_fixture_t fixture = {
        .identities = {
            { 0x11110000, 9, 0 },
            { 0x22220000, 17, 7 },
        },
    };
    const uintptr_t before[] = { 0x11110000, 0x22220000 };
    const uintptr_t after[] = { 0x11110000 };

    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID,
              0x1000, 3, 1) == 0);
    CHECK(kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, 0x3000) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_DELETE,
              before, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(kzt_loader_event_hook_destroy(&hook) != 0);
    CHECK(kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, 0x3000) != 0);
    CHECK(fixture.unload_calls == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_CONSISTENT,
              before, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(fixture.unload_calls == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_DELETE,
              before, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_CONSISTENT,
              after, 1, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(fixture.unload_calls == 1);
    CHECK(fixture.unloaded.link_map_addr == 0x22220000);
    CHECK(fixture.unloaded.generation == 17);
    CHECK(fixture.unloaded.namespace_id == 7);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_CONSISTENT,
              after, 1, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(fixture.unload_calls == 1);
    CHECK(kzt_loader_event_hook_destroy(&hook) == 0);
}

static void test_add_does_not_discard_pending_delete(void)
{
    kzt_loader_event_hook_t hook;
    lifecycle_fixture_t fixture = {
        .identities = {
            { 0x11110000, 9, 0 },
            { 0x22220000, 17, 7 },
        },
    };
    const uintptr_t before[] = { 0x11110000, 0x22220000 };
    const uintptr_t after[] = { 0x11110000 };

    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID,
              0x1000, 3, 1) == 0);
    CHECK(kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, 0x3000) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_DELETE,
              before, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_ADD,
              before, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_CONSISTENT,
              after, 1, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(fixture.unload_calls == 1);
    CHECK(fixture.unloaded.generation == 17);
    CHECK(fixture.unloaded.namespace_id == 7);
    kzt_loader_event_hook_destroy(&hook);
}

static void test_same_address_new_identity_retires_old_generation(void)
{
    kzt_loader_event_hook_t hook;
    lifecycle_fixture_t fixture = {
        .identities = {
            { 0x11110000, 9, 0 },
            { 0x22220000, 17, 7 },
        },
    };
    const uintptr_t maps[] = { 0x11110000, 0x22220000 };

    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID,
              0x1000, 3, 1) == 0);
    CHECK(kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, 0x3000) == 0);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_DELETE,
              maps, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    fixture.identities[1].generation = 18;
    fixture.identities[1].namespace_id = 9;
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_CONSISTENT,
              maps, 2, resolve_lifecycle_identity,
              prepare_lifecycle_unload, cancel_lifecycle_unload,
              publish_lifecycle_unload, &fixture) == 0);
    CHECK(fixture.unload_calls == 1);
    CHECK(fixture.unloaded.link_map_addr == 0x22220000);
    CHECK(fixture.unloaded.generation == 17);
    CHECK(fixture.unloaded.namespace_id == 7);
    kzt_loader_event_hook_destroy(&hook);
}

typedef struct lifecycle_allocation_fixture {
    kzt_loader_lifecycle_identity_t identities[65];
    size_t prepare_calls;
    size_t cancel_calls;
    size_t unload_calls;
} lifecycle_allocation_fixture_t;

static int resolve_allocation_identity(
    uintptr_t link_map_addr,
    kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_allocation_fixture_t *fixture = opaque;

    for (size_t i = 0; i < 65; ++i) {
        if (fixture->identities[i].link_map_addr == link_map_addr) {
            *identity = fixture->identities[i];
            return 0;
        }
    }
    return -1;
}

static int prepare_allocation_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_allocation_fixture_t *fixture = opaque;

    CHECK(identity != NULL);
    ++fixture->prepare_calls;
    return 0;
}

static int cancel_allocation_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_allocation_fixture_t *fixture = opaque;

    CHECK(identity != NULL);
    ++fixture->cancel_calls;
    return 0;
}

static void publish_allocation_unload(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque)
{
    lifecycle_allocation_fixture_t *fixture = opaque;

    CHECK(identity != NULL);
    ++fixture->unload_calls;
}

static void test_pending_growth_allocation_failure_cancels_all(void)
{
    kzt_loader_event_hook_t hook;
    lifecycle_allocation_fixture_t fixture = { 0 };
    uintptr_t live_maps[65];

    for (size_t i = 0; i < 65; ++i) {
        live_maps[i] = 0x40000000 + i * 0x1000;
        fixture.identities[i] = (kzt_loader_lifecycle_identity_t) {
            .link_map_addr = live_maps[i],
            .generation = i + 1,
            .namespace_id = 0,
        };
    }
    CHECK(kzt_loader_event_hook_install(
              &hook, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID,
              0x1000, 3, 1) == 0);
    CHECK(kzt_loader_event_hook_enable_lifecycle(
              &hook, 0x2000, 0x3000) == 0);
    kzt_loader_event_hook_test_set_alloc_failure_after(1);
    CHECK(kzt_loader_event_hook_publish_lifecycle(
              &hook, KZT_LOADER_DEBUG_DELETE,
              live_maps, 65, resolve_allocation_identity,
              prepare_allocation_unload, cancel_allocation_unload,
              publish_allocation_unload, &fixture) != 0);
    CHECK(kzt_loader_event_hook_lifecycle_result(&hook) ==
          KZT_LOADER_LIFECYCLE_ALLOCATION);
    CHECK(fixture.prepare_calls == 65);
    CHECK(fixture.cancel_calls == 65);
    CHECK(fixture.unload_calls == 0);
    CHECK(hook.pending_delete_count == 0);
    kzt_loader_event_hook_test_set_alloc_failure_after(-1);
    CHECK(kzt_loader_event_hook_destroy(&hook) == 0);
}

int main(void)
{
    test_version_and_pattern_fail_open();
    test_event_publishes_exact_map_with_monotonic_sequence();
    test_delete_consistent_publishes_exact_removed_identity();
    test_add_does_not_discard_pending_delete();
    test_same_address_new_identity_retires_old_generation();
    test_pending_growth_allocation_failure_cancels_all();
    puts("kzt-loader-event-hook: all tests passed");
    return 0;
}
