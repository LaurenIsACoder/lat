#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "dlopen_recycle_transaction.h"
#include "elf_plt_relocation.h"
#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"

typedef struct fake_library { int id; } fake_library_t;

typedef struct recycle_fixture {
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_registry_t *registry;
    fake_library_t library;
    uintptr_t link_map_addr;
    unsigned long generation;
    int active;
    int prepared;
    int guest_open_result;
    int reload_result;
    int plt_relocation_result;
    int guest_close_calls;
    int guest_open_calls;
    uintptr_t delta;
    uintptr_t internal_l_addr;
    int latx_hasfix;
    int had_relocate_elf;
    int had_relocate_plt;
    int latx_type;
} recycle_fixture_t;

static int failures;

#define CHECK(name, expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s\n", name); ++failures; } } while (0)

static kzt_guest_object_observation_t observation(uintptr_t map)
{
    return (kzt_guest_object_observation_t){
        .link_map_addr = map,
        .load_bias = { .value = 0x500000, .status = KZT_GUEST_FIELD_OK },
        .dynamic_addr = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .map_start = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { .value = 0, .status = KZT_GUEST_FIELD_OK },
        .path = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .soname = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_library_binding_key_t binding_key(uintptr_t map,
                                                    unsigned long generation)
{
    return (kzt_guest_library_binding_key_t){
        .link_map_addr = map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
}

static unsigned long current_generation(recycle_fixture_t *fixture)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;
    unsigned long generation = 0;
    CHECK("transaction registry snapshot",
          kzt_guest_registry_find_by_link_map(
              fixture->registry, fixture->link_map_addr, &snapshot) == 0 &&
          snapshot != NULL);
    if (snapshot) generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    return generation;
}

static void fixture_init(recycle_fixture_t *fixture)
{
    kzt_guest_object_observation_t observed;
    kzt_guest_library_binding_key_t key;
    *fixture = (recycle_fixture_t){
        .bindings = kzt_guest_library_bindings_init(),
        .registry = kzt_guest_registry_init(),
        .library = { .id = 1 },
        .link_map_addr = 0xd000,
        .active = 1,
        .delta = 0x400000,
        .internal_l_addr = 0x400000,
        .latx_hasfix = 1,
        .had_relocate_elf = 1,
        .had_relocate_plt = 1,
        .latx_type = 3,
    };
    observed = observation(fixture->link_map_addr);
    CHECK("transaction track", kzt_guest_library_track(
          fixture->bindings, (library_t *)&fixture->library) == 0);
    CHECK("transaction initial observe", kzt_guest_registry_observe(
          fixture->registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    fixture->generation = current_generation(fixture);
    key = binding_key(fixture->link_map_addr, fixture->generation);
    CHECK("transaction initial binding observation",
          kzt_guest_library_note_observation(fixture->bindings, &key) ==
          KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("transaction initial pair", kzt_guest_library_note_exact_pair(
          fixture->bindings, fixture->link_map_addr,
          (library_t *)&fixture->library,
          KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    kzt_guest_library_inactivate(fixture->bindings, fixture->registry,
                                 (library_t *)&fixture->library,
                                 fixture->link_map_addr);
    fixture->active = 0;
    /* Model the stale pointer retained by the old wrappers after dlclose. */
    fixture->link_map_addr = 0xd000;
}

static void fixture_destroy(recycle_fixture_t *fixture)
{
    kzt_guest_library_bindings_destroy(&fixture->bindings);
    kzt_guest_registry_destroy(&fixture->registry);
}

static void recycle_prepare(void *opaque)
{
    recycle_fixture_t *fixture = opaque;
    fixture->prepared = 1;
    fixture->link_map_addr = 0;
    fixture->delta = 0;
    fixture->internal_l_addr = 0;
    fixture->latx_hasfix = 0;
    fixture->had_relocate_elf = 0;
    fixture->had_relocate_plt = 0;
    fixture->latx_type = 0;
}

static int recycle_guest_open(void *opaque)
{
    recycle_fixture_t *fixture = opaque;
    kzt_guest_object_observation_t observed;
    kzt_guest_library_binding_key_t key;
    if (fixture->guest_open_result != 0)
        return fixture->guest_open_result;
    ++fixture->guest_open_calls;
    fixture->link_map_addr = 0xd000;
    fixture->delta = 0x500000 + (uintptr_t)fixture->guest_open_calls * 0x100000;
    fixture->internal_l_addr = fixture->delta;
    fixture->latx_hasfix = 1;
    fixture->active = 1;
    observed = observation(fixture->link_map_addr);
    CHECK("transaction guest observation", kzt_guest_registry_observe(
          fixture->registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    fixture->generation = current_generation(fixture);
    key = binding_key(fixture->link_map_addr, fixture->generation);
    CHECK("transaction guest binding observation",
          kzt_guest_library_note_observation(fixture->bindings, &key) ==
          KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("transaction guest incarnation live",
          kzt_guest_library_reactivate(
              fixture->bindings, (library_t *)&fixture->library) == 0);
    return 0;
}

static int simulated_plt_relocation(void *opaque, int *need_resolver)
{
    recycle_fixture_t *fixture = opaque;
    if (need_resolver)
        *need_resolver = 1;
    return fixture->plt_relocation_result;
}

static int recycle_reload(void *opaque)
{
    recycle_fixture_t *fixture = opaque;
    kzt_guest_library_binding_result_t pair_result;
    int need_resolver = 0;
    if (fixture->reload_result != 0)
        return fixture->reload_result;
    fixture->had_relocate_elf = 1;
    if (elf_plt_relocation_apply(simulated_plt_relocation, fixture,
                                 &need_resolver) != 0)
        return -1;
    fixture->had_relocate_plt = 1;
    fixture->active = 1;
    CHECK("transaction reactivate", kzt_guest_library_reactivate(
          fixture->bindings, (library_t *)&fixture->library) == 0);
    pair_result = kzt_guest_library_note_exact_pair(
        fixture->bindings, fixture->link_map_addr,
        (library_t *)&fixture->library, KZT_GUEST_LIBRARY_OBJECT_EMULATED);
    CHECK("transaction publish pair",
          pair_result == KZT_GUEST_LIBRARY_BINDING_ADDED ||
          pair_result == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    return 0;
}

static void recycle_rollback(void *opaque, int guest_opened)
{
    recycle_fixture_t *fixture = opaque;
    if (guest_opened && fixture->link_map_addr)
        ++fixture->guest_close_calls;
    kzt_guest_library_inactivate(fixture->bindings, fixture->registry,
                                 (library_t *)&fixture->library,
                                 fixture->link_map_addr);
    fixture->active = 0;
    fixture->link_map_addr = 0;
    fixture->delta = 0;
    fixture->internal_l_addr = 0;
    fixture->latx_hasfix = 0;
    fixture->had_relocate_elf = 0;
    fixture->had_relocate_plt = 0;
    fixture->latx_type = 0;
}

static void check_failed_state(const char *prefix, recycle_fixture_t *fixture)
{
    kzt_guest_library_binding_state_t lifecycle;
    size_t pending = 99, live_entries = 99;
    (void)prefix;
    CHECK("failure active false", fixture->active == 0);
    CHECK("failure link_map cleared", fixture->link_map_addr == 0);
    CHECK("failure delta cleared", fixture->delta == 0);
    CHECK("failure internal l_addr cleared", fixture->internal_l_addr == 0);
    CHECK("failure latx_hasfix cleared", fixture->latx_hasfix == 0);
    CHECK("failure relocate flag cleared", fixture->had_relocate_elf == 0);
    CHECK("failure PLT flag cleared", fixture->had_relocate_plt == 0);
    CHECK("failure LATX type cleared", fixture->latx_type == 0);
    CHECK("failure binding snapshot",
          kzt_guest_library_binding_test_snapshot(
              fixture->bindings, (library_t *)&fixture->library,
              &lifecycle, &pending, &live_entries) == 0);
    CHECK("failure lifecycle dead",
          lifecycle == KZT_GUEST_LIBRARY_BINDING_DEAD);
    CHECK("failure pending empty", pending == 0);
    CHECK("failure live pair absent", live_entries == 0);
}

static void test_guest_open_failure(void)
{
    recycle_fixture_t fixture;
    size_t count = 0;
    void *result;
    fixture_init(&fixture);
    fixture.guest_open_result = -1;
    result = dlopen_recycle_transaction(
        (void *)0x55, &count, 1, &fixture, recycle_prepare,
        recycle_guest_open, recycle_reload, recycle_rollback);
    CHECK("guest failure returned null", result == NULL);
    CHECK("guest failure count unchanged", count == 0);
    CHECK("guest failure prepared", fixture.prepared == 1);
    CHECK("guest failure no close", fixture.guest_close_calls == 0);
    check_failed_state("guest", &fixture);
    fixture_destroy(&fixture);
}

static void test_reload_failure(void)
{
    recycle_fixture_t fixture;
    kzt_guest_object_observation_t observed;
    unsigned long failed_generation, reused_generation;
    size_t count = 0;
    void *result;
    fixture_init(&fixture);
    fixture.reload_result = -1;
    result = dlopen_recycle_transaction(
        (void *)0x66, &count, 1, &fixture, recycle_prepare,
        recycle_guest_open, recycle_reload, recycle_rollback);
    failed_generation = fixture.generation;
    CHECK("reload failure returned null", result == NULL);
    CHECK("reload failure count unchanged", count == 0);
    CHECK("reload failure closes guest once", fixture.guest_close_calls == 1);
    check_failed_state("reload", &fixture);

    observed = observation(0xd000);
    CHECK("reload failure observation retired",
          kzt_guest_registry_observe(fixture.registry, &observed) ==
          KZT_GUEST_REGISTRY_ADDED);
    fixture.link_map_addr = 0xd000;
    reused_generation = current_generation(&fixture);
    CHECK("reload failure reuse generation",
          reused_generation > failed_generation);
    fixture_destroy(&fixture);
}

static void test_plt_relocation_failure_rolls_back_and_retry_overwrites(void)
{
    recycle_fixture_t fixture;
    size_t count = 0;
    void *result;

    fixture_init(&fixture);
    fixture.plt_relocation_result = -1;
    result = dlopen_recycle_transaction(
        (void *)0x76, &count, 1, &fixture, recycle_prepare,
        recycle_guest_open, recycle_reload, recycle_rollback);
    CHECK("PLT failure returned null", result == NULL);
    CHECK("PLT failure count unchanged", count == 0);
    CHECK("PLT failure compensates once", fixture.guest_close_calls == 1);
    check_failed_state("plt", &fixture);

    fixture.plt_relocation_result = 0;
    result = dlopen_recycle_transaction(
        (void *)0x76, &count, 1, &fixture, recycle_prepare,
        recycle_guest_open, recycle_reload, recycle_rollback);
    CHECK("PLT retry returned handle", result == (void *)0x76);
    CHECK("PLT retry increments count", count == 1);
    CHECK("PLT retry did not compensate", fixture.guest_close_calls == 1);
    CHECK("PLT retry overwrote delta", fixture.delta == 0x700000);
    CHECK("PLT retry overwrote l_addr", fixture.internal_l_addr == 0x700000);
    CHECK("PLT retry set fix flag", fixture.latx_hasfix == 1);
    CHECK("PLT retry set relocation flag", fixture.had_relocate_elf == 1);
    CHECK("PLT retry set PLT flag", fixture.had_relocate_plt == 1);
    fixture_destroy(&fixture);
}

static void test_success_commits_handle_count_and_pair(void)
{
    recycle_fixture_t fixture;
    kzt_guest_library_binding_state_t lifecycle;
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t binding_handle;
    size_t pending = 99, live_entries = 99, count = 0;
    void *result;
    fixture_init(&fixture);
    result = dlopen_recycle_transaction(
        (void *)0x77, &count, 1, &fixture, recycle_prepare,
        recycle_guest_open, recycle_reload, recycle_rollback);
    CHECK("success returned old handle", result == (void *)0x77);
    CHECK("success count incremented", count == 1);
    CHECK("success active", fixture.active == 1);
    CHECK("success binding snapshot",
          kzt_guest_library_binding_test_snapshot(
              fixture.bindings, (library_t *)&fixture.library, &lifecycle,
              &pending, &live_entries) == 0);
    CHECK("success lifecycle live",
          lifecycle == KZT_GUEST_LIBRARY_BINDING_LIVE);
    CHECK("success pending empty", pending == 0);
    CHECK("success exact pair live", live_entries == 1);
    key = binding_key(fixture.link_map_addr, fixture.generation);
    CHECK("success pair lookup", kzt_guest_library_lookup(
          fixture.bindings, &key, &binding_handle) == 0);
    kzt_guest_library_handle_release(&binding_handle);
    fixture_destroy(&fixture);
}

int main(void)
{
    test_guest_open_failure();
    test_reload_failure();
    test_plt_relocation_failure_rolls_back_and_retry_overwrites();
    test_success_commits_handle_count_and_pair();
    if (failures)
        fprintf(stderr, "dlopen recycle transaction: %d failure(s)\n",
                failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
