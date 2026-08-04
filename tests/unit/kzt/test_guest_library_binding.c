#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"

#ifdef __APPLE__
typedef struct pthread_barrier {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned int count;
    unsigned int target;
    unsigned int generation;
} pthread_barrier_t;

#define PTHREAD_BARRIER_SERIAL_THREAD 1

static int pthread_barrier_init(pthread_barrier_t *barrier,
                                const void *attributes,
                                unsigned int count)
{
    (void)attributes;
    if (!barrier || !count || pthread_mutex_init(&barrier->lock, NULL) != 0)
        return -1;
    if (pthread_cond_init(&barrier->cond, NULL) != 0) {
        pthread_mutex_destroy(&barrier->lock);
        return -1;
    }
    barrier->count = 0;
    barrier->target = count;
    barrier->generation = 0;
    return 0;
}

static int pthread_barrier_wait(pthread_barrier_t *barrier)
{
    unsigned int generation;

    pthread_mutex_lock(&barrier->lock);
    generation = barrier->generation;
    if (++barrier->count == barrier->target) {
        barrier->count = 0;
        ++barrier->generation;
        pthread_cond_broadcast(&barrier->cond);
        pthread_mutex_unlock(&barrier->lock);
        return PTHREAD_BARRIER_SERIAL_THREAD;
    }
    while (generation == barrier->generation)
        pthread_cond_wait(&barrier->cond, &barrier->lock);
    pthread_mutex_unlock(&barrier->lock);
    return 0;
}

static int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
    int cond_result = pthread_cond_destroy(&barrier->cond);
    int mutex_result = pthread_mutex_destroy(&barrier->lock);

    return cond_result ? cond_result : mutex_result;
}

static int macos_pthread_cond_clockwait(pthread_cond_t *cond,
                                        pthread_mutex_t *lock,
                                        clockid_t clock_id,
                                        const struct timespec *deadline)
{
    struct timespec now, realtime, timeout;
    time_t seconds;
    long nanoseconds;

    if (clock_gettime(clock_id, &now) != 0 ||
        clock_gettime(CLOCK_REALTIME, &realtime) != 0)
        return -1;
    seconds = deadline->tv_sec - now.tv_sec;
    nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += 1000000000L;
    }
    if (seconds < 0) {
        seconds = 0;
        nanoseconds = 0;
    }
    timeout.tv_sec = realtime.tv_sec + seconds;
    timeout.tv_nsec = realtime.tv_nsec + nanoseconds;
    if (timeout.tv_nsec >= 1000000000L) {
        ++timeout.tv_sec;
        timeout.tv_nsec -= 1000000000L;
    }
    return pthread_cond_timedwait(cond, lock, &timeout);
}

#define pthread_cond_clockwait macos_pthread_cond_clockwait
#endif

typedef struct fake_library { int id; } fake_library_t;
static int failures;
static library_t *exact_cleanup_library;

#define CHECK(name, expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s\n", name); ++failures; } } while (0)

static void exact_cleanup(library_t *library, void *opaque)
{
    CHECK("exact cleanup opaque", opaque == (void *)(uintptr_t)0x51);
    exact_cleanup_library = library;
}

static kzt_guest_library_binding_key_t key(uintptr_t map,
                                           unsigned long generation)
{
    return (kzt_guest_library_binding_key_t){
        .link_map_addr = map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
}

static kzt_guest_object_observation_t observation(uintptr_t map)
{
    return (kzt_guest_object_observation_t){
        .link_map_addr = map,
        .load_bias = { .value = 0x400000, .status = KZT_GUEST_FIELD_OK },
        .dynamic_addr = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .map_start = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { .value = 0, .status = KZT_GUEST_FIELD_OK },
        .path = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .soname = { .status = KZT_GUEST_FIELD_UNKNOWN },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static unsigned long registry_generation(kzt_guest_registry_t *registry,
                                         uintptr_t map)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;
    unsigned long generation = 0;
    CHECK("registry snapshot", kzt_guest_registry_find_by_link_map(
          registry, map, &snapshot) == 0 && snapshot != NULL);
    if (snapshot) generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    return generation;
}

static int reverse_outputs_are_clear(
    const kzt_guest_library_binding_key_t *key,
    const kzt_guest_library_handle_t *handle)
{
    return key->link_map_addr == 0 && key->generation == 0 &&
           key->namespace_id == 0 &&
           key->namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN &&
           handle->bindings == NULL && handle->entry == NULL &&
           handle->library == NULL &&
           handle->object_type == KZT_GUEST_LIBRARY_OBJECT_MAIN;
}

static void test_reverse_lookup_unique_main_binding(void)
{
    fake_library_t lib = { 80 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t expected = key(0x11000, 81);
    kzt_guest_library_binding_key_t found = { 0 };
    kzt_guest_library_handle_t handle = { 0 };

    CHECK("reverse unique access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("reverse unique track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse unique bind", kzt_guest_library_bind(
          access.bindings, &expected, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("reverse unique lookup",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &handle) == 0);
    CHECK("reverse unique key",
          found.link_map_addr == expected.link_map_addr &&
          found.generation == expected.generation &&
          found.namespace_id == expected.namespace_id &&
          found.namespace_kind == expected.namespace_kind);
    CHECK("reverse unique handle",
          handle.library == (library_t *)&lib &&
          handle.object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED);
    CHECK("reverse unique retained key",
          kzt_guest_library_handle_matches_key(&handle, &expected));
    expected.generation++;
    CHECK("reverse unique rejects different key",
          !kzt_guest_library_handle_matches_key(&handle, &expected));
    kzt_guest_library_handle_release(&handle);
    CHECK("reverse unique released handle rejects key",
          !kzt_guest_library_handle_matches_key(&handle, &found));
    kzt_guest_library_access_destroy(&access);
}

static void test_init_failure_is_fail_open(void)
{
    fake_library_t lib = { 1 };
    kzt_guest_library_binding_key_t k = key(0x1000, 1);
    kzt_guest_library_binding_test_set_alloc_failure_after(0);
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    CHECK("init failure", bindings == NULL);
    CHECK("disabled bind", kzt_guest_library_bind(bindings, &k,
          (library_t *)&lib, KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_DISABLED);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);
}

static void test_loader_quiescence_lease_acquire_release(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_lease_t first = { 0 };
    kzt_guest_library_loader_quiescence_lease_t second = { 0 };
    kzt_guest_library_loader_quiescence_lease_t copied = { 0 };
    unsigned int readers = 0;

    CHECK("loader lease init", bindings != NULL);
    if (!bindings) return;
    CHECK("loader lease acquire",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &first) == 0);
    CHECK("loader lease token",
          first.bindings == bindings && first.cookie != 0);
    CHECK("loader lease concurrent acquire",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &second) == 0);
    copied = first;
    kzt_guest_library_loader_quiescence_release(&copied);
    CHECK("loader lease copied token ignored",
          kzt_guest_library_binding_test_loader_state(
              bindings, &readers, NULL, NULL, NULL) == 0 &&
          readers == 2);
    kzt_guest_library_loader_quiescence_release(&first);
    CHECK("loader lease release clears token",
          first.bindings == NULL && first.cookie == 0);
    kzt_guest_library_loader_quiescence_release(&second);
    CHECK("loader lease reacquire after all readers",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &second) == 0);
    kzt_guest_library_loader_quiescence_release(&second);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_loader_quiescence_writer_token_is_stable(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_writer_t writer = { 0 };
    kzt_guest_library_loader_quiescence_writer_t copied = { 0 };
    kzt_guest_library_loader_quiescence_lease_t reader = { 0 };
    unsigned int waiters = 0;

    CHECK("writer token init", bindings != NULL);
    if (!bindings) return;
    CHECK("writer token begin",
          kzt_guest_library_loader_quiescence_writer_begin(
              bindings, &writer) == 0);
    CHECK("writer token active",
          writer.bindings == bindings && writer.cookie != 0);
    copied = writer;
    kzt_guest_library_loader_quiescence_writer_end(&copied);
    CHECK("writer copied token ignored",
          kzt_guest_library_binding_test_loader_state(
              bindings, NULL, &waiters, NULL, NULL) == 0 &&
              waiters == 1);
    CHECK("writer token rejects reader",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &reader) != 0);
    kzt_guest_library_loader_quiescence_writer_end(&writer);
    CHECK("writer release clears token",
          writer.bindings == NULL && writer.cookie == 0);
    CHECK("writer release reopens reader admission",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &reader) == 0);
    kzt_guest_library_loader_quiescence_release(&reader);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_loader_quiescence_lease_rejects_active_scope(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_loader_quiescence_lease_t lease = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .cookie = 1,
    };

    CHECK("active scope lease init", bindings != NULL);
    if (!bindings) return;
    CHECK("active scope begin", kzt_guest_library_loader_scope_begin(
          bindings, &scope) == 0);
    CHECK("active scope rejects lease",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &lease) != 0);
    CHECK("active scope clears rejected lease",
          lease.bindings == NULL && lease.cookie == 0);
    kzt_guest_library_loader_scope_end(&scope);
    CHECK("ended scope permits lease",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &lease) == 0);
    kzt_guest_library_loader_quiescence_release(&lease);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_both_arrival_orders_and_retry(void)
{
    fake_library_t wrapped = { 2 }, emulated = { 3 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t a = key(0x2000, 7);
    kzt_guest_library_binding_key_t b = key(0x3000, 8);
    kzt_guest_library_handle_t handle;

    CHECK("track wrapped", kzt_guest_library_track(
          bindings, (library_t *)&wrapped) == 0);
    CHECK("track emulated", kzt_guest_library_track(
          bindings, (library_t *)&emulated) == 0);

    CHECK("pair first pending", kzt_guest_library_note_exact_pair(
          bindings, a.link_map_addr, (library_t *)&wrapped,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_binding_test_set_alloc_failure_after(0);
    CHECK("transient observation failure", kzt_guest_library_note_observation(
          bindings, &a) == KZT_GUEST_LIBRARY_BINDING_ERROR);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);
    CHECK("observation retry binds", kzt_guest_library_note_observation(
          bindings, &a) == KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("wrapped exact lookup", kzt_guest_library_lookup(
          bindings, &a, &handle) == 0 &&
          handle.library == (library_t *)&wrapped &&
          handle.object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED);
    kzt_guest_library_handle_release(&handle);

    CHECK("observation first", kzt_guest_library_note_observation(
          bindings, &b) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("emulated pair binds", kzt_guest_library_note_exact_pair(
          bindings, b.link_map_addr, (library_t *)&emulated,
          KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("emulated exact lookup", kzt_guest_library_lookup(
          bindings, &b, &handle) == 0 &&
          handle.library == (library_t *)&emulated &&
          handle.object_type == KZT_GUEST_LIBRARY_OBJECT_EMULATED);
    kzt_guest_library_handle_release(&handle);

    b.namespace_id = 4;
    b.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
    CHECK("non-main namespace fail open", kzt_guest_library_note_observation(
          bindings, &b) == KZT_GUEST_LIBRARY_BINDING_ERROR);
    CHECK("main executable type fail open", kzt_guest_library_note_exact_pair(
          bindings, 0x4000, (library_t *)&emulated,
          KZT_GUEST_LIBRARY_OBJECT_MAIN) == KZT_GUEST_LIBRARY_BINDING_ERROR);

    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_forced_growth_with_held_handle(void)
{
    fake_library_t libs[24];
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_handle_t held;
    kzt_guest_library_binding_key_t first = key(0x5000, 1);

    for (size_t i = 0; i < 24; ++i) {
        libs[i].id = (int)i;
        CHECK("growth track", kzt_guest_library_track(
              bindings, (library_t *)&libs[i]) == 0);
    }
    CHECK("growth first bind", kzt_guest_library_bind(
          bindings, &first, (library_t *)&libs[0],
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("growth hold", kzt_guest_library_lookup(
          bindings, &first, &held) == 0);
    for (size_t i = 1; i < 24; ++i) {
        kzt_guest_library_binding_key_t next =
            key(0x5000 + i * 0x100, i + 1);
        CHECK("growth bind", kzt_guest_library_bind(
              bindings, &next, (library_t *)&libs[i],
              KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
              KZT_GUEST_LIBRARY_BINDING_ADDED);
    }
    CHECK("held survives realloc", held.library == (library_t *)&libs[0]);
    kzt_guest_library_handle_release(&held);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_pending_cancel_and_address_reuse(void)
{
    fake_library_t old = { 4 }, replacement = { 5 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t old_key = key(0x9000, 11);
    kzt_guest_library_binding_key_t new_key = key(0x9000, 12);
    kzt_guest_library_handle_t handle;

    CHECK("cancel track", kzt_guest_library_track(
          bindings, (library_t *)&old) == 0);
    CHECK("cancel pending", kzt_guest_library_note_exact_pair(
          bindings, old_key.link_map_addr, (library_t *)&old,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_unbind(bindings, NULL, (library_t *)&old,
                             old_key.link_map_addr);
    CHECK("late attach rejected", kzt_guest_library_note_exact_pair(
          bindings, old_key.link_map_addr, (library_t *)&old,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ERROR);
    CHECK("canceled observation cannot bind", kzt_guest_library_note_observation(
          bindings, &old_key) == KZT_GUEST_LIBRARY_BINDING_CANCELLED);
    CHECK("canceled lookup", kzt_guest_library_lookup(
          bindings, &old_key, &handle) != 0);

    CHECK("reuse track", kzt_guest_library_track(
          bindings, (library_t *)&replacement) == 0);
    CHECK("reuse observation", kzt_guest_library_note_observation(
          bindings, &new_key) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("reuse exact pair", kzt_guest_library_note_exact_pair(
          bindings, new_key.link_map_addr, (library_t *)&replacement,
          KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("old generation absent", kzt_guest_library_lookup(
          bindings, &old_key, &handle) != 0);
    CHECK("new generation present", kzt_guest_library_lookup(
          bindings, &new_key, &handle) == 0 &&
          handle.library == (library_t *)&replacement);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_unclaimed_observation_address_reuse_pair_first(void)
{
    fake_library_t old = { 40 }, replacement = { 41 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t stale = key(0x9800, 30);
    kzt_guest_library_binding_key_t fresh = key(0x9800, 31);
    kzt_guest_library_handle_t handle;

    CHECK("unclaimed old track", kzt_guest_library_track(
          bindings, (library_t *)&old) == 0);
    CHECK("unclaimed old observation", kzt_guest_library_note_observation(
          bindings, &stale) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    /* There is deliberately no exact pair/entry for the old observation. */
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&old,
                                 stale.link_map_addr);

    CHECK("unclaimed replacement track", kzt_guest_library_track(
          bindings, (library_t *)&replacement) == 0);
    CHECK("replacement pair waits for fresh observation",
          kzt_guest_library_note_exact_pair(
              bindings, fresh.link_map_addr, (library_t *)&replacement,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("pair first remains fail open", kzt_guest_library_lookup(
          bindings, &fresh, &handle) != 0);
    CHECK("fresh observation binds replacement",
          kzt_guest_library_note_observation(bindings, &fresh) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("stale generation stays absent", kzt_guest_library_lookup(
          bindings, &stale, &handle) != 0);
    CHECK("fresh generation lookup", kzt_guest_library_lookup(
          bindings, &fresh, &handle) == 0 &&
          handle.library == (library_t *)&replacement);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_observation_first_unload_retires_registry_generation(void)
{
    fake_library_t lib = { 42 };
    uintptr_t map = 0x9900;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    unsigned long first, second;

    CHECK("joint track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("joint registry first", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    first = registry_generation(registry, map);
    CHECK("joint binding observation", kzt_guest_library_note_observation(
          bindings, &(kzt_guest_library_binding_key_t){
              .link_map_addr = map,
              .generation = first,
              .namespace_id = 0,
              .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
          }) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);

    /* No exact pair is ever supplied.  Unload must still retire the registry
     * identity attached to the binding-side observation. */
    kzt_guest_library_inactivate(bindings, registry, (library_t *)&lib, map);
    CHECK("joint identical reuse added", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    second = registry_generation(registry, map);
    CHECK("joint reuse gets new generation", second > first);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_unload_retires_only_hinted_unclaimed_observation(void)
{
    fake_library_t a = { 44 }, b = { 45 };
    uintptr_t map_a = 0x9b00, map_b = 0x9c00;
    kzt_guest_object_observation_t observed_a = observation(map_a);
    kzt_guest_object_observation_t observed_b = observation(map_b);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t key_a, key_b;
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_library_handle_t handle;

    CHECK("two-lib track a", kzt_guest_library_track(
          bindings, (library_t *)&a) == 0);
    CHECK("two-lib track b", kzt_guest_library_track(
          bindings, (library_t *)&b) == 0);
    CHECK("two-lib observe registry a", kzt_guest_registry_observe(
          registry, &observed_a) == KZT_GUEST_REGISTRY_ADDED);
    CHECK("two-lib observe registry b", kzt_guest_registry_observe(
          registry, &observed_b) == KZT_GUEST_REGISTRY_ADDED);
    key_a = key(map_a, registry_generation(registry, map_a));
    key_b = key(map_b, registry_generation(registry, map_b));
    CHECK("two-lib binding observation a", kzt_guest_library_note_observation(
          bindings, &key_a) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("two-lib binding observation b", kzt_guest_library_note_observation(
          bindings, &key_b) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);

    kzt_guest_library_inactivate(bindings, registry, (library_t *)&a, map_a);
    CHECK("two-lib a retired", kzt_guest_registry_find_by_link_map(
          registry, map_a, &snapshot) != 0 && snapshot == NULL);
    CHECK("two-lib b remains live", kzt_guest_registry_find_by_link_map(
          registry, map_b, &snapshot) == 0 && snapshot != NULL &&
          snapshot->generation == key_b.generation &&
          snapshot->state != KZT_GUEST_OBJECT_UNLOADING &&
          snapshot->state != KZT_GUEST_OBJECT_DEAD);
    kzt_guest_object_snapshot_free(snapshot);
    snapshot = NULL;
    CHECK("two-lib b completes exact pair",
          kzt_guest_library_note_exact_pair(
              bindings, map_b, (library_t *)&b,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("two-lib b lookup", kzt_guest_library_lookup(
          bindings, &key_b, &handle) == 0 &&
          handle.library == (library_t *)&b);
    kzt_guest_library_handle_release(&handle);

    kzt_guest_library_unbind(bindings, registry, (library_t *)&b, map_b);
    kzt_guest_library_unbind(bindings, registry, (library_t *)&a, 0);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_missing_unload_hint_preserves_unclaimed_observation(void)
{
    fake_library_t lib = { 46 };
    uintptr_t map = 0x9d00;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_library_binding_key_t observed_key;

    CHECK("no-hint track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("no-hint registry", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    observed_key = key(map, registry_generation(registry, map));
    CHECK("no-hint observation", kzt_guest_library_note_observation(
          bindings, &observed_key) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    kzt_guest_library_inactivate(bindings, registry, (library_t *)&lib, 0);
    CHECK("no-hint remains live", kzt_guest_registry_find_by_link_map(
          registry, map, &snapshot) == 0 && snapshot != NULL &&
          snapshot->generation == observed_key.generation);
    kzt_guest_object_snapshot_free(snapshot);

    CHECK("no-hint explicit cleanup", kzt_guest_registry_retire(
          registry, map, observed_key.generation) == 0);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_exact_pinned_cleanup_consumes_handle(void)
{
    fake_library_t lib = { 49 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t exact = key(0x9d80, 17);
    kzt_guest_library_handle_t handle = { 0 };

    exact_cleanup_library = NULL;
    CHECK("exact-cleanup track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("exact-cleanup observe", kzt_guest_library_note_observation(
          bindings, &exact) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("exact-cleanup bind", kzt_guest_library_note_exact_pair(
          bindings, exact.link_map_addr, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("exact-cleanup lookup", kzt_guest_library_lookup(
          bindings, &exact, &handle) == 0);
    CHECK("exact-cleanup consume",
          kzt_guest_library_cleanup_exact_handle(
              &handle, exact_cleanup, (void *)(uintptr_t)0x51) == 0);
    CHECK("exact-cleanup handle cleared",
          handle.bindings == NULL && handle.entry == NULL &&
              handle.library == NULL);
    CHECK("exact-cleanup callback pinned library",
          exact_cleanup_library == (library_t *)&lib);
    CHECK("exact-cleanup lookup closed", kzt_guest_library_lookup(
          bindings, &exact, &handle) != 0);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_dead_library_stale_hint_does_not_retire_reused_address(void)
{
    fake_library_t old = { 47 }, replacement = { 48 };
    uintptr_t map = 0x9e00;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_library_binding_key_t old_key, replacement_key;

    CHECK("stale-hint track old", kzt_guest_library_track(
          bindings, (library_t *)&old) == 0);
    CHECK("stale-hint registry old", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    old_key = key(map, registry_generation(registry, map));
    CHECK("stale-hint observe old", kzt_guest_library_note_observation(
          bindings, &old_key) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    kzt_guest_library_unbind(bindings, registry, (library_t *)&old, map);

    CHECK("stale-hint track replacement", kzt_guest_library_track(
          bindings, (library_t *)&replacement) == 0);
    CHECK("stale-hint registry replacement", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    replacement_key = key(map, registry_generation(registry, map));
    CHECK("stale-hint replacement generation",
          replacement_key.generation > old_key.generation);
    CHECK("stale-hint observe replacement",
          kzt_guest_library_note_observation(bindings, &replacement_key) ==
          KZT_GUEST_LIBRARY_BINDING_UNCHANGED);

    /* A is already DEAD.  Repeating its obsolete address hint must not own
     * or retire the observation which now belongs to B's generation. */
    kzt_guest_library_unbind(bindings, registry, (library_t *)&old, map);
    CHECK("stale-hint replacement remains live",
          kzt_guest_registry_find_by_link_map(registry, map, &snapshot) == 0 &&
          snapshot && snapshot->generation == replacement_key.generation &&
          snapshot->state != KZT_GUEST_OBJECT_UNLOADING &&
          snapshot->state != KZT_GUEST_OBJECT_DEAD);
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_library_unbind(bindings, registry,
                             (library_t *)&replacement, map);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_tracking_allocation_failure_unload_is_fail_open(void)
{
    fake_library_t untracked = { 43 };
    uintptr_t map = 0x9a00;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_object_snapshot_t *snapshot = NULL;
    unsigned long first;

    kzt_guest_library_binding_test_set_alloc_failure_after(0);
    CHECK("alloc-fail track", kzt_guest_library_track(
          bindings, (library_t *)&untracked) != 0);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);

    CHECK("alloc-fail registry first", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    first = registry_generation(registry, map);
    CHECK("alloc-fail binding observation",
          kzt_guest_library_note_observation(
              bindings, &(kzt_guest_library_binding_key_t){
                  .link_map_addr = map,
                  .generation = first,
                  .namespace_id = 0,
                  .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
              }) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);

    /* With no lifecycle record there is no provable unload owner.  The stale
     * address hint must therefore preserve the exact observation fail-open. */
    kzt_guest_library_binding_test_set_alloc_failure_after(0);
    kzt_guest_library_unbind(bindings, registry, (library_t *)&untracked,
                             map);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);
    CHECK("alloc-fail observation remains live",
          kzt_guest_registry_find_by_link_map(registry, map, &snapshot) == 0 &&
          snapshot && snapshot->generation == first &&
          snapshot->state != KZT_GUEST_OBJECT_UNLOADING &&
          snapshot->state != KZT_GUEST_OBJECT_DEAD);
    kzt_guest_object_snapshot_free(snapshot);
    CHECK("alloc-fail explicit cleanup",
          kzt_guest_registry_retire(registry, map, first) == 0);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_inactive_can_reload_but_destroyed_cannot(void)
{
    fake_library_t lib = { 7 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t first = key(0xb000, 20);
    kzt_guest_library_binding_key_t second = key(0xb000, 21);
    kzt_guest_library_handle_t handle;

    CHECK("reload track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("reload observe first", kzt_guest_library_note_observation(
          bindings, &first) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("reload bind first", kzt_guest_library_note_exact_pair(
          bindings, first.link_map_addr, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&lib,
                                 first.link_map_addr);
    CHECK("reload reactivate", kzt_guest_library_reactivate(
          bindings, (library_t *)&lib) == 0);
    CHECK("reload observe second", kzt_guest_library_note_observation(
          bindings, &second) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("reload bind second", kzt_guest_library_note_exact_pair(
          bindings, second.link_map_addr, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_EMULATED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("reload lookup", kzt_guest_library_lookup(
          bindings, &second, &handle) == 0);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_unbind(bindings, NULL, (library_t *)&lib,
                             second.link_map_addr);
    CHECK("destroyed no reactivate", kzt_guest_library_reactivate(
          bindings, (library_t *)&lib) != 0);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void run_different_library_address_reuse(int force_gate_alloc_failure,
                                                const char *prefix)
{
    fake_library_t old_library = { 41 };
    fake_library_t new_library = { 42 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_callback_access_t stale = { 0 };
    kzt_guest_library_callback_access_t current = { 0 };
    uintptr_t map = force_gate_alloc_failure ? 0xa11000 : 0xa10000;

    CHECK(prefix, bindings != NULL);
    if (!bindings) return;
    CHECK("reuse old track", kzt_guest_library_track(
          bindings, (library_t *)&old_library) == 0);
    CHECK("reuse old loader pair", kzt_guest_library_publish_loader_pair(
          bindings, map, (library_t *)&old_library,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    if (force_gate_alloc_failure)
        kzt_guest_library_binding_test_set_alloc_failure_after(0);
    kzt_guest_library_inactivate(bindings, NULL,
                                 (library_t *)&old_library, map);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);

    /* A callback left over from the old causal chain has no new loader scope
     * and must still be rejected before the first guest read. */
    CHECK("reuse stale callback rejected",
          kzt_guest_library_callback_access_begin(
              bindings, map, &stale) != 0);

    CHECK("reuse new track", kzt_guest_library_track(
          bindings, (library_t *)&new_library) == 0);
    CHECK("reuse loader scope", kzt_guest_library_loader_scope_begin(
          bindings, &scope) == 0);
    CHECK("reuse current callback admitted",
          kzt_guest_library_callback_access_begin_scoped(
              bindings, map, &scope, &current) == 0);
    kzt_guest_library_callback_access_end(&current);
    CHECK("reuse pending loader pair",
          kzt_guest_library_loader_scope_note_pair(
              &scope, map, (library_t *)&new_library,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("reuse new loader pair", kzt_guest_library_loader_scope_publish_pair(
          &scope, map, (library_t *)&new_library,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_loader_scope_end(&scope);

    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_different_library_reuses_closed_callback_address(void)
{
    run_different_library_address_reuse(0, "reuse normal init");
    run_different_library_address_reuse(1, "reuse fallback init");
}

static void prepare_scoped_pair(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_scope_t *scope, uintptr_t map,
    library_t *library)
{
    kzt_guest_library_callback_access_t access = { 0 };

    CHECK("transaction scope", kzt_guest_library_loader_scope_begin(
          bindings, scope) == 0);
    CHECK("transaction callback", kzt_guest_library_callback_access_begin_scoped(
          bindings, map, scope, &access) == 0);
    kzt_guest_library_callback_access_end(&access);
    CHECK("transaction prepare", kzt_guest_library_loader_scope_note_pair(
          scope, map, library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
}

static void test_loader_pair_is_invisible_until_publish(void)
{
    fake_library_t lib = { 61 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_binding_key_t observed = key(0xc900, 30);
    kzt_guest_library_handle_t handle;
    size_t active_pending = 99, live_entries = 99;

    CHECK("transaction init", bindings != NULL);
    if (!bindings) return;
    CHECK("transaction track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("transaction observe", kzt_guest_library_note_observation(
          bindings, &observed) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    prepare_scoped_pair(bindings, &scope, observed.link_map_addr,
                        (library_t *)&lib);
    CHECK("transaction prepared invisible", kzt_guest_library_lookup(
          bindings, &observed, &handle) != 0);
    CHECK("transaction prepared snapshot",
          kzt_guest_library_binding_test_snapshot(
              bindings, (library_t *)&lib, NULL, &active_pending,
              &live_entries) == 0);
    CHECK("transaction prepared has no global state",
          active_pending == 0 && live_entries == 0);
    CHECK("transaction publish", kzt_guest_library_loader_scope_publish_pair(
          &scope, observed.link_map_addr, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("transaction published visible", kzt_guest_library_lookup(
          bindings, &observed, &handle) == 0);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_loader_scope_end(&scope);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_loader_pair_cancel_and_failed_publish_are_invisible(void)
{
    fake_library_t prepared = { 62 }, wrong = { 63 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_binding_key_t cancelled = key(0xca00, 31);
    kzt_guest_library_binding_key_t failed = key(0xcb00, 32);
    kzt_guest_library_handle_t handle;
    size_t active_pending = 99, live_entries = 99;

    CHECK("cancel init", bindings != NULL);
    if (!bindings) return;
    CHECK("cancel track prepared", kzt_guest_library_track(
          bindings, (library_t *)&prepared) == 0);
    CHECK("cancel track wrong", kzt_guest_library_track(
          bindings, (library_t *)&wrong) == 0);
    CHECK("cancel observe", kzt_guest_library_note_observation(
          bindings, &cancelled) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    prepare_scoped_pair(bindings, &scope, cancelled.link_map_addr,
                        (library_t *)&prepared);
    kzt_guest_library_loader_scope_end(&scope);
    CHECK("cancelled pair invisible", kzt_guest_library_lookup(
          bindings, &cancelled, &handle) != 0);
    CHECK("cancelled pair snapshot",
          kzt_guest_library_binding_test_snapshot(
              bindings, (library_t *)&prepared, NULL, &active_pending,
              &live_entries) == 0);
    CHECK("cancelled pair has no global state",
          active_pending == 0 && live_entries == 0);

    CHECK("failed observe", kzt_guest_library_note_observation(
          bindings, &failed) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    prepare_scoped_pair(bindings, &scope, failed.link_map_addr,
                        (library_t *)&prepared);
    CHECK("failed publish rejected",
          kzt_guest_library_loader_scope_publish_pair(
              &scope, failed.link_map_addr, (library_t *)&wrong,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ERROR);
    kzt_guest_library_loader_scope_end(&scope);
    CHECK("failed publish invisible", kzt_guest_library_lookup(
          bindings, &failed, &handle) != 0);
    CHECK("failed publish snapshot",
          kzt_guest_library_binding_test_snapshot(
              bindings, (library_t *)&prepared, NULL, &active_pending,
              &live_entries) == 0);
    CHECK("failed publish has no global state",
          active_pending == 0 && live_entries == 0);
    kzt_guest_library_bindings_destroy(&bindings);
}

static int callback_rejected(kzt_guest_library_bindings_t *bindings,
                             uintptr_t map,
                             const kzt_guest_library_loader_scope_t *scope)
{
    kzt_guest_library_callback_access_t access = { 0 };
    int result = kzt_guest_library_callback_access_begin_scoped(
        bindings, map, scope, &access);
    if (result == 0)
        kzt_guest_library_callback_access_end(&access);
    return result != 0;
}

static void run_failed_loader_keeps_tombstone(int force_gate_alloc_failure)
{
    fake_library_t old_library = { 51 }, new_library = { 52 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_callback_access_t access = { 0 };
    uintptr_t map = force_gate_alloc_failure ? 0xc200 : 0xc100;

    CHECK("failed-loader init", bindings != NULL);
    if (!bindings) return;
    CHECK("failed-loader old track", kzt_guest_library_track(
          bindings, (library_t *)&old_library) == 0);
    CHECK("failed-loader old pair", kzt_guest_library_publish_loader_pair(
          bindings, map, (library_t *)&old_library,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    if (force_gate_alloc_failure)
        kzt_guest_library_binding_test_set_alloc_failure_after(0);
    kzt_guest_library_inactivate(bindings, NULL,
                                 (library_t *)&old_library, map);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);
    CHECK("failed-loader new track", kzt_guest_library_track(
          bindings, (library_t *)&new_library) == 0);
    CHECK("failed-loader scope", kzt_guest_library_loader_scope_begin(
          bindings, &scope) == 0);
    CHECK("failed-loader scoped temporary read",
          kzt_guest_library_callback_access_begin_scoped(
              bindings, map, &scope, &access) == 0);
    kzt_guest_library_callback_access_end(&access);
    kzt_guest_library_loader_scope_end(&scope);

    CHECK("failed-loader tombstone retained",
          callback_rejected(bindings, map, NULL));
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_failed_loader_keeps_normal_and_fallback_tombstones(void)
{
    run_failed_loader_keeps_tombstone(0);
    run_failed_loader_keeps_tombstone(1);
}

typedef struct scope_transfer_arg {
    kzt_guest_library_bindings_t *bindings;
    uintptr_t map;
    kzt_guest_library_loader_scope_t scope;
    int result;
} scope_transfer_arg_t;

static void *scope_transfer_thread(void *opaque)
{
    scope_transfer_arg_t *arg = opaque;
    kzt_guest_library_callback_access_t access = { 0 };
    arg->result = kzt_guest_library_callback_access_begin_scoped(
        arg->bindings, arg->map, &arg->scope, &access);
    if (arg->result == 0)
        kzt_guest_library_callback_access_end(&access);
    return NULL;
}

static void test_loader_scope_identity_and_nesting(void)
{
    fake_library_t old_library = { 53 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t outer = { 0 }, inner = { 0 };
    kzt_guest_library_loader_scope_t stale_inner = { 0 }, forged = { 0 };
    kzt_guest_library_callback_access_t access = { 0 };
    scope_transfer_arg_t transfer = { 0 };
    pthread_t thread;
    uintptr_t map = 0xc300;

    CHECK("scope-id init", bindings != NULL);
    if (!bindings) return;
    CHECK("scope-id track", kzt_guest_library_track(
          bindings, (library_t *)&old_library) == 0);
    CHECK("scope-id pair", kzt_guest_library_publish_loader_pair(
          bindings, map, (library_t *)&old_library,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_inactivate(bindings, NULL,
                                 (library_t *)&old_library, map);

    CHECK("scope-id outer begin", kzt_guest_library_loader_scope_begin(
          bindings, &outer) == 0);
    CHECK("scope-id inner begin", kzt_guest_library_loader_scope_begin(
          bindings, &inner) == 0);
    stale_inner = inner;
    CHECK("scope-id inner active", kzt_guest_library_callback_access_begin_scoped(
          bindings, map, &inner, &access) == 0);
    kzt_guest_library_callback_access_end(&access);
    kzt_guest_library_loader_scope_end(&inner);
    CHECK("scope-id ended copy rejected",
          callback_rejected(bindings, map, &stale_inner));
    CHECK("scope-id outer restored", kzt_guest_library_callback_access_begin_scoped(
          bindings, map, &outer, &access) == 0);
    kzt_guest_library_callback_access_end(&access);

    forged = outer;
    forged.cookie++;
    CHECK("scope-id forged rejected",
          callback_rejected(bindings, map, &forged));

    transfer.bindings = bindings;
    transfer.map = map;
    transfer.scope = outer;
    transfer.result = 0;
    CHECK("scope-id transfer create", pthread_create(
          &thread, NULL, scope_transfer_thread, &transfer) == 0);
    CHECK("scope-id transfer join", pthread_join(thread, NULL) == 0);
    CHECK("scope-id cross-thread rejected", transfer.result != 0);
    kzt_guest_library_loader_scope_end(&outer);
    kzt_guest_library_bindings_destroy(&bindings);
}

typedef struct concurrent_scope_arg {
    kzt_guest_library_bindings_t *bindings;
    pthread_barrier_t *barrier;
    uintptr_t map;
    int result;
} concurrent_scope_arg_t;

static void *concurrent_scope_thread(void *opaque)
{
    concurrent_scope_arg_t *arg = opaque;
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_callback_access_t access = { 0 };

    arg->result = kzt_guest_library_loader_scope_begin(
        arg->bindings, &scope);
    pthread_barrier_wait(arg->barrier);
    if (arg->result == 0)
        arg->result = kzt_guest_library_callback_access_begin_scoped(
            arg->bindings, arg->map, &scope, &access);
    if (arg->result == 0)
        kzt_guest_library_callback_access_end(&access);
    kzt_guest_library_loader_scope_end(&scope);
    return NULL;
}

static void test_concurrent_loader_scopes_do_not_invalidate_each_other(void)
{
    fake_library_t old_a = { 59 }, old_b = { 60 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    pthread_barrier_t barrier;
    pthread_t threads[2];
    concurrent_scope_arg_t args[2] = {
        { .bindings = bindings, .map = 0xc700 },
        { .bindings = bindings, .map = 0xc800 },
    };

    CHECK("concurrent-scope init", bindings != NULL);
    if (!bindings) return;
    CHECK("concurrent-scope track a", kzt_guest_library_track(
          bindings, (library_t *)&old_a) == 0);
    CHECK("concurrent-scope track b", kzt_guest_library_track(
          bindings, (library_t *)&old_b) == 0);
    CHECK("concurrent-scope pair a", kzt_guest_library_publish_loader_pair(
          bindings, args[0].map, (library_t *)&old_a,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("concurrent-scope pair b", kzt_guest_library_publish_loader_pair(
          bindings, args[1].map, (library_t *)&old_b,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&old_a,
                                 args[0].map);
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&old_b,
                                 args[1].map);
    CHECK("concurrent-scope barrier", pthread_barrier_init(
          &barrier, NULL, 2) == 0);
    args[0].barrier = &barrier;
    args[1].barrier = &barrier;
    CHECK("concurrent-scope create a", pthread_create(
          &threads[0], NULL, concurrent_scope_thread, &args[0]) == 0);
    CHECK("concurrent-scope create b", pthread_create(
          &threads[1], NULL, concurrent_scope_thread, &args[1]) == 0);
    CHECK("concurrent-scope join a", pthread_join(threads[0], NULL) == 0);
    CHECK("concurrent-scope join b", pthread_join(threads[1], NULL) == 0);
    CHECK("concurrent-scope a active", args[0].result == 0);
    CHECK("concurrent-scope b active", args[1].result == 0);
    pthread_barrier_destroy(&barrier);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_loader_scope_cannot_reopen_unobserved_address(void)
{
    fake_library_t old_a = { 54 }, old_b = { 55 }, replacement = { 56 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_callback_access_t access = { 0 };
    uintptr_t map_a = 0xc400, map_b = 0xc500;

    CHECK("scope-object init", bindings != NULL);
    if (!bindings) return;
    CHECK("scope-object track a", kzt_guest_library_track(
          bindings, (library_t *)&old_a) == 0);
    CHECK("scope-object track b", kzt_guest_library_track(
          bindings, (library_t *)&old_b) == 0);
    CHECK("scope-object old a", kzt_guest_library_publish_loader_pair(
          bindings, map_a, (library_t *)&old_a,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("scope-object old b", kzt_guest_library_publish_loader_pair(
          bindings, map_b, (library_t *)&old_b,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&old_a, map_a);
    kzt_guest_library_inactivate(bindings, NULL, (library_t *)&old_b, map_b);
    CHECK("scope-object replacement track", kzt_guest_library_track(
          bindings, (library_t *)&replacement) == 0);
    CHECK("scope-object begin", kzt_guest_library_loader_scope_begin(
          bindings, &scope) == 0);
    CHECK("scope-object observe a", kzt_guest_library_callback_access_begin_scoped(
          bindings, map_a, &scope, &access) == 0);
    kzt_guest_library_callback_access_end(&access);
    CHECK("scope-object unrelated publication rejected",
          kzt_guest_library_loader_scope_publish_pair(
              &scope, map_b, (library_t *)&replacement,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
              KZT_GUEST_LIBRARY_BINDING_ERROR);
    kzt_guest_library_loader_scope_end(&scope);
    CHECK("scope-object b remains closed",
          callback_rejected(bindings, map_b, NULL));
    kzt_guest_library_bindings_destroy(&bindings);
}

typedef struct publish_reader_arg {
    kzt_guest_library_bindings_t *bindings;
    library_t *library;
    uintptr_t map;
    int done;
} publish_reader_arg_t;

static void *publish_reader_unload_thread(void *opaque)
{
    publish_reader_arg_t *arg = opaque;
    kzt_guest_library_inactivate(arg->bindings, NULL, arg->library, arg->map);
    __atomic_store_n(&arg->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void test_publish_while_reader_preserves_unload_wait(void)
{
    fake_library_t old_library = { 57 }, replacement = { 58 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_callback_access_t held = { 0 };
    kzt_guest_library_callback_access_t scoped = { 0 };
    kzt_guest_library_loader_scope_t scope = { 0 };
    publish_reader_arg_t arg = { .bindings = bindings,
                                 .library = (library_t *)&old_library,
                                 .map = 0xc600 };
    pthread_t thread;
    struct timespec delay = { .tv_nsec = 20 * 1000 * 1000 };

    CHECK("publish-reader init", bindings != NULL);
    if (!bindings) return;
    CHECK("publish-reader old track", kzt_guest_library_track(
          bindings, (library_t *)&old_library) == 0);
    CHECK("publish-reader old pair", kzt_guest_library_publish_loader_pair(
          bindings, arg.map, (library_t *)&old_library,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("publish-reader held", kzt_guest_library_callback_access_begin(
          bindings, arg.map, &held) == 0);
    CHECK("publish-reader replacement track", kzt_guest_library_track(
          bindings, (library_t *)&replacement) == 0);
    CHECK("publish-reader create", pthread_create(
          &thread, NULL, publish_reader_unload_thread, &arg) == 0);
    for (int i = 0; i < 20 &&
         !callback_rejected(bindings, arg.map, NULL); ++i)
        nanosleep(&delay, NULL);
    CHECK("publish-reader closed", callback_rejected(
          bindings, arg.map, NULL));
    CHECK("publish-reader scope", kzt_guest_library_loader_scope_begin(
          bindings, &scope) == 0);
    CHECK("publish-reader scoped observation",
          kzt_guest_library_callback_access_begin_scoped(
              bindings, arg.map, &scope, &scoped) == 0);
    kzt_guest_library_callback_access_end(&scoped);
    CHECK("publish-reader pending pair",
          kzt_guest_library_loader_scope_note_pair(
              &scope, arg.map, (library_t *)&replacement,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) !=
              KZT_GUEST_LIBRARY_BINDING_ERROR);
    CHECK("publish-reader publication",
          kzt_guest_library_loader_scope_publish_pair(
              &scope, arg.map, (library_t *)&replacement,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) !=
              KZT_GUEST_LIBRARY_BINDING_ERROR);
    kzt_guest_library_loader_scope_end(&scope);
    kzt_guest_library_callback_access_end(&held);
    for (int i = 0; i < 20 &&
         !__atomic_load_n(&arg.done, __ATOMIC_ACQUIRE); ++i)
        nanosleep(&delay, NULL);
    CHECK("publish-reader unload completes",
          __atomic_load_n(&arg.done, __ATOMIC_ACQUIRE));
    if (__atomic_load_n(&arg.done, __ATOMIC_ACQUIRE)) {
        pthread_join(thread, NULL);
        CHECK("publish-reader reopened after old readers drain",
              kzt_guest_library_callback_access_begin(
                  bindings, arg.map, &held) == 0);
        kzt_guest_library_callback_access_end(&held);
        kzt_guest_library_bindings_destroy(&bindings);
    }
}

static void test_registry_retire_failures_are_observable_fail_open(void)
{
    fake_library_t missing = { 43 };
    fake_library_t disabled = { 44 };
    fake_library_t replaced = { 45 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_registry_t *registry;
    unsigned long registry_missing = 0;
    unsigned long retire_unprovable = 0;
    kzt_guest_object_observation_t observed = observation(0xa20000);
    kzt_guest_library_binding_key_t missing_key = key(0xa21000, 1);
    kzt_guest_library_binding_key_t disabled_key = key(0xa22000, 1);
    kzt_guest_library_binding_key_t replaced_key;
    unsigned long generation;

    CHECK("fail-open bindings", bindings != NULL);
    if (!bindings) return;

    CHECK("fail-open missing track", kzt_guest_library_track(
          bindings, (library_t *)&missing) == 0);
    CHECK("fail-open missing bind", kzt_guest_library_bind(
          bindings, &missing_key, (library_t *)&missing,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    kzt_guest_library_inactivate(bindings, NULL,
                                 (library_t *)&missing, 0xa21000);

    kzt_guest_registry_test_set_alloc_failure_after(1);
    registry = kzt_guest_registry_init();
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    CHECK("fail-open disabled registry", registry != NULL);
    CHECK("fail-open disabled track", kzt_guest_library_track(
          bindings, (library_t *)&disabled) == 0);
    CHECK("fail-open disabled bind", kzt_guest_library_bind(
          bindings, &disabled_key, (library_t *)&disabled,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&disabled, 0xa22000);
    kzt_guest_registry_destroy(&registry);

    registry = kzt_guest_registry_init();
    CHECK("fail-open replacement registry", registry != NULL);
    CHECK("fail-open replacement observe", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    generation = registry_generation(registry, observed.link_map_addr);
    replaced_key = key(observed.link_map_addr, generation);
    CHECK("fail-open replacement track", kzt_guest_library_track(
          bindings, (library_t *)&replaced) == 0);
    CHECK("fail-open replacement bind", kzt_guest_library_bind(
          bindings, &replaced_key, (library_t *)&replaced,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("fail-open replacement retire", kzt_guest_registry_retire(
          registry, observed.link_map_addr, generation) == 0);
    CHECK("fail-open replacement observe new", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&replaced,
                                 observed.link_map_addr);

    CHECK("fail-open diagnostics",
          kzt_guest_library_binding_test_get_diagnostics(
              bindings, &registry_missing, &retire_unprovable) == 0);
    CHECK("fail-open registry missing observed",
          registry_missing >= 1);
    CHECK("fail-open registry disabled observed",
          retire_unprovable >= 1);
    CHECK("fail-open generation replacement observed",
          retire_unprovable >= 2);

    kzt_guest_registry_destroy(&registry);
    kzt_guest_library_bindings_destroy(&bindings);
}

typedef struct unbind_thread_arg {
    kzt_guest_library_bindings_t *bindings;
    library_t *library;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int done;
} unbind_thread_arg_t;

static void *unbind_thread(void *opaque)
{
    unbind_thread_arg_t *arg = opaque;
    pthread_mutex_lock(&arg->lock);
    arg->started = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    kzt_guest_library_unbind(arg->bindings, NULL, arg->library, 0);
    pthread_mutex_lock(&arg->lock);
    arg->done = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    return NULL;
}

static void test_lookup_and_unbind_threads(void)
{
    fake_library_t lib = { 6 };
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_library_binding_key_t k = key(0xa000, 13);
    kzt_guest_library_handle_t held, probe;
    pthread_t thread;
    unbind_thread_arg_t arg = {
        .bindings = bindings, .library = (library_t *)&lib,
        .lock = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER,
    };
    CHECK("thread track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("thread add", kzt_guest_library_bind(bindings, &k,
          (library_t *)&lib, KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("thread acquire", kzt_guest_library_lookup(bindings, &k, &held) == 0);
    CHECK("thread create", pthread_create(&thread, NULL, unbind_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    while (!arg.started) pthread_cond_wait(&arg.cond, &arg.lock);
    pthread_mutex_unlock(&arg.lock);
    while (kzt_guest_library_lookup(bindings, &k, &probe) == 0)
        kzt_guest_library_handle_release(&probe);
    pthread_mutex_lock(&arg.lock);
    CHECK("unbind waits for handle", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_handle_release(&held);
    pthread_join(thread, NULL);
    CHECK("no dead return", kzt_guest_library_lookup(bindings, &k, &probe) != 0);
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_bindings_destroy(&bindings);
}

static void test_reverse_lookup_handle_pins_unload(void)
{
    fake_library_t lib = { 84 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t expected = key(0x16000, 86);
    kzt_guest_library_binding_key_t found = { 0 };
    kzt_guest_library_handle_t held = { 0 }, probe = { 0 };
    pthread_t thread;
    unbind_thread_arg_t arg = {
        .library = (library_t *)&lib,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    CHECK("reverse unload access init",
          kzt_guest_library_access_init(&access) == 0);
    arg.bindings = access.bindings;
    CHECK("reverse unload track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse unload bind", kzt_guest_library_bind(
          access.bindings, &expected, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("reverse unload acquire",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &held) == 0);
    CHECK("reverse unload thread",
          pthread_create(&thread, NULL, unbind_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    while (!arg.started) pthread_cond_wait(&arg.cond, &arg.lock);
    pthread_mutex_unlock(&arg.lock);
    do {
        found = expected;
        probe = (kzt_guest_library_handle_t){
            .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
            .entry = (void *)(uintptr_t)2,
            .library = (library_t *)(uintptr_t)3,
            .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
        };
        if (kzt_guest_library_access_lookup_by_library(
                &access, (library_t *)&lib, &found, &probe) != 0)
            break;
        kzt_guest_library_handle_release(&probe);
    } while (1);
    CHECK("reverse unload closes lookup",
          reverse_outputs_are_clear(&found, &probe));
    pthread_mutex_lock(&arg.lock);
    CHECK("reverse unload waits for handle", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_handle_release(&held);
    CHECK("reverse unload join", pthread_join(thread, NULL) == 0);
    found = expected;
    CHECK("reverse unload dead lookup",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &probe) != 0 &&
          reverse_outputs_are_clear(&found, &probe));
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_access_destroy(&access);
}

typedef struct lock_order_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int lease_ready;
    int start_lookup;
    int retire_waiting;
    int lookup_done;
    int lookup_result;
} lock_order_sync_t;

typedef struct lock_order_unload_arg {
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_registry_t *registry;
    library_t *library;
    uintptr_t link_map_addr;
} lock_order_unload_arg_t;

typedef struct lock_order_lookup_arg {
    kzt_guest_library_access_t *access;
    kzt_guest_registry_t *registry;
    kzt_guest_library_binding_key_t key;
    kzt_guest_registry_source_lease_t *lease;
    lock_order_sync_t *sync;
} lock_order_lookup_arg_t;

static void lock_order_retire_waiting(void *opaque)
{
    lock_order_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    sync->retire_waiting = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void *lock_order_unload_worker(void *opaque)
{
    lock_order_unload_arg_t *arg = opaque;

    kzt_guest_library_inactivate(arg->bindings, arg->registry, arg->library,
                                 arg->link_map_addr);
    return NULL;
}

static void *lock_order_lookup_worker(void *opaque)
{
    lock_order_lookup_arg_t *arg = opaque;
    kzt_guest_library_handle_t handle;
    int result = kzt_guest_registry_source_lease_acquire(
        arg->registry, arg->key.link_map_addr, arg->key.generation,
        arg->key.namespace_id, arg->lease);

    pthread_mutex_lock(&arg->sync->lock);
    arg->sync->lease_ready = result == 0;
    pthread_cond_broadcast(&arg->sync->cond);
    while (result == 0 && !arg->sync->start_lookup) {
        pthread_cond_wait(&arg->sync->cond, &arg->sync->lock);
    }
    pthread_mutex_unlock(&arg->sync->lock);

    if (result == 0) {
        /* This is the production provider-lookup lock path while the same
         * lazy-completion thread owns the exact source lease. */
        result = kzt_guest_library_access_lookup(
            arg->access, &arg->key, &handle);
    }

    if (result == 0) {
        kzt_guest_library_handle_release(&handle);
    }
    pthread_mutex_lock(&arg->sync->lock);
    arg->sync->lookup_result = result;
    arg->sync->lookup_done = 1;
    pthread_cond_broadcast(&arg->sync->cond);
    pthread_mutex_unlock(&arg->sync->lock);
    return NULL;
}

static int timed_wait_for_flag(pthread_cond_t *cond, pthread_mutex_t *lock,
                               int *flag)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 30;
    while (!*flag) {
        int result = pthread_cond_clockwait(
            cond, lock, CLOCK_MONOTONIC, &deadline);
        if (result != 0) {
            fprintf(stderr, "timed wait failed: flag=%d error=%d\n",
                    *flag, result);
            return -1;
        }
    }
    return 0;
}

typedef struct loader_scope_wait_arg {
    kzt_guest_library_bindings_t *bindings;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int done;
    int result;
} loader_scope_wait_arg_t;

static void *loader_scope_wait_thread(void *opaque)
{
    loader_scope_wait_arg_t *arg = opaque;
    kzt_guest_library_loader_scope_t scope = { 0 };

    pthread_mutex_lock(&arg->lock);
    arg->started = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    arg->result = kzt_guest_library_loader_scope_begin(
        arg->bindings, &scope);
    if (arg->result == 0)
        kzt_guest_library_loader_scope_end(&scope);
    pthread_mutex_lock(&arg->lock);
    arg->done = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    return NULL;
}

static void test_loader_scope_waits_for_all_quiescence_leases(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_lease_t first = { 0 };
    kzt_guest_library_loader_quiescence_lease_t second = { 0 };
    loader_scope_wait_arg_t arg = {
        .bindings = bindings,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;
    unsigned int waiters = 0;
    kzt_guest_library_loader_quiescence_lease_t late = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .cookie = 1,
    };

    CHECK("lease wait init", bindings != NULL);
    if (!bindings) return;
    CHECK("lease wait acquire",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &first) == 0);
    CHECK("lease wait concurrent acquire",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &second) == 0);
    CHECK("lease wait thread", pthread_create(
          &thread, NULL, loader_scope_wait_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    CHECK("lease wait worker started",
          timed_wait_for_flag(&arg.cond, &arg.lock, &arg.started) == 0);
    pthread_mutex_unlock(&arg.lock);
    for (int i = 0; i < 1000; ++i) {
        struct timespec delay = { .tv_nsec = 1000000L };

        CHECK("lease wait snapshot",
              kzt_guest_library_binding_test_loader_state(
                  bindings, NULL, &waiters, NULL, NULL) == 0);
        if (waiters == 1) break;
        pthread_mutex_lock(&arg.lock);
        int done = arg.done;
        pthread_mutex_unlock(&arg.lock);
        if (done) break;
        nanosleep(&delay, NULL);
    }
    pthread_mutex_lock(&arg.lock);
    CHECK("loader begin waits while lease held",
          waiters == 1 && !arg.done);
    pthread_mutex_unlock(&arg.lock);
    CHECK("waiting loader rejects later lease",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &late) != 0);
    CHECK("waiting loader clears rejected lease",
          late.bindings == NULL && late.cookie == 0);
    kzt_guest_library_loader_quiescence_release(&first);
    pthread_mutex_lock(&arg.lock);
    CHECK("loader begin still waits for second lease", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_loader_quiescence_release(&second);
    pthread_mutex_lock(&arg.lock);
    CHECK("loader begin resumes after release",
          timed_wait_for_flag(&arg.cond, &arg.lock, &arg.done) == 0 &&
          arg.result == 0);
    pthread_mutex_unlock(&arg.lock);
    CHECK("lease wait join", pthread_join(thread, NULL) == 0);
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_bindings_destroy(&bindings);
}

typedef struct loader_destroy_arg {
    kzt_guest_library_bindings_t *bindings;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int done;
} loader_destroy_arg_t;

static void *loader_destroy_thread(void *opaque)
{
    loader_destroy_arg_t *arg = opaque;

    pthread_mutex_lock(&arg->lock);
    arg->started = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    kzt_guest_library_bindings_destroy(&arg->bindings);
    pthread_mutex_lock(&arg->lock);
    arg->done = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    return NULL;
}

static void test_loader_quiescence_teardown_drains_readers_and_waiters(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_lease_t first = { 0 };
    kzt_guest_library_loader_quiescence_lease_t second = { 0 };
    loader_scope_wait_arg_t waiter = {
        .bindings = bindings,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    loader_destroy_arg_t destroy = {
        .bindings = bindings,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    pthread_t waiter_thread, destroy_thread;
    unsigned int waiters = 0;
    int is_shutting_down = 0;

    CHECK("lease teardown init", bindings != NULL);
    if (!bindings) return;
    CHECK("lease teardown acquire first",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &first) == 0);
    CHECK("lease teardown acquire second",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &second) == 0);
    CHECK("lease teardown waiter thread", pthread_create(
          &waiter_thread, NULL, loader_scope_wait_thread, &waiter) == 0);
    for (int i = 0; i < 1000; ++i) {
        struct timespec delay = { .tv_nsec = 1000000L };

        CHECK("lease teardown waiter snapshot",
              kzt_guest_library_binding_test_loader_state(
                  bindings, NULL, &waiters, NULL, NULL) == 0);
        if (waiters == 1) break;
        nanosleep(&delay, NULL);
    }
    CHECK("lease teardown waiter blocked", waiters == 1);
    CHECK("lease teardown destroy thread", pthread_create(
          &destroy_thread, NULL, loader_destroy_thread, &destroy) == 0);
    pthread_mutex_lock(&destroy.lock);
    CHECK("lease teardown destroy started",
          timed_wait_for_flag(
              &destroy.cond, &destroy.lock, &destroy.started) == 0);
    pthread_mutex_unlock(&destroy.lock);
    for (int i = 0; i < 1000; ++i) {
        struct timespec delay = { .tv_nsec = 1000000L };

        CHECK("lease teardown shutdown snapshot",
              kzt_guest_library_binding_test_loader_state(
                  bindings, NULL, NULL, NULL, &is_shutting_down) == 0);
        if (is_shutting_down) break;
        nanosleep(&delay, NULL);
    }
    CHECK("lease teardown gate closed", is_shutting_down);
    pthread_mutex_lock(&waiter.lock);
    CHECK("lease teardown wakes loader waiter",
          timed_wait_for_flag(
              &waiter.cond, &waiter.lock, &waiter.done) == 0 &&
          waiter.result != 0);
    pthread_mutex_unlock(&waiter.lock);
    pthread_mutex_lock(&destroy.lock);
    CHECK("lease teardown waits for readers", !destroy.done);
    pthread_mutex_unlock(&destroy.lock);
    kzt_guest_library_loader_quiescence_release(&first);
    pthread_mutex_lock(&destroy.lock);
    CHECK("lease teardown waits for last reader", !destroy.done);
    pthread_mutex_unlock(&destroy.lock);
    kzt_guest_library_loader_quiescence_release(&second);
    pthread_mutex_lock(&destroy.lock);
    CHECK("lease teardown completes after last reader",
          timed_wait_for_flag(
              &destroy.cond, &destroy.lock, &destroy.done) == 0);
    pthread_mutex_unlock(&destroy.lock);
    CHECK("lease teardown waiter join",
          pthread_join(waiter_thread, NULL) == 0);
    CHECK("lease teardown destroy join",
          pthread_join(destroy_thread, NULL) == 0);
    CHECK("lease teardown destroyed binding", destroy.bindings == NULL);
    pthread_cond_destroy(&waiter.cond);
    pthread_mutex_destroy(&waiter.lock);
    pthread_cond_destroy(&destroy.cond);
    pthread_mutex_destroy(&destroy.lock);
}

static void test_loader_quiescence_teardown_drains_writer(void)
{
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_writer_t writer = { 0 };
    loader_destroy_arg_t destroy = {
        .bindings = bindings,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    pthread_t destroy_thread;
    int is_shutting_down = 0;

    CHECK("writer teardown init", bindings != NULL);
    if (!bindings) return;
    CHECK("writer teardown begin",
          kzt_guest_library_loader_quiescence_writer_begin(
              bindings, &writer) == 0);
    CHECK("writer teardown destroy thread", pthread_create(
          &destroy_thread, NULL, loader_destroy_thread, &destroy) == 0);
    pthread_mutex_lock(&destroy.lock);
    CHECK("writer teardown destroy started",
          timed_wait_for_flag(
              &destroy.cond, &destroy.lock, &destroy.started) == 0);
    pthread_mutex_unlock(&destroy.lock);
    for (int i = 0; i < 1000; ++i) {
        struct timespec delay = { .tv_nsec = 1000000L };

        CHECK("writer teardown shutdown snapshot",
              kzt_guest_library_binding_test_loader_state(
                  bindings, NULL, NULL, NULL, &is_shutting_down) == 0);
        if (is_shutting_down) break;
        nanosleep(&delay, NULL);
    }
    CHECK("writer teardown gate closed", is_shutting_down);
    pthread_mutex_lock(&destroy.lock);
    CHECK("writer teardown waits for writer", !destroy.done);
    pthread_mutex_unlock(&destroy.lock);
    kzt_guest_library_loader_quiescence_writer_end(&writer);
    pthread_mutex_lock(&destroy.lock);
    CHECK("writer teardown completes after release",
          timed_wait_for_flag(
              &destroy.cond, &destroy.lock, &destroy.done) == 0);
    pthread_mutex_unlock(&destroy.lock);
    CHECK("writer teardown destroy join",
          pthread_join(destroy_thread, NULL) == 0);
    CHECK("writer teardown destroyed binding", destroy.bindings == NULL);
    pthread_cond_destroy(&destroy.cond);
    pthread_mutex_destroy(&destroy.lock);
}

typedef struct observation_unload_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int retire_waiters;
    int retire_calls;
    struct {
        kzt_guest_library_bindings_t *bindings;
        kzt_guest_library_binding_key_t key;
        library_t *library;
        int from_observation;
    } retire[4];
    int lifecycle_waiters;
    kzt_guest_library_bindings_t *lifecycle_wait_bindings;
    library_t *lifecycle_wait_library;
} observation_unload_sync_t;

typedef struct observation_unload_arg {
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_registry_t *registry;
    library_t *library;
    uintptr_t link_map_addr;
    observation_unload_sync_t *sync;
    int started;
    int done;
} observation_unload_arg_t;

static void observation_retire_waiting(void *opaque)
{
    observation_unload_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    ++sync->retire_waiters;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void observation_before_registry_retire(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key,
    library_t *library, int from_observation, void *opaque)
{
    observation_unload_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    if (sync->retire_calls < (int)(sizeof(sync->retire) /
                                   sizeof(sync->retire[0]))) {
        sync->retire[sync->retire_calls].bindings = bindings;
        sync->retire[sync->retire_calls].key = *key;
        sync->retire[sync->retire_calls].library = library;
        sync->retire[sync->retire_calls].from_observation =
            from_observation;
    }
    ++sync->retire_calls;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void observation_before_lifecycle_wait(
    kzt_guest_library_bindings_t *bindings, library_t *library,
    void *opaque)
{
    observation_unload_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    ++sync->lifecycle_waiters;
    sync->lifecycle_wait_bindings = bindings;
    sync->lifecycle_wait_library = library;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void *observation_unload_worker(void *opaque)
{
    observation_unload_arg_t *arg = opaque;

    pthread_mutex_lock(&arg->sync->lock);
    arg->started = 1;
    pthread_cond_broadcast(&arg->sync->cond);
    pthread_mutex_unlock(&arg->sync->lock);
    kzt_guest_library_inactivate(arg->bindings, arg->registry, arg->library,
                                 arg->link_map_addr);
    pthread_mutex_lock(&arg->sync->lock);
    arg->done = 1;
    pthread_cond_broadcast(&arg->sync->cond);
    pthread_mutex_unlock(&arg->sync->lock);
    return NULL;
}

static int timed_wait_for_count(pthread_cond_t *cond, pthread_mutex_t *lock,
                                int *value, int expected)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 30;
    while (*value < expected) {
        int result = pthread_cond_clockwait(
            cond, lock, CLOCK_MONOTONIC, &deadline);
        if (result != 0) {
            fprintf(stderr,
                    "timed wait failed: value=%d expected=%d error=%d\n",
                    *value, expected, result);
            return -1;
        }
    }
    return 0;
}

static void test_concurrent_observation_unloads_keep_exact_owners(void)
{
    fake_library_t a = { 70 }, b = { 71 };
    uintptr_t map_a = 0xe000, map_b = 0xe100;
    kzt_guest_object_observation_t observed_a = observation(map_a);
    kzt_guest_object_observation_t observed_b = observation(map_b);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_registry_source_lease_t lease_a = { 0 }, lease_b = { 0 };
    kzt_guest_library_binding_key_t key_a, key_b;
    observation_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    observation_unload_arg_t arg_a = {
        .bindings = bindings, .registry = registry,
        .library = (library_t *)&a, .link_map_addr = map_a, .sync = &sync,
    };
    observation_unload_arg_t arg_b = {
        .bindings = bindings, .registry = registry,
        .library = (library_t *)&b, .link_map_addr = map_b, .sync = &sync,
    };
    pthread_t thread_a, thread_b;

    CHECK("owner-race track a", kzt_guest_library_track(
          bindings, (library_t *)&a) == 0);
    CHECK("owner-race track b", kzt_guest_library_track(
          bindings, (library_t *)&b) == 0);
    CHECK("owner-race registry a", kzt_guest_registry_observe(
          registry, &observed_a) == KZT_GUEST_REGISTRY_ADDED);
    CHECK("owner-race registry b", kzt_guest_registry_observe(
          registry, &observed_b) == KZT_GUEST_REGISTRY_ADDED);
    key_a = key(map_a, registry_generation(registry, map_a));
    key_b = key(map_b, registry_generation(registry, map_b));
    CHECK("owner-race observation a", kzt_guest_library_note_observation(
          bindings, &key_a) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("owner-race observation b", kzt_guest_library_note_observation(
          bindings, &key_b) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("owner-race lease a", kzt_guest_registry_source_lease_acquire(
          registry, map_a, key_a.generation, 0, &lease_a) == 0);
    CHECK("owner-race lease b", kzt_guest_registry_source_lease_acquire(
          registry, map_b, key_b.generation, 0, &lease_b) == 0);

    kzt_guest_registry_test_set_before_retire_wait(
        observation_retire_waiting, &sync);
    kzt_guest_library_binding_test_set_before_registry_retire(
        observation_before_registry_retire, &sync);
    CHECK("owner-race thread a", pthread_create(
          &thread_a, NULL, observation_unload_worker, &arg_a) == 0);
    CHECK("owner-race thread b", pthread_create(
          &thread_b, NULL, observation_unload_worker, &arg_b) == 0);
    pthread_mutex_lock(&sync.lock);
    CHECK("owner-race both blocked", timed_wait_for_count(
          &sync.cond, &sync.lock, &sync.retire_waiters, 2) == 0);
    CHECK("owner-race retire identities", sync.retire_calls == 2 &&
          sync.retire[0].bindings == bindings &&
          sync.retire[1].bindings == bindings &&
          sync.retire[0].from_observation &&
          sync.retire[1].from_observation &&
          ((sync.retire[0].library == (library_t *)&a &&
            sync.retire[0].key.link_map_addr == map_a &&
            sync.retire[1].library == (library_t *)&b &&
            sync.retire[1].key.link_map_addr == map_b) ||
           (sync.retire[0].library == (library_t *)&b &&
            sync.retire[0].key.link_map_addr == map_b &&
            sync.retire[1].library == (library_t *)&a &&
            sync.retire[1].key.link_map_addr == map_a)));
    pthread_mutex_unlock(&sync.lock);

    kzt_guest_registry_source_lease_release(&lease_a);
    pthread_mutex_lock(&sync.lock);
    CHECK("owner-race a completes", timed_wait_for_flag(
          &sync.cond, &sync.lock, &arg_a.done) == 0);
    CHECK("owner-race b remains blocked", !arg_b.done);
    pthread_mutex_unlock(&sync.lock);

    kzt_guest_registry_source_lease_release(&lease_b);
    pthread_mutex_lock(&sync.lock);
    CHECK("owner-race b completes", timed_wait_for_flag(
          &sync.cond, &sync.lock, &arg_b.done) == 0);
    pthread_mutex_unlock(&sync.lock);
    CHECK("owner-race join a", pthread_join(thread_a, NULL) == 0);
    CHECK("owner-race join b", pthread_join(thread_b, NULL) == 0);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_duplicate_unload_waits_for_lifecycle_owner(void)
{
    fake_library_t lib = { 72 };
    uintptr_t map = 0xe200, unowned_map = 0xe300;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_object_observation_t unowned = observation(unowned_map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings = kzt_guest_library_bindings_init();
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_library_binding_key_t observed_key, unowned_key;
    observation_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    observation_unload_arg_t first = {
        .bindings = bindings, .registry = registry,
        .library = (library_t *)&lib, .link_map_addr = map, .sync = &sync,
    };
    observation_unload_arg_t second = {
        .bindings = bindings, .registry = registry,
        .library = (library_t *)&lib, .link_map_addr = unowned_map,
        .sync = &sync,
    };
    pthread_t first_thread, second_thread;

    CHECK("duplicate-owner track", kzt_guest_library_track(
          bindings, (library_t *)&lib) == 0);
    CHECK("duplicate-owner registry", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    CHECK("duplicate-owner unowned registry", kzt_guest_registry_observe(
          registry, &unowned) == KZT_GUEST_REGISTRY_ADDED);
    observed_key = key(map, registry_generation(registry, map));
    unowned_key = key(unowned_map,
                      registry_generation(registry, unowned_map));
    CHECK("duplicate-owner observation", kzt_guest_library_note_observation(
          bindings, &observed_key) == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("duplicate-owner unowned observation",
          kzt_guest_library_note_observation(bindings, &unowned_key) ==
          KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    CHECK("duplicate-owner lease", kzt_guest_registry_source_lease_acquire(
          registry, map, observed_key.generation, 0, &lease) == 0);

    kzt_guest_registry_test_set_before_retire_wait(
        observation_retire_waiting, &sync);
    kzt_guest_library_binding_test_set_before_registry_retire(
        observation_before_registry_retire, &sync);
    kzt_guest_library_binding_test_set_before_lifecycle_wait(
        observation_before_lifecycle_wait, &sync);
    CHECK("duplicate-owner first thread", pthread_create(
          &first_thread, NULL, observation_unload_worker, &first) == 0);
    pthread_mutex_lock(&sync.lock);
    CHECK("duplicate-owner first blocked", timed_wait_for_count(
          &sync.cond, &sync.lock, &sync.retire_waiters, 1) == 0);
    pthread_mutex_unlock(&sync.lock);
    CHECK("duplicate-owner second thread", pthread_create(
          &second_thread, NULL, observation_unload_worker, &second) == 0);
    pthread_mutex_lock(&sync.lock);
    CHECK("duplicate-owner second entered exact wait", timed_wait_for_count(
          &sync.cond, &sync.lock, &sync.lifecycle_waiters, 1) == 0);
    CHECK("duplicate-owner wait identity",
          sync.lifecycle_wait_bindings == bindings &&
          sync.lifecycle_wait_library == (library_t *)&lib);
    CHECK("duplicate-owner second waits", second.started && !second.done);
    CHECK("duplicate-owner only first hint retired",
          sync.retire_calls == 1 &&
          sync.retire[0].bindings == bindings &&
          sync.retire[0].library == (library_t *)&lib &&
          sync.retire[0].from_observation &&
          sync.retire[0].key.link_map_addr == map &&
          sync.retire[0].key.generation == observed_key.generation);
    pthread_mutex_unlock(&sync.lock);

    kzt_guest_registry_source_lease_release(&lease);
    pthread_mutex_lock(&sync.lock);
    CHECK("duplicate-owner first completes", timed_wait_for_flag(
          &sync.cond, &sync.lock, &first.done) == 0);
    CHECK("duplicate-owner second completes", timed_wait_for_flag(
          &sync.cond, &sync.lock, &second.done) == 0);
    pthread_mutex_unlock(&sync.lock);
    CHECK("duplicate-owner first join", pthread_join(first_thread, NULL) == 0);
    CHECK("duplicate-owner second join", pthread_join(second_thread, NULL) == 0);
    CHECK("duplicate-owner second hint not claimed",
          kzt_guest_registry_find_by_link_map(
              registry, unowned_map, &snapshot) == 0 && snapshot &&
          snapshot->generation == unowned_key.generation &&
          snapshot->state != KZT_GUEST_OBJECT_UNLOADING &&
          snapshot->state != KZT_GUEST_OBJECT_DEAD);
    kzt_guest_object_snapshot_free(snapshot);
    CHECK("duplicate-owner unowned cleanup", kzt_guest_registry_retire(
          registry, unowned_map, unowned_key.generation) == 0);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_lifecycle_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_source_lease_unload_allows_provider_lookup(void)
{
    fake_library_t lib = { 60 };
    fake_library_t growth[24];
    uintptr_t map = 0xd000;
    kzt_guest_object_observation_t observed = observation(map);
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_access_t access;
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_guest_library_binding_state_t lifecycle_state;
    kzt_guest_library_binding_key_t binding_key;
    lock_order_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    lock_order_unload_arg_t unload_arg;
    lock_order_lookup_arg_t lookup_arg;
    pthread_t unload_thread;
    pthread_t lookup_thread;
    size_t live_entries = 1;

    CHECK("lock-order.registry", registry != NULL);
    CHECK("lock-order.access", kzt_guest_library_access_init(&access) == 0);
    CHECK("lock-order.track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("lock-order.observe", kzt_guest_registry_observe(
          registry, &observed) == KZT_GUEST_REGISTRY_ADDED);
    binding_key = key(map, registry_generation(registry, map));
    CHECK("lock-order.bind", kzt_guest_library_bind(
          access.bindings, &binding_key, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);

    lookup_arg = (lock_order_lookup_arg_t) {
        .access = &access,
        .registry = registry,
        .key = binding_key,
        .lease = &lease,
        .sync = &sync,
    };
    CHECK("lock-order.lookup-thread", pthread_create(
          &lookup_thread, NULL, lock_order_lookup_worker, &lookup_arg) == 0);
    pthread_mutex_lock(&sync.lock);
    CHECK("lock-order.lease-barrier", timed_wait_for_flag(
          &sync.cond, &sync.lock, &sync.lease_ready) == 0);
    pthread_mutex_unlock(&sync.lock);

    unload_arg = (lock_order_unload_arg_t) {
        .bindings = access.bindings,
        .registry = registry,
        .library = (library_t *)&lib,
        .link_map_addr = map,
    };
    kzt_guest_registry_test_set_before_retire_wait(
        lock_order_retire_waiting, &sync);
    CHECK("lock-order.unload-thread", pthread_create(
          &unload_thread, NULL, lock_order_unload_worker, &unload_arg) == 0);
    pthread_mutex_lock(&sync.lock);
    CHECK("lock-order.retire-wait-barrier", timed_wait_for_flag(
          &sync.cond, &sync.lock, &sync.retire_waiting) == 0);
    pthread_mutex_unlock(&sync.lock);

    /* Force lifecycle realloc while unload owns no binding-side pointer. */
    for (size_t i = 0; i < 24; ++i) {
        growth[i].id = 100 + (int)i;
        CHECK("lock-order.concurrent-lifecycle-growth",
              kzt_guest_library_track(
                  access.bindings, (library_t *)&growth[i]) == 0);
    }

    CHECK("lock-order.entry-closed", kzt_guest_library_binding_test_snapshot(
          access.bindings, (library_t *)&lib, &lifecycle_state, NULL,
          &live_entries) == 0 &&
          lifecycle_state == KZT_GUEST_LIBRARY_BINDING_UNLOADING &&
          live_entries == 0);

    pthread_mutex_lock(&sync.lock);
    sync.start_lookup = 1;
    pthread_cond_broadcast(&sync.cond);
    CHECK("lock-order.lookup-not-blocked", timed_wait_for_flag(
          &sync.cond, &sync.lock, &sync.lookup_done) == 0);
    CHECK("lock-order.lookup-fast-fail", sync.lookup_done &&
          sync.lookup_result != 0);
    pthread_mutex_unlock(&sync.lock);

    /* Also releases the old implementation if it deadlocks in lookup, so the
     * test reports a bounded failure instead of hanging the suite. */
    kzt_guest_registry_source_lease_release(&lease);
    CHECK("lock-order.lookup-join", pthread_join(lookup_thread, NULL) == 0);
    CHECK("lock-order.unload-join", pthread_join(unload_thread, NULL) == 0);
    CHECK("lock-order.final-dead", kzt_guest_library_binding_test_snapshot(
          access.bindings, (library_t *)&lib, &lifecycle_state, NULL,
          &live_entries) == 0 &&
          lifecycle_state == KZT_GUEST_LIBRARY_BINDING_DEAD &&
          live_entries == 0);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_access_destroy(&access);
    kzt_guest_registry_destroy(&registry);
}

typedef struct access_teardown_arg {
    kzt_guest_library_access_t *access;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int done;
} access_teardown_arg_t;

static void *access_teardown_thread(void *opaque)
{
    access_teardown_arg_t *arg = opaque;
    pthread_mutex_lock(&arg->lock);
    arg->started = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    kzt_guest_library_access_begin_teardown(arg->access);
    pthread_mutex_lock(&arg->lock);
    arg->done = 1;
    pthread_cond_broadcast(&arg->cond);
    pthread_mutex_unlock(&arg->lock);
    return NULL;
}

static void test_context_access_closes_before_destroy(void)
{
    fake_library_t lib = { 50 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t k = key(0xc000, 50);
    kzt_guest_library_handle_t held, probe;
    pthread_t thread;
    access_teardown_arg_t arg = {
        .access = &access,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    CHECK("access init", kzt_guest_library_access_init(&access) == 0);
    CHECK("access track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("access bind", kzt_guest_library_bind(
          access.bindings, &k, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("access acquire", kzt_guest_library_access_lookup(
          &access, &k, &held) == 0);
    CHECK("access teardown thread", pthread_create(
          &thread, NULL, access_teardown_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    while (!arg.started) pthread_cond_wait(&arg.cond, &arg.lock);
    pthread_mutex_unlock(&arg.lock);
    while (kzt_guest_library_lookup(access.bindings, &k, &probe) == 0)
        kzt_guest_library_handle_release(&probe);
    pthread_mutex_lock(&arg.lock);
    CHECK("context teardown waits for held handle", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_handle_release(&held);
    pthread_join(thread, NULL);
    CHECK("closed context rejects lookup", kzt_guest_library_access_lookup(
          &access, &k, &probe) != 0);
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_access_destroy(&access);
}

static void test_reverse_lookup_handle_pins_teardown(void)
{
    fake_library_t lib = { 85 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t expected = key(0x17000, 87);
    kzt_guest_library_binding_key_t found = { 0 };
    kzt_guest_library_handle_t held = { 0 }, probe = { 0 };
    pthread_t thread;
    access_teardown_arg_t arg = {
        .access = &access,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    CHECK("reverse teardown access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("reverse teardown track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse teardown bind", kzt_guest_library_bind(
          access.bindings, &expected, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("reverse teardown acquire",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &held) == 0);
    CHECK("reverse teardown thread", pthread_create(
          &thread, NULL, access_teardown_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    while (!arg.started) pthread_cond_wait(&arg.cond, &arg.lock);
    pthread_mutex_unlock(&arg.lock);
    do {
        found = expected;
        probe = (kzt_guest_library_handle_t){
            .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
            .entry = (void *)(uintptr_t)2,
            .library = (library_t *)(uintptr_t)3,
            .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
        };
        if (kzt_guest_library_access_lookup_by_library(
                &access, (library_t *)&lib, &found, &probe) != 0)
            break;
        kzt_guest_library_handle_release(&probe);
    } while (1);
    CHECK("reverse teardown closes lookup",
          reverse_outputs_are_clear(&found, &probe));
    pthread_mutex_lock(&arg.lock);
    CHECK("reverse teardown waits for handle", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_handle_release(&held);
    CHECK("reverse teardown join", pthread_join(thread, NULL) == 0);
    found = expected;
    CHECK("reverse teardown closed lookup",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &probe) != 0 &&
          reverse_outputs_are_clear(&found, &probe));
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_access_destroy(&access);
}

static void test_reverse_lookup_zero_match_clears_outputs(void)
{
    fake_library_t lib = { 81 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t found = key(0x12000, 82);
    kzt_guest_library_handle_t handle = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .entry = (void *)(uintptr_t)2,
        .library = (library_t *)(uintptr_t)3,
        .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
    };

    CHECK("reverse zero access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("reverse zero track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse zero lookup",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &handle) != 0);
    CHECK("reverse zero clears outputs",
          reverse_outputs_are_clear(&found, &handle));
    kzt_guest_library_access_destroy(&access);
}

static void test_wrapped_producer_cannot_own_two_live_identities(void)
{
    fake_library_t lib = { 82 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t first = key(0x13000, 83);
    kzt_guest_library_binding_key_t second = key(0x14000, 84);
    kzt_guest_library_binding_key_t found = first;
    kzt_guest_library_handle_t handle = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .entry = (void *)(uintptr_t)2,
        .library = (library_t *)(uintptr_t)3,
        .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
    };

    CHECK("reverse duplicate access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("reverse duplicate track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse duplicate first bind", kzt_guest_library_bind(
          access.bindings, &first, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("wrapped producer second identity conflicts", kzt_guest_library_bind(
          access.bindings, &second, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_CONFLICT);
    CHECK("wrapped producer first identity remains unique",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &handle) == 0 &&
          found.link_map_addr == first.link_map_addr &&
          found.generation == first.generation &&
          handle.library == (library_t *)&lib);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_inactivate(
        access.bindings, NULL, (library_t *)&lib, first.link_map_addr);
    CHECK("retired wrapped identity is no longer visible",
          kzt_guest_library_access_lookup(
              &access, &first, &handle) != 0);
    CHECK("wrapped producer reactivates for reload",
          kzt_guest_library_reactivate(
              access.bindings, (library_t *)&lib) == 0);
    CHECK("new generation binds after old identity retires",
          kzt_guest_library_bind(
              access.bindings, &second, (library_t *)&lib,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("reloaded producer has only new identity",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &handle) == 0 &&
          found.link_map_addr == second.link_map_addr &&
          found.generation == second.generation);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_access_destroy(&access);
}

static void test_reverse_lookup_non_main_binding_is_rejected(void)
{
    fake_library_t lib = { 83 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t explicit = key(0x15000, 85);
    kzt_guest_library_binding_key_t found = explicit;
    kzt_guest_library_handle_t handle = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .entry = (void *)(uintptr_t)2,
        .library = (library_t *)(uintptr_t)3,
        .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
    };

    explicit.namespace_id = 7;
    explicit.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
    CHECK("reverse non-main access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("reverse non-main track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("reverse non-main publication rejected", kzt_guest_library_bind(
          access.bindings, &explicit, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ERROR);
    CHECK("reverse non-main lookup",
          kzt_guest_library_access_lookup_by_library(
              &access, (library_t *)&lib, &found, &handle) != 0);
    CHECK("reverse non-main clears outputs",
          reverse_outputs_are_clear(&found, &handle));
    kzt_guest_library_access_destroy(&access);
}

static void test_symbol_evidence_cache_is_generation_local(void)
{
    fake_library_t lib = { 89 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t first = key(0x17000, 90);
    kzt_guest_library_binding_key_t second = key(0x17000, 91);
    kzt_guest_library_handle_t handle = { 0 };
    uintptr_t address = 0;
    uintptr_t bridge = 0;
    unsigned char type = 0;

    CHECK("symbol cache access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("symbol cache track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("symbol cache first bind", kzt_guest_library_bind(
          access.bindings, &first, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("symbol cache first lookup", kzt_guest_library_access_lookup(
          &access, &first, &handle) == 0);
    kzt_guest_library_symbol_evidence_store(
        &handle, "cached_function", 1, 0x17100, 2);
    CHECK("symbol cache first hit",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 1, &address, &type, &bridge) == 0 &&
          address == 0x17100 && type == 2 && !bridge);
    CHECK("bridge cache misses before exact selection",
          !bridge);
    kzt_guest_library_symbol_bridge_store(
        &handle, "cached_function", 1, 0x17200);
    CHECK("bridge cache first hit",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 1, &address, &type, &bridge) == 0 &&
          bridge == 0x17200);
    CHECK("symbol cache dynamic revision misses",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 2, &address, &type, &bridge) != 0 &&
          !bridge);
    CHECK("symbol cache first hit remains revision local",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 1, &address, &type, &bridge) == 0 &&
          address == 0x17100 && type == 2 && bridge == 0x17200);
    CHECK("bridge cache dynamic revision misses",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 2, &address, &type, &bridge) != 0 &&
          !bridge);
    kzt_guest_library_symbol_evidence_store(
        &handle, "cached_function", 2, 0x17300, 2);
    CHECK("new symbol evidence invalidates old bridge",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 1, &address, &type, &bridge) != 0 &&
          !bridge);
    kzt_guest_library_handle_release(&handle);

    kzt_guest_library_inactivate(
        access.bindings, NULL, (library_t *)&lib, first.link_map_addr);
    CHECK("symbol cache reactivate", kzt_guest_library_reactivate(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("symbol cache second bind", kzt_guest_library_bind(
          access.bindings, &second, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("symbol cache second lookup", kzt_guest_library_access_lookup(
          &access, &second, &handle) == 0);
    CHECK("symbol cache old generation misses",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "cached_function", 1, &address, &type, &bridge) != 0);
    CHECK("bridge cache old generation misses",
          !bridge);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_access_destroy(&access);
}

static void test_symbol_bridge_cache_does_not_cross_symbol_aliases(void)
{
    fake_library_t lib = { 90 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t binding_key = key(0x18000, 92);
    kzt_guest_library_handle_t handle = { 0 };
    uintptr_t address = 0;
    uintptr_t bridge = 0;
    unsigned char type = 0;
    char symbol[32];

    CHECK("alias cache access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("alias cache track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("alias cache bind", kzt_guest_library_bind(
          access.bindings, &binding_key, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("alias cache lookup", kzt_guest_library_access_lookup(
          &access, &binding_key, &handle) == 0);
    kzt_guest_library_symbol_evidence_store(
        &handle, "original_alias", 1, 0x18100, 2);
    kzt_guest_library_symbol_bridge_store(
        &handle, "original_alias", 1, 0x18200);
    for (size_t i = 0; i < 16; ++i) {
        snprintf(symbol, sizeof(symbol), "replacement_alias_%zu", i);
        kzt_guest_library_symbol_evidence_store(
            &handle, symbol, 1, 0x18100, 2);
    }
    CHECK("evicted alias cannot inherit old bridge",
          kzt_guest_library_symbol_evidence_lookup(
              &handle, "replacement_alias_15", 1, &address, &type,
              &bridge) == 0 &&
          address == 0x18100 && type == 2 && !bridge);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_access_destroy(&access);
}

static void test_symbol_bridge_cache_rejects_unloading_handle(void)
{
    fake_library_t lib = { 91 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t binding_key = key(0x19000, 93);
    kzt_guest_library_handle_t held = { 0 }, probe = { 0 };
    uintptr_t address = 1;
    uintptr_t bridge = 1;
    unsigned char type = 1;
    pthread_t thread;
    unbind_thread_arg_t arg = {
        .library = (library_t *)&lib,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    CHECK("unload cache access init",
          kzt_guest_library_access_init(&access) == 0);
    arg.bindings = access.bindings;
    CHECK("unload cache track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("unload cache bind", kzt_guest_library_bind(
          access.bindings, &binding_key, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("unload cache lookup", kzt_guest_library_access_lookup(
          &access, &binding_key, &held) == 0);
    kzt_guest_library_symbol_evidence_store(
        &held, "unloading_symbol", 1, 0x19100, 2);
    kzt_guest_library_symbol_bridge_store(
        &held, "unloading_symbol", 1, 0x19200);
    CHECK("unload cache thread", pthread_create(
          &thread, NULL, unbind_thread, &arg) == 0);
    pthread_mutex_lock(&arg.lock);
    while (!arg.started) pthread_cond_wait(&arg.cond, &arg.lock);
    pthread_mutex_unlock(&arg.lock);
    while (kzt_guest_library_lookup(
               access.bindings, &binding_key, &probe) == 0) {
        kzt_guest_library_handle_release(&probe);
    }
    CHECK("unloading handle rejects cached evidence",
          kzt_guest_library_symbol_evidence_lookup(
              &held, "unloading_symbol", 1, &address, &type,
              &bridge) != 0 &&
          !address && !type && !bridge);
    pthread_mutex_lock(&arg.lock);
    CHECK("unload cache waits for held handle", !arg.done);
    pthread_mutex_unlock(&arg.lock);
    kzt_guest_library_handle_release(&held);
    pthread_join(thread, NULL);
    pthread_cond_destroy(&arg.cond);
    pthread_mutex_destroy(&arg.lock);
    kzt_guest_library_access_destroy(&access);
}

#define SYMBOL_CACHE_BENCHMARK_ROUNDS 21
#define SYMBOL_CACHE_BENCHMARK_REPEATS 100000

static volatile uintptr_t symbol_cache_benchmark_sink;

static uint64_t symbol_cache_benchmark_now(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return a < b ? -1 : a > b;
}

static uint64_t benchmark_symbol_evidence_lookup(
    const kzt_guest_library_handle_t *handle, int include_bridge)
{
    uintptr_t address = 0;
    uintptr_t bridge = 0;
    unsigned char type = 0;
    uint64_t start = symbol_cache_benchmark_now();

    for (size_t i = 0; i < SYMBOL_CACHE_BENCHMARK_REPEATS; ++i) {
        if (kzt_guest_library_symbol_evidence_lookup(
                handle, "benchmark_symbol", 1, &address, &type,
                include_bridge ? &bridge : NULL) != 0) {
            return 0;
        }
        symbol_cache_benchmark_sink ^= address ^ bridge ^ type;
    }
    return symbol_cache_benchmark_now() - start;
}

static void test_symbol_bridge_cache_performance(void)
{
    fake_library_t lib = { 92 };
    kzt_guest_library_access_t access;
    kzt_guest_library_binding_key_t binding_key = key(0x1a000, 94);
    kzt_guest_library_handle_t handle = { 0 };
    uint64_t evidence_only[SYMBOL_CACHE_BENCHMARK_ROUNDS];
    uint64_t evidence_with_bridge[SYMBOL_CACHE_BENCHMARK_ROUNDS];
    uint64_t baseline;
    uint64_t candidate;
    uint64_t limit;

    CHECK("benchmark cache access init",
          kzt_guest_library_access_init(&access) == 0);
    CHECK("benchmark cache track", kzt_guest_library_track(
          access.bindings, (library_t *)&lib) == 0);
    CHECK("benchmark cache bind", kzt_guest_library_bind(
          access.bindings, &binding_key, (library_t *)&lib,
          KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
          KZT_GUEST_LIBRARY_BINDING_ADDED);
    CHECK("benchmark cache lookup", kzt_guest_library_access_lookup(
          &access, &binding_key, &handle) == 0);
    kzt_guest_library_symbol_evidence_store(
        &handle, "benchmark_symbol", 1, 0x1a100, 2);
    kzt_guest_library_symbol_bridge_store(
        &handle, "benchmark_symbol", 1, 0x1a200);
    for (size_t i = 0; i < SYMBOL_CACHE_BENCHMARK_ROUNDS; ++i) {
        if (i & 1) {
            evidence_with_bridge[i] =
                benchmark_symbol_evidence_lookup(&handle, 1);
            evidence_only[i] =
                benchmark_symbol_evidence_lookup(&handle, 0);
        } else {
            evidence_only[i] =
                benchmark_symbol_evidence_lookup(&handle, 0);
            evidence_with_bridge[i] =
                benchmark_symbol_evidence_lookup(&handle, 1);
        }
        CHECK("benchmark cache sample", evidence_only[i] &&
              evidence_with_bridge[i]);
    }
    qsort(evidence_only, SYMBOL_CACHE_BENCHMARK_ROUNDS,
          sizeof(evidence_only[0]), compare_u64);
    qsort(evidence_with_bridge, SYMBOL_CACHE_BENCHMARK_ROUNDS,
          sizeof(evidence_with_bridge[0]), compare_u64);
    baseline = evidence_only[SYMBOL_CACHE_BENCHMARK_ROUNDS / 2];
    candidate = evidence_with_bridge[SYMBOL_CACHE_BENCHMARK_ROUNDS / 2];
    limit = baseline + baseline / 10 +
            SYMBOL_CACHE_BENCHMARK_REPEATS * UINT64_C(5);
    printf("symbol-bridge-cache-performance baseline_total_ns=%llu "
           "candidate_total_ns=%llu limit_total_ns=%llu "
           "candidate_ns_op=%llu result=%s\n",
           (unsigned long long)baseline,
           (unsigned long long)candidate,
           (unsigned long long)limit,
           (unsigned long long)(candidate /
                                SYMBOL_CACHE_BENCHMARK_REPEATS),
           candidate <= limit ? "PASS" : "FAIL");
    CHECK("symbol bridge cache performance", candidate <= limit);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_access_destroy(&access);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) {
        test_symbol_bridge_cache_performance();
        return failures ? EXIT_FAILURE : EXIT_SUCCESS;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--benchmark]\n", argv[0]);
        return 2;
    }
    test_reverse_lookup_unique_main_binding();
    test_reverse_lookup_zero_match_clears_outputs();
    test_wrapped_producer_cannot_own_two_live_identities();
    test_reverse_lookup_non_main_binding_is_rejected();
    test_symbol_evidence_cache_is_generation_local();
    test_symbol_bridge_cache_does_not_cross_symbol_aliases();
    test_symbol_bridge_cache_rejects_unloading_handle();
    test_init_failure_is_fail_open();
    test_loader_quiescence_lease_acquire_release();
    test_loader_quiescence_writer_token_is_stable();
    test_loader_quiescence_lease_rejects_active_scope();
    test_both_arrival_orders_and_retry();
    test_forced_growth_with_held_handle();
    test_pending_cancel_and_address_reuse();
    test_unclaimed_observation_address_reuse_pair_first();
    test_observation_first_unload_retires_registry_generation();
    test_unload_retires_only_hinted_unclaimed_observation();
    test_missing_unload_hint_preserves_unclaimed_observation();
    test_exact_pinned_cleanup_consumes_handle();
    test_dead_library_stale_hint_does_not_retire_reused_address();
    test_tracking_allocation_failure_unload_is_fail_open();
    test_inactive_can_reload_but_destroyed_cannot();
    test_different_library_reuses_closed_callback_address();
    test_loader_pair_is_invisible_until_publish();
    test_loader_pair_cancel_and_failed_publish_are_invisible();
    test_failed_loader_keeps_normal_and_fallback_tombstones();
    test_loader_scope_identity_and_nesting();
    test_concurrent_loader_scopes_do_not_invalidate_each_other();
    test_loader_scope_waits_for_all_quiescence_leases();
    test_loader_quiescence_teardown_drains_readers_and_waiters();
    test_loader_quiescence_teardown_drains_writer();
    test_loader_scope_cannot_reopen_unobserved_address();
    test_registry_retire_failures_are_observable_fail_open();
    test_lookup_and_unbind_threads();
    test_reverse_lookup_handle_pins_unload();
    test_concurrent_observation_unloads_keep_exact_owners();
    test_duplicate_unload_waits_for_lifecycle_owner();
    test_source_lease_unload_allows_provider_lookup();
    test_context_access_closes_before_destroy();
    test_reverse_lookup_handle_pins_teardown();
    /* Keep last: a broken reader/publication protocol intentionally leaves
     * its unload thread blocked so the red run remains bounded. */
    test_publish_while_reader_preserves_unload_wait();
    if (failures) fprintf(stderr, "%d failure(s)\n", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
