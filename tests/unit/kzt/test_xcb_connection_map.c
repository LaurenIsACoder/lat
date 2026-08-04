#include "kzt_xcb_connection_map.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(label, condition)                                             \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s: FAIL\n", label);                         \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

typedef struct destroy_log {
    pthread_mutex_t lock;
    unsigned int count;
} destroy_log_t;

typedef struct remove_race {
    kzt_xcb_connection_map_t *map;
    void *guest;
    void *native;
    int by_native;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int started;
    int finished;
    int result;
    kzt_xcb_connection_lease_t lease;
} remove_race_t;

typedef struct destroy_race {
    kzt_xcb_connection_map_t *map;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int started;
    int finished;
} destroy_race_t;

typedef struct operation_race {
    kzt_xcb_connection_map_t *map;
    void *guest;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int started;
    int acquired;
    int result;
} operation_race_t;

static void destroy_guest(void *guest, void *opaque)
{
    destroy_log_t *log = opaque;

    pthread_mutex_lock(&log->lock);
    ++log->count;
    pthread_mutex_unlock(&log->lock);
    free(guest);
}

static void *new_guest(void)
{
    void *guest = malloc(1);

    CHECK("guest allocation", guest != NULL);
    return guest;
}

static void deadline_after(struct timespec *deadline, long milliseconds)
{
    clock_gettime(CLOCK_REALTIME, deadline);
    deadline->tv_nsec += milliseconds * 1000 * 1000;
    while (deadline->tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline->tv_sec;
        deadline->tv_nsec -= 1000 * 1000 * 1000;
    }
}

static int wait_flag(pthread_mutex_t *lock, pthread_cond_t *changed,
                     int *flag, long milliseconds)
{
    struct timespec deadline;

    deadline_after(&deadline, milliseconds);
    pthread_mutex_lock(lock);
    while (!*flag &&
           pthread_cond_timedwait(changed, lock, &deadline) == 0) {
    }
    pthread_mutex_unlock(lock);
    return *flag;
}

static void *remove_worker(void *opaque)
{
    remove_race_t *race = opaque;

    pthread_mutex_lock(&race->lock);
    race->started = 1;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    if (race->by_native) {
        race->result = kzt_xcb_connection_map_begin_remove_by_native(
            race->map, race->native, &race->lease);
    } else {
        race->result = kzt_xcb_connection_map_begin_remove_by_guest(
            race->map, race->guest, &race->lease);
    }
    pthread_mutex_lock(&race->lock);
    race->finished = 1;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    return NULL;
}

static void *destroy_worker(void *opaque)
{
    destroy_race_t *race = opaque;

    pthread_mutex_lock(&race->lock);
    race->started = 1;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    kzt_xcb_connection_map_destroy(&race->map);
    pthread_mutex_lock(&race->lock);
    race->finished = 1;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    return NULL;
}

static void *operation_worker(void *opaque)
{
    operation_race_t *race = opaque;
    kzt_xcb_connection_lease_t lease = { 0 };

    pthread_mutex_lock(&race->lock);
    race->started = 1;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    race->result = kzt_xcb_connection_map_acquire_by_guest(
        race->map, race->guest, &lease);
    if (race->result == 0) {
        race->result = kzt_xcb_connection_lease_lock_mirror(&lease);
    }
    pthread_mutex_lock(&race->lock);
    race->acquired = race->result == 0;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->lock);
    if (race->result == 0) {
        kzt_xcb_connection_lease_unlock_mirror(&lease);
        kzt_xcb_connection_map_release_pair(
            race->map, lease.native, lease.guest);
    }
    return NULL;
}

static void test_dynamic_capacity_and_lookup(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *guests[16];
    uint64_t previous_generation = 0;
    size_t i;

    CHECK("capacity map", map != NULL);
    for (i = 0; i < 16; ++i) {
        void *canonical = NULL;
        uint64_t generation = 0;
        void *native = (void *)(uintptr_t)(0x1000 + i * 0x10);

        guests[i] = new_guest();
        CHECK("capacity register", kzt_xcb_connection_map_register(
              map, native, guests[i], &canonical, &generation) ==
              KZT_XCB_CONNECTION_MAP_ADDED);
        CHECK("capacity canonical", canonical == guests[i]);
        CHECK("capacity monotonic", generation > previous_generation);
        previous_generation = generation;
    }
    CHECK("capacity size", kzt_xcb_connection_map_size(map) == 16);
    for (i = 0; i < 16; ++i) {
        kzt_xcb_connection_lease_t by_guest = { 0 };
        kzt_xcb_connection_lease_t by_native = { 0 };
        void *native = (void *)(uintptr_t)(0x1000 + i * 0x10);

        CHECK("capacity acquire guest",
              kzt_xcb_connection_map_acquire_by_guest(
                  map, guests[i], &by_guest) == 0);
        CHECK("capacity acquire native",
              kzt_xcb_connection_map_acquire_by_native(
                  map, native, &by_native) == 0);
        CHECK("capacity guest pair",
              by_guest.guest == guests[i] && by_guest.native == native);
        CHECK("capacity native pair",
              by_native.guest == guests[i] && by_native.native == native);
        CHECK("capacity generation",
              by_guest.generation == by_native.generation);
        kzt_xcb_connection_map_release_pair(map, native, guests[i]);
        kzt_xcb_connection_map_release_pair(map, native, guests[i]);
    }
    kzt_xcb_connection_map_destroy(&map);
    CHECK("capacity destroy", map == NULL && log.count == 16);
    pthread_mutex_destroy(&log.lock);
}

static void test_duplicate_native_and_unknown_connection(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x2000;
    void *first = new_guest();
    void *duplicate = new_guest();
    void *canonical = NULL;
    uint64_t first_generation = 0;
    uint64_t duplicate_generation = 0;
    kzt_xcb_connection_lease_t lease = {
        .guest = (void *)(uintptr_t)1,
    };

    CHECK("duplicate map", map != NULL);
    CHECK("duplicate first", kzt_xcb_connection_map_register(
          map, native, first, &canonical, &first_generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    canonical = NULL;
    CHECK("duplicate unchanged", kzt_xcb_connection_map_register(
          map, native, duplicate, &canonical, &duplicate_generation) ==
          KZT_XCB_CONNECTION_MAP_UNCHANGED);
    CHECK("duplicate canonical", canonical == first);
    CHECK("duplicate generation",
          duplicate_generation == first_generation);
    CHECK("duplicate size", kzt_xcb_connection_map_size(map) == 1);
    CHECK("unknown guest", kzt_xcb_connection_map_acquire_by_guest(
          map, duplicate, &lease) != 0 && lease.guest == NULL);
    CHECK("unknown native", kzt_xcb_connection_map_acquire_by_native(
          map, (void *)(uintptr_t)0x2010, &lease) != 0 &&
          lease.native == NULL);
    free(duplicate);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("duplicate ownership", log.count == 1);
    pthread_mutex_destroy(&log.lock);
}

static void test_maps_are_isolated(void)
{
    destroy_log_t first_log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    destroy_log_t second_log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *first = kzt_xcb_connection_map_init(
        destroy_guest, &first_log);
    kzt_xcb_connection_map_t *second = kzt_xcb_connection_map_init(
        destroy_guest, &second_log);
    void *native = (void *)(uintptr_t)0x3000;
    void *first_guest = new_guest();
    void *second_guest = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t lease;

    CHECK("isolation maps", first != NULL && second != NULL);
    CHECK("isolation first", kzt_xcb_connection_map_register(
          first, native, first_guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("isolation second", kzt_xcb_connection_map_register(
          second, native, second_guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("isolation first lookup", kzt_xcb_connection_map_acquire_by_native(
          first, native, &lease) == 0 && lease.guest == first_guest);
    kzt_xcb_connection_map_release_pair(first, native, first_guest);
    CHECK("isolation second lookup", kzt_xcb_connection_map_acquire_by_native(
          second, native, &lease) == 0 && lease.guest == second_guest);
    kzt_xcb_connection_map_release_pair(second, native, second_guest);
    kzt_xcb_connection_map_destroy(&first);
    kzt_xcb_connection_map_destroy(&second);
    CHECK("isolation destroy", first_log.count == 1 && second_log.count == 1);
    pthread_mutex_destroy(&first_log.lock);
    pthread_mutex_destroy(&second_log.lock);
}

static void test_remove_waits_and_generation_is_not_reused(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x4000;
    void *old_guest = new_guest();
    void *new_connection_guest = new_guest();
    void *canonical;
    uint64_t old_generation;
    uint64_t new_generation;
    kzt_xcb_connection_lease_t held = { 0 };
    remove_race_t race = {
        .map = map,
        .guest = old_guest,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("remove map", map != NULL);
    CHECK("remove register", kzt_xcb_connection_map_register(
          map, native, old_guest, &canonical, &old_generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("remove held lease", kzt_xcb_connection_map_acquire_by_guest(
          map, old_guest, &held) == 0);
    CHECK("remove thread", pthread_create(
          &thread, NULL, remove_worker, &race) == 0);
    CHECK("remove starts", wait_flag(
          &race.lock, &race.changed, &race.started, 100));
    for (;;) {
        kzt_xcb_connection_lease_t probe = { 0 };

        if (kzt_xcb_connection_map_acquire_by_guest(
                map, old_guest, &probe) != 0) {
            break;
        }
        kzt_xcb_connection_map_release_pair(
            map, probe.native, probe.guest);
    }
    CHECK("remove waits lease", !wait_flag(
          &race.lock, &race.changed, &race.finished, 30));
    kzt_xcb_connection_map_release_pair(map, held.native, held.guest);
    CHECK("remove finishes", wait_flag(
          &race.lock, &race.changed, &race.finished, 100));
    CHECK("remove result", race.result == 0);
    CHECK("remove join", pthread_join(thread, NULL) == 0);
    CHECK("remove lease", race.lease.guest == old_guest &&
          race.lease.native == native &&
          race.lease.generation == old_generation);
    kzt_xcb_connection_map_finish_remove(&race.lease);
    CHECK("remove callback", log.count == 1);
    CHECK("remove absent", kzt_xcb_connection_map_size(map) == 0);
    CHECK("remove reregister", kzt_xcb_connection_map_register(
          map, native, new_connection_guest, &canonical, &new_generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("remove generation", new_generation > old_generation);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("remove destroy", log.count == 2);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.lock);
    pthread_mutex_destroy(&log.lock);
}

static void test_remove_by_native_waits_for_guest_lease(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x4800;
    void *guest = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t held = { 0 };
    remove_race_t race = {
        .map = map,
        .native = native,
        .by_native = 1,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("native remove map", map != NULL);
    CHECK("native remove register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("native remove held guest lease",
          kzt_xcb_connection_map_acquire_by_guest(
              map, guest, &held) == 0);
    CHECK("native remove thread", pthread_create(
          &thread, NULL, remove_worker, &race) == 0);
    CHECK("native remove starts", wait_flag(
          &race.lock, &race.changed, &race.started, 100));
    for (;;) {
        kzt_xcb_connection_lease_t probe = { 0 };

        if (kzt_xcb_connection_map_acquire_by_guest(
                map, guest, &probe) != 0) {
            break;
        }
        kzt_xcb_connection_map_release_pair(
            map, probe.native, probe.guest);
    }
    CHECK("native remove waits guest lease", !wait_flag(
          &race.lock, &race.changed, &race.finished, 30));
    kzt_xcb_connection_map_release_pair(map, held.native, held.guest);
    CHECK("native remove finishes", wait_flag(
          &race.lock, &race.changed, &race.finished, 100));
    CHECK("native remove result", race.result == 0);
    CHECK("native remove join", pthread_join(thread, NULL) == 0);
    CHECK("native remove lease", race.lease.guest == guest &&
          race.lease.native == native &&
          race.lease.generation == generation);
    kzt_xcb_connection_map_finish_remove(&race.lease);
    CHECK("native remove absent", kzt_xcb_connection_map_size(map) == 0);
    CHECK("native remove callback", log.count == 1);
    kzt_xcb_connection_map_destroy(&map);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.lock);
    pthread_mutex_destroy(&log.lock);
}

static void test_destroy_waits_for_users_and_removal(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x5000;
    void *guest = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t held = { 0 };
    destroy_race_t race = {
        .map = map,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("destroy map", map != NULL);
    CHECK("destroy register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("destroy acquire", kzt_xcb_connection_map_acquire_by_guest(
          map, guest, &held) == 0);
    CHECK("destroy thread", pthread_create(
          &thread, NULL, destroy_worker, &race) == 0);
    CHECK("destroy starts", wait_flag(
          &race.lock, &race.changed, &race.started, 100));
    CHECK("destroy waits user", !wait_flag(
          &race.lock, &race.changed, &race.finished, 30));
    kzt_xcb_connection_map_release_pair(map, native, guest);
    CHECK("destroy finishes", wait_flag(
          &race.lock, &race.changed, &race.finished, 100));
    CHECK("destroy join", pthread_join(thread, NULL) == 0);
    CHECK("destroy cleanup", race.map == NULL && log.count == 1);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.lock);
    pthread_mutex_destroy(&log.lock);

    log = (destroy_log_t) { .lock = PTHREAD_MUTEX_INITIALIZER };
    map = kzt_xcb_connection_map_init(destroy_guest, &log);
    guest = new_guest();
    CHECK("destroy removal register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("destroy removal begin",
          kzt_xcb_connection_map_begin_remove_by_guest(
              map, guest, &held) == 0);
    race = (destroy_race_t) {
        .map = map,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    CHECK("destroy removal thread", pthread_create(
          &thread, NULL, destroy_worker, &race) == 0);
    CHECK("destroy removal starts", wait_flag(
          &race.lock, &race.changed, &race.started, 100));
    CHECK("destroy waits removal", !wait_flag(
          &race.lock, &race.changed, &race.finished, 30));
    kzt_xcb_connection_map_finish_remove(&held);
    CHECK("destroy removal finishes", wait_flag(
          &race.lock, &race.changed, &race.finished, 100));
    CHECK("destroy removal join", pthread_join(thread, NULL) == 0);
    CHECK("destroy removal cleanup", race.map == NULL && log.count == 1);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.lock);
    pthread_mutex_destroy(&log.lock);
}

static void test_cancelled_remove_rolls_back_closing_state(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x6000;
    void *guest = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t held = { 0 };
    kzt_xcb_connection_lease_t probe = { 0 };
    remove_race_t race = {
        .map = map,
        .guest = guest,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;
    void *thread_result = NULL;

    CHECK("cancel remove map", map != NULL);
    CHECK("cancel remove register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("cancel remove held", kzt_xcb_connection_map_acquire_by_guest(
          map, guest, &held) == 0);
    CHECK("cancel remove thread", pthread_create(
          &thread, NULL, remove_worker, &race) == 0);
    CHECK("cancel remove starts", wait_flag(
          &race.lock, &race.changed, &race.started, 100));
    for (;;) {
        if (kzt_xcb_connection_map_acquire_by_guest(
                map, guest, &probe) != 0) {
            break;
        }
        kzt_xcb_connection_map_release_pair(
            map, probe.native, probe.guest);
    }
    CHECK("cancel remove request", pthread_cancel(thread) == 0);
    CHECK("cancel remove join", pthread_join(
          thread, &thread_result) == 0 &&
          thread_result == PTHREAD_CANCELED);
    CHECK("cancel remove rollback", kzt_xcb_connection_map_acquire_by_guest(
          map, guest, &probe) == 0);
    kzt_xcb_connection_map_release_pair(map, probe.native, probe.guest);
    kzt_xcb_connection_map_release_pair(map, held.native, held.guest);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("cancel remove destroy", map == NULL && log.count == 1);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.lock);
    pthread_mutex_destroy(&log.lock);
}

static void test_same_connection_serializes_and_different_connections_run(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *guest_a = new_guest();
    void *guest_b = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t held = { 0 };
    operation_race_t same = {
        .map = map,
        .guest = guest_a,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    operation_race_t different = {
        .map = map,
        .guest = guest_b,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t same_thread;
    pthread_t different_thread;

    CHECK("operation map", map != NULL);
    CHECK("operation register a", kzt_xcb_connection_map_register(
          map, (void *)(uintptr_t)0x7000, guest_a,
          &canonical, &generation) == KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("operation register b", kzt_xcb_connection_map_register(
          map, (void *)(uintptr_t)0x8000, guest_b,
          &canonical, &generation) == KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("operation hold a", kzt_xcb_connection_map_acquire_by_guest(
          map, guest_a, &held) == 0);
    CHECK("operation lock a", kzt_xcb_connection_lease_lock_mirror(
          &held) == 0);
    CHECK("operation same thread", pthread_create(
          &same_thread, NULL, operation_worker, &same) == 0);
    CHECK("operation same starts", wait_flag(
          &same.lock, &same.changed, &same.started, 100));
    CHECK("operation same waits", !wait_flag(
          &same.lock, &same.changed, &same.acquired, 30));
    CHECK("operation different thread", pthread_create(
          &different_thread, NULL, operation_worker, &different) == 0);
    CHECK("operation different runs", wait_flag(
          &different.lock, &different.changed, &different.acquired, 100));
    CHECK("operation different result", different.result == 0);
    CHECK("operation different join", pthread_join(
          different_thread, NULL) == 0);
    kzt_xcb_connection_lease_unlock_mirror(&held);
    kzt_xcb_connection_map_release_pair(map, held.native, held.guest);
    CHECK("operation same continues", wait_flag(
          &same.lock, &same.changed, &same.acquired, 100));
    CHECK("operation same result", same.result == 0);
    CHECK("operation same join", pthread_join(same_thread, NULL) == 0);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("operation cleanup", map == NULL && log.count == 2);
    pthread_cond_destroy(&same.changed);
    pthread_mutex_destroy(&same.lock);
    pthread_cond_destroy(&different.changed);
    pthread_mutex_destroy(&different.lock);
    pthread_mutex_destroy(&log.lock);
}

static void test_mirror_lock_is_recursive(void)
{
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x8800;
    void *guest = new_guest();
    void *canonical;
    uint64_t generation;
    kzt_xcb_connection_lease_t lease = { 0 };

    CHECK("recursive map", map != NULL);
    CHECK("recursive register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("recursive acquire", kzt_xcb_connection_map_acquire_by_guest(
          map, guest, &lease) == 0);
    CHECK("recursive first lock",
          kzt_xcb_connection_lease_lock_mirror(&lease) == 0);
    CHECK("recursive second lock",
          kzt_xcb_connection_lease_lock_mirror(&lease) == 0);
    kzt_xcb_connection_lease_unlock_mirror(&lease);
    kzt_xcb_connection_lease_unlock_mirror(&lease);
    kzt_xcb_connection_map_release_pair(map, lease.native, lease.guest);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("recursive cleanup", log.count == 1);
    pthread_mutex_destroy(&log.lock);
}

static void run_operation_benchmark(void)
{
    const unsigned int iterations = 200000;
    destroy_log_t log = { .lock = PTHREAD_MUTEX_INITIALIZER };
    kzt_xcb_connection_map_t *map = kzt_xcb_connection_map_init(
        destroy_guest, &log);
    void *native = (void *)(uintptr_t)0x9000;
    void *guest = new_guest();
    void *canonical;
    uint64_t generation;
    struct timespec start;
    struct timespec end;
    uint64_t elapsed_ns;
    double ns_per_pair;
    unsigned int i;

    CHECK("benchmark map", map != NULL);
    CHECK("benchmark register", kzt_xcb_connection_map_register(
          map, native, guest, &canonical, &generation) ==
          KZT_XCB_CONNECTION_MAP_ADDED);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < iterations; ++i) {
        kzt_xcb_connection_lease_t lease = { 0 };

        CHECK("benchmark acquire", kzt_xcb_connection_map_acquire_by_guest(
              map, guest, &lease) == 0);
        CHECK("benchmark mirror in", kzt_xcb_connection_lease_lock_mirror(
              &lease) == 0);
        kzt_xcb_connection_lease_unlock_mirror(&lease);
        CHECK("benchmark mirror out", kzt_xcb_connection_lease_lock_mirror(
              &lease) == 0);
        kzt_xcb_connection_lease_unlock_mirror(&lease);
        kzt_xcb_connection_map_release_pair(
            map, lease.native, lease.guest);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (uint64_t)(
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        end.tv_nsec - start.tv_nsec);
    ns_per_pair = (double)elapsed_ns / iterations;
    printf("kzt-xcb-connection-map-performance: %.2f ns/wrapper-lease\n",
           ns_per_pair);
    CHECK("benchmark upper bound", ns_per_pair < 500.0);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("benchmark cleanup", log.count == 1);
    pthread_mutex_destroy(&log.lock);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) {
        run_operation_benchmark();
        return 0;
    }
    test_dynamic_capacity_and_lookup();
    test_duplicate_native_and_unknown_connection();
    test_maps_are_isolated();
    test_remove_waits_and_generation_is_not_reused();
    test_remove_by_native_waits_for_guest_lease();
    test_destroy_waits_for_users_and_removal();
    test_cancelled_remove_rolls_back_closing_state();
    test_same_connection_serializes_and_different_connections_run();
    test_mirror_lock_is_recursive();
    puts("kzt-xcb-connection-map: all tests passed");
    return 0;
}
