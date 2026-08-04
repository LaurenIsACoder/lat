#include "kzt_xcb_connection_guard.h"

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
    unsigned int count;
} destroy_log_t;

typedef struct guard_worker {
    kzt_xcb_connection_map_t *map;
    void *guest;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int ready;
    int take_active;
    int hold;
    int result;
} guard_worker_t;

typedef struct destroy_worker {
    kzt_xcb_connection_map_t *map;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int started;
    int finished;
} destroy_worker_t;

static void destroy_guest(void *guest, void *opaque)
{
    destroy_log_t *log = opaque;

    ++log->count;
    free(guest);
}

static void register_pair(kzt_xcb_connection_map_t *map, void *native,
                          void **guest)
{
    void *canonical = NULL;
    uint64_t generation = 0;

    *guest = malloc(1);
    CHECK("guest allocation", *guest != NULL);
    CHECK("register pair",
          kzt_xcb_connection_map_register(
              map, native, *guest, &canonical, &generation) ==
              KZT_XCB_CONNECTION_MAP_ADDED);
    CHECK("canonical guest", canonical == *guest && generation != 0);
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

static void *guard_worker_run(void *opaque)
{
    guard_worker_t *worker = opaque;
    kzt_xcb_connection_lease_t lease = { 0 };

    worker->result = kzt_xcb_connection_guard_prepare(
        worker->map, worker->guest);
    if (worker->result == 0 && worker->take_active) {
        worker->result = kzt_xcb_connection_guard_take(
            worker->map, worker->guest, &lease);
    }
    pthread_mutex_lock(&worker->lock);
    worker->ready = 1;
    pthread_cond_broadcast(&worker->changed);
    pthread_mutex_unlock(&worker->lock);
    while (worker->hold) {
        pthread_testcancel();
    }
    return NULL;
}

static void *destroy_worker_run(void *opaque)
{
    destroy_worker_t *worker = opaque;

    pthread_mutex_lock(&worker->lock);
    worker->started = 1;
    pthread_cond_broadcast(&worker->changed);
    pthread_mutex_unlock(&worker->lock);
    kzt_xcb_connection_map_destroy(&worker->map);
    pthread_mutex_lock(&worker->lock);
    worker->finished = 1;
    pthread_cond_broadcast(&worker->changed);
    pthread_mutex_unlock(&worker->lock);
    return NULL;
}

static void test_prepare_take_and_cancel(void)
{
    destroy_log_t log = { 0 };
    kzt_xcb_connection_map_t *map =
        kzt_xcb_connection_map_init(destroy_guest, &log);
    void *native_a = (void *)(uintptr_t)0x1000;
    void *native_b = (void *)(uintptr_t)0x2000;
    void *guest_a;
    void *guest_b;
    kzt_xcb_connection_lease_t lease = { 0 };
    kzt_xcb_connection_lease_t removal = { 0 };

    CHECK("map", map != NULL);
    register_pair(map, native_a, &guest_a);
    register_pair(map, native_b, &guest_b);

    CHECK("prepare known",
          kzt_xcb_connection_guard_prepare(map, guest_a) == 0);
    CHECK("take wrong guest",
          kzt_xcb_connection_guard_take(map, guest_b, &lease) != 0);
    CHECK("take known",
          kzt_xcb_connection_guard_take(map, guest_a, &lease) == 0);
    CHECK("taken pair", lease.native == native_a && lease.guest == guest_a);
    CHECK("single take",
          kzt_xcb_connection_guard_take(map, guest_a, &removal) != 0);
    memset(&removal, 0, sizeof(removal));
    CHECK("lookup active lease", kzt_xcb_connection_guard_active_lease(
          map, native_a, guest_a, &removal) == 0 &&
          removal.generation == lease.generation);
    CHECK("release taken lease", kzt_xcb_connection_guard_release(
          map, lease.native, lease.guest) == 0);

    CHECK("prepare stale", kzt_xcb_connection_guard_prepare(map, guest_a) == 0);
    CHECK("prepare replaces and releases stale",
          kzt_xcb_connection_guard_prepare(map, guest_b) == 0);
    kzt_xcb_connection_guard_cancel();
    CHECK("remove first after stale release",
          kzt_xcb_connection_map_begin_remove_by_guest(
              map, guest_a, &removal) == 0);
    kzt_xcb_connection_map_finish_remove(&removal);
    CHECK("remove second after cancel",
          kzt_xcb_connection_map_begin_remove_by_guest(
              map, guest_b, &removal) == 0);
    kzt_xcb_connection_map_finish_remove(&removal);
    CHECK("destroy callbacks", log.count == 2);
    kzt_xcb_connection_map_destroy(&map);
}

static void test_unknown_never_creates_pending_lease(void)
{
    destroy_log_t log = { 0 };
    kzt_xcb_connection_map_t *map =
        kzt_xcb_connection_map_init(destroy_guest, &log);
    kzt_xcb_connection_lease_t lease = { 0 };

    CHECK("unknown map", map != NULL);
    CHECK("unknown prepare",
          kzt_xcb_connection_guard_prepare(
              map, (void *)(uintptr_t)0x3000) != 0);
    CHECK("unknown take",
          kzt_xcb_connection_guard_take(
              map, (void *)(uintptr_t)0x3000, &lease) != 0);
    kzt_xcb_connection_guard_cancel();
    kzt_xcb_connection_map_destroy(&map);
    CHECK("unknown destroy", log.count == 0);
}

static void test_thread_exit_releases_pending_lease(void)
{
    destroy_log_t log = { 0 };
    kzt_xcb_connection_map_t *map =
        kzt_xcb_connection_map_init(destroy_guest, &log);
    void *guest;
    kzt_xcb_connection_lease_t removal = { 0 };
    guard_worker_t worker = {
        .map = map,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("pending exit map", map != NULL);
    register_pair(map, (void *)(uintptr_t)0x4000, &guest);
    worker.guest = guest;
    CHECK("pending exit thread", pthread_create(
          &thread, NULL, guard_worker_run, &worker) == 0);
    CHECK("pending exit join", pthread_join(thread, NULL) == 0);
    CHECK("pending exit prepare", worker.result == 0);
    CHECK("pending exit remove", kzt_xcb_connection_map_begin_remove_by_guest(
          map, guest, &removal) == 0);
    kzt_xcb_connection_map_finish_remove(&removal);
    kzt_xcb_connection_map_destroy(&map);
    CHECK("pending exit cleanup", log.count == 1);
    pthread_cond_destroy(&worker.changed);
    pthread_mutex_destroy(&worker.lock);
}

static void test_cancelled_thread_releases_active_lease_for_destroy(void)
{
    destroy_log_t log = { 0 };
    kzt_xcb_connection_map_t *map =
        kzt_xcb_connection_map_init(destroy_guest, &log);
    void *guest;
    guard_worker_t guard = {
        .map = map,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
        .take_active = 1,
        .hold = 1,
    };
    destroy_worker_t destroy = {
        .map = map,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER,
    };
    pthread_t guard_thread;
    pthread_t destroy_thread;
    void *thread_result = NULL;

    CHECK("active cancel map", map != NULL);
    register_pair(map, (void *)(uintptr_t)0x5000, &guest);
    guard.guest = guest;
    CHECK("active cancel guard thread", pthread_create(
          &guard_thread, NULL, guard_worker_run, &guard) == 0);
    CHECK("active cancel ready", wait_flag(
          &guard.lock, &guard.changed, &guard.ready, 100));
    CHECK("active cancel take", guard.result == 0);
    CHECK("active cancel destroy thread", pthread_create(
          &destroy_thread, NULL, destroy_worker_run, &destroy) == 0);
    CHECK("active cancel destroy starts", wait_flag(
          &destroy.lock, &destroy.changed, &destroy.started, 100));
    CHECK("active cancel destroy waits", !wait_flag(
          &destroy.lock, &destroy.changed, &destroy.finished, 30));
    CHECK("active cancel request", pthread_cancel(guard_thread) == 0);
    CHECK("active cancel join", pthread_join(
          guard_thread, &thread_result) == 0 &&
          thread_result == PTHREAD_CANCELED);
    CHECK("active cancel destroy completes", wait_flag(
          &destroy.lock, &destroy.changed, &destroy.finished, 100));
    CHECK("active cancel destroy join", pthread_join(
          destroy_thread, NULL) == 0);
    CHECK("active cancel cleanup", destroy.map == NULL && log.count == 1);
    pthread_cond_destroy(&guard.changed);
    pthread_mutex_destroy(&guard.lock);
    pthread_cond_destroy(&destroy.changed);
    pthread_mutex_destroy(&destroy.lock);
}

int main(void)
{
    test_prepare_take_and_cancel();
    test_unknown_never_creates_pending_lease();
    test_thread_exit_releases_pending_lease();
    test_cancelled_thread_releases_active_lease_for_destroy();
    puts("kzt-xcb-connection-guard: all tests passed");
    return 0;
}
