#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_registry.h"

#define SAME_LINK_THREADS 16
#define DIFFERENT_LINK_THREADS 12
#define SNAPSHOT_THREADS 8
#define SNAPSHOT_ITERATIONS 64
#define SNAPSHOT_OBJECTS 6

static int failures;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void check_string(const char *name, const char *got,
                         const char *expected)
{
    if ((!got && !expected) || (got && expected && !strcmp(got, expected))) {
        return;
    }

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static void thread_check_true(int *thread_failures, const char *name,
                              int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++*thread_failures;
}

static void thread_check_int(int *thread_failures, const char *name,
                             int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++*thread_failures;
}

static void thread_check_ulong(int *thread_failures, const char *name,
                               unsigned long got, unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++*thread_failures;
}

static void thread_check_string(int *thread_failures, const char *name,
                                const char *got, const char *expected)
{
    if ((!got && !expected) || (got && expected && !strcmp(got, expected))) {
        return;
    }

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++*thread_failures;
}

static kzt_guest_object_observation_t make_observation(
    uintptr_t link_map_addr,
    uintptr_t index,
    const char *path)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { 0x100000 + index * 0x1000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x101000 + index * 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .path = { path, KZT_GUEST_FIELD_OK },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static int wait_for_barrier(pthread_barrier_t *barrier)
{
    int ret = pthread_barrier_wait(barrier);

    return ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : ret;
}

typedef struct observe_worker {
    kzt_guest_registry_t *registry;
    pthread_barrier_t *barrier;
    kzt_guest_object_observation_t observation;
    kzt_guest_registry_result_t result;
    int failures;
} observe_worker_t;

static void *observe_worker_main(void *opaque)
{
    observe_worker_t *worker = opaque;

    if (wait_for_barrier(worker->barrier) != 0) {
        worker->result = KZT_GUEST_REGISTRY_ERROR;
        ++worker->failures;
        return NULL;
    }

    worker->result = kzt_guest_registry_observe(worker->registry,
                                                &worker->observation);
    return NULL;
}

static void join_observe_workers(pthread_t *threads,
                                 observe_worker_t *workers,
                                 size_t count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        check_int("pthread.join", pthread_join(threads[i], NULL), 0);
        failures += workers[i].failures;
    }
}

static const kzt_guest_object_snapshot_t *find_dump_object(
    const kzt_guest_registry_dump_t *dump,
    uintptr_t link_map_addr)
{
    size_t i;

    for (i = 0; i < dump->count; ++i) {
        if (dump->objects[i].link_map_addr == link_map_addr) {
            return &dump->objects[i];
        }
    }

    return NULL;
}

static void test_concurrent_same_link_map_converges_to_one_generation(void)
{
    static const uintptr_t link_map_addr = 0x710000;
    static const char path[] = "/guest/libsame-concurrent.so";
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    pthread_barrier_t barrier;
    pthread_t threads[SAME_LINK_THREADS];
    observe_worker_t workers[SAME_LINK_THREADS];
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_registry_dump_t dump = { 0 };
    kzt_guest_registry_diagnostics_t diagnostics = { 0 };
    unsigned long added = 0;
    unsigned long unchanged = 0;
    size_t i;

    check_true("registry.init.same", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("barrier.init.same",
              pthread_barrier_init(&barrier, NULL, SAME_LINK_THREADS), 0);

    for (i = 0; i < SAME_LINK_THREADS; ++i) {
        workers[i] = (observe_worker_t) {
            .registry = registry,
            .barrier = &barrier,
            .observation = make_observation(link_map_addr, 0, path),
            .result = KZT_GUEST_REGISTRY_ERROR,
        };
        check_int("pthread.create.same",
                  pthread_create(&threads[i], NULL, observe_worker_main,
                                 &workers[i]), 0);
    }

    join_observe_workers(threads, workers, SAME_LINK_THREADS);
    check_int("barrier.destroy.same", pthread_barrier_destroy(&barrier), 0);

    for (i = 0; i < SAME_LINK_THREADS; ++i) {
        if (workers[i].result == KZT_GUEST_REGISTRY_ADDED) {
            ++added;
        } else if (workers[i].result == KZT_GUEST_REGISTRY_UNCHANGED) {
            ++unchanged;
        } else {
            fprintf(stderr, "same-link worker %lu unexpected result %d\n",
                    (unsigned long)i, workers[i].result);
            ++failures;
        }
    }

    check_ulong("same.added", added, 1);
    check_ulong("same.unchanged", unchanged, SAME_LINK_THREADS - 1);

    check_int("same.find",
              kzt_guest_registry_find_by_link_map(registry, link_map_addr,
                                                  &snapshot), 0);
    check_true("same.snapshot", snapshot != NULL);
    if (snapshot) {
        check_ulong("same.snapshot.generation", snapshot->generation, 1);
        check_string("same.snapshot.path", snapshot->path.value, path);
        kzt_guest_object_snapshot_free(snapshot);
    }

    check_int("same.dump", kzt_guest_registry_dump_snapshot(registry, &dump),
              0);
    check_ulong("same.dump.count", dump.count, 1);
    if (dump.count == 1) {
        check_ulong("same.dump.generation", dump.objects[0].generation, 1);
        check_string("same.dump.path", dump.objects[0].path.value, path);
    }
    kzt_guest_registry_dump_free(&dump);

    check_int("same.diagnostics",
              kzt_guest_registry_get_diagnostics(registry, &diagnostics), 0);
    check_ulong("same.diagnostics.observations", diagnostics.observations,
                SAME_LINK_THREADS);
    check_ulong("same.diagnostics.added", diagnostics.added, 1);
    check_ulong("same.diagnostics.unchanged", diagnostics.unchanged,
                SAME_LINK_THREADS - 1);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy.same", registry == NULL);
}

static void test_concurrent_different_link_maps_create_distinct_objects(void)
{
    static const uintptr_t base_link_map_addr = 0x720000;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    pthread_barrier_t barrier;
    pthread_t threads[DIFFERENT_LINK_THREADS];
    observe_worker_t workers[DIFFERENT_LINK_THREADS];
    char paths[DIFFERENT_LINK_THREADS][64];
    unsigned char seen_generation[DIFFERENT_LINK_THREADS + 1] = { 0 };
    kzt_guest_registry_dump_t dump = { 0 };
    size_t i;

    check_true("registry.init.different", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("barrier.init.different",
              pthread_barrier_init(&barrier, NULL, DIFFERENT_LINK_THREADS), 0);

    for (i = 0; i < DIFFERENT_LINK_THREADS; ++i) {
        uintptr_t link_map_addr = base_link_map_addr + i * 0x1000;

        snprintf(paths[i], sizeof(paths[i]),
                 "/guest/libdifferent-%02lu.so", (unsigned long)i);
        workers[i] = (observe_worker_t) {
            .registry = registry,
            .barrier = &barrier,
            .observation = make_observation(link_map_addr, i + 1, paths[i]),
            .result = KZT_GUEST_REGISTRY_ERROR,
        };
        check_int("pthread.create.different",
                  pthread_create(&threads[i], NULL, observe_worker_main,
                                 &workers[i]), 0);
    }

    join_observe_workers(threads, workers, DIFFERENT_LINK_THREADS);
    check_int("barrier.destroy.different",
              pthread_barrier_destroy(&barrier), 0);

    for (i = 0; i < DIFFERENT_LINK_THREADS; ++i) {
        kzt_guest_object_snapshot_t *snapshot = NULL;
        unsigned long generation;

        check_int("different.result", workers[i].result,
                  KZT_GUEST_REGISTRY_ADDED);
        check_int("different.find",
                  kzt_guest_registry_find_by_link_map(
                      registry, workers[i].observation.link_map_addr,
                      &snapshot),
                  0);
        check_true("different.snapshot", snapshot != NULL);
        if (!snapshot) {
            continue;
        }

        check_string("different.snapshot.path", snapshot->path.value,
                     paths[i]);
        generation = snapshot->generation;
        check_true("different.generation.range",
                   generation >= 1 && generation <= DIFFERENT_LINK_THREADS);
        if (generation >= 1 && generation <= DIFFERENT_LINK_THREADS) {
            check_true("different.generation.unique",
                       !seen_generation[generation]);
            seen_generation[generation] = 1;
        }
        kzt_guest_object_snapshot_free(snapshot);
    }

    for (i = 1; i <= DIFFERENT_LINK_THREADS; ++i) {
        check_true("different.generation.seen", seen_generation[i]);
    }

    check_int("different.dump",
              kzt_guest_registry_dump_snapshot(registry, &dump), 0);
    check_ulong("different.dump.count", dump.count, DIFFERENT_LINK_THREADS);
    for (i = 0; i < DIFFERENT_LINK_THREADS; ++i) {
        const kzt_guest_object_snapshot_t *object = find_dump_object(
            &dump, base_link_map_addr + i * 0x1000);

        check_true("different.dump.object", object != NULL);
        if (object) {
            check_string("different.dump.path", object->path.value, paths[i]);
        }
    }
    kzt_guest_registry_dump_free(&dump);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy.different", registry == NULL);
}

typedef struct snapshot_worker {
    kzt_guest_registry_t *registry;
    pthread_barrier_t *barrier;
    uintptr_t link_map_addr;
    const char *expected_path;
    const char *source_path;
    int failures;
} snapshot_worker_t;

static void *snapshot_worker_main(void *opaque)
{
    snapshot_worker_t *worker = opaque;
    size_t i;

    if (wait_for_barrier(worker->barrier) != 0) {
        ++worker->failures;
        return NULL;
    }

    for (i = 0; i < SNAPSHOT_ITERATIONS; ++i) {
        kzt_guest_object_snapshot_t *first = NULL;
        kzt_guest_object_snapshot_t *second = NULL;
        kzt_guest_registry_dump_t first_dump = { 0 };
        kzt_guest_registry_dump_t second_dump = { 0 };
        const kzt_guest_object_snapshot_t *first_object;
        const kzt_guest_object_snapshot_t *second_object;

        thread_check_int(
            &worker->failures, "snapshot.find.first",
            kzt_guest_registry_find_by_link_map(worker->registry,
                                                worker->link_map_addr,
                                                &first),
            0);
        thread_check_int(
            &worker->failures, "snapshot.find.second",
            kzt_guest_registry_find_by_link_map(worker->registry,
                                                worker->link_map_addr,
                                                &second),
            0);
        thread_check_true(&worker->failures, "snapshot.find.first.ptr",
                          first != NULL);
        thread_check_true(&worker->failures, "snapshot.find.second.ptr",
                          second != NULL);
        if (first && second) {
            thread_check_string(&worker->failures, "snapshot.find.path.first",
                                first->path.value, worker->expected_path);
            thread_check_string(&worker->failures, "snapshot.find.path.second",
                                second->path.value, worker->expected_path);
            thread_check_true(&worker->failures,
                              "snapshot.find.path.not-source",
                              first->path.value != worker->source_path);
            thread_check_true(&worker->failures,
                              "snapshot.find.path.distinct",
                              first->path.value != second->path.value);
        }

        thread_check_int(&worker->failures, "snapshot.dump.first",
                         kzt_guest_registry_dump_snapshot(worker->registry,
                                                          &first_dump),
                         0);
        thread_check_int(&worker->failures, "snapshot.dump.second",
                         kzt_guest_registry_dump_snapshot(worker->registry,
                                                          &second_dump),
                         0);
        thread_check_ulong(&worker->failures, "snapshot.dump.first.count",
                           first_dump.count, SNAPSHOT_OBJECTS);
        thread_check_ulong(&worker->failures, "snapshot.dump.second.count",
                           second_dump.count, SNAPSHOT_OBJECTS);

        first_object = find_dump_object(&first_dump, worker->link_map_addr);
        second_object = find_dump_object(&second_dump, worker->link_map_addr);
        thread_check_true(&worker->failures, "snapshot.dump.first.object",
                          first_object != NULL);
        thread_check_true(&worker->failures, "snapshot.dump.second.object",
                          second_object != NULL);
        if (first_object && second_object) {
            thread_check_string(&worker->failures, "snapshot.dump.path.first",
                                first_object->path.value,
                                worker->expected_path);
            thread_check_string(&worker->failures, "snapshot.dump.path.second",
                                second_object->path.value,
                                worker->expected_path);
            thread_check_true(&worker->failures,
                              "snapshot.dump.path.not-source",
                              first_object->path.value != worker->source_path);
            thread_check_true(&worker->failures,
                              "snapshot.dump.path.distinct",
                              first_object->path.value !=
                              second_object->path.value);
            if (first) {
                thread_check_true(&worker->failures,
                                  "snapshot.dump.path.not-find",
                                  first_object->path.value !=
                                  first->path.value);
            }
        }

        kzt_guest_registry_dump_free(&second_dump);
        kzt_guest_registry_dump_free(&first_dump);
        kzt_guest_object_snapshot_free(second);
        kzt_guest_object_snapshot_free(first);
    }

    return NULL;
}

static void test_concurrent_query_and_dump_return_owned_snapshots(void)
{
    static const uintptr_t base_link_map_addr = 0x730000;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    pthread_barrier_t barrier;
    pthread_t threads[SNAPSHOT_THREADS];
    snapshot_worker_t workers[SNAPSHOT_THREADS];
    char paths[SNAPSHOT_OBJECTS][64];
    size_t i;

    check_true("registry.init.snapshot", registry != NULL);
    if (!registry) {
        return;
    }

    for (i = 0; i < SNAPSHOT_OBJECTS; ++i) {
        kzt_guest_object_observation_t observation;

        snprintf(paths[i], sizeof(paths[i]), "/guest/libsnapshot-%02lu.so",
                 (unsigned long)i);
        observation = make_observation(base_link_map_addr + i * 0x1000,
                                       i + 1, paths[i]);
        check_int("snapshot.prepopulate",
                  kzt_guest_registry_observe(registry, &observation),
                  KZT_GUEST_REGISTRY_ADDED);
    }

    check_int("barrier.init.snapshot",
              pthread_barrier_init(&barrier, NULL, SNAPSHOT_THREADS), 0);

    for (i = 0; i < SNAPSHOT_THREADS; ++i) {
        size_t object_index = i % SNAPSHOT_OBJECTS;

        workers[i] = (snapshot_worker_t) {
            .registry = registry,
            .barrier = &barrier,
            .link_map_addr = base_link_map_addr + object_index * 0x1000,
            .expected_path = paths[object_index],
            .source_path = paths[object_index],
        };
        check_int("pthread.create.snapshot",
                  pthread_create(&threads[i], NULL, snapshot_worker_main,
                                 &workers[i]), 0);
    }

    for (i = 0; i < SNAPSHOT_THREADS; ++i) {
        check_int("pthread.join.snapshot", pthread_join(threads[i], NULL), 0);
        failures += workers[i].failures;
    }
    check_int("barrier.destroy.snapshot", pthread_barrier_destroy(&barrier),
              0);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy.snapshot", registry == NULL);
}

int main(void)
{
    test_concurrent_same_link_map_converges_to_one_generation();
    test_concurrent_different_link_maps_create_distinct_objects();
    test_concurrent_query_and_dump_return_owned_snapshots();

    if (failures) {
        fprintf(stderr, "kzt-guest-registry-concurrency: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-guest-registry-concurrency: all tests passed");
    return 0;
}
