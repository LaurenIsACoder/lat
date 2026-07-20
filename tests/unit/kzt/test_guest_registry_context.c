#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_registry_context.h"

#ifdef __APPLE__
typedef struct kzt_test_barrier {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    unsigned int waiting;
    unsigned int participants;
    unsigned int generation;
} kzt_test_barrier_t;

#define pthread_barrier_t kzt_test_barrier_t
#define PTHREAD_BARRIER_SERIAL_THREAD 1

static int pthread_barrier_init(kzt_test_barrier_t *barrier,
                                const void *attributes,
                                unsigned int participants)
{
    (void)attributes;
    memset(barrier, 0, sizeof(*barrier));
    barrier->participants = participants;
    return pthread_mutex_init(&barrier->lock, NULL) ||
           pthread_cond_init(&barrier->condition, NULL);
}

static int pthread_barrier_wait(kzt_test_barrier_t *barrier)
{
    unsigned int generation;

    pthread_mutex_lock(&barrier->lock);
    generation = barrier->generation;
    if (++barrier->waiting == barrier->participants) {
        barrier->waiting = 0;
        ++barrier->generation;
        pthread_cond_broadcast(&barrier->condition);
        pthread_mutex_unlock(&barrier->lock);
        return PTHREAD_BARRIER_SERIAL_THREAD;
    }
    while (generation == barrier->generation) {
        pthread_cond_wait(&barrier->condition, &barrier->lock);
    }
    pthread_mutex_unlock(&barrier->lock);
    return 0;
}

static int pthread_barrier_destroy(kzt_test_barrier_t *barrier)
{
    int condition_result = pthread_cond_destroy(&barrier->condition);
    int mutex_result = pthread_mutex_destroy(&barrier->lock);

    return condition_result ? condition_result : mutex_result;
}
#endif

#define CONTEXT_THREADS 16
#define CONTEXT_RACE_ROUNDS 32

typedef struct registry_context_fixture {
    pthread_mutex_t lock;
    pthread_barrier_t barrier;
    kzt_guest_registry_context_t context;
    kzt_guest_registry_t *results[CONTEXT_THREADS];
    int worker_failures;
} registry_context_fixture_t;

typedef struct registry_context_worker {
    registry_context_fixture_t *fixture;
    size_t index;
} registry_context_worker_t;

static int failures;

static void check_true(const char *name, int condition)
{
    if (!condition) {
        fprintf(stderr, "%s: condition failed\n", name);
        ++failures;
    }
}

static int wait_at_barrier(registry_context_fixture_t *fixture)
{
    int result = pthread_barrier_wait(&fixture->barrier);

    if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD) {
        __atomic_add_fetch(&fixture->worker_failures, 1, __ATOMIC_RELAXED);
        return -1;
    }
    return 0;
}

static void *context_get_worker(void *opaque)
{
    registry_context_worker_t *worker = opaque;

    if (wait_at_barrier(worker->fixture) == 0) {
        worker->fixture->results[worker->index] =
            kzt_guest_registry_context_get(&worker->fixture->context,
                                           &worker->fixture->lock);
    }
    return NULL;
}

static void *context_destroy_worker(void *opaque)
{
    registry_context_fixture_t *fixture = opaque;

    if (wait_at_barrier(fixture) == 0) {
        kzt_guest_registry_context_destroy(&fixture->context,
                                           &fixture->lock);
    }
    return NULL;
}

static void *context_confirm_main_head_worker(void *opaque)
{
    registry_context_fixture_t *fixture = opaque;

    if (wait_at_barrier(fixture) == 0) {
        (void)kzt_guest_registry_context_confirm_main_namespace_head(
            &fixture->context, &fixture->lock, 0x12340000);
    }
    return NULL;
}

static void init_fixture(registry_context_fixture_t *fixture,
                         unsigned int participants)
{
    memset(fixture, 0, sizeof(*fixture));
    check_true("context.lock-init",
               pthread_mutex_init(&fixture->lock, NULL) == 0);
    check_true("context.barrier-init",
               pthread_barrier_init(&fixture->barrier, NULL,
                                    participants) == 0);
}

static void destroy_fixture(registry_context_fixture_t *fixture)
{
    check_true("context.barrier-destroy",
               pthread_barrier_destroy(&fixture->barrier) == 0);
    check_true("context.lock-destroy",
               pthread_mutex_destroy(&fixture->lock) == 0);
}

static void test_concurrent_lazy_init_publishes_one_registry(void)
{
    registry_context_fixture_t fixture;
    registry_context_worker_t workers[CONTEXT_THREADS];
    pthread_t threads[CONTEXT_THREADS];
    size_t i;

    init_fixture(&fixture, CONTEXT_THREADS);
    for (i = 0; i < CONTEXT_THREADS; ++i) {
        workers[i].fixture = &fixture;
        workers[i].index = i;
        check_true("context.create",
                   pthread_create(&threads[i], NULL, context_get_worker,
                                  &workers[i]) == 0);
    }
    for (i = 0; i < CONTEXT_THREADS; ++i) {
        check_true("context.join", pthread_join(threads[i], NULL) == 0);
    }
    check_true("context.worker-results", fixture.worker_failures == 0);
    check_true("context.lazy-published", fixture.results[0] != NULL);
    for (i = 1; i < CONTEXT_THREADS; ++i) {
        check_true("context.single-publication",
                   fixture.results[i] == fixture.results[0]);
    }

    kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
    check_true("context.no-reinit",
               kzt_guest_registry_context_get(&fixture.context,
                                              &fixture.lock) == NULL);
    kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
    destroy_fixture(&fixture);
}

static void test_init_and_destroy_race_closes_publication_gate(void)
{
    unsigned int round;

    for (round = 0; round < CONTEXT_RACE_ROUNDS; ++round) {
        registry_context_fixture_t fixture;
        registry_context_worker_t workers[CONTEXT_THREADS];
        pthread_t getters[CONTEXT_THREADS];
        pthread_t destroyer;
        kzt_guest_registry_t *published = NULL;
        size_t i;

        init_fixture(&fixture, CONTEXT_THREADS + 1);
        for (i = 0; i < CONTEXT_THREADS; ++i) {
            workers[i].fixture = &fixture;
            workers[i].index = i;
            check_true("race.create-getter",
                       pthread_create(&getters[i], NULL, context_get_worker,
                                      &workers[i]) == 0);
        }
        check_true("race.create-destroyer",
                   pthread_create(&destroyer, NULL, context_destroy_worker,
                                  &fixture) == 0);
        for (i = 0; i < CONTEXT_THREADS; ++i) {
            check_true("race.join-getter",
                       pthread_join(getters[i], NULL) == 0);
        }
        check_true("race.join-destroyer",
                   pthread_join(destroyer, NULL) == 0);
        check_true("race.worker-results", fixture.worker_failures == 0);

        for (i = 0; i < CONTEXT_THREADS; ++i) {
            if (!fixture.results[i]) {
                continue;
            }
            if (!published) {
                published = fixture.results[i];
            }
            check_true("race.single-publication",
                       fixture.results[i] == published);
        }
        check_true("race.closed",
                   kzt_guest_registry_context_get(&fixture.context,
                                                  &fixture.lock) == NULL);
        kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
        destroy_fixture(&fixture);
    }
}

static void test_failed_init_is_not_retried_on_hot_path(void)
{
    registry_context_fixture_t fixture;

    init_fixture(&fixture, 1);
    kzt_guest_registry_test_set_alloc_failure_after(0);
    check_true("failure.first",
               kzt_guest_registry_context_get(&fixture.context,
                                              &fixture.lock) == NULL);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_true("failure.not-retried",
               kzt_guest_registry_context_get(&fixture.context,
                                              &fixture.lock) == NULL);
    kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
    destroy_fixture(&fixture);
}

static void test_main_namespace_head_is_context_owned_and_conflict_safe(void)
{
    registry_context_fixture_t fixture;
    uintptr_t head = 0;

    init_fixture(&fixture, 1);
    check_true("main-head.empty",
               kzt_guest_registry_context_get_main_namespace_head(
                   &fixture.context, &head) != 0 && head == 0);
    check_true("main-head.confirm",
               kzt_guest_registry_context_confirm_main_namespace_head(
                   &fixture.context, &fixture.lock, 0x12340000) == 0);
    check_true("main-head.get",
               kzt_guest_registry_context_get_main_namespace_head(
                   &fixture.context, &head) == 0 && head == 0x12340000);
    check_true("main-head.idempotent",
               kzt_guest_registry_context_confirm_main_namespace_head(
                   &fixture.context, &fixture.lock, 0x12340000) == 0);
    check_true("main-head.conflict",
               kzt_guest_registry_context_confirm_main_namespace_head(
                   &fixture.context, &fixture.lock, 0x56780000) != 0);

    kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
    head = 1;
    check_true("main-head.cleared-on-destroy",
               kzt_guest_registry_context_get_main_namespace_head(
                   &fixture.context, &head) != 0 && head == 0);
    check_true("main-head.closed-after-destroy",
               kzt_guest_registry_context_confirm_main_namespace_head(
                   &fixture.context, &fixture.lock, 0x12340000) != 0);
    destroy_fixture(&fixture);
}

static void test_registry_evidence_cache_requires_exact_object_identity(void)
{
    registry_context_fixture_t fixture;
    kzt_guest_registry_t *registry;
    kzt_guest_object_observation_t observation = {
        .link_map_addr = 0x70000000,
        .load_bias = { 0x700000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x701000, KZT_GUEST_FIELD_OK },
        .map_start = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { NULL, KZT_GUEST_FIELD_UNKNOWN },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };

    init_fixture(&fixture, 1);
    registry = kzt_guest_registry_context_get(&fixture.context,
                                              &fixture.lock);
    check_true("evidence.registry", registry != NULL);
    check_true("evidence.observe",
               kzt_guest_registry_observe(registry, &observation) ==
                   KZT_GUEST_REGISTRY_ADDED);
    check_true("evidence.no-head-no-reuse",
               !kzt_guest_registry_context_has_main_namespace_evidence(
                   &fixture.context, registry, observation.link_map_addr,
                   observation.load_bias.value,
                   observation.dynamic_addr.value));
    check_true("evidence.confirm-head",
               kzt_guest_registry_context_confirm_main_namespace_head(
                   &fixture.context, &fixture.lock, 0x60000000) == 0);
    check_true("evidence.exact-reuse",
               kzt_guest_registry_context_has_main_namespace_evidence(
                   &fixture.context, registry, observation.link_map_addr,
                   observation.load_bias.value,
                   observation.dynamic_addr.value));
    check_true("evidence.wrong-load-bias",
               !kzt_guest_registry_context_has_main_namespace_evidence(
                   &fixture.context, registry, observation.link_map_addr,
                   observation.load_bias.value + 0x1000,
                   observation.dynamic_addr.value));
    check_true("evidence.wrong-dynamic",
               !kzt_guest_registry_context_has_main_namespace_evidence(
                   &fixture.context, registry, observation.link_map_addr,
                   observation.load_bias.value,
                   observation.dynamic_addr.value + 0x1000));

    kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
    destroy_fixture(&fixture);
}

static void test_main_namespace_head_cannot_publish_after_destroy(void)
{
    unsigned int round;

    for (round = 0; round < CONTEXT_RACE_ROUNDS; ++round) {
        registry_context_fixture_t fixture;
        pthread_t confirmer;
        pthread_t destroyer;
        uintptr_t head = 1;

        init_fixture(&fixture, 2);
        check_true("main-head-race.create-confirmer",
                   pthread_create(&confirmer, NULL,
                                  context_confirm_main_head_worker,
                                  &fixture) == 0);
        check_true("main-head-race.create-destroyer",
                   pthread_create(&destroyer, NULL,
                                  context_destroy_worker, &fixture) == 0);
        check_true("main-head-race.join-confirmer",
                   pthread_join(confirmer, NULL) == 0);
        check_true("main-head-race.join-destroyer",
                   pthread_join(destroyer, NULL) == 0);
        check_true("main-head-race.closed",
                   kzt_guest_registry_context_get_main_namespace_head(
                       &fixture.context, &head) != 0 && head == 0);
        kzt_guest_registry_context_destroy(&fixture.context, &fixture.lock);
        destroy_fixture(&fixture);
    }
}

int main(void)
{
    test_concurrent_lazy_init_publishes_one_registry();
    test_init_and_destroy_race_closes_publication_gate();
    test_failed_init_is_not_retried_on_hot_path();
    test_main_namespace_head_is_context_owned_and_conflict_safe();
    test_registry_evidence_cache_requires_exact_object_identity();
    test_main_namespace_head_cannot_publish_after_destroy();

    if (failures) {
        fprintf(stderr, "kzt-guest-registry-context: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("kzt-guest-registry-context: all contract tests passed");
    return 0;
}
