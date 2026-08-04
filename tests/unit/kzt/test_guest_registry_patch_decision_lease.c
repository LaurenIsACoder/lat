#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kzt_guest_registry.h"

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got != expected) {
        fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
        ++failures;
    }
}

static void check_true(const char *name, int value)
{
    if (!value) {
        fprintf(stderr, "%s: false\n", name);
        ++failures;
    }
}

static kzt_guest_object_observation_t observation(uintptr_t link_map,
                                                   uintptr_t map_start,
                                                   uintptr_t map_end)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_dynamic_view_t dynamic_view(uintptr_t dynamic_addr)
{
    return (kzt_guest_dynamic_view_t) {
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .dynamic_addr = dynamic_addr,
        .load_bias = 0x400000,
        .has_null = 1,
    };
}

typedef struct sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int waiters;
    int done;
} sync_t;

static int sync_init(sync_t *sync)
{
    memset(sync, 0, sizeof(*sync));
    return pthread_mutex_init(&sync->lock, NULL) ||
           pthread_cond_init(&sync->cond, NULL) ? -1 : 0;
}

static void sync_destroy(sync_t *sync)
{
    pthread_cond_destroy(&sync->cond);
    pthread_mutex_destroy(&sync->lock);
}

static void sync_before_patch_decision_wait(void *opaque)
{
    sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    ++sync->waiters;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void sync_mark_done(sync_t *sync)
{
    pthread_mutex_lock(&sync->lock);
    ++sync->done;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static int sync_wait_for(sync_t *sync, int *value, int expected)
{
    int result = 0;

    pthread_mutex_lock(&sync->lock);
    while (*value < expected) {
        if (pthread_cond_wait(&sync->cond, &sync->lock) != 0) {
            result = -1;
            break;
        }
    }
    pthread_mutex_unlock(&sync->lock);
    return result;
}

static int sync_wait_for_timed(sync_t *sync, int *value, int expected)
{
    struct timespec deadline;
    int result = 0;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 100 * 1000 * 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&sync->lock);
    while (*value < expected) {
        int status = pthread_cond_timedwait(&sync->cond, &sync->lock,
                                            &deadline);
        if (status == ETIMEDOUT) {
            result = -1;
            break;
        }
        if (status != 0) {
            result = -1;
            break;
        }
    }
    pthread_mutex_unlock(&sync->lock);
    return result;
}

static int sync_expect_not_done(sync_t *sync)
{
    struct timespec deadline;
    int result = 0;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 100 * 1000 * 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&sync->lock);
    while (!sync->done) {
        int status = pthread_cond_timedwait(&sync->cond, &sync->lock,
                                            &deadline);
        if (status == ETIMEDOUT) {
            break;
        }
        if (status != 0) {
            result = -1;
            break;
        }
    }
    if (sync->done) {
        result = -1;
    }
    pthread_mutex_unlock(&sync->lock);
    return result;
}

static void setup_source(kzt_guest_registry_t *registry)
{
    kzt_guest_object_observation_t source = observation(0x1000, 0x500000,
                                                          0x504000);
    kzt_guest_dynamic_view_t view = dynamic_view(0x401000);

    check_int("source.observe", kzt_guest_registry_observe(registry, &source),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("source.view", kzt_guest_registry_commit_dynamic_view(
                  registry, 0x1000, 1, &view), KZT_GUEST_REGISTRY_UPDATED);
}

typedef enum mutation_kind {
    MUTATE_DYNAMIC_VIEW,
    MUTATE_OVERLAPPING_OWNER,
    MUTATE_RETIRE,
    MUTATE_LAZY_RESOLVER,
} mutation_kind_t;

typedef struct mutation_worker {
    kzt_guest_registry_t *registry;
    mutation_kind_t kind;
    sync_t *sync;
    int result;
} mutation_worker_t;

static void *mutation_worker_main(void *opaque)
{
    mutation_worker_t *worker = opaque;
    kzt_guest_object_observation_t owner = observation(0x2000, 0x500000,
                                                         0x502000);
    kzt_guest_dynamic_view_t view = dynamic_view(0x402000);
    kzt_guest_lazy_resolver_t resolver = {
        .link_map_slot = 0x501000,
        .resolver_slot = 0x501008,
        .guest_link_map = 0x1000,
        .guest_resolver = 0x502000,
    };

    if (worker->kind == MUTATE_DYNAMIC_VIEW) {
        worker->result = kzt_guest_registry_commit_dynamic_view(
            worker->registry, 0x1000, 1, &view);
    } else if (worker->kind == MUTATE_OVERLAPPING_OWNER) {
        worker->result = kzt_guest_registry_observe(worker->registry, &owner);
    } else if (worker->kind == MUTATE_RETIRE) {
        worker->result = kzt_guest_registry_retire(worker->registry, 0x1000, 1);
    } else {
        worker->result = kzt_guest_registry_publish_lazy_resolver(
            worker->registry, 0x1000, 1, 0, &resolver);
    }
    sync_mark_done(worker->sync);
    return NULL;
}

typedef struct destroy_worker {
    kzt_guest_registry_t *registry;
    sync_t *sync;
} destroy_worker_t;

typedef struct loader_unload_worker {
    kzt_guest_registry_t *registry;
    kzt_guest_loader_identity_t identity;
    sync_t *sync;
    int result;
} loader_unload_worker_t;

static void *loader_unload_worker_main(void *opaque)
{
    loader_unload_worker_t *worker = opaque;

    worker->result = kzt_guest_registry_begin_loader_unload(
        worker->registry, &worker->identity);
    sync_mark_done(worker->sync);
    return NULL;
}

static void *destroy_worker_main(void *opaque)
{
    destroy_worker_t *worker = opaque;

    kzt_guest_registry_destroy(&worker->registry);
    sync_mark_done(worker->sync);
    return NULL;
}

static void test_mutators_wait_for_all_decisions(void)
{
    const mutation_kind_t kinds[] = {
        MUTATE_DYNAMIC_VIEW,
        MUTATE_OVERLAPPING_OWNER,
        MUTATE_RETIRE,
    };
    size_t i;

    for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
        kzt_guest_registry_t *registry = kzt_guest_registry_init();
        kzt_guest_registry_source_lease_t source = { 0 };
        kzt_guest_registry_patch_decision_lease_t first = { 0 };
        kzt_guest_registry_patch_decision_lease_t second = { 0 };
        mutation_worker_t worker;
        pthread_t thread;
        sync_t sync;

        check_true("mutator.registry", registry != NULL);
        if (!registry || sync_init(&sync) != 0) {
            kzt_guest_registry_destroy(&registry);
            continue;
        }
        setup_source(registry);
        check_int("mutator.source", kzt_guest_registry_source_lease_acquire(
                      registry, 0x1000, 1, 0, &source), 0);
        check_int("mutator.first", kzt_guest_registry_patch_decision_lease_acquire(
                      &source, &first), 0);
        check_int("mutator.second", kzt_guest_registry_patch_decision_lease_acquire(
                      &source, &second), 0);
        worker = (mutation_worker_t) { registry, kinds[i], &sync, -99 };
        kzt_guest_registry_test_set_before_patch_decision_wait(
            sync_before_patch_decision_wait, &sync);
        check_int("mutator.create", pthread_create(&thread, NULL,
                                                    mutation_worker_main,
                                                    &worker), 0);
        check_int("mutator.wait-registered", sync_wait_for(&sync, &sync.waiters, 1), 0);
        kzt_guest_registry_patch_decision_lease_release(&first);
        check_int("mutator.one-release-still-blocked", sync_expect_not_done(&sync), 0);
        kzt_guest_registry_patch_decision_lease_release(&second);
        if (kinds[i] == MUTATE_RETIRE) {
            kzt_guest_registry_source_lease_release(&source);
        }
        check_int("mutator.done", sync_wait_for(&sync, &sync.done, 1), 0);
        check_int("mutator.join", pthread_join(thread, NULL), 0);
        check_true("mutator.success", worker.result == 0 ||
                   worker.result == KZT_GUEST_REGISTRY_ADDED ||
                   worker.result == KZT_GUEST_REGISTRY_UPDATED);
        kzt_guest_registry_test_set_before_patch_decision_wait(NULL, NULL);
        kzt_guest_registry_source_lease_release(&source);
        kzt_guest_registry_destroy(&registry);
        sync_destroy(&sync);
    }
}

static void test_waiter_admission_blocks_new_leases(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_source_lease_t late_source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };
    kzt_guest_registry_patch_decision_lease_t late_decision = { 0 };
    mutation_worker_t worker;
    pthread_t thread;
    sync_t sync;

    check_true("admission.registry", registry != NULL);
    if (!registry || sync_init(&sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    setup_source(registry);
    check_int("admission.source", kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("admission.decision", kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);
    worker = (mutation_worker_t) { registry, MUTATE_RETIRE, &sync, -99 };
    kzt_guest_registry_test_set_before_patch_decision_wait(
        sync_before_patch_decision_wait, &sync);
    check_int("admission.create", pthread_create(&thread, NULL,
                                                  mutation_worker_main, &worker), 0);
    check_int("admission.wait-registered", sync_wait_for(&sync, &sync.waiters, 1), 0);
    check_int("admission.new-source-rejected", kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &late_source), -1);
    check_int("admission.new-decision-rejected",
              kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &late_decision), -1);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    check_int("admission.retire-still-waits-source", sync_expect_not_done(&sync), 0);
    kzt_guest_registry_source_lease_release(&source);
    check_int("admission.retire-done", sync_wait_for(&sync, &sync.done, 1), 0);
    check_int("admission.join", pthread_join(thread, NULL), 0);
    check_int("admission.retire-ok", worker.result, 0);
    kzt_guest_registry_test_set_before_patch_decision_wait(NULL, NULL);
    kzt_guest_registry_destroy(&registry);
    sync_destroy(&sync);
}

static void test_retire_and_existing_mutator_finish_without_deadlock(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };
    mutation_worker_t ordinary;
    mutation_worker_t retire;
    pthread_t ordinary_thread;
    pthread_t retire_thread;
    sync_t wait_sync;
    sync_t ordinary_sync;
    sync_t retire_sync;

    check_true("ordered.registry", registry != NULL);
    if (!registry || sync_init(&wait_sync) != 0 ||
        sync_init(&ordinary_sync) != 0 || sync_init(&retire_sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    setup_source(registry);
    check_int("ordered.source", kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("ordered.decision", kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);

    ordinary = (mutation_worker_t) { registry, MUTATE_DYNAMIC_VIEW,
                                     &ordinary_sync, -99 };
    retire = (mutation_worker_t) { registry, MUTATE_RETIRE, &retire_sync,
                                   -99 };
    kzt_guest_registry_test_set_before_patch_decision_wait(
        sync_before_patch_decision_wait, &wait_sync);
    check_int("ordered.ordinary.create", pthread_create(&ordinary_thread, NULL,
                                                          mutation_worker_main,
                                                          &ordinary), 0);
    check_int("ordered.ordinary.waiting", sync_wait_for(&wait_sync,
                                                          &wait_sync.waiters, 1), 0);
    check_int("ordered.retire.create", pthread_create(&retire_thread, NULL,
                                                        mutation_worker_main,
                                                        &retire), 0);
    check_int("ordered.retire.joins-wait", sync_wait_for_timed(
                  &wait_sync, &wait_sync.waiters, 2), 0);
    check_int("ordered.retire.not-early", sync_expect_not_done(&retire_sync), 0);

    kzt_guest_registry_patch_decision_lease_release(&decision);
    check_int("ordered.ordinary.done", sync_wait_for(&ordinary_sync,
                                                       &ordinary_sync.done, 1), 0);
    check_int("ordered.retire.waits-source", sync_expect_not_done(&retire_sync), 0);
    kzt_guest_registry_source_lease_release(&source);
    check_int("ordered.retire.done", sync_wait_for(&retire_sync,
                                                     &retire_sync.done, 1), 0);
    check_int("ordered.ordinary.join", pthread_join(ordinary_thread, NULL), 0);
    check_int("ordered.retire.join", pthread_join(retire_thread, NULL), 0);
    /* Condition-variable wakeups are not FIFO.  The ordinary update either
     * commits first or revalidates after retire marked the object UNLOADING. */
    if (ordinary.result != KZT_GUEST_REGISTRY_UPDATED &&
        ordinary.result != KZT_GUEST_REGISTRY_ERROR) {
        fprintf(stderr, "ordered.ordinary-result: got %d\n", ordinary.result);
        ++failures;
    }
    check_int("ordered.retire-result", retire.result, 0);
    kzt_guest_registry_test_set_before_patch_decision_wait(NULL, NULL);
    kzt_guest_registry_destroy(&registry);
    sync_destroy(&wait_sync);
    sync_destroy(&ordinary_sync);
    sync_destroy(&retire_sync);
}

static void test_loader_delete_prepare_drains_source_lease_before_unmap(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_source_lease_t late_source = { 0 };
    kzt_guest_loader_identity_t identity = { 0 };
    loader_unload_worker_t worker;
    pthread_t thread;
    sync_t sync;

    check_true("loader-prepare.registry", registry != NULL);
    if (!registry || sync_init(&sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    setup_source(registry);
    check_int("loader-prepare.publish",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9000, 0x1000, 0, &identity),
              0);
    check_int("loader-prepare.source",
              kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source),
              0);
    worker = (loader_unload_worker_t) {
        .registry = registry,
        .identity = identity,
        .sync = &sync,
        .result = -99,
    };
    kzt_guest_registry_test_set_before_retire_wait(
        sync_before_patch_decision_wait, &sync);
    check_int("loader-prepare.create",
              pthread_create(&thread, NULL, loader_unload_worker_main,
                             &worker),
              0);
    check_int("loader-prepare.waiting",
              sync_wait_for(&sync, &sync.waiters, 1), 0);
    check_int("loader-prepare.new-source-rejected",
              kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &late_source),
              -1);
    check_int("loader-prepare.not-before-release",
              sync_expect_not_done(&sync), 0);
    kzt_guest_registry_source_lease_release(&source);
    check_int("loader-prepare.done",
              sync_wait_for(&sync, &sync.done, 1), 0);
    check_int("loader-prepare.join", pthread_join(thread, NULL), 0);
    check_int("loader-prepare.result", worker.result, 0);
    check_int("loader-prepare.cancel",
              kzt_guest_registry_cancel_loader_unload(
                  registry, &identity),
              0);
    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_registry_destroy(&registry);
    sync_destroy(&sync);
}

static void test_resolver_publish_is_not_writer_evidence(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };
    kzt_guest_lazy_resolver_t resolver = {
        .link_map_slot = 0x501000,
        .resolver_slot = 0x501008,
        .guest_link_map = 0x1000,
        .guest_resolver = 0x502000,
    };

    check_true("resolver.registry", registry != NULL);
    if (!registry) {
        return;
    }
    setup_source(registry);
    check_int("resolver.source", kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("resolver.decision", kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);
    check_int("resolver.publish", kzt_guest_registry_publish_lazy_resolver(
                  registry, 0x1000, 1, 0, &resolver), 0);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    kzt_guest_registry_source_lease_release(&source);
    kzt_guest_registry_destroy(&registry);
}

static void test_destroy_drains_decision_after_source_and_waiter(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };
    mutation_worker_t mutation;
    destroy_worker_t destroy;
    pthread_t mutation_thread;
    pthread_t destroy_thread;
    sync_t mutation_sync;
    sync_t destroy_sync;

    check_true("destroy.registry", registry != NULL);
    if (!registry || sync_init(&mutation_sync) != 0 ||
        sync_init(&destroy_sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    setup_source(registry);
    check_int("destroy.source", kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("destroy.decision", kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);
    mutation = (mutation_worker_t) { registry, MUTATE_DYNAMIC_VIEW,
                                     &mutation_sync, -99 };
    kzt_guest_registry_test_set_before_patch_decision_wait(
        sync_before_patch_decision_wait, &mutation_sync);
    check_int("destroy.mutation.create", pthread_create(&mutation_thread, NULL,
                                                          mutation_worker_main,
                                                          &mutation), 0);
    check_int("destroy.waiter", sync_wait_for(&mutation_sync,
                                                &mutation_sync.waiters, 1), 0);
    destroy = (destroy_worker_t) { registry, &destroy_sync };
    check_int("destroy.create", pthread_create(&destroy_thread, NULL,
                                                destroy_worker_main, &destroy), 0);
    kzt_guest_registry_source_lease_release(&source);
    check_int("destroy.still-drains-decision", sync_expect_not_done(&destroy_sync), 0);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    check_int("destroy.mutation-unblocked", sync_wait_for(&mutation_sync,
                                                            &mutation_sync.done, 1), 0);
    check_int("destroy.done", sync_wait_for(&destroy_sync, &destroy_sync.done, 1), 0);
    check_int("destroy.mutation.join", pthread_join(mutation_thread, NULL), 0);
    check_int("destroy.join", pthread_join(destroy_thread, NULL), 0);
    check_int("destroy.mutation-disabled", mutation.result, KZT_GUEST_REGISTRY_DISABLED);
    check_true("destroy.null", destroy.registry == NULL);
    kzt_guest_registry_test_set_before_patch_decision_wait(NULL, NULL);
    sync_destroy(&mutation_sync);
    sync_destroy(&destroy_sync);
}

int main(void)
{
    test_mutators_wait_for_all_decisions();
    test_waiter_admission_blocks_new_leases();
    test_retire_and_existing_mutator_finish_without_deadlock();
    test_loader_delete_prepare_drains_source_lease_before_unmap();
    test_resolver_publish_is_not_writer_evidence();
    test_destroy_drains_decision_after_source_and_waiter();
    return failures ? 1 : 0;
}
