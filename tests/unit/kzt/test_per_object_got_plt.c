#include <pthread.h>
#include <stdio.h>

#include "elf.h"
#include "kzt_per_object_got_plt.h"

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got != expected) {
        fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
        ++failures;
    }
}

static int unexpected_apply(uintptr_t link_map_addr,
                            unsigned long generation,
                            const kzt_guest_dynamic_view_t *view,
                            void *opaque)
{
    int *calls = opaque;

    (void)link_map_addr;
    (void)generation;
    (void)view;
    ++*calls;
    return 0;
}

typedef struct apply_state {
    int calls;
    int fail;
    uintptr_t link_map_addr;
    unsigned long generation;
} apply_state_t;

static int record_apply(uintptr_t link_map_addr,
                        unsigned long generation,
                        const kzt_guest_dynamic_view_t *view,
                        void *opaque)
{
    apply_state_t *state = opaque;

    if (!state || !view) {
        return -1;
    }
    ++state->calls;
    state->link_map_addr = link_map_addr;
    state->generation = generation;
    return state->fail ? -1 : 0;
}

static kzt_guest_dynamic_view_t complete_view(void)
{
    return (kzt_guest_dynamic_view_t) {
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .dynamic_addr = 0x401000,
        .load_bias = 0x400000,
        .has_null = 1,
        .jmprel = { 1, 0x402000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .pltrelsz = { 1, sizeof(Elf64_Rela), KZT_GUEST_DYNAMIC_SCALAR },
        .pltrel = { 1, DT_RELA, KZT_GUEST_DYNAMIC_SCALAR },
        .pltgot = { 1, 0x403000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
    };
}

static void test_complete_view_is_written_once(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = {
        .link_map_addr = 0x1000,
        .load_bias = { 0x400000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x401000, KZT_GUEST_FIELD_OK },
        .map_start = { 0x400000, KZT_GUEST_FIELD_OK },
        .map_end = { 0x408000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
    kzt_guest_dynamic_view_t view = complete_view();
    apply_state_t state = { 0 };
    kzt_per_object_got_plt_request_t request = {
        .registry = registry,
        .link_map_addr = object.link_map_addr,
        .apply = record_apply,
        .opaque = &state,
    };
    kzt_per_object_got_plt_result_t result = { 0 };

    if (!registry) {
        ++failures;
        return;
    }
    check_int("applied.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("applied.view",
              kzt_guest_registry_commit_dynamic_view(registry, 0x1000, 1,
                                                     &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("applied.first", kzt_per_object_got_plt_apply(&request, &result),
              0);
    check_int("applied.status", result.status, KZT_PER_OBJECT_GOT_PLT_APPLIED);
    check_int("applied.calls", state.calls, 1);
    check_int("applied.link-map", state.link_map_addr, 0x1000);
    check_int("applied.generation", state.generation, 1);
    check_int("applied.repeat", kzt_per_object_got_plt_apply(&request, &result),
              0);
    check_int("applied.repeat-status", result.status,
              KZT_PER_OBJECT_GOT_PLT_ALREADY_APPLIED);
    check_int("applied.repeat-calls", state.calls, 1);
    kzt_guest_registry_destroy(&registry);
}

static void test_failed_write_can_retry(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = {
        .link_map_addr = 0x1000,
        .load_bias = { 0x400000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x401000, KZT_GUEST_FIELD_OK },
        .map_start = { 0x400000, KZT_GUEST_FIELD_OK },
        .map_end = { 0x408000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
    kzt_guest_dynamic_view_t view = complete_view();
    apply_state_t state = { .fail = 1 };
    kzt_per_object_got_plt_request_t request = {
        .registry = registry,
        .link_map_addr = object.link_map_addr,
        .apply = record_apply,
        .opaque = &state,
    };
    kzt_per_object_got_plt_result_t result = { 0 };

    if (!registry) {
        ++failures;
        return;
    }
    check_int("retry.observe", kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("retry.view", kzt_guest_registry_commit_dynamic_view(
                  registry, 0x1000, 1, &view), KZT_GUEST_REGISTRY_UPDATED);
    check_int("retry.failed", kzt_per_object_got_plt_apply(&request, &result),
              0);
    check_int("retry.failed-status", result.status,
              KZT_PER_OBJECT_GOT_PLT_FAIL_OPEN);
    state.fail = 0;
    check_int("retry.applied", kzt_per_object_got_plt_apply(&request, &result),
              0);
    check_int("retry.applied-status", result.status,
              KZT_PER_OBJECT_GOT_PLT_APPLIED);
    check_int("retry.calls", state.calls, 2);
    kzt_guest_registry_destroy(&registry);
}

typedef struct concurrent_apply_state {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int entered;
    int released;
    int calls;
} concurrent_apply_state_t;

typedef struct concurrent_apply_worker {
    kzt_per_object_got_plt_request_t request;
    kzt_per_object_got_plt_result_t result;
    int return_code;
} concurrent_apply_worker_t;

static int blocking_apply(uintptr_t link_map_addr,
                          unsigned long generation,
                          const kzt_guest_dynamic_view_t *view,
                          void *opaque)
{
    concurrent_apply_state_t *state = opaque;

    (void)link_map_addr;
    (void)generation;
    (void)view;
    pthread_mutex_lock(&state->lock);
    ++state->calls;
    state->entered = 1;
    pthread_cond_broadcast(&state->cond);
    while (!state->released) {
        pthread_cond_wait(&state->cond, &state->lock);
    }
    pthread_mutex_unlock(&state->lock);
    return 0;
}

static void *concurrent_apply_main(void *opaque)
{
    concurrent_apply_worker_t *worker = opaque;

    worker->return_code = kzt_per_object_got_plt_apply(&worker->request,
                                                        &worker->result);
    return NULL;
}

static void test_concurrent_observers_write_once(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = {
        .link_map_addr = 0x1000,
        .load_bias = { 0x400000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x401000, KZT_GUEST_FIELD_OK },
        .map_start = { 0x400000, KZT_GUEST_FIELD_OK },
        .map_end = { 0x408000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
    kzt_guest_dynamic_view_t view = complete_view();
    concurrent_apply_state_t state = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    concurrent_apply_worker_t first = {
        .request = {
            .registry = registry,
            .link_map_addr = object.link_map_addr,
            .apply = blocking_apply,
            .opaque = &state,
        },
    };
    kzt_per_object_got_plt_request_t second_request = first.request;
    kzt_per_object_got_plt_result_t second_result = { 0 };
    pthread_t thread;

    if (!registry) {
        ++failures;
        return;
    }
    check_int("concurrent.observe", kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("concurrent.view", kzt_guest_registry_commit_dynamic_view(
                  registry, 0x1000, 1, &view), KZT_GUEST_REGISTRY_UPDATED);
    check_int("concurrent.create", pthread_create(&thread, NULL,
                                                   concurrent_apply_main,
                                                   &first), 0);
    pthread_mutex_lock(&state.lock);
    while (!state.entered) {
        pthread_cond_wait(&state.cond, &state.lock);
    }
    pthread_mutex_unlock(&state.lock);
    check_int("concurrent.second", kzt_per_object_got_plt_apply(
                  &second_request, &second_result), 0);
    check_int("concurrent.second-status", second_result.status,
              KZT_PER_OBJECT_GOT_PLT_IN_PROGRESS);
    pthread_mutex_lock(&state.lock);
    state.released = 1;
    pthread_cond_broadcast(&state.cond);
    pthread_mutex_unlock(&state.lock);
    check_int("concurrent.join", pthread_join(thread, NULL), 0);
    check_int("concurrent.first-return", first.return_code, 0);
    check_int("concurrent.first-status", first.result.status,
              KZT_PER_OBJECT_GOT_PLT_APPLIED);
    check_int("concurrent.calls", state.calls, 1);
    pthread_cond_destroy(&state.cond);
    pthread_mutex_destroy(&state.lock);
    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = {
        .link_map_addr = 0x1000,
        .load_bias = { 0x400000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x401000, KZT_GUEST_FIELD_OK },
        .map_start = { 0x400000, KZT_GUEST_FIELD_OK },
        .map_end = { 0x408000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
    int calls = 0;
    kzt_per_object_got_plt_request_t request = {
        .registry = registry,
        .link_map_addr = object.link_map_addr,
        .apply = unexpected_apply,
        .opaque = &calls,
    };
    kzt_per_object_got_plt_result_t result = { 0 };

    if (!registry) {
        return 1;
    }
    check_int("fail-open.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("fail-open.run",
              kzt_per_object_got_plt_apply(&request, &result), 0);
    check_int("fail-open.status", result.status,
              KZT_PER_OBJECT_GOT_PLT_FAIL_OPEN);
    check_int("fail-open.calls", calls, 0);
    kzt_guest_registry_destroy(&registry);
    test_complete_view_is_written_once();
    test_failed_write_can_retry();
    test_concurrent_observers_write_once();

    if (failures) {
        fprintf(stderr, "per-object GOT/PLT: %d failure(s)\n", failures);
        return 1;
    }
    puts("per-object GOT/PLT: PASS");
    return 0;
}
