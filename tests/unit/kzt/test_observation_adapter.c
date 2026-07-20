#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/kzt_observation_adapter.h"
#include "target/i386/latx/include/kzt_guest_library_binding.h"

#define EVENT_READER_READ 1
#define EVENT_LEGACY_FLOW 2
#define EVENT_DIAGNOSTIC 3

#define TEST_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef struct fake_read_failure {
    uintptr_t addr;
    size_t size;
} fake_read_failure_t;

typedef struct fake_reader_memory {
    uintptr_t base;
    size_t size;
    const fake_read_failure_t *failures;
    size_t failure_count;
} fake_reader_memory_t;

typedef struct observation_trace {
    int events[128];
    size_t event_count;
    int reader_calls;
    int dynamic_reader_calls;
    int legacy_calls;
    int diagnostic_calls;
    int legacy_return;
    uintptr_t legacy_link_map_addr;
    kzt_observation_adapter_result_t diagnostic_result;
    int diagnostic_emitted;
    unsigned long diagnostic_result_observations;
    int dynamic_attempted;
    int dynamic_cache_hit;
    int dynamic_parse_return;
    uintptr_t dynamic_addr;
    kzt_guest_dynamic_status_t dynamic_status;
    kzt_guest_dynamic_error_t dynamic_error;
    size_t dynamic_entry_count;
    uintptr_t dynamic_read_error_addr;
    int dynamic_commit_attempted;
    kzt_guest_registry_result_t dynamic_commit_result;
    int dynamic_registry_emitted;
    int dynamic_comparison_attempted;
    int dynamic_comparison_blocking;
    int dynamic_comparison_matched;
} observation_trace_t;

typedef struct fake_callback_event {
    struct link_map_x64 link_map;
    char guest_name[64];
    Elf64_Dyn dynamic[4];
    fake_reader_memory_t memory;
    kzt_guest_link_map_reader_ops_t ops;
    observation_trace_t trace;
    struct callback_barrier *barrier;
    const kzt_guest_library_loader_scope_t *loader_scope;
    library_t *loader_library;
    kzt_guest_library_binding_result_t pending_pair_result;
    int namespace_id_present;
    uintptr_t namespace_id;
    int map_range_present;
    uintptr_t map_start;
    uintptr_t map_end;
} fake_callback_event_t;

typedef enum callback_pause_point {
    CALLBACK_PAUSE_NONE = 0,
    CALLBACK_PAUSE_INITIAL_READER,
    CALLBACK_PAUSE_DYNAMIC_READER,
    CALLBACK_PAUSE_LEGACY,
} callback_pause_point_t;

typedef struct callback_barrier {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    callback_pause_point_t pause_point;
    int reached;
    int released;
} callback_barrier_t;

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

    fprintf(stderr, "%s: got %lu expected %lu\n", name, got, expected);
    ++failures;
}

static void check_uintptr(const char *name, uintptr_t got,
                          uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void record_event(observation_trace_t *trace, int event)
{
    if (trace->event_count < TEST_ARRAY_SIZE(trace->events)) {
        trace->events[trace->event_count++] = event;
    }
}

static int ranges_overlap(uintptr_t left_addr, size_t left_size,
                          uintptr_t right_addr, size_t right_size)
{
    uintptr_t left_end = left_addr + left_size;
    uintptr_t right_end = right_addr + right_size;

    return left_addr < right_end && right_addr < left_end;
}

static int fake_read_memory(uintptr_t guest_addr, void *dst, size_t size,
                            void *opaque)
{
    fake_callback_event_t *event = opaque;
    fake_reader_memory_t *memory = &event->memory;
    size_t i;

    ++event->trace.reader_calls;
    if (ranges_overlap(guest_addr, size, (uintptr_t)event->dynamic,
                       sizeof(event->dynamic))) {
        ++event->trace.dynamic_reader_calls;
    }
    record_event(&event->trace, EVENT_READER_READ);

    if (event->barrier) {
        callback_pause_point_t point =
            ranges_overlap(guest_addr, size, (uintptr_t)event->dynamic,
                           sizeof(event->dynamic))
                ? CALLBACK_PAUSE_DYNAMIC_READER
                : CALLBACK_PAUSE_INITIAL_READER;
        pthread_mutex_lock(&event->barrier->lock);
        if (event->barrier->pause_point == point &&
            !event->barrier->reached) {
            event->barrier->reached = 1;
            pthread_cond_broadcast(&event->barrier->cond);
            while (!event->barrier->released)
                pthread_cond_wait(&event->barrier->cond,
                                  &event->barrier->lock);
        }
        pthread_mutex_unlock(&event->barrier->lock);
    }

    for (i = 0; i < memory->failure_count; ++i) {
        if (ranges_overlap(guest_addr, size,
                           memory->failures[i].addr,
                           memory->failures[i].size)) {
            return -1;
        }
    }

    if (guest_addr < memory->base ||
        size > memory->size ||
        guest_addr - memory->base > memory->size - size) {
        return -1;
    }

    memcpy(dst, (const void *)guest_addr, size);
    return 0;
}

static int fake_legacy_flow(uintptr_t link_map_addr, void *opaque)
{
    fake_callback_event_t *event = opaque;
    observation_trace_t *trace = &event->trace;

    ++trace->legacy_calls;
    trace->legacy_link_map_addr = link_map_addr;
    record_event(trace, EVENT_LEGACY_FLOW);
    if (event->loader_scope && event->loader_library) {
        event->pending_pair_result =
            kzt_guest_library_loader_scope_note_pair(
                event->loader_scope, link_map_addr,
                event->loader_library,
                KZT_GUEST_LIBRARY_OBJECT_WRAPPED);
    }
    if (event->barrier) {
        pthread_mutex_lock(&event->barrier->lock);
        if (event->barrier->pause_point == CALLBACK_PAUSE_LEGACY &&
            !event->barrier->reached) {
            event->barrier->reached = 1;
            pthread_cond_broadcast(&event->barrier->cond);
            while (!event->barrier->released)
                pthread_cond_wait(&event->barrier->cond,
                                  &event->barrier->lock);
        }
        pthread_mutex_unlock(&event->barrier->lock);
    }
    return trace->legacy_return;
}

static void fake_diagnostic(
    const kzt_observation_adapter_diagnostic_t *diagnostic,
    void *opaque)
{
    observation_trace_t *trace = opaque;

    ++trace->diagnostic_calls;
    trace->diagnostic_result = diagnostic->result;
    trace->diagnostic_emitted = diagnostic->emitted;
    trace->diagnostic_result_observations =
        diagnostic->registry.result_observations;
    trace->dynamic_attempted = diagnostic->dynamic.attempted;
    trace->dynamic_cache_hit = diagnostic->dynamic.cache_hit;
    trace->dynamic_parse_return = diagnostic->dynamic.parse_return;
    trace->dynamic_addr = diagnostic->dynamic.dynamic_addr;
    trace->dynamic_status = diagnostic->dynamic.status;
    trace->dynamic_error = diagnostic->dynamic.error;
    trace->dynamic_entry_count = diagnostic->dynamic.entry_count;
    trace->dynamic_read_error_addr = diagnostic->dynamic.read_error_addr;
    trace->dynamic_commit_attempted = diagnostic->dynamic.commit_attempted;
    trace->dynamic_commit_result = diagnostic->dynamic.commit_result;
    trace->dynamic_registry_emitted = diagnostic->dynamic.registry.emitted;
    trace->dynamic_comparison_attempted =
        diagnostic->dynamic.comparison_attempted;
    trace->dynamic_comparison_blocking =
        diagnostic->dynamic.comparison.blocking;
    trace->dynamic_comparison_matched =
        diagnostic->dynamic.comparison.matched;
    record_event(trace, EVENT_DIAGNOSTIC);
}

static void init_fake_callback_event(fake_callback_event_t *event,
                                     const char *path,
                                     uintptr_t load_bias)
{
    memset(event, 0, sizeof(*event));
    strcpy(event->guest_name, path);
    event->dynamic[0].d_tag = DT_SYMTAB;
    event->dynamic[0].d_un.d_ptr = load_bias + 0x3000;
    event->dynamic[1].d_tag = DT_STRTAB;
    event->dynamic[1].d_un.d_ptr = load_bias + 0x4000;
    event->dynamic[2].d_tag = DT_STRSZ;
    event->dynamic[2].d_un.d_val = 0x180;
    event->dynamic[3].d_tag = DT_NULL;
    event->dynamic[3].d_un.d_val = 0;
    event->link_map.l_addr = load_bias;
    event->link_map.l_name = event->guest_name;
    event->link_map.l_ld = event->dynamic;
    event->namespace_id_present = 1;
    event->namespace_id = 7;
    event->map_range_present = 1;
    event->map_start = load_bias;
    event->map_end = load_bias + 0x20000;
    event->memory.base = (uintptr_t)&event->link_map;
    event->memory.size = sizeof(*event) -
                         offsetof(fake_callback_event_t, link_map);
    event->ops.read_memory = fake_read_memory;
    event->ops.opaque = event;
    event->trace.legacy_return = 77;
}

static kzt_guest_object_observation_t make_observation(uintptr_t link_map_addr,
                                                       uintptr_t load_bias,
                                                       const char *path)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { load_bias, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { load_bias + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { load_bias, KZT_GUEST_FIELD_OK },
        .map_end = { load_bias + 0x20000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 7, KZT_GUEST_FIELD_OK },
        .path = { path, KZT_GUEST_FIELD_OK },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static void assert_old_flow_exactly_once(const char *name,
                                         const fake_callback_event_t *event,
                                         int expected_return)
{
    check_int(name, event->trace.legacy_calls, 1);
    check_int("old-flow.return", event->trace.legacy_return, expected_return);
    check_true("old-flow.link-map",
               event->trace.legacy_link_map_addr ==
               (uintptr_t)&event->link_map);
}

static void assert_reader_before_old_flow(const fake_callback_event_t *event)
{
    size_t i;
    size_t first_reader = TEST_ARRAY_SIZE(event->trace.events);
    size_t legacy = TEST_ARRAY_SIZE(event->trace.events);

    for (i = 0; i < event->trace.event_count; ++i) {
        if (event->trace.events[i] == EVENT_READER_READ &&
            first_reader == TEST_ARRAY_SIZE(event->trace.events)) {
            first_reader = i;
        }
        if (event->trace.events[i] == EVENT_LEGACY_FLOW &&
            legacy == TEST_ARRAY_SIZE(event->trace.events)) {
            legacy = i;
        }
    }

    check_true("adapter.reader-ran",
               first_reader != TEST_ARRAY_SIZE(event->trace.events));
    check_true("adapter.before-old-flow", first_reader < legacy);
}

static int run_adapter(fake_callback_event_t *event,
                       kzt_guest_registry_t *registry,
                       int enabled,
                       kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_request_t request = {
        .enabled = enabled,
        .link_map_addr = (uintptr_t)&event->link_map,
        .registry = registry,
        .reader_ops = &event->ops,
        .namespace_id_present = event->namespace_id_present,
        .namespace_id = event->namespace_id,
        .map_range_present = event->map_range_present,
        .map_start = event->map_start,
        .map_end = event->map_end,
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = event,
    };

    return kzt_observe_guest_object_from_callback(&request, result);
}

static int run_adapter_with_diagnostics(
    fake_callback_event_t *event,
    kzt_guest_registry_t *registry,
    int enabled,
    int force_dynamic_compare,
    kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_request_t request = {
        .enabled = enabled,
        .diagnostics_enabled = 1,
        .dynamic_diagnostics_force_compare = force_dynamic_compare,
        .link_map_addr = (uintptr_t)&event->link_map,
        .registry = registry,
        .reader_ops = &event->ops,
        .namespace_id_present = event->namespace_id_present,
        .namespace_id = event->namespace_id,
        .map_range_present = event->map_range_present,
        .map_start = event->map_start,
        .map_end = event->map_end,
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = event,
        .diagnostic = fake_diagnostic,
        .diagnostic_opaque = &event->trace,
    };

    return kzt_observe_guest_object_from_callback(&request, result);
}

static int run_adapter_with_bindings(
    fake_callback_event_t *event, kzt_guest_registry_t *registry,
    kzt_guest_library_bindings_t *bindings,
    kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_request_t request = {
        .enabled = 1,
        .link_map_addr = (uintptr_t)&event->link_map,
        .registry = registry,
        .library_bindings = bindings,
        .reader_ops = &event->ops,
        .namespace_id_present = event->namespace_id_present,
        .namespace_id = event->namespace_id,
        .map_range_present = event->map_range_present,
        .map_start = event->map_start,
        .map_end = event->map_end,
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = event,
    };
    return kzt_observe_guest_object_from_callback(&request, result);
}

static int run_adapter_with_loader_scope(
    fake_callback_event_t *event, kzt_guest_registry_t *registry,
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_loader_scope_t *loader_scope,
    kzt_observation_adapter_result_t *result)
{
    kzt_observation_adapter_request_t request = {
        .enabled = 1,
        .link_map_addr = (uintptr_t)&event->link_map,
        .registry = registry,
        .library_bindings = bindings,
        .loader_scope = loader_scope,
        .reader_ops = &event->ops,
        .namespace_id_present = event->namespace_id_present,
        .namespace_id = event->namespace_id,
        .map_range_present = event->map_range_present,
        .map_start = event->map_start,
        .map_end = event->map_end,
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = event,
    };
    return kzt_observe_guest_object_from_callback(&request, result);
}

static unsigned long registry_object_count(kzt_guest_registry_t *registry)
{
    kzt_guest_registry_dump_t dump = { 0 };
    unsigned long count = 0;

    if (kzt_guest_registry_dump_snapshot(registry, &dump) == 0) {
        count = dump.count;
    }
    kzt_guest_registry_dump_free(&dump);
    return count;
}

static int registry_object_state(kzt_guest_registry_t *registry,
                                 uintptr_t link_map_addr,
                                 unsigned long *generation,
                                 kzt_guest_object_state_t *state)
{
    kzt_guest_registry_dump_t dump = { 0 };
    int found = 0;

    if (kzt_guest_registry_dump_snapshot(registry, &dump) == 0) {
        for (size_t i = 0; i < dump.count; ++i) {
            if (dump.objects[i].link_map_addr != link_map_addr)
                continue;
            if (generation) *generation = dump.objects[i].generation;
            if (state) *state = dump.objects[i].state;
            found = 1;
            break;
        }
    }
    kzt_guest_registry_dump_free(&dump);
    return found ? 0 : -1;
}

typedef struct adapter_unload_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_registry_t *registry;
    fake_callback_event_t *event;
    library_t *library;
    kzt_guest_library_binding_key_t expected_key;
    int phase2_entered;
    int phase2_count;
    int allow_phase2_retire;
    kzt_guest_library_bindings_t *hook_bindings;
    kzt_guest_library_binding_key_t hook_key;
    library_t *hook_library;
    int hook_from_observation;
    int registry_waiters;
    int unload_done;
    int adapter_done;
    int adapter_return;
    kzt_observation_adapter_result_t adapter_result;
} adapter_unload_sync_t;

static int wait_for_callback_barrier(callback_barrier_t *barrier);
static void release_callback_barrier(callback_barrier_t *barrier);
static int wait_for_unloading_lifecycle(adapter_unload_sync_t *sync);

static int wait_for_value_at_least(pthread_cond_t *cond,
                                   pthread_mutex_t *lock,
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
                    "adapter timed wait failed: value=%d expected=%d error=%d\n",
                    *value, expected, result);
            return -1;
        }
    }
    return 0;
}

static int wait_for_adapter_outcome(adapter_unload_sync_t *sync)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 30;
    while (!sync->adapter_done && !sync->registry_waiters) {
        int result = pthread_cond_clockwait(
            &sync->cond, &sync->lock, CLOCK_MONOTONIC, &deadline);
        if (result != 0) {
            fprintf(stderr,
                    "adapter outcome timeout: done=%d registry_waiters=%d error=%d\n",
                    sync->adapter_done, sync->registry_waiters, result);
            return -1;
        }
    }
    return 0;
}

static void adapter_before_registry_retire(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key,
    library_t *library, int from_observation, void *opaque)
{
    adapter_unload_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    sync->hook_bindings = bindings;
    sync->hook_key = *key;
    sync->hook_library = library;
    sync->hook_from_observation = from_observation;
    sync->phase2_entered = 1;
    ++sync->phase2_count;
    pthread_cond_broadcast(&sync->cond);
    while (!sync->allow_phase2_retire)
        pthread_cond_wait(&sync->cond, &sync->lock);
    pthread_mutex_unlock(&sync->lock);
}

static void adapter_registry_retire_waiting(void *opaque)
{
    adapter_unload_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    ++sync->registry_waiters;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void *adapter_unload_worker(void *opaque)
{
    adapter_unload_sync_t *sync = opaque;

    kzt_guest_library_inactivate(
        sync->bindings, sync->registry, sync->library,
        sync->expected_key.link_map_addr);
    pthread_mutex_lock(&sync->lock);
    sync->unload_done = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
    return NULL;
}

static void *adapter_callback_worker(void *opaque)
{
    adapter_unload_sync_t *sync = opaque;

    sync->adapter_return = run_adapter_with_bindings(
        sync->event, sync->registry, sync->bindings,
        &sync->adapter_result);
    pthread_mutex_lock(&sync->lock);
    sync->adapter_done = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
    return NULL;
}

typedef struct source_lease_participant {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    kzt_guest_registry_t *registry;
    kzt_guest_library_binding_key_t key;
    kzt_guest_registry_source_lease_t lease;
    int acquired;
    int release;
} source_lease_participant_t;

static void *source_lease_participant_worker(void *opaque)
{
    source_lease_participant_t *participant = opaque;
    int acquired = kzt_guest_registry_source_lease_acquire(
        participant->registry, participant->key.link_map_addr,
        participant->key.generation, participant->key.namespace_id,
        &participant->lease) == 0;

    pthread_mutex_lock(&participant->lock);
    participant->acquired = acquired ? 1 : -1;
    pthread_cond_broadcast(&participant->cond);
    while (acquired && !participant->release)
        pthread_cond_wait(&participant->cond, &participant->lock);
    pthread_mutex_unlock(&participant->lock);
    if (acquired)
        kzt_guest_registry_source_lease_release(&participant->lease);
    return NULL;
}

static void test_three_participant_adapter_does_not_duplicate_retire(void)
{
    struct fake_library { int value; } library = { 9 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;
    unsigned long generation = 0;
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    source_lease_participant_t lease_participant = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .registry = registry,
    };
    pthread_t lease_thread, unload_thread;

    init_fake_callback_event(&event, "/guest/libthree-participant.so",
                             0x280000);
    event.namespace_id = 0;
    check_int("three.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("three.loader-pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    check_int("three.initial-adapter", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    check_int("three.generation", registry_object_state(
                  registry, (uintptr_t)&event.link_map, &generation, NULL), 0);
    sync.expected_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = (uintptr_t)&event.link_map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    lease_participant.key = sync.expected_key;

    check_int("three.lease-thread", pthread_create(
                  &lease_thread, NULL, source_lease_participant_worker,
                  &lease_participant), 0);
    pthread_mutex_lock(&lease_participant.lock);
    check_int("three.lease-acquired", wait_for_value_at_least(
                  &lease_participant.cond, &lease_participant.lock,
                  &lease_participant.acquired, 1), 0);
    pthread_mutex_unlock(&lease_participant.lock);

    kzt_guest_library_binding_test_set_before_registry_retire(
        adapter_before_registry_retire, &sync);
    kzt_guest_registry_test_set_before_retire_wait(
        adapter_registry_retire_waiting, &sync);
    check_int("three.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    pthread_mutex_lock(&sync.lock);
    check_int("three.phase2", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.phase2_entered, 1), 0);
    sync.allow_phase2_retire = 1;
    pthread_cond_broadcast(&sync.cond);
    check_int("three.registry-wait", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.registry_waiters, 1), 0);
    check_true("three.binding-blocked-by-source", !sync.unload_done);
    pthread_mutex_unlock(&sync.lock);

    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    check_int("three.third-adapter", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 0);
    check_int("three.third-disabled", result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_true("three.third-no-invalid-read",
               event.trace.reader_calls == 0 &&
               event.trace.legacy_calls == 0);
    pthread_mutex_lock(&sync.lock);
    check_true("three.single-retire-owner",
               sync.phase2_count == 1 && sync.registry_waiters == 1 &&
               !sync.unload_done);
    pthread_mutex_unlock(&sync.lock);

    pthread_mutex_lock(&lease_participant.lock);
    lease_participant.release = 1;
    pthread_cond_broadcast(&lease_participant.cond);
    pthread_mutex_unlock(&lease_participant.lock);
    check_int("three.lease-join", pthread_join(lease_thread, NULL), 0);
    check_int("three.unload-join", pthread_join(unload_thread, NULL), 0);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&lease_participant.cond);
    pthread_mutex_destroy(&lease_participant.lock);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_binding_owned_retire_excludes_adapter_retire(void)
{
    struct fake_library { int value; } library = { 2 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_observation_adapter_result_t initial_result;
    unsigned long generation = 0;
    kzt_guest_object_state_t state = KZT_GUEST_OBJECT_DISCOVERED;
    kzt_guest_library_binding_state_t lifecycle_state;
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    pthread_t unload_thread, adapter_thread;
    int adapter_started = 0;

    init_fake_callback_event(&event, "/guest/libretire-owned.so", 0x180000);
    event.namespace_id = 0;
    check_int("retire-owned.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("retire-owned.observation-first",
              run_adapter_with_bindings(
                  &event, registry, bindings, &initial_result), 77);
    check_int("retire-owned.initial-result", initial_result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("retire-owned.snapshot", registry_object_state(
                  registry, (uintptr_t)&event.link_map, &generation, &state),
              0);
    sync.expected_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = (uintptr_t)&event.link_map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    check_int("retire-owned.lease", kzt_guest_registry_source_lease_acquire(
                  registry, sync.expected_key.link_map_addr, generation, 0,
                  &lease), 0);

    kzt_guest_library_binding_test_set_before_registry_retire(
        adapter_before_registry_retire, &sync);
    kzt_guest_registry_test_set_before_retire_wait(
        adapter_registry_retire_waiting, &sync);
    check_int("retire-owned.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    pthread_mutex_lock(&sync.lock);
    check_int("retire-owned.phase2-barrier", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.phase2_entered, 1), 0);
    check_true("retire-owned.hook-identity",
               sync.hook_bindings == bindings &&
               sync.hook_library == (library_t *)&library &&
               sync.hook_from_observation &&
               sync.hook_key.link_map_addr == sync.expected_key.link_map_addr &&
               sync.hook_key.generation == sync.expected_key.generation);
    pthread_mutex_unlock(&sync.lock);

    adapter_started = pthread_create(
        &adapter_thread, NULL, adapter_callback_worker, &sync) == 0;
    check_true("retire-owned.adapter-thread", adapter_started);
    if (adapter_started) {
        pthread_mutex_lock(&sync.lock);
        check_int("retire-owned.adapter-outcome",
                  wait_for_adapter_outcome(&sync), 0);
        check_true("retire-owned.adapter-did-not-retire",
                   sync.adapter_done && sync.registry_waiters == 0);
        check_true("retire-owned.unload-still-paused", !sync.unload_done);
        pthread_mutex_unlock(&sync.lock);
    }

    pthread_mutex_lock(&sync.lock);
    sync.allow_phase2_retire = 1;
    pthread_cond_broadcast(&sync.cond);
    check_int("retire-owned.binding-waits-on-lease", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.registry_waiters, 1), 0);
    check_true("retire-owned.unload-not-returned", !sync.unload_done);
    pthread_mutex_unlock(&sync.lock);
    kzt_guest_registry_source_lease_release(&lease);

    pthread_mutex_lock(&sync.lock);
    check_int("retire-owned.unload-completes", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.unload_done, 1), 0);
    pthread_mutex_unlock(&sync.lock);
    if (adapter_started) {
        check_int("retire-owned.adapter-join",
                  pthread_join(adapter_thread, NULL), 0);
        check_int("retire-owned.adapter-result", sync.adapter_result,
                  KZT_OBSERVATION_ADAPTER_DISABLED);
        check_int("retire-owned.adapter-return", sync.adapter_return, 0);
    }
    check_int("retire-owned.unload-join", pthread_join(unload_thread, NULL),
              0);
    check_int("retire-owned.final-snapshot", registry_object_state(
                  registry, sync.expected_key.link_map_addr, NULL, &state), 0);
    check_int("retire-owned.final-dead", state, KZT_GUEST_OBJECT_DEAD);
    check_int("retire-owned.lifecycle-snapshot",
              kzt_guest_library_binding_test_snapshot(
                  bindings, (library_t *)&library, &lifecycle_state,
                  NULL, NULL), 0);
    check_int("retire-owned.lifecycle-dead", lifecycle_state,
              KZT_GUEST_LIBRARY_BINDING_DEAD);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_adapter_note_before_unload_leaves_single_retire_owner(void)
{
    struct fake_library { int value; } library = { 3 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_observation_adapter_result_t result;
    unsigned long generation = 0;
    kzt_guest_object_state_t state = KZT_GUEST_OBJECT_DISCOVERED;
    kzt_guest_library_binding_state_t lifecycle_state;
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    pthread_t unload_thread;

    init_fake_callback_event(&event, "/guest/libadapter-first.so", 0x1a0000);
    event.namespace_id = 0;
    check_int("adapter-first.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("adapter-first.callback", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    check_int("adapter-first.result", result, KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("adapter-first.live", registry_object_state(
                  registry, (uintptr_t)&event.link_map, &generation, &state),
              0);
    check_true("adapter-first.note-did-not-retire",
               state != KZT_GUEST_OBJECT_UNLOADING &&
               state != KZT_GUEST_OBJECT_DEAD);
    sync.expected_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = (uintptr_t)&event.link_map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    check_int("adapter-first.lease", kzt_guest_registry_source_lease_acquire(
                  registry, sync.expected_key.link_map_addr, generation, 0,
                  &lease), 0);
    kzt_guest_library_binding_test_set_before_registry_retire(
        adapter_before_registry_retire, &sync);
    kzt_guest_registry_test_set_before_retire_wait(
        adapter_registry_retire_waiting, &sync);
    check_int("adapter-first.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    pthread_mutex_lock(&sync.lock);
    check_int("adapter-first.phase2", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.phase2_entered, 1), 0);
    check_true("adapter-first.single-binding-owner",
               sync.hook_library == (library_t *)&library &&
               sync.hook_from_observation &&
               sync.hook_key.generation == generation);
    sync.allow_phase2_retire = 1;
    pthread_cond_broadcast(&sync.cond);
    check_int("adapter-first.retire-wait", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.registry_waiters, 1), 0);
    check_true("adapter-first.unload-blocked", !sync.unload_done);
    pthread_mutex_unlock(&sync.lock);
    kzt_guest_registry_source_lease_release(&lease);
    check_int("adapter-first.join", pthread_join(unload_thread, NULL), 0);
    check_int("adapter-first.final", registry_object_state(
                  registry, sync.expected_key.link_map_addr, NULL, &state), 0);
    check_int("adapter-first.dead", state, KZT_GUEST_OBJECT_DEAD);
    check_int("adapter-first.lifecycle", kzt_guest_library_binding_test_snapshot(
                  bindings, (library_t *)&library, &lifecycle_state,
                  NULL, NULL), 0);
    check_int("adapter-first.lifecycle-dead", lifecycle_state,
              KZT_GUEST_LIBRARY_BINDING_DEAD);

    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_cancelled_pending_without_owner_is_adapter_retired(void)
{
    struct fake_library { int value; } library = { 4 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;
    kzt_guest_object_state_t state = KZT_GUEST_OBJECT_DISCOVERED;
    kzt_guest_library_binding_state_t lifecycle_state;
    size_t active_pending = 1;
    callback_barrier_t barrier = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .pause_point = CALLBACK_PAUSE_INITIAL_READER,
    };
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    pthread_t callback_thread, unload_thread;

    init_fake_callback_event(&event, "/guest/libcancelled-pending.so",
                             0x1c0000);
    event.namespace_id = 0;
    check_int("cancelled-pending.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("cancelled-pending.pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library,
                  KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    sync.expected_key.link_map_addr = (uintptr_t)&event.link_map;
    event.barrier = &barrier;
    check_int("cancelled-pending.callback-thread", pthread_create(
                  &callback_thread, NULL, adapter_callback_worker, &sync), 0);
    check_int("cancelled-pending.reader-barrier",
              wait_for_callback_barrier(&barrier), 0);
    check_int("cancelled-pending.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    check_int("cancelled-pending.unloading",
              wait_for_unloading_lifecycle(&sync), 0);
    release_callback_barrier(&barrier);
    check_int("cancelled-pending.callback-join",
              pthread_join(callback_thread, NULL), 0);
    check_int("cancelled-pending.unload-join",
              pthread_join(unload_thread, NULL), 0);
    result = sync.adapter_result;
    check_int("cancelled-pending.callback", sync.adapter_return, 77);
    check_int("cancelled-pending.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("cancelled-pending.snapshot", registry_object_state(
                  registry, (uintptr_t)&event.link_map, NULL, &state), 0);
    check_int("cancelled-pending.adapter-retired", state,
              KZT_GUEST_OBJECT_DEAD);
    check_int("cancelled-pending.binding-state",
              kzt_guest_library_binding_test_snapshot(
                  bindings, (library_t *)&library, &lifecycle_state,
                  &active_pending, NULL), 0);
    check_true("cancelled-pending.no-owner-left",
               lifecycle_state == KZT_GUEST_LIBRARY_BINDING_DEAD &&
               active_pending == 0);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    pthread_cond_destroy(&barrier.cond);
    pthread_mutex_destroy(&barrier.lock);
}

static int wait_for_callback_barrier(callback_barrier_t *barrier)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 30;
    pthread_mutex_lock(&barrier->lock);
    while (!barrier->reached) {
        int result = pthread_cond_clockwait(
            &barrier->cond, &barrier->lock, CLOCK_MONOTONIC, &deadline);
        if (result != 0) {
            fprintf(stderr, "callback barrier timeout: point=%d error=%d\n",
                    barrier->pause_point, result);
            pthread_mutex_unlock(&barrier->lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&barrier->lock);
    return 0;
}

static void release_callback_barrier(callback_barrier_t *barrier)
{
    pthread_mutex_lock(&barrier->lock);
    barrier->released = 1;
    pthread_cond_broadcast(&barrier->cond);
    pthread_mutex_unlock(&barrier->lock);
}

static int wait_for_unloading_lifecycle(adapter_unload_sync_t *sync)
{
    struct timespec deadline;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 30;
    for (;;) {
        kzt_guest_library_binding_state_t state;
        if (kzt_guest_library_binding_test_snapshot(
                sync->bindings, sync->library, &state, NULL, NULL) == 0 &&
            state != KZT_GUEST_LIBRARY_BINDING_LIVE)
            return state == KZT_GUEST_LIBRARY_BINDING_UNLOADING ? 0 : 1;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            fprintf(stderr, "lifecycle did not leave LIVE before timeout\n");
            return -1;
        }
        sched_yield();
    }
}

static int unload_stays_blocked(adapter_unload_sync_t *sync)
{
    struct timespec deadline;
    int result = 0;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_nsec += 100 * 1000 * 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&sync->lock);
    while (!sync->unload_done && result == 0)
        result = pthread_cond_clockwait(
            &sync->cond, &sync->lock, CLOCK_MONOTONIC, &deadline);
    int blocked = !sync->unload_done;
    pthread_mutex_unlock(&sync->lock);
    return blocked;
}

static void test_exact_retire_owner_uses_complete_key(void)
{
    struct fake_library { int value; } library = { 5 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;
    unsigned long generation = 0;
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    pthread_t unload_thread;

    init_fake_callback_event(&event, "/guest/libexact-owner.so", 0x1e0000);
    event.namespace_id = 0;
    check_int("exact-owner.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("exact-owner.pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    check_int("exact-owner.initial", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    check_int("exact-owner.snapshot", registry_object_state(
                  registry, (uintptr_t)&event.link_map, &generation, NULL), 0);
    sync.expected_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = (uintptr_t)&event.link_map,
        .generation = generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    kzt_guest_library_binding_test_set_before_registry_retire(
        adapter_before_registry_retire, &sync);
    check_int("exact-owner.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    pthread_mutex_lock(&sync.lock);
    check_int("exact-owner.phase2", wait_for_value_at_least(
                  &sync.cond, &sync.lock, &sync.phase2_entered, 1), 0);
    pthread_mutex_unlock(&sync.lock);

    check_int("exact-owner.same-generation",
              kzt_guest_library_note_observation(bindings,
                                                  &sync.expected_key),
              KZT_GUEST_LIBRARY_BINDING_RETIRE_OWNED);
    kzt_guest_library_binding_key_t other = sync.expected_key;
    ++other.generation;
    check_true("exact-owner.other-generation-not-owned",
               kzt_guest_library_note_observation(bindings, &other) !=
                   KZT_GUEST_LIBRARY_BINDING_RETIRE_OWNED);

    pthread_mutex_lock(&sync.lock);
    sync.allow_phase2_retire = 1;
    pthread_cond_broadcast(&sync.cond);
    pthread_mutex_unlock(&sync.lock);
    check_int("exact-owner.join", pthread_join(unload_thread, NULL), 0);
    kzt_guest_library_binding_test_set_before_registry_retire(NULL, NULL);
    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void run_callback_lifetime_wait_test(callback_pause_point_t point,
                                            const char *name)
{
    struct fake_library { int value; } library = { 6 };
    fake_callback_event_t event;
    callback_barrier_t barrier = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .pause_point = point,
    };
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;
    adapter_unload_sync_t sync = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .bindings = bindings,
        .registry = registry,
        .event = &event,
        .library = (library_t *)&library,
    };
    pthread_t callback_thread, unload_thread;

    init_fake_callback_event(&event, "/guest/libcallback-lifetime.so",
                             0x200000 + (uintptr_t)point * 0x10000);
    event.namespace_id = 0;
    check_int(name, kzt_guest_library_track(bindings,
                                            (library_t *)&library), 0);
    check_int("callback-lifetime.pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    check_int("callback-lifetime.initial", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    event.barrier = &barrier;
    check_int("callback-lifetime.callback-thread", pthread_create(
                  &callback_thread, NULL, adapter_callback_worker, &sync), 0);
    check_int("callback-lifetime.barrier", wait_for_callback_barrier(&barrier),
              0);
    check_int("callback-lifetime.unload-thread", pthread_create(
                  &unload_thread, NULL, adapter_unload_worker, &sync), 0);
    check_int("callback-lifetime.unloading",
              wait_for_unloading_lifecycle(&sync), 0);
    check_true("callback-lifetime.unload-waits",
               unload_stays_blocked(&sync));
    release_callback_barrier(&barrier);
    check_int("callback-lifetime.callback-join",
              pthread_join(callback_thread, NULL), 0);
    check_int("callback-lifetime.unload-join",
              pthread_join(unload_thread, NULL), 0);
    check_int("callback-lifetime.legacy-once", event.trace.legacy_calls, 1);

    pthread_cond_destroy(&sync.cond);
    pthread_mutex_destroy(&sync.lock);
    pthread_cond_destroy(&barrier.cond);
    pthread_mutex_destroy(&barrier.lock);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_callback_lifetime_covers_all_guest_work(void)
{
    run_callback_lifetime_wait_test(CALLBACK_PAUSE_INITIAL_READER,
                                    "callback-lifetime.initial-reader");
    run_callback_lifetime_wait_test(CALLBACK_PAUSE_DYNAMIC_READER,
                                    "callback-lifetime.dynamic-reader");
    run_callback_lifetime_wait_test(CALLBACK_PAUSE_LEGACY,
                                    "callback-lifetime.legacy");
}

static void test_unload_winner_rejects_late_callback_before_any_work(void)
{
    struct fake_library { int value; } library = { 7 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;

    init_fake_callback_event(&event, "/guest/libunload-wins.so", 0x240000);
    event.namespace_id = 0;
    check_int("unload-wins.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("unload-wins.pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    check_int("unload-wins.initial", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&library,
                                 (uintptr_t)&event.link_map);
    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    check_int("unload-wins.callback", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 0);
    check_int("unload-wins.result", result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_true("unload-wins.no-work",
               event.trace.reader_calls == 0 &&
               event.trace.legacy_calls == 0 &&
               event.trace.diagnostic_calls == 0);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_callback_gate_allocation_failure_is_safe_fail_open(void)
{
    struct fake_library { int value; } library = { 8 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;

    init_fake_callback_event(&event, "/guest/libgate-alloc-fail.so", 0x260000);
    event.namespace_id = 0;
    check_int("gate-alloc-fail.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("gate-alloc-fail.pair", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library, KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_binding_test_set_alloc_failure_after(0);
    check_int("gate-alloc-fail.callback", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 77);
    check_int("gate-alloc-fail.legacy", event.trace.legacy_calls, 1);
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&library,
                                 (uintptr_t)&event.link_map);
    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    check_int("gate-alloc-fail.late-callback", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 0);
    check_true("gate-alloc-fail.late-no-work",
               event.trace.reader_calls == 0 &&
               event.trace.legacy_calls == 0);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void run_adapter_address_reuse_test(int force_gate_alloc_failure,
                                          const char *name)
{
    struct fake_library { int value; } old_library = { 10 },
                                          new_library = { 11 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_observation_adapter_result_t result;

    init_fake_callback_event(&event, "/guest/libadapter-reuse.so", 0x2a0000);
    event.namespace_id = 0;
    check_int(name, kzt_guest_library_track(
                  bindings, (library_t *)&old_library), 0);
    check_int("adapter-reuse old pair",
              kzt_guest_library_publish_loader_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&old_library,
                  KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    if (!force_gate_alloc_failure) {
        check_int("adapter-reuse seed gate", run_adapter_with_bindings(
                      &event, registry, bindings, &result), 77);
    } else {
        kzt_guest_library_binding_test_set_alloc_failure_after(0);
    }
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&old_library,
                                 (uintptr_t)&event.link_map);
    kzt_guest_library_binding_test_set_alloc_failure_after(-1);

    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    check_int("adapter-reuse stale return", run_adapter_with_bindings(
                  &event, registry, bindings, &result), 0);
    check_int("adapter-reuse stale disabled", result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_true("adapter-reuse stale no read",
               event.trace.reader_calls == 0 &&
               event.trace.legacy_calls == 0);

    check_int("adapter-reuse new track", kzt_guest_library_track(
                  bindings, (library_t *)&new_library), 0);
    check_int("adapter-reuse scope", kzt_guest_library_loader_scope_begin(
                  bindings, &scope), 0);
    check_int("adapter-reuse current return", run_adapter_with_loader_scope(
                  &event, registry, bindings, &scope, &result), 77);
    check_true("adapter-reuse current read",
               event.trace.reader_calls > 0 &&
               event.trace.legacy_calls == 1);
    check_true("adapter-reuse pending pair",
               kzt_guest_library_loader_scope_note_pair(
                   &scope, (uintptr_t)&event.link_map,
                   (library_t *)&new_library,
                   KZT_GUEST_LIBRARY_OBJECT_WRAPPED) !=
                   KZT_GUEST_LIBRARY_BINDING_ERROR);
    check_true("adapter-reuse new pair",
               kzt_guest_library_loader_scope_publish_pair(
                   &scope, (uintptr_t)&event.link_map,
                   (library_t *)&new_library,
                   KZT_GUEST_LIBRARY_OBJECT_WRAPPED) !=
                   KZT_GUEST_LIBRARY_BINDING_ERROR);
    kzt_guest_library_loader_scope_end(&scope);

    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_adapter_address_reuse_requires_loader_causality(void)
{
    run_adapter_address_reuse_test(0, "adapter-reuse normal");
    run_adapter_address_reuse_test(1, "adapter-reuse fallback");
}

static void run_adapter_pending_then_wrapper_result(int wrapper_success)
{
    struct fake_library { int value; } old_library = { 12 },
                                          new_library = { 13 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_scope_t scope = { 0 };
    kzt_guest_library_callback_access_t probe = { 0 };
    kzt_observation_adapter_result_t result;
    uintptr_t map;

    init_fake_callback_event(&event, "/guest/libpending-wrapper.so", 0x2b0000);
    event.namespace_id = 0;
    map = (uintptr_t)&event.link_map;
    check_int("pending-wrapper old track", kzt_guest_library_track(
                  bindings, (library_t *)&old_library), 0);
    check_int("pending-wrapper old pair", kzt_guest_library_publish_loader_pair(
                  bindings, map, (library_t *)&old_library,
                  KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_library_inactivate(bindings, registry,
                                 (library_t *)&old_library, map);
    check_int("pending-wrapper new track", kzt_guest_library_track(
                  bindings, (library_t *)&new_library), 0);
    check_int("pending-wrapper scope", kzt_guest_library_loader_scope_begin(
                  bindings, &scope), 0);
    event.loader_scope = &scope;
    event.loader_library = (library_t *)&new_library;
    check_int("pending-wrapper adapter", run_adapter_with_loader_scope(
                  &event, registry, bindings, &scope, &result), 77);
    check_true("pending-wrapper callback observed",
               event.pending_pair_result == KZT_GUEST_LIBRARY_BINDING_PENDING ||
               event.pending_pair_result == KZT_GUEST_LIBRARY_BINDING_ADDED ||
               event.pending_pair_result == KZT_GUEST_LIBRARY_BINDING_UNCHANGED);
    check_true("pending-wrapper not yet reopened",
               kzt_guest_library_callback_access_begin(
                   bindings, map, &probe) != 0);

    if (wrapper_success) {
        check_true("pending-wrapper final publish",
                   kzt_guest_library_loader_scope_publish_pair(
                       &scope, map, (library_t *)&new_library,
                       KZT_GUEST_LIBRARY_OBJECT_WRAPPED) !=
                   KZT_GUEST_LIBRARY_BINDING_ERROR);
    }
    kzt_guest_library_loader_scope_end(&scope);
    if (wrapper_success) {
        check_int("pending-wrapper success reopened",
                  kzt_guest_library_callback_access_begin(
                      bindings, map, &probe), 0);
        kzt_guest_library_callback_access_end(&probe);
    } else {
        check_true("pending-wrapper failure closed",
                   kzt_guest_library_callback_access_begin(
                       bindings, map, &probe) != 0);
    }
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_callback_pending_observation_waits_for_wrapper_success(void)
{
    run_adapter_pending_then_wrapper_result(0);
    run_adapter_pending_then_wrapper_result(1);
}

static void assert_dynamic_view_complete(const char *name,
                                         kzt_guest_registry_t *registry,
                                         const fake_callback_event_t *event,
                                         unsigned long expected_generation)
{
    kzt_guest_dynamic_view_t view = { 0 };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long generation = 0;

    check_int(name, kzt_guest_registry_find_dynamic_view(
                  registry, (uintptr_t)&event->link_map, &view, &status,
                  &generation), 0);
    check_int("dynamic.status", status, KZT_GUEST_FIELD_OK);
    check_ulong("dynamic.generation", generation, expected_generation);
    check_uintptr("dynamic.addr", view.dynamic_addr,
                  (uintptr_t)event->dynamic);
    check_uintptr("dynamic.load-bias", view.load_bias,
                  event->link_map.l_addr);
    check_int("dynamic.view-status", view.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_ulong("dynamic.entry-count", view.entry_count, 3);
    check_int("dynamic.has-null", view.has_null, 1);
    check_true("dynamic.symtab.present", view.symtab.present);
    check_uintptr("dynamic.symtab", view.symtab.value,
                  event->link_map.l_addr + 0x3000);
    check_int("dynamic.symtab.semantics", view.symtab.address_semantics,
              KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_true("dynamic.strtab.present", view.strtab.present);
    check_uintptr("dynamic.strtab", view.strtab.value,
                  event->link_map.l_addr + 0x4000);
    check_int("dynamic.strtab.semantics", view.strtab.address_semantics,
              KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_true("dynamic.strsz.present", view.strsz.present);
    check_ulong("dynamic.strsz", view.strsz.value, 0x180);
    check_int("dynamic.strsz.semantics", view.strsz.address_semantics,
              KZT_GUEST_DYNAMIC_SCALAR);
}

static void assert_dynamic_view_read_error(const char *name,
                                           kzt_guest_registry_t *registry,
                                           const fake_callback_event_t *event)
{
    kzt_guest_dynamic_view_t view = { 0 };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long generation = 0;

    check_int(name, kzt_guest_registry_find_dynamic_view(
                  registry, (uintptr_t)&event->link_map, &view, &status,
                  &generation), 0);
    check_int("dynamic.read-error.status", status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_ulong("dynamic.read-error.generation", generation, 1);
    check_uintptr("dynamic.read-error.addr", view.dynamic_addr,
                  (uintptr_t)event->dynamic);
    check_int("dynamic.read-error.view-status", view.status,
              KZT_GUEST_DYNAMIC_READ_ERROR);
    check_ulong("dynamic.read-error.entry-count", view.entry_count, 1);
    check_int("dynamic.read-error.no-null", view.has_null, 0);
}

static void assert_dynamic_view_not_parsed(const char *name,
                                           kzt_guest_registry_t *registry,
                                           const fake_callback_event_t *event)
{
    kzt_guest_dynamic_view_t view = { 0 };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long generation = 0;

    check_int(name, kzt_guest_registry_find_dynamic_view(
                  registry, (uintptr_t)&event->link_map, &view, &status,
                  &generation), 0);
    check_int("dynamic.not-parsed.status", status,
              KZT_GUEST_FIELD_NOT_PARSED);
    check_ulong("dynamic.not-parsed.generation", generation, 1);
    check_uintptr("dynamic.not-parsed.addr", view.dynamic_addr, 0);
}

static void test_active_observation_adds_object_and_preserves_old_flow(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libactive.so", 0x100000);
    event.trace.legacy_return = 23;

    ret = run_adapter(&event, registry, 1, &result);

    check_int("active.return", ret, 23);
    check_int("active.result", result, KZT_OBSERVATION_ADAPTER_ADDED);
    assert_old_flow_exactly_once("active.old-flow", &event, 23);
    assert_reader_before_old_flow(&event);
    check_ulong("active.registry-count", registry_object_count(registry), 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_exact_pair_retries_after_transient_observation_failure(void)
{
    struct fake_library { int value; } library = { 1 };
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_observation_adapter_result_t result;
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t handle;

    init_fake_callback_event(&event, "/guest/libexact.so", 0x160000);
    event.namespace_id = 0;
    check_int("exact.track", kzt_guest_library_track(
                  bindings, (library_t *)&library), 0);
    check_int("exact.pending", kzt_guest_library_note_exact_pair(
                  bindings, (uintptr_t)&event.link_map,
                  (library_t *)&library,
                  KZT_GUEST_LIBRARY_OBJECT_WRAPPED),
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    kzt_guest_registry_test_set_alloc_failure_after(0);
    (void)run_adapter_with_bindings(&event, registry, bindings, &result);
    check_int("exact.transient-result", result,
              KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    (void)run_adapter_with_bindings(&event, registry, bindings, &result);
    check_int("exact.retry-result", result, KZT_OBSERVATION_ADAPTER_ADDED);
    key = (kzt_guest_library_binding_key_t){
        .link_map_addr = (uintptr_t)&event.link_map,
        .generation = 1,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    check_int("exact.lookup", kzt_guest_library_lookup(
                  bindings, &key, &handle), 0);
    check_true("exact.library", handle.library == (library_t *)&library);
    kzt_guest_library_handle_release(&handle);
    kzt_guest_library_unbind(bindings, registry, (library_t *)&library,
                             (uintptr_t)&event.link_map);
    kzt_guest_library_bindings_destroy(&bindings);
    kzt_guest_registry_destroy(&registry);
}

static void test_dynamic_parser_success_commits_snapshot(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdynamic.so", 0x180000);
    event.trace.legacy_return = 41;
    check_int("dynamic-success.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);

    check_int("dynamic-success.return", ret, 41);
    check_int("dynamic-success.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    assert_old_flow_exactly_once("dynamic-success.old-flow", &event, 41);
    assert_dynamic_view_complete("dynamic-success.view", registry, &event, 1);
    check_int("dynamic-success.diagnostic-attempted",
              event.trace.dynamic_attempted, 1);
    check_int("dynamic-success.diagnostic-parse-return",
              event.trace.dynamic_parse_return, 0);
    check_int("dynamic-success.diagnostic-status",
              event.trace.dynamic_status, KZT_GUEST_DYNAMIC_COMPLETE);
    check_int("dynamic-success.diagnostic-commit",
              event.trace.dynamic_commit_attempted, 1);
    check_int("dynamic-success.diagnostic-commit-result",
              event.trace.dynamic_commit_result, KZT_GUEST_REGISTRY_UPDATED);

    kzt_guest_registry_destroy(&registry);
}

static void test_dynamic_parser_reuses_same_generation_complete_view(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdynamic-cache.so", 0x1a0000);
    event.trace.legacy_return = 44;
    check_int("dynamic-cache.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);
    check_int("dynamic-cache.first-return", ret, 44);
    check_int("dynamic-cache.first-result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("dynamic-cache.first-attempted", event.trace.dynamic_attempted, 1);
    check_true("dynamic-cache.first-read",
               event.trace.dynamic_reader_calls > 0);
    assert_dynamic_view_complete("dynamic-cache.first-view", registry, &event,
                                 1);

    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 45;
    result = KZT_OBSERVATION_ADAPTER_DISABLED;
    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);

    check_int("dynamic-cache.second-return", ret, 45);
    check_int("dynamic-cache.second-result", result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    assert_old_flow_exactly_once("dynamic-cache.second-old-flow", &event, 45);
    check_int("dynamic-cache.second-cache-hit",
              event.trace.dynamic_cache_hit, 1);
    check_int("dynamic-cache.second-attempted",
              event.trace.dynamic_attempted, 0);
    check_int("dynamic-cache.second-dynamic-reads",
              event.trace.dynamic_reader_calls, 0);
    assert_dynamic_view_complete("dynamic-cache.second-view", registry, &event,
                                 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_dynamic_parser_read_failure_is_fail_open(void)
{
    fake_callback_event_t event;
    fake_read_failure_t failure;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdynamic-readfail.so",
                             0x190000);
    event.trace.legacy_return = 42;
    failure.addr = (uintptr_t)&event.dynamic[1];
    failure.size = sizeof(event.dynamic[1]);
    event.memory.failures = &failure;
    event.memory.failure_count = 1;
    check_int("dynamic-readfail.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);

    check_int("dynamic-readfail.return", ret, 42);
    check_int("dynamic-readfail.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    assert_old_flow_exactly_once("dynamic-readfail.old-flow", &event, 42);
    assert_dynamic_view_read_error("dynamic-readfail.view", registry, &event);
    check_int("dynamic-readfail.diagnostic-attempted",
              event.trace.dynamic_attempted, 1);
    check_int("dynamic-readfail.diagnostic-status",
              event.trace.dynamic_status, KZT_GUEST_DYNAMIC_READ_ERROR);
    check_uintptr("dynamic-readfail.diagnostic-read-addr",
                  event.trace.dynamic_read_error_addr,
                  (uintptr_t)&event.dynamic[1]);
    check_int("dynamic-readfail.diagnostic-commit-result",
              event.trace.dynamic_commit_result, KZT_GUEST_REGISTRY_UPDATED);

    kzt_guest_registry_destroy(&registry);
}

static void test_dynamic_diagnostics_preserve_complete_view(void)
{
    fake_callback_event_t event;
    fake_read_failure_t failure;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };

    check_true("dynamic-compare.registry", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdynamic-compare.so",
                             0x1d0000);
    check_int("dynamic-compare.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config), 0);
    check_int("dynamic-compare.seed", run_adapter_with_diagnostics(
                  &event, registry, 1, 0, &result), 77);
    assert_dynamic_view_complete("dynamic-compare.seed-view", registry,
                                 &event, 1);

    memset(&event.trace, 0, sizeof(event.trace));
    event.trace.legacy_return = 77;
    failure.addr = (uintptr_t)&event.dynamic[1];
    failure.size = sizeof(event.dynamic[1]);
    event.memory.failures = &failure;
    event.memory.failure_count = 1;
    check_int("dynamic-compare.read-failure", run_adapter_with_diagnostics(
                  &event, registry, 1, 1, &result), 77);
    check_int("dynamic-compare.result", result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    assert_dynamic_view_complete("dynamic-compare.preserved", registry,
                                 &event, 1);
    check_int("dynamic-compare.attempted",
              event.trace.dynamic_comparison_attempted, 1);
    check_int("dynamic-compare.blocking",
              event.trace.dynamic_comparison_blocking, 1);
    check_int("dynamic-compare.matched",
              event.trace.dynamic_comparison_matched, 0);
    check_int("dynamic-compare.commit", event.trace.dynamic_commit_result,
              KZT_GUEST_REGISTRY_UNCHANGED);
    assert_old_flow_exactly_once("dynamic-compare.old-flow", &event, 77);

    kzt_guest_registry_destroy(&registry);
}

static void test_dynamic_commit_failure_is_fail_open(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };
    kzt_guest_registry_diagnostics_t diagnostics = { 0 };
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdynamic-commitfail.so",
                             0x1a0000);
    event.trace.legacy_return = 43;
    check_int("dynamic-commitfail.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    kzt_guest_registry_test_set_dynamic_commit_failure_after(0);
    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);
    kzt_guest_registry_test_set_dynamic_commit_failure_after(-1);

    check_int("dynamic-commitfail.return", ret, 43);
    check_int("dynamic-commitfail.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    assert_old_flow_exactly_once("dynamic-commitfail.old-flow", &event, 43);
    assert_dynamic_view_not_parsed("dynamic-commitfail.view", registry,
                                   &event);
    check_int("dynamic-commitfail.diagnostic-attempted",
              event.trace.dynamic_attempted, 1);
    check_int("dynamic-commitfail.diagnostic-status",
              event.trace.dynamic_status, KZT_GUEST_DYNAMIC_COMPLETE);
    check_int("dynamic-commitfail.diagnostic-commit-result",
              event.trace.dynamic_commit_result, KZT_GUEST_REGISTRY_ERROR);
    check_int("dynamic-commitfail.diagnostics",
              kzt_guest_registry_get_diagnostics(registry, &diagnostics), 0);
    check_ulong("dynamic-commitfail.error-count", diagnostics.errors, 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_disabled_adapter_skips_observation_but_preserves_old_flow(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_ADDED;
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdisabled.so", 0x200000);
    event.trace.legacy_return = 24;

    ret = run_adapter(&event, registry, 0, &result);

    check_int("disabled.return", ret, 24);
    check_int("disabled.result", result, KZT_OBSERVATION_ADAPTER_DISABLED);
    assert_old_flow_exactly_once("disabled.old-flow", &event, 24);
    check_int("disabled.reader-calls", event.trace.reader_calls, 0);
    check_ulong("disabled.registry-count", registry_object_count(registry), 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_reader_failure_is_fail_open_for_old_flow(void)
{
    fake_callback_event_t event;
    fake_read_failure_t failure;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_ADDED;
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libreaderfail.so", 0x300000);
    event.trace.legacy_return = 25;
    failure.addr = (uintptr_t)&event.link_map +
                   offsetof(struct link_map_x64, l_addr);
    failure.size = sizeof(event.link_map.l_addr);
    event.memory.failures = &failure;
    event.memory.failure_count = 1;

    ret = run_adapter(&event, registry, 1, &result);

    check_int("reader-failure.return", ret, 25);
    check_int("reader-failure.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    assert_old_flow_exactly_once("reader-failure.old-flow", &event, 25);
    assert_reader_before_old_flow(&event);
    check_ulong("reader-failure.registry-count",
                registry_object_count(registry), 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_partial_link_map_fields_are_registered(void)
{
    static const struct {
        const char *name;
        size_t offset;
        size_t size;
    } cases[] = {
        { "load-bias", offsetof(struct link_map_x64, l_addr),
          sizeof(((struct link_map_x64 *)0)->l_addr) },
        { "dynamic", offsetof(struct link_map_x64, l_ld),
          sizeof(((struct link_map_x64 *)0)->l_ld) },
        { "path", offsetof(struct link_map_x64, l_name),
          sizeof(((struct link_map_x64 *)0)->l_name) },
    };
    size_t i;

    for (i = 0; i < TEST_ARRAY_SIZE(cases); ++i) {
        fake_callback_event_t event;
        fake_read_failure_t failure;
        kzt_guest_registry_t *registry = kzt_guest_registry_init();
        kzt_guest_object_snapshot_t *snapshot = NULL;
        kzt_observation_adapter_result_t result =
            KZT_OBSERVATION_ADAPTER_DISABLED;

        check_true("partial-fields.registry", registry != NULL);
        if (!registry) {
            continue;
        }
        init_fake_callback_event(&event, "/guest/libpartial-fields.so",
                                 0x330000 + i * 0x10000);
        failure.addr = (uintptr_t)&event.link_map + cases[i].offset;
        failure.size = cases[i].size;
        event.memory.failures = &failure;
        event.memory.failure_count = 1;

        check_int(cases[i].name, run_adapter(&event, registry, 1, &result),
                  77);
        check_int("partial-fields.result", result,
                  KZT_OBSERVATION_ADAPTER_ADDED);
        check_int("partial-fields.find", kzt_guest_registry_find_by_link_map(
                      registry, (uintptr_t)&event.link_map, &snapshot), 0);
        check_true("partial-fields.snapshot", snapshot != NULL);
        if (snapshot) {
            check_uintptr("partial-fields.identity", snapshot->link_map_addr,
                          (uintptr_t)&event.link_map);
            if (i == 0) {
                check_int("partial-fields.load-bias", snapshot->load_bias.status,
                          KZT_GUEST_FIELD_READ_ERROR);
            } else if (i == 1) {
                check_int("partial-fields.dynamic", snapshot->dynamic_addr.status,
                          KZT_GUEST_FIELD_READ_ERROR);
            } else {
                check_int("partial-fields.path", snapshot->path.status,
                          KZT_GUEST_FIELD_READ_ERROR);
            }
            kzt_guest_object_snapshot_free(snapshot);
        }
        assert_old_flow_exactly_once("partial-fields.old-flow", &event, 77);
        kzt_guest_registry_destroy(&registry);
    }
}

static void test_verified_hints_fill_private_link_map_evidence(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_observation_adapter_result_t result =
        KZT_OBSERVATION_ADAPTER_DISABLED;

    check_true("verified-hints.registry", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libverified-hints.so", 0x360000);
    event.link_map.l_ns = 91;
    event.link_map.l_map_start = 0x111000;
    event.link_map.l_map_end = 0x112000;
    event.namespace_id = 0;

    check_int("verified-hints.return",
              run_adapter(&event, registry, 1, &result), 77);
    check_int("verified-hints.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("verified-hints.find", kzt_guest_registry_find_by_link_map(
                  registry, (uintptr_t)&event.link_map, &snapshot), 0);
    check_true("verified-hints.snapshot", snapshot != NULL);
    if (snapshot) {
        check_int("verified-hints.namespace.status",
                  snapshot->namespace_id.status, KZT_GUEST_FIELD_OK);
        check_uintptr("verified-hints.namespace.value",
                      snapshot->namespace_id.value, 0);
        check_int("verified-hints.map-start.status",
                  snapshot->map_start.status, KZT_GUEST_FIELD_OK);
        check_uintptr("verified-hints.map-start.value",
                      snapshot->map_start.value, event.map_start);
        check_int("verified-hints.map-end.status",
                  snapshot->map_end.status, KZT_GUEST_FIELD_OK);
        check_uintptr("verified-hints.map-end.value",
                      snapshot->map_end.value, event.map_end);
        kzt_guest_object_snapshot_free(snapshot);
    }
    assert_old_flow_exactly_once("verified-hints.old-flow", &event, 77);
    kzt_guest_registry_destroy(&registry);
}

static void test_invalid_or_absent_hints_remain_unknown_and_fail_open(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_observation_adapter_result_t result =
        KZT_OBSERVATION_ADAPTER_DISABLED;

    check_true("invalid-hints.registry", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libinvalid-hints.so", 0x370000);
    event.namespace_id_present = 0;
    event.namespace_id = 0;
    event.map_range_present = 1;
    event.map_start = 0x390000;
    event.map_end = 0x380000;
    event.link_map.l_ns = 0;
    event.link_map.l_map_start = 0x370000;
    event.link_map.l_map_end = 0x390000;

    check_int("invalid-hints.return",
              run_adapter(&event, registry, 1, &result), 77);
    check_int("invalid-hints.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("invalid-hints.find", kzt_guest_registry_find_by_link_map(
                  registry, (uintptr_t)&event.link_map, &snapshot), 0);
    check_true("invalid-hints.snapshot", snapshot != NULL);
    if (snapshot) {
        check_int("invalid-hints.namespace",
                  snapshot->namespace_id.status, KZT_GUEST_FIELD_UNKNOWN);
        check_int("invalid-hints.map-start",
                  snapshot->map_start.status, KZT_GUEST_FIELD_UNKNOWN);
        check_int("invalid-hints.map-end",
                  snapshot->map_end.status, KZT_GUEST_FIELD_UNKNOWN);
        kzt_guest_object_snapshot_free(snapshot);
    }
    assert_old_flow_exactly_once("invalid-hints.old-flow", &event, 77);
    kzt_guest_registry_destroy(&registry);
}

static void test_registry_failure_is_fail_open_for_old_flow(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_ADDED;
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libregistryfail.so", 0x400000);
    event.trace.legacy_return = 26;

    kzt_guest_registry_test_set_alloc_failure_after(0);
    ret = run_adapter(&event, registry, 1, &result);
    kzt_guest_registry_test_set_alloc_failure_after(-1);

    check_int("registry-failure.return", ret, 26);
    check_int("registry-failure.result", result,
              KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED);
    assert_old_flow_exactly_once("registry-failure.old-flow", &event, 26);
    assert_reader_before_old_flow(&event);
    check_ulong("registry-failure.registry-count",
                registry_object_count(registry), 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_conflict_result_does_not_change_old_flow(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t original;
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_ADDED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 4,
    };
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libconflict-new.so", 0x500000);
    event.trace.legacy_return = 27;
    original = make_observation((uintptr_t)&event.link_map,
                                0x510000,
                                "/guest/libconflict-old.so");
    check_int("conflict.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);
    check_int("conflict.prepopulate",
              kzt_guest_registry_observe(registry, &original),
              KZT_GUEST_REGISTRY_ADDED);

    ret = run_adapter_with_diagnostics(&event, registry, 1, 0, &result);

    check_int("conflict.return", ret, 27);
    check_int("conflict.result", result, KZT_OBSERVATION_ADAPTER_CONFLICT);
    assert_old_flow_exactly_once("conflict.old-flow", &event, 27);
    assert_reader_before_old_flow(&event);
    check_ulong("conflict.registry-count",
                registry_object_count(registry), 1);
    assert_dynamic_view_not_parsed("conflict.view", registry, &event);
    check_int("conflict.diagnostic-calls", event.trace.diagnostic_calls, 1);
    check_int("conflict.dynamic-not-attempted",
              event.trace.dynamic_attempted, 0);
    check_int("conflict.dynamic-no-commit",
              event.trace.dynamic_commit_attempted, 0);
    check_int("conflict.dynamic-commit-result",
              event.trace.dynamic_commit_result, KZT_GUEST_REGISTRY_RESULT_COUNT);

    kzt_guest_registry_destroy(&registry);
}

static void test_no_callback_event_does_not_create_registry_objects(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_ulong("no-callback.registry-count",
                registry_object_count(registry), 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_enabled_diagnostics_are_throttled_and_fail_open(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 1,
    };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdiagnostic.so", 0x700000);
    event.trace.legacy_return = 31;
    check_int("diagnostic.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    check_int("diagnostic.added.return",
              run_adapter_with_diagnostics(&event, registry, 1, 0, &result),
              31);
    check_int("diagnostic.added.result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("diagnostic.added.calls", event.trace.diagnostic_calls, 1);
    check_int("diagnostic.added.callback-result",
              event.trace.diagnostic_result, KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("diagnostic.added.emitted", event.trace.diagnostic_emitted, 1);
    check_int("diagnostic.added.legacy-calls", event.trace.legacy_calls, 1);

    check_int("diagnostic.unchanged.return",
              run_adapter_with_diagnostics(&event, registry, 1, 0, &result),
              31);
    check_int("diagnostic.unchanged.result", result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    check_int("diagnostic.unchanged.calls", event.trace.diagnostic_calls, 2);
    check_int("diagnostic.unchanged.callback-result",
              event.trace.diagnostic_result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    check_ulong("diagnostic.unchanged.observations",
                event.trace.diagnostic_result_observations, 1);
    check_int("diagnostic.unchanged.legacy-calls",
              event.trace.legacy_calls, 2);

    check_int("diagnostic.suppressed.return",
              run_adapter_with_diagnostics(&event, registry, 1, 0, &result),
              31);
    check_int("diagnostic.suppressed.result", result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    check_int("diagnostic.suppressed.calls", event.trace.diagnostic_calls, 2);
    check_int("diagnostic.suppressed.legacy-calls",
              event.trace.legacy_calls, 3);

    kzt_guest_registry_destroy(&registry);
}

static void test_reader_failures_are_throttled(void)
{
    fake_callback_event_t event;
    fake_read_failure_t failure;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_DISABLED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 1,
    };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdiagnostic-fail.so",
                             0x710000);
    failure.addr = (uintptr_t)&event.link_map +
                   offsetof(struct link_map_x64, l_addr);
    failure.size = sizeof(event.link_map.l_addr);
    event.memory.failures = &failure;
    event.memory.failure_count = 1;
    event.trace.legacy_return = 37;
    check_int("reader-diagnostic.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    check_int("reader-diagnostic.first-return",
              run_adapter_with_diagnostics(&event, registry, 1, 0, &result),
              37);
    check_int("reader-diagnostic.first-result", result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("reader-diagnostic.first-calls",
              event.trace.diagnostic_calls, 1);
    check_int("reader-diagnostic.first-emitted",
              event.trace.diagnostic_emitted, 1);
    check_int("reader-diagnostic.first-legacy",
              event.trace.legacy_calls, 1);

    check_int("reader-diagnostic.second-return",
              run_adapter_with_diagnostics(&event, registry, 1, 0, &result),
              37);
    check_int("reader-diagnostic.second-result", result,
              KZT_OBSERVATION_ADAPTER_UNCHANGED);
    check_int("reader-diagnostic.second-calls",
              event.trace.diagnostic_calls, 2);
    check_int("reader-diagnostic.second-legacy",
              event.trace.legacy_calls, 2);

    kzt_guest_registry_destroy(&registry);
}

static void test_disabled_adapter_diagnostics_are_throttled(void)
{
    fake_callback_event_t event;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_observation_adapter_result_t result = KZT_OBSERVATION_ADAPTER_ADDED;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 1,
    };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    init_fake_callback_event(&event, "/guest/libdiagnostic-disabled.so",
                             0x720000);
    event.trace.legacy_return = 39;
    check_int("disabled-diagnostic.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    check_int("disabled-diagnostic.first-return",
              run_adapter_with_diagnostics(&event, registry, 0, 0, &result),
              39);
    check_int("disabled-diagnostic.first-result", result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_int("disabled-diagnostic.first-calls",
              event.trace.diagnostic_calls, 1);
    check_int("disabled-diagnostic.first-emitted",
              event.trace.diagnostic_emitted, 1);
    check_int("disabled-diagnostic.first-legacy",
              event.trace.legacy_calls, 1);
    check_int("disabled-diagnostic.reader-calls",
              event.trace.reader_calls, 0);

    check_int("disabled-diagnostic.second-return",
              run_adapter_with_diagnostics(&event, registry, 0, 0, &result),
              39);
    check_int("disabled-diagnostic.second-result", result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_int("disabled-diagnostic.second-calls",
              event.trace.diagnostic_calls, 1);
    check_int("disabled-diagnostic.second-legacy",
              event.trace.legacy_calls, 2);
    check_int("disabled-diagnostic.second-reader-calls",
              event.trace.reader_calls, 0);

    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_active_observation_adds_object_and_preserves_old_flow();
    test_exact_pair_retries_after_transient_observation_failure();
    test_binding_owned_retire_excludes_adapter_retire();
    test_adapter_note_before_unload_leaves_single_retire_owner();
    test_cancelled_pending_without_owner_is_adapter_retired();
    test_exact_retire_owner_uses_complete_key();
    /* The direct test above proves exact-generation owner matching.  This
     * separate test proves the real adapter gate/registry path with a source
     * lease participant, binding retire owner, and third callback participant. */
    test_three_participant_adapter_does_not_duplicate_retire();
    test_callback_lifetime_covers_all_guest_work();
    test_unload_winner_rejects_late_callback_before_any_work();
    test_callback_gate_allocation_failure_is_safe_fail_open();
    test_adapter_address_reuse_requires_loader_causality();
    test_callback_pending_observation_waits_for_wrapper_success();
    test_dynamic_parser_success_commits_snapshot();
    test_dynamic_parser_reuses_same_generation_complete_view();
    test_dynamic_parser_read_failure_is_fail_open();
    test_dynamic_diagnostics_preserve_complete_view();
    test_dynamic_commit_failure_is_fail_open();
    test_disabled_adapter_skips_observation_but_preserves_old_flow();
    test_reader_failure_is_fail_open_for_old_flow();
    test_partial_link_map_fields_are_registered();
    test_verified_hints_fill_private_link_map_evidence();
    test_invalid_or_absent_hints_remain_unknown_and_fail_open();
    test_registry_failure_is_fail_open_for_old_flow();
    test_conflict_result_does_not_change_old_flow();
    test_no_callback_event_does_not_create_registry_objects();
    test_enabled_diagnostics_are_throttled_and_fail_open();
    test_reader_failures_are_throttled();
    test_disabled_adapter_diagnostics_are_throttled();

    if (failures) {
        fprintf(stderr, "kzt-observation-adapter: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-observation-adapter: all contract tests passed");
    return 0;
}
