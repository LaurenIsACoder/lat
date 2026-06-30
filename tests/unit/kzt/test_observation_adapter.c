#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/kzt_observation_adapter.h"

#define EVENT_READER_READ 1
#define EVENT_LEGACY_FLOW 2

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
    int legacy_calls;
    int legacy_return;
    uintptr_t legacy_link_map_addr;
} observation_trace_t;

typedef struct fake_callback_event {
    struct link_map_x64 link_map;
    char guest_name[64];
    fake_reader_memory_t memory;
    kzt_guest_link_map_reader_ops_t ops;
    observation_trace_t trace;
} fake_callback_event_t;

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
    record_event(&event->trace, EVENT_READER_READ);

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
    observation_trace_t *trace = opaque;

    ++trace->legacy_calls;
    trace->legacy_link_map_addr = link_map_addr;
    record_event(trace, EVENT_LEGACY_FLOW);
    return trace->legacy_return;
}

static void init_fake_callback_event(fake_callback_event_t *event,
                                     const char *path,
                                     uintptr_t load_bias)
{
    memset(event, 0, sizeof(*event));
    strcpy(event->guest_name, path);
    event->link_map.l_addr = load_bias;
    event->link_map.l_name = event->guest_name;
    event->link_map.l_ld = (Elf64_Dyn *)(load_bias + 0x1000);
    event->link_map.l_ns = 7;
    event->link_map.l_map_start = load_bias;
    event->link_map.l_map_end = load_bias + 0x20000;
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
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = &event->trace,
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
              KZT_OBSERVATION_ADAPTER_READER_FAILED);
    assert_old_flow_exactly_once("reader-failure.old-flow", &event, 25);
    assert_reader_before_old_flow(&event);
    check_ulong("reader-failure.registry-count",
                registry_object_count(registry), 0);

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
    check_int("conflict.prepopulate",
              kzt_guest_registry_observe(registry, &original),
              KZT_GUEST_REGISTRY_ADDED);

    ret = run_adapter(&event, registry, 1, &result);

    check_int("conflict.return", ret, 27);
    check_int("conflict.result", result, KZT_OBSERVATION_ADAPTER_CONFLICT);
    assert_old_flow_exactly_once("conflict.old-flow", &event, 27);
    assert_reader_before_old_flow(&event);
    check_ulong("conflict.registry-count",
                registry_object_count(registry), 1);

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

int main(void)
{
    test_active_observation_adds_object_and_preserves_old_flow();
    test_disabled_adapter_skips_observation_but_preserves_old_flow();
    test_reader_failure_is_fail_open_for_old_flow();
    test_registry_failure_is_fail_open_for_old_flow();
    test_conflict_result_does_not_change_old_flow();
    test_no_callback_event_does_not_create_registry_objects();

    if (failures) {
        fprintf(stderr, "kzt-observation-adapter: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-observation-adapter: all contract tests passed");
    return 0;
}
