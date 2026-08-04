#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/debug.h"
#include "target/i386/latx/include/kzt_observation_adapter.h"

int relocation_log;
int kzt_registry_diagnostics;
int option_kzt;
int wine_option_kzt;

typedef struct gate_trace {
    int reader_calls;
    int legacy_calls;
    int diagnostic_outputs;
    int legacy_return;
    uintptr_t legacy_link_map_addr;
    kzt_observation_adapter_result_t result;
    kzt_observation_adapter_result_t diagnostic_result;
    int diagnostic_emitted;
} gate_trace_t;

typedef struct gate_fixture {
    struct link_map_x64 link_map;
    char guest_name[64];
    kzt_guest_link_map_reader_ops_t reader_ops;
    gate_trace_t trace;
} gate_fixture_t;

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

static int fake_read_memory(uintptr_t guest_addr, void *dst, size_t size,
                            void *opaque)
{
    gate_fixture_t *fixture = opaque;
    uintptr_t base = (uintptr_t)&fixture->link_map;
    size_t available = sizeof(*fixture) -
                       offsetof(gate_fixture_t, link_map);

    ++fixture->trace.reader_calls;
    if (guest_addr < base || size > available ||
        guest_addr - base > available - size) {
        return -1;
    }

    memcpy(dst, (const void *)guest_addr, size);
    return 0;
}

static int fake_legacy_flow(uintptr_t link_map_addr, void *opaque)
{
    gate_trace_t *trace = opaque;

    ++trace->legacy_calls;
    trace->legacy_link_map_addr = link_map_addr;
    return trace->legacy_return;
}

static void fake_registry_diagnostic_output(
    const kzt_observation_adapter_diagnostic_t *diagnostic,
    void *opaque)
{
    gate_trace_t *trace = opaque;

    ++trace->diagnostic_outputs;
    trace->diagnostic_result = diagnostic->result;
    trace->diagnostic_emitted = diagnostic->emitted;
}

static void init_fixture(gate_fixture_t *fixture, const char *path,
                         uintptr_t load_bias)
{
    memset(fixture, 0, sizeof(*fixture));
    strcpy(fixture->guest_name, path);
    fixture->link_map.l_addr = load_bias;
    fixture->link_map.l_name = fixture->guest_name;
    fixture->link_map.l_ld = (Elf64_Dyn *)(load_bias + 0x1000);
    fixture->link_map.l_ns = 9;
    fixture->link_map.l_map_start = load_bias;
    fixture->link_map.l_map_end = load_bias + 0x20000;
    fixture->reader_ops.read_memory = fake_read_memory;
    fixture->reader_ops.opaque = fixture;
    fixture->trace.legacy_return = 73;
    fixture->trace.result = KZT_OBSERVATION_ADAPTER_DISABLED;
}

static int kzt_active(void)
{
    return option_kzt || wine_option_kzt;
}

static int run_gate_like_callback(gate_fixture_t *fixture,
                                  kzt_guest_registry_t *registry)
{
    kzt_guest_registry_diagnostic_config_t diagnostic_config = {
        .enabled = kzt_active(),
        .throttle_limit = 1,
    };
    kzt_observation_adapter_request_t request = {
        .enabled = kzt_active(),
        .diagnostics_enabled = kzt_registry_diagnostics_enabled(),
        .link_map_addr = (uintptr_t)&fixture->link_map,
        .registry = registry,
        .reader_ops = &fixture->reader_ops,
        .legacy_flow = fake_legacy_flow,
        .legacy_opaque = &fixture->trace,
        .diagnostic = fake_registry_diagnostic_output,
        .diagnostic_opaque = &fixture->trace,
    };

    check_int("gate.configure",
              kzt_guest_registry_configure_diagnostics(registry,
                                                       &diagnostic_config),
              0);
    return kzt_observe_guest_object_from_callback(&request,
                                                  &fixture->trace.result);
}

static void reset_options(void)
{
    relocation_log = LOG_NONE;
    kzt_registry_diagnostics = 0;
    option_kzt = 0;
    wine_option_kzt = 0;
}

static void assert_legacy_exactly_once(const char *name,
                                       const gate_fixture_t *fixture)
{
    check_int(name, fixture->trace.legacy_calls, 1);
    check_true("legacy.link-map",
               fixture->trace.legacy_link_map_addr ==
               (uintptr_t)&fixture->link_map);
}

static void test_gate_defaults_closed(void)
{
    reset_options();

    check_int("default.diagnostics-enabled",
              kzt_registry_diagnostics_enabled(), 0);
}

static void test_diagnostics_option_alone_does_not_output(void)
{
    gate_fixture_t fixture;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    reset_options();
    kzt_registry_diagnostics = 1;
    init_fixture(&fixture, "/guest/libkzt-off.so", 0x100000);

    ret = run_gate_like_callback(&fixture, registry);

    check_int("kzt-off.return", ret, 73);
    check_int("kzt-off.result", fixture.trace.result,
              KZT_OBSERVATION_ADAPTER_DISABLED);
    check_int("kzt-off.diagnostic-outputs",
              fixture.trace.diagnostic_outputs, 0);
    check_int("kzt-off.reader-calls", fixture.trace.reader_calls, 0);
    assert_legacy_exactly_once("kzt-off.legacy-calls", &fixture);

    kzt_guest_registry_destroy(&registry);
}

static void test_active_kzt_without_diagnostics_does_not_output(void)
{
    gate_fixture_t fixture;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    reset_options();
    option_kzt = 2;
    init_fixture(&fixture, "/guest/libdiagnostics-off.so", 0x200000);

    ret = run_gate_like_callback(&fixture, registry);

    check_int("diagnostics-off.return", ret, 73);
    check_int("diagnostics-off.result", fixture.trace.result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("diagnostics-off.diagnostic-outputs",
              fixture.trace.diagnostic_outputs, 0);
    check_true("diagnostics-off.reader-ran", fixture.trace.reader_calls > 0);
    assert_legacy_exactly_once("diagnostics-off.legacy-calls", &fixture);

    kzt_guest_registry_destroy(&registry);
}

static void test_active_kzt_with_diagnostics_outputs(void)
{
    gate_fixture_t fixture;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    reset_options();
    option_kzt = 2;
    kzt_registry_diagnostics = 1;
    init_fixture(&fixture, "/guest/libdiagnostics-on.so", 0x300000);

    ret = run_gate_like_callback(&fixture, registry);

    check_int("diagnostics-on.return", ret, 73);
    check_int("diagnostics-on.result", fixture.trace.result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("diagnostics-on.diagnostic-outputs",
              fixture.trace.diagnostic_outputs, 1);
    check_int("diagnostics-on.diagnostic-result",
              fixture.trace.diagnostic_result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("diagnostics-on.diagnostic-emitted",
              fixture.trace.diagnostic_emitted, 1);
    check_true("diagnostics-on.reader-ran", fixture.trace.reader_calls > 0);
    assert_legacy_exactly_once("diagnostics-on.legacy-calls", &fixture);

    kzt_guest_registry_destroy(&registry);
}

static void test_debug_log_level_is_equivalent_diagnostics_option(void)
{
    gate_fixture_t fixture;
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    int ret;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    reset_options();
    option_kzt = 2;
    relocation_log = LOG_DEBUG;
    init_fixture(&fixture, "/guest/libdiagnostics-debug.so", 0x400000);

    ret = run_gate_like_callback(&fixture, registry);

    check_int("debug-log.return", ret, 73);
    check_int("debug-log.result", fixture.trace.result,
              KZT_OBSERVATION_ADAPTER_ADDED);
    check_int("debug-log.diagnostic-outputs",
              fixture.trace.diagnostic_outputs, 1);
    assert_legacy_exactly_once("debug-log.legacy-calls", &fixture);

    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_gate_defaults_closed();
    test_diagnostics_option_alone_does_not_output();
    test_active_kzt_without_diagnostics_does_not_output();
    test_active_kzt_with_diagnostics_outputs();
    test_debug_log_level_is_equivalent_diagnostics_option();

    if (failures) {
        fprintf(stderr, "kzt-registry-diagnostics-gate: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-registry-diagnostics-gate: all gate tests passed");
    return 0;
}
