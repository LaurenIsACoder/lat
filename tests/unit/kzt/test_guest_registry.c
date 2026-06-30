#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_registry.h"

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

static void check_not_int(const char *name, int got, int unexpected)
{
    if (got != unexpected) {
        return;
    }

    fprintf(stderr, "%s: got unexpected %d\n", name, got);
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

static void check_uintptr(const char *name, uintptr_t got, uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
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

static void check_contains(const char *name, const char *haystack,
                           const char *needle)
{
    if (haystack && needle && strstr(haystack, needle)) {
        return;
    }

    fprintf(stderr, "%s: missing \"%s\" in \"%s\"\n", name,
            needle ? needle : "(null)", haystack ? haystack : "(null)");
    ++failures;
}

static kzt_guest_object_observation_t make_observation(uintptr_t link_map_addr)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { 0x100000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x101000, KZT_GUEST_FIELD_OK },
        .map_start = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .path = { "/guest/libfoo.so", KZT_GUEST_FIELD_OK },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_object_snapshot_t *find_snapshot(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;

    check_int("find_by_link_map", kzt_guest_registry_find_by_link_map(
                  registry, link_map_addr, &snapshot), 0);
    check_true("find_by_link_map.snapshot", snapshot != NULL);
    return snapshot;
}

static void assert_not_found(kzt_guest_registry_t *registry,
                             uintptr_t link_map_addr)
{
    kzt_guest_object_snapshot_t *snapshot = (void *)0x1;

    check_not_int("find_by_link_map.missing",
                  kzt_guest_registry_find_by_link_map(registry,
                                                      link_map_addr,
                                                      &snapshot),
                  0);
    check_true("find_by_link_map.missing-snapshot", snapshot == NULL);
}

static void assert_snapshot_identity(
    const kzt_guest_object_snapshot_t *snapshot,
    uintptr_t link_map_addr,
    unsigned long generation)
{
    check_uintptr("snapshot.link_map_addr", snapshot->link_map_addr,
                  link_map_addr);
    check_ulong("snapshot.generation", snapshot->generation, generation);
    check_int("snapshot.state", snapshot->state, KZT_GUEST_OBJECT_DISCOVERED);
}

static void test_first_and_repeat_observation_keep_generation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x1000);
    kzt_guest_object_snapshot_t *snapshot;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    observation.load_bias.value = 0;
    observation.path.value = "";

    check_int("observe.added",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);

    snapshot = find_snapshot(registry, 0x1000);
    assert_snapshot_identity(snapshot, 0x1000, 1);
    check_int("snapshot.load_bias.status", snapshot->load_bias.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("snapshot.load_bias.value", snapshot->load_bias.value, 0);
    check_int("snapshot.path.status", snapshot->path.status,
              KZT_GUEST_FIELD_OK);
    check_string("snapshot.path.value", snapshot->path.value, "");
    check_int("snapshot.soname.status", snapshot->soname.status,
              KZT_GUEST_FIELD_NOT_PARSED);
    check_int("snapshot.dynamic_view_status", snapshot->dynamic_view_status,
              KZT_GUEST_FIELD_NOT_PARSED);
    check_int("snapshot.map_start.status", snapshot->map_start.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_int("snapshot.namespace_id.status", snapshot->namespace_id.status,
              KZT_GUEST_FIELD_UNKNOWN);
    kzt_guest_object_snapshot_free(snapshot);

    check_int("observe.unchanged",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_UNCHANGED);

    snapshot = find_snapshot(registry, 0x1000);
    assert_snapshot_identity(snapshot, 0x1000, 1);
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_unknown_fields_are_completed_without_generation_change(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x2000);
    kzt_guest_object_snapshot_t *snapshot;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    observation.load_bias.status = KZT_GUEST_FIELD_UNKNOWN;
    observation.dynamic_addr.status = KZT_GUEST_FIELD_READ_ERROR;
    observation.path.value = NULL;
    observation.path.status = KZT_GUEST_FIELD_UNKNOWN;

    check_int("observe.partial-added",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);

    snapshot = find_snapshot(registry, 0x2000);
    assert_snapshot_identity(snapshot, 0x2000, 1);
    check_int("snapshot.load_bias.unknown", snapshot->load_bias.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_int("snapshot.dynamic_addr.read-error",
              snapshot->dynamic_addr.status, KZT_GUEST_FIELD_READ_ERROR);
    check_int("snapshot.path.unknown", snapshot->path.status,
              KZT_GUEST_FIELD_UNKNOWN);
    kzt_guest_object_snapshot_free(snapshot);

    observation.load_bias.value = 0x220000;
    observation.load_bias.status = KZT_GUEST_FIELD_OK;
    observation.dynamic_addr.value = 0x221000;
    observation.dynamic_addr.status = KZT_GUEST_FIELD_OK;
    observation.path.value = "/guest/libfilled.so";
    observation.path.status = KZT_GUEST_FIELD_OK;

    check_int("observe.updated",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_UPDATED);

    snapshot = find_snapshot(registry, 0x2000);
    assert_snapshot_identity(snapshot, 0x2000, 1);
    check_int("snapshot.load_bias.ok", snapshot->load_bias.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("snapshot.load_bias.filled", snapshot->load_bias.value,
                  0x220000);
    check_int("snapshot.dynamic_addr.ok", snapshot->dynamic_addr.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("snapshot.dynamic_addr.filled", snapshot->dynamic_addr.value,
                  0x221000);
    check_int("snapshot.path.ok", snapshot->path.status, KZT_GUEST_FIELD_OK);
    check_string("snapshot.path.filled", snapshot->path.value,
                 "/guest/libfilled.so");
    kzt_guest_object_snapshot_free(snapshot);

    observation.load_bias.status = KZT_GUEST_FIELD_READ_ERROR;
    observation.dynamic_addr.status = KZT_GUEST_FIELD_UNKNOWN;
    observation.path.value = NULL;
    observation.path.status = KZT_GUEST_FIELD_READ_ERROR;

    check_int("observe.failed-fields-unchanged",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_UNCHANGED);

    snapshot = find_snapshot(registry, 0x2000);
    assert_snapshot_identity(snapshot, 0x2000, 1);
    check_int("snapshot.load_bias.still-ok", snapshot->load_bias.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("snapshot.load_bias.still-filled", snapshot->load_bias.value,
                  0x220000);
    check_int("snapshot.dynamic_addr.still-ok", snapshot->dynamic_addr.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("snapshot.dynamic_addr.still-filled",
                  snapshot->dynamic_addr.value, 0x221000);
    check_int("snapshot.path.still-ok", snapshot->path.status,
              KZT_GUEST_FIELD_OK);
    check_string("snapshot.path.still-filled", snapshot->path.value,
                 "/guest/libfilled.so");
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_identity_conflict_preserves_original_record(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x3000);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_dump_t dump = { 0 };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    observation.load_bias.value = 0x300000;
    observation.dynamic_addr.value = 0x301000;
    observation.path.value = "/guest/liboriginal.so";

    check_int("observe.added",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);

    observation.load_bias.value = 0x310000;
    observation.dynamic_addr.value = 0x311000;
    observation.path.value = "/guest/libconflict.so";

    check_int("observe.conflict",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_CONFLICT);

    snapshot = find_snapshot(registry, 0x3000);
    assert_snapshot_identity(snapshot, 0x3000, 1);
    check_uintptr("snapshot.load_bias.original", snapshot->load_bias.value,
                  0x300000);
    check_uintptr("snapshot.dynamic_addr.original",
                  snapshot->dynamic_addr.value, 0x301000);
    check_string("snapshot.path.original", snapshot->path.value,
                 "/guest/liboriginal.so");
    kzt_guest_object_snapshot_free(snapshot);

    check_int("dump.snapshot",
              kzt_guest_registry_dump_snapshot(registry, &dump),
              0);
    check_ulong("dump.count", dump.count, 1);
    assert_snapshot_identity(&dump.objects[0], 0x3000, 1);
    check_string("dump.path.original", dump.objects[0].path.value,
                 "/guest/liboriginal.so");
    kzt_guest_registry_dump_free(&dump);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_partial_observation_and_invalid_identity(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0);
    kzt_guest_object_snapshot_t *snapshot;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("observe.invalid-link-map",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ERROR);
    assert_not_found(registry, 0);

    observation = make_observation(0x4000);
    observation.load_bias.status = KZT_GUEST_FIELD_READ_ERROR;
    observation.dynamic_addr.status = KZT_GUEST_FIELD_UNKNOWN;
    observation.path.value = "/guest/path-truncated";
    observation.path.status = KZT_GUEST_FIELD_TRUNCATED;

    check_int("observe.partial-added",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);

    snapshot = find_snapshot(registry, 0x4000);
    assert_snapshot_identity(snapshot, 0x4000, 1);
    check_int("snapshot.load_bias.read-error", snapshot->load_bias.status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_int("snapshot.dynamic_addr.unknown", snapshot->dynamic_addr.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_int("snapshot.path.truncated", snapshot->path.status,
              KZT_GUEST_FIELD_TRUNCATED);
    check_string("snapshot.path.truncated-value", snapshot->path.value,
                 "/guest/path-truncated");
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_query_and_dump_snapshots_are_caller_owned(void)
{
    static const char path_literal[] = "/guest/libowned.so";
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x5000);
    kzt_guest_object_snapshot_t *first;
    kzt_guest_object_snapshot_t *second;
    kzt_guest_registry_dump_t dump = { 0 };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    observation.path.value = path_literal;
    check_int("observe.added",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);

    first = find_snapshot(registry, 0x5000);
    second = find_snapshot(registry, 0x5000);
    check_string("first.path", first->path.value, path_literal);
    check_string("second.path", second->path.value, path_literal);
    check_true("first.path.not-observation", first->path.value != path_literal);
    check_true("second.path.not-observation",
               second->path.value != path_literal);
    check_true("snapshots.path.distinct",
               first->path.value != second->path.value);

    check_int("dump.snapshot",
              kzt_guest_registry_dump_snapshot(registry, &dump),
              0);
    check_ulong("dump.count", dump.count, 1);
    check_string("dump.path", dump.objects[0].path.value, path_literal);
    check_true("dump.path.not-observation",
               dump.objects[0].path.value != path_literal);
    check_true("dump.path.not-first",
               dump.objects[0].path.value != first->path.value);
    check_true("dump.path.not-second",
               dump.objects[0].path.value != second->path.value);

    kzt_guest_registry_dump_free(&dump);
    kzt_guest_object_snapshot_free(first);
    kzt_guest_object_snapshot_free(second);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

typedef struct dump_text_sink {
    char text[8192];
    size_t used;
    unsigned long calls;
    kzt_guest_registry_t *registry;
} dump_text_sink_t;

static int collect_dump_text_line(const char *line, void *opaque)
{
    dump_text_sink_t *sink = opaque;
    kzt_guest_registry_diagnostics_t diagnostics = { 0 };
    size_t len;
    size_t remaining;

    if (sink->registry) {
        check_int("dump.sink-can-query-registry",
                  kzt_guest_registry_get_diagnostics(sink->registry,
                                                     &diagnostics),
                  0);
    }

    ++sink->calls;
    len = strlen(line);
    remaining = sizeof(sink->text) - sink->used;
    if (remaining <= 2) {
        return 0;
    }
    if (len >= remaining - 1) {
        len = remaining - 2;
    }
    memcpy(sink->text + sink->used, line, len);
    sink->used += len;
    sink->text[sink->used++] = '\n';
    sink->text[sink->used] = '\0';
    return 0;
}

static void test_diagnostics_are_opt_in_and_throttled(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x8000);
    kzt_guest_registry_observation_diagnostic_t diagnostic = { 0 };
    kzt_guest_registry_diagnostic_report_t report;
    kzt_guest_registry_diagnostic_config_t config = {
        .enabled = 1,
        .throttle_limit = 2,
    };
    dump_text_sink_t sink = { 0 };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("observe.diagnostic-disabled",
              kzt_guest_registry_observe_with_diagnostic(registry,
                                                         &observation,
                                                         &diagnostic),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("diagnostic.default-enabled", diagnostic.enabled, 0);
    check_int("diagnostic.default-emitted", diagnostic.emitted, 0);
    check_int("diagnostic.default-result", diagnostic.result,
              KZT_GUEST_REGISTRY_ADDED);

    check_int("diagnostic.report.disabled",
              kzt_guest_registry_get_diagnostic_report(registry, &report),
              0);
    check_int("report.default-enabled", report.config.enabled, 0);
    check_ulong("report.default-added-events",
                report.events[KZT_GUEST_REGISTRY_ADDED].observed, 0);
    check_ulong("report.default-added-counter", report.counters.added, 1);

    check_int("diagnostic.configure",
              kzt_guest_registry_configure_diagnostics(registry, &config),
              0);

    check_int("observe.unchanged.first",
              kzt_guest_registry_observe_with_diagnostic(registry,
                                                         &observation,
                                                         &diagnostic),
              KZT_GUEST_REGISTRY_UNCHANGED);
    check_int("diagnostic.first-enabled", diagnostic.enabled, 1);
    check_int("diagnostic.first-emitted", diagnostic.emitted, 1);
    check_ulong("diagnostic.first-observations",
                diagnostic.result_observations, 1);
    check_ulong("diagnostic.first-suppressed", diagnostic.result_suppressed,
                0);

    check_int("observe.unchanged.second",
              kzt_guest_registry_observe_with_diagnostic(registry,
                                                         &observation,
                                                         &diagnostic),
              KZT_GUEST_REGISTRY_UNCHANGED);
    check_int("diagnostic.second-emitted", diagnostic.emitted, 1);
    check_ulong("diagnostic.second-observations",
                diagnostic.result_observations, 2);

    check_int("observe.unchanged.third",
              kzt_guest_registry_observe_with_diagnostic(registry,
                                                         &observation,
                                                         &diagnostic),
              KZT_GUEST_REGISTRY_UNCHANGED);
    check_int("diagnostic.third-emitted", diagnostic.emitted, 0);
    check_ulong("diagnostic.third-observations",
                diagnostic.result_observations, 3);
    check_ulong("diagnostic.third-suppressed", diagnostic.result_suppressed,
                1);

    check_int("diagnostic.report.enabled",
              kzt_guest_registry_get_diagnostic_report(registry, &report),
              0);
    check_int("report.enabled", report.config.enabled, 1);
    check_ulong("report.throttle-limit", report.config.throttle_limit, 2);
    check_ulong("report.unchanged-observed",
                report.events[KZT_GUEST_REGISTRY_UNCHANGED].observed, 3);
    check_ulong("report.unchanged-emitted",
                report.events[KZT_GUEST_REGISTRY_UNCHANGED].emitted, 2);
    check_ulong("report.unchanged-suppressed",
                report.events[KZT_GUEST_REGISTRY_UNCHANGED].suppressed, 1);
    check_uintptr("report.unchanged-last-link-map",
                  report.events[KZT_GUEST_REGISTRY_UNCHANGED]
                      .last_link_map_addr,
                  0x8000);

    sink.registry = registry;
    check_int("dump.text",
              kzt_guest_registry_dump_text(registry, collect_dump_text_line,
                                           &sink),
              0);
    check_true("dump.text-called", sink.calls > 0);
    check_contains("dump.text-summary", sink.text,
                   "enabled=1 throttle_limit=2");
    check_contains("dump.text-event", sink.text,
                   "result=unchanged observed=3 emitted=2 suppressed=1");
    check_contains("dump.text-object", sink.text,
                   "object link_map=0x8000 generation=1 state=0");

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_init_failure_creates_disabled_registry_diagnostics(void)
{
    kzt_guest_registry_t *registry;
    kzt_guest_object_observation_t observation = make_observation(0x6000);
    kzt_guest_registry_diagnostics_t diagnostics = { 0 };

    kzt_guest_registry_test_set_alloc_failure_after(1);
    registry = kzt_guest_registry_init();
    kzt_guest_registry_test_set_alloc_failure_after(-1);

    check_true("registry.disabled-init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("observe.disabled",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_DISABLED);

    check_int("diagnostics.disabled",
              kzt_guest_registry_get_diagnostics(registry, &diagnostics), 0);
    check_ulong("diagnostics.init-failures", diagnostics.init_failures, 1);
    check_ulong("diagnostics.alloc-failures", diagnostics.allocation_failures,
                1);
    check_ulong("diagnostics.disabled-observe", diagnostics.disabled, 1);
    check_ulong("diagnostics.observations", diagnostics.observations, 1);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_destroyed_registry_rejects_new_observation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7000);

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
    check_int("observe.after-destroy",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_DISABLED);
}

int main(void)
{
    test_first_and_repeat_observation_keep_generation();
    test_unknown_fields_are_completed_without_generation_change();
    test_identity_conflict_preserves_original_record();
    test_partial_observation_and_invalid_identity();
    test_query_and_dump_snapshots_are_caller_owned();
    test_diagnostics_are_opt_in_and_throttled();
    test_init_failure_creates_disabled_registry_diagnostics();
    test_destroyed_registry_rejects_new_observation();

    if (failures) {
        fprintf(stderr, "kzt-guest-registry: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-guest-registry: all contract tests passed");
    return 0;
}
