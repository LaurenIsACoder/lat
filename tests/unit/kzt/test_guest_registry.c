#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    check_int("snapshot.path.over-limit-unknown", snapshot->path.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_string("snapshot.path.over-limit-no-prefix", snapshot->path.value,
                 NULL);
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
    check_contains("dump.text-loader-lifecycle", sink.text,
                   "loader_identity_publications=0 "
                   "loader_close_referenced=0 "
                   "loader_close_unload_unproven=0 "
                   "loader_close_retired=0 loader_close_stale=0 "
                   "loader_close_identity_missing=0");
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

static void test_cond_init_failure_is_clean(void)
{
    kzt_guest_registry_t *registry;

    kzt_guest_registry_test_fail_next_cond_init();
    registry = kzt_guest_registry_init();
    check_true("cond-init.failure", registry == NULL);

    registry = kzt_guest_registry_init();
    check_true("cond-init.next-succeeds", registry != NULL);
    kzt_guest_registry_destroy(&registry);
}

static void test_source_lease_acquire_release(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6800);
    kzt_guest_object_observation_t unknown_namespace =
        make_observation(0x6880);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_source_lease_t lease = { 0 };
    unsigned long generation;

    check_true("lease.registry", registry != NULL);
    if (!registry) {
        return;
    }
    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_int("lease.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);

    check_int("lease.acquire", kzt_guest_registry_source_lease_acquire(
                  registry, observation.link_map_addr, generation, 0,
                  &lease), 0);
    check_true("lease.active", lease.active == 1 &&
                                   lease.registry == registry &&
                                   lease.namespace_id == 0);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("lease.snapshot-active", snapshot->active_source_leases, 1);
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_source_lease_release(&lease);
    check_true("lease.cleared", lease.active == 0 && lease.registry == NULL);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("lease.snapshot-idle", snapshot->active_source_leases, 0);
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_registry_source_lease_release(&lease);

    check_not_int("lease.stale", kzt_guest_registry_source_lease_acquire(
                      registry, observation.link_map_addr, generation + 1,
                      0, &lease), 0);
    check_true("lease.stale-cleared", lease.active == 0);
    check_not_int("lease.namespace-mismatch",
                  kzt_guest_registry_source_lease_acquire(
                      registry, observation.link_map_addr, generation, 1,
                      &lease), 0);
    check_true("lease.namespace-mismatch-cleared", lease.active == 0);
    check_int("lease.unknown-namespace-observe", kzt_guest_registry_observe(
                  registry, &unknown_namespace), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, unknown_namespace.link_map_addr);
    generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_not_int("lease.unknown-namespace",
                  kzt_guest_registry_source_lease_acquire(
                      registry, unknown_namespace.link_map_addr, generation,
                      0, &lease), 0);
    check_true("lease.unknown-namespace-cleared", lease.active == 0);
    kzt_guest_registry_destroy(&registry);
}

typedef struct retire_wait_fixture {
    pthread_mutex_t lock;
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    unsigned long generation;
    int called;
    int done;
    int result;
} retire_wait_fixture_t;

typedef struct registry_hook_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int before_wait_count;
    int api_entered;
    int release_api;
    int destroy_disabled;
} registry_hook_sync_t;

static void before_retire_wait_hook(void *opaque)
{
    registry_hook_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    ++sync->before_wait_count;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static void after_api_enter_hook(void *opaque)
{
    registry_hook_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    sync->api_entered = 1;
    pthread_cond_broadcast(&sync->cond);
    while (!sync->release_api) {
        pthread_cond_wait(&sync->cond, &sync->lock);
    }
    pthread_mutex_unlock(&sync->lock);
}

static void after_destroy_disable_hook(void *opaque)
{
    registry_hook_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    sync->destroy_disabled = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static int registry_hook_sync_init(registry_hook_sync_t *sync)
{
    memset(sync, 0, sizeof(*sync));
    if (pthread_mutex_init(&sync->lock, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&sync->cond, NULL) != 0) {
        pthread_mutex_destroy(&sync->lock);
        return -1;
    }
    return 0;
}

static void registry_hook_sync_destroy(registry_hook_sync_t *sync)
{
    pthread_cond_destroy(&sync->cond);
    pthread_mutex_destroy(&sync->lock);
}

static void *retire_wait_worker(void *opaque)
{
    retire_wait_fixture_t *fixture = opaque;
    int result;

    pthread_mutex_lock(&fixture->lock);
    fixture->called = 1;
    pthread_mutex_unlock(&fixture->lock);
    result = kzt_guest_registry_retire(
        fixture->registry, fixture->link_map_addr, fixture->generation);
    pthread_mutex_lock(&fixture->lock);
    fixture->result = result;
    fixture->done = 1;
    pthread_mutex_unlock(&fixture->lock);
    return NULL;
}

static void test_retire_waits_for_source_lease(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6900);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_source_lease_t lease = { 0 };
    retire_wait_fixture_t fixture;
    pthread_t thread;
    struct timespec start;
    int done = 0;
    int thread_created;

    check_true("retire-wait.registry", registry != NULL);
    if (!registry) {
        return;
    }
    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_int("retire-wait.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    memset(&fixture, 0, sizeof(fixture));
    fixture.registry = registry;
    fixture.link_map_addr = observation.link_map_addr;
    fixture.generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("retire-wait.lock", pthread_mutex_init(&fixture.lock, NULL), 0);
    check_int("retire-wait.acquire", kzt_guest_registry_source_lease_acquire(
                  registry, fixture.link_map_addr, fixture.generation,
                  0, &lease), 0);
    thread_created = pthread_create(
        &thread, NULL, retire_wait_worker, &fixture);
    check_int("retire-wait.thread", thread_created, 0);
    if (thread_created != 0) {
        kzt_guest_registry_source_lease_release(&lease);
        pthread_mutex_destroy(&fixture.lock);
        kzt_guest_registry_destroy(&registry);
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;

        pthread_mutex_lock(&fixture.lock);
        done = fixture.done;
        pthread_mutex_unlock(&fixture.lock);
        snapshot = NULL;
        if (kzt_guest_registry_find_by_link_map(
                registry, fixture.link_map_addr, &snapshot) != 0) {
            kzt_guest_object_snapshot_free(snapshot);
            break;
        }
        kzt_guest_object_snapshot_free(snapshot);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (done || now.tv_sec - start.tv_sec >= 2) {
            break;
        }
        sched_yield();
    }
    pthread_mutex_lock(&fixture.lock);
    done = fixture.done;
    pthread_mutex_unlock(&fixture.lock);
    check_true("retire-wait.blocked", done == 0);

    kzt_guest_registry_source_lease_release(&lease);
    check_int("retire-wait.join", pthread_join(thread, NULL), 0);
    check_true("retire-wait.done", fixture.done == 1);
    check_int("retire-wait.result", fixture.result, 0);
    check_not_int("retire-wait.dead", kzt_guest_registry_find_by_link_map(
                      registry, fixture.link_map_addr, &snapshot), 0);
    check_true("retire-wait.no-snapshot", snapshot == NULL);
    pthread_mutex_destroy(&fixture.lock);
    kzt_guest_registry_destroy(&registry);
}

static void test_double_retire_cannot_kill_reused_generation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6a00);
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_guest_object_snapshot_t *snapshot;
    retire_wait_fixture_t retire = { 0 };
    registry_hook_sync_t sync;
    pthread_t thread;
    unsigned long old_generation;
    unsigned long new_generation;

    check_true("double-retire.registry", registry != NULL);
    if (!registry || registry_hook_sync_init(&sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_int("double-retire.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    old_generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("double-retire.lease", kzt_guest_registry_source_lease_acquire(
                  registry, observation.link_map_addr, old_generation,
                  0, &lease), 0);
    kzt_guest_registry_test_set_before_retire_wait(
        before_retire_wait_hook, &sync);
    retire.registry = registry;
    retire.link_map_addr = observation.link_map_addr;
    retire.generation = old_generation;
    check_int("double-retire.lock", pthread_mutex_init(
                  &retire.lock, NULL), 0);
    check_int("double-retire.thread", pthread_create(
                  &thread, NULL, retire_wait_worker, &retire), 0);
    pthread_mutex_lock(&sync.lock);
    while (sync.before_wait_count < 1) {
        pthread_cond_wait(&sync.cond, &sync.lock);
    }
    pthread_mutex_unlock(&sync.lock);

    check_not_int("double-retire.second-rejected",
                  kzt_guest_registry_retire(
                      registry, observation.link_map_addr, old_generation),
                  0);
    kzt_guest_registry_source_lease_release(&lease);
    check_int("double-retire.join", pthread_join(thread, NULL), 0);
    check_int("double-retire.first-success", retire.result, 0);
    check_int("double-retire.reobserve", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    new_generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_true("double-retire.new-generation",
               new_generation > old_generation);
    check_not_int("double-retire.old-generation-rejected",
                  kzt_guest_registry_retire(
                      registry, observation.link_map_addr, old_generation),
                  0);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_true("double-retire.reused-live", snapshot != NULL &&
               snapshot->generation == new_generation);
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    pthread_mutex_destroy(&retire.lock);
    registry_hook_sync_destroy(&sync);
    kzt_guest_registry_destroy(&registry);
}

typedef struct simultaneous_retire_fixture {
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    unsigned long generation;
    pthread_barrier_t *barrier;
    int result;
} simultaneous_retire_fixture_t;

static void *simultaneous_retire_worker(void *opaque)
{
    simultaneous_retire_fixture_t *fixture = opaque;

    pthread_barrier_wait(fixture->barrier);
    fixture->result = kzt_guest_registry_retire(
        fixture->registry, fixture->link_map_addr, fixture->generation);
    return NULL;
}

static void test_simultaneous_retire_has_one_owner(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6a80);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_dump_t dump = { 0 };
    simultaneous_retire_fixture_t fixtures[2];
    pthread_barrier_t barrier;
    pthread_t threads[2];
    unsigned long generation;
    int successes = 0;
    int rejections = 0;

    check_true("one-retire.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("one-retire.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("one-retire.barrier", pthread_barrier_init(
                  &barrier, NULL, 3), 0);
    for (int i = 0; i < 2; ++i) {
        fixtures[i] = (simultaneous_retire_fixture_t) {
            .registry = registry,
            .link_map_addr = observation.link_map_addr,
            .generation = generation,
            .barrier = &barrier,
            .result = -2,
        };
        check_int("one-retire.thread", pthread_create(
                      &threads[i], NULL, simultaneous_retire_worker,
                      &fixtures[i]), 0);
    }
    pthread_barrier_wait(&barrier);
    for (int i = 0; i < 2; ++i) {
        check_int("one-retire.join", pthread_join(threads[i], NULL), 0);
        successes += fixtures[i].result == 0;
        rejections += fixtures[i].result != 0;
    }
    check_int("one-retire.exactly-one-success", successes, 1);
    check_int("one-retire.exactly-one-rejection", rejections, 1);
    check_int("one-retire.dump", kzt_guest_registry_dump_snapshot(
                  registry, &dump), 0);
    check_ulong("one-retire.single-object", dump.count, 1);
    if (dump.count == 1) {
        check_ulong("one-retire.same-generation",
                    dump.objects[0].generation, generation);
        check_int("one-retire.final-dead", dump.objects[0].state,
                  KZT_GUEST_OBJECT_DEAD);
    }
    kzt_guest_registry_dump_free(&dump);
    pthread_barrier_destroy(&barrier);
    kzt_guest_registry_destroy(&registry);
}

typedef struct registry_observe_worker {
    kzt_guest_registry_t *registry;
    kzt_guest_object_observation_t observation;
    kzt_guest_registry_result_t result;
} registry_observe_worker_t;

typedef struct registry_destroy_worker {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    kzt_guest_registry_t *registry;
    int called;
    int done;
} registry_destroy_worker_t;

static void *registry_observe_worker_main(void *opaque)
{
    registry_observe_worker_t *worker = opaque;

    worker->result = kzt_guest_registry_observe(
        worker->registry, &worker->observation);
    return NULL;
}

static void *registry_destroy_worker_main(void *opaque)
{
    registry_destroy_worker_t *worker = opaque;

    pthread_mutex_lock(&worker->lock);
    worker->called = 1;
    pthread_cond_broadcast(&worker->cond);
    pthread_mutex_unlock(&worker->lock);
    kzt_guest_registry_destroy(&worker->registry);
    pthread_mutex_lock(&worker->lock);
    worker->done = 1;
    pthread_cond_broadcast(&worker->cond);
    pthread_mutex_unlock(&worker->lock);
    return NULL;
}

static void test_destroy_drains_waiter_and_inflight_api(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6b00);
    kzt_guest_registry_source_lease_t lease = { 0 };
    kzt_guest_object_snapshot_t *snapshot;
    retire_wait_fixture_t retire = { 0 };
    registry_observe_worker_t observe_worker;
    registry_destroy_worker_t destroy_worker;
    registry_hook_sync_t sync;
    pthread_t retire_thread;
    pthread_t observe_thread;
    pthread_t destroy_thread;

    check_true("destroy-race.registry", registry != NULL);
    if (!registry || registry_hook_sync_init(&sync) != 0) {
        kzt_guest_registry_destroy(&registry);
        return;
    }
    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_int("destroy-race.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    retire.registry = registry;
    retire.link_map_addr = observation.link_map_addr;
    retire.generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("destroy-race.retire-lock", pthread_mutex_init(
                  &retire.lock, NULL), 0);
    check_int("destroy-race.lease", kzt_guest_registry_source_lease_acquire(
                  registry, retire.link_map_addr, retire.generation,
                  0, &lease), 0);
    kzt_guest_registry_test_set_before_retire_wait(
        before_retire_wait_hook, &sync);
    check_int("destroy-race.retire-thread", pthread_create(
                  &retire_thread, NULL, retire_wait_worker, &retire), 0);
    pthread_mutex_lock(&sync.lock);
    while (sync.before_wait_count < 1) {
        pthread_cond_wait(&sync.cond, &sync.lock);
    }
    pthread_mutex_unlock(&sync.lock);

    observe_worker = (registry_observe_worker_t) {
        .registry = registry,
        .observation = make_observation(0x6c00),
    };
    kzt_guest_registry_test_set_after_api_enter(after_api_enter_hook, &sync);
    check_int("destroy-race.observe-thread", pthread_create(
                  &observe_thread, NULL, registry_observe_worker_main,
                  &observe_worker), 0);
    pthread_mutex_lock(&sync.lock);
    while (!sync.api_entered) {
        pthread_cond_wait(&sync.cond, &sync.lock);
    }
    pthread_mutex_unlock(&sync.lock);

    memset(&destroy_worker, 0, sizeof(destroy_worker));
    destroy_worker.registry = registry;
    check_int("destroy-race.destroy-lock", pthread_mutex_init(
                  &destroy_worker.lock, NULL), 0);
    check_int("destroy-race.destroy-cond", pthread_cond_init(
                  &destroy_worker.cond, NULL), 0);
    kzt_guest_registry_test_set_after_destroy_disable(
        after_destroy_disable_hook, &sync);
    check_int("destroy-race.destroy-thread", pthread_create(
                  &destroy_thread, NULL, registry_destroy_worker_main,
                  &destroy_worker), 0);
    pthread_mutex_lock(&destroy_worker.lock);
    while (!destroy_worker.called) {
        pthread_cond_wait(&destroy_worker.cond, &destroy_worker.lock);
    }
    check_true("destroy-race.blocked", destroy_worker.done == 0);
    pthread_mutex_unlock(&destroy_worker.lock);
    pthread_mutex_lock(&sync.lock);
    while (!sync.destroy_disabled) {
        pthread_cond_wait(&sync.cond, &sync.lock);
    }
    pthread_mutex_unlock(&sync.lock);

    pthread_mutex_lock(&sync.lock);
    sync.release_api = 1;
    pthread_cond_broadcast(&sync.cond);
    pthread_mutex_unlock(&sync.lock);
    check_int("destroy-race.observe-join", pthread_join(
                  observe_thread, NULL), 0);
    check_int("destroy-race.observe-disabled", observe_worker.result,
              KZT_GUEST_REGISTRY_DISABLED);
    kzt_guest_registry_source_lease_release(&lease);
    check_int("destroy-race.retire-join", pthread_join(
                  retire_thread, NULL), 0);
    check_not_int("destroy-race.retire-cancelled", retire.result, 0);
    check_int("destroy-race.destroy-join", pthread_join(
                  destroy_thread, NULL), 0);
    check_true("destroy-race.destroyed", destroy_worker.done == 1 &&
               destroy_worker.registry == NULL);

    kzt_guest_registry_test_set_after_api_enter(NULL, NULL);
    kzt_guest_registry_test_set_before_retire_wait(NULL, NULL);
    kzt_guest_registry_test_set_after_destroy_disable(NULL, NULL);
    pthread_cond_destroy(&destroy_worker.cond);
    pthread_mutex_destroy(&destroy_worker.lock);
    pthread_mutex_destroy(&retire.lock);
    registry_hook_sync_destroy(&sync);
    registry = NULL;
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

static void test_retired_address_gets_new_generation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7100);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_dump_t dump = { 0 };
    check_int("reuse.first", kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    unsigned long first_generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("reuse.retire", kzt_guest_registry_retire(
                  registry, observation.link_map_addr, first_generation), 0);
    check_int("reuse.dead.filtered", kzt_guest_registry_find_by_link_map(
                  registry, observation.link_map_addr, &snapshot), -1);
    check_true("reuse.dead.no-snapshot", snapshot == NULL);
    check_int("reuse.dead.dump", kzt_guest_registry_dump_snapshot(
                  registry, &dump), 0);
    check_ulong("reuse.dead.dump-count", dump.count, 1);
    check_int("reuse.dead.diagnostic-state", dump.objects[0].state,
              KZT_GUEST_OBJECT_DEAD);
    kzt_guest_registry_dump_free(&dump);
    check_int("reuse.observe", kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("reuse.new-generation", snapshot->generation,
                first_generation + 1);
    check_int("reuse.live-state", snapshot->state,
              KZT_GUEST_OBJECT_DISCOVERED);
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_registry_destroy(&registry);
}

static void test_lazy_resolver_publish_find_lifecycle(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7200);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_lazy_resolver_t resolver = {
        .link_map_slot = 0x7210,
        .resolver_slot = 0x7218,
        .guest_link_map = 0x7200,
        .guest_resolver = 0x7300,
    };
    kzt_guest_lazy_resolver_t found;
    kzt_guest_registry_lazy_source_t source;
    unsigned long generation;

    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_int("lazy.observe", kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);

    check_int("lazy.publish-pair", kzt_guest_registry_publish_lazy_resolver(
                  registry, observation.link_map_addr, generation, 0,
                  &resolver), 0);
    check_int("lazy.find-pair", kzt_guest_registry_find_lazy_resolver(
                  registry, observation.link_map_addr, generation, 0,
                  &found), 0);
    check_uintptr("lazy.find-link-map", found.guest_link_map,
                  resolver.guest_link_map);
    check_uintptr("lazy.find-resolver", found.guest_resolver,
                  resolver.guest_resolver);
    memset(&source, 0xa5, sizeof(source));
    kzt_guest_registry_test_set_alloc_failure_after(0);
    check_int("lazy.find-source-no-allocation",
              kzt_guest_registry_find_lazy_source(
                  registry, observation.link_map_addr, &source), 0);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_ulong("lazy.find-source-generation", source.generation, generation);
    check_uintptr("lazy.find-source-namespace", source.namespace_id, 0);
    check_uintptr("lazy.find-source-resolver", source.guest_resolver,
                  resolver.guest_resolver);

    resolver.guest_link_map = 0x7201;
    check_not_int("lazy.reject-link-map-mismatch",
                  kzt_guest_registry_publish_lazy_resolver(
                      registry, observation.link_map_addr, generation, 0,
                      &resolver), 0);
    resolver.guest_link_map = observation.link_map_addr;
    check_not_int("lazy.reject-generation",
                  kzt_guest_registry_find_lazy_resolver(
                      registry, observation.link_map_addr, generation + 1, 0,
                      &found), 0);
    check_not_int("lazy.reject-non-main-publish",
                  kzt_guest_registry_publish_lazy_resolver(
                      registry, observation.link_map_addr, generation, 1,
                      &resolver), 0);
    check_not_int("lazy.reject-non-main-find",
                  kzt_guest_registry_find_lazy_resolver(
                      registry, observation.link_map_addr, generation, 1,
                      &found), 0);
    check_int("lazy.retire", kzt_guest_registry_retire(
                  registry, observation.link_map_addr, generation), 0);
    check_not_int("lazy.retired-invalid",
                  kzt_guest_registry_find_lazy_resolver(
                      registry, observation.link_map_addr, generation, 0,
                      &found), 0);
    memset(&source, 0xa5, sizeof(source));
    check_not_int("lazy.retired-source-invalid",
                  kzt_guest_registry_find_lazy_source(
                      registry, observation.link_map_addr, &source), 0);
    check_ulong("lazy.retired-source-zero-generation", source.generation, 0);
    check_uintptr("lazy.retired-source-zero-namespace", source.namespace_id, 0);
    check_uintptr("lazy.retired-source-zero-resolver", source.guest_resolver, 0);
    kzt_guest_registry_destroy(&registry);
}

static void test_map_range_supplement_is_exact_and_allocation_free(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7300);
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_observation_diagnostic_t diagnostic = { 0 };
    unsigned long generation;

    check_true("range.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("range.observe",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_test_set_alloc_failure_after(0);
    check_int("range.supplement-no-allocation",
              kzt_guest_registry_supplement_map_range(
                  registry, observation.link_map_addr, generation,
                  0x100000, 0x120000, &diagnostic),
              KZT_GUEST_REGISTRY_UPDATED);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_ulong("range.diagnostic-generation", diagnostic.generation,
                generation);

    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("range.generation-stable", snapshot->generation, generation);
    check_int("range.start-status", snapshot->map_start.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("range.start", snapshot->map_start.value, 0x100000);
    check_int("range.end-status", snapshot->map_end.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("range.end", snapshot->map_end.value, 0x120000);
    kzt_guest_object_snapshot_free(snapshot);

    check_int("range.repeat",
              kzt_guest_registry_supplement_map_range(
                  registry, observation.link_map_addr, generation,
                  0x100000, 0x120000, NULL),
              KZT_GUEST_REGISTRY_UNCHANGED);
    check_int("range.conflict",
              kzt_guest_registry_supplement_map_range(
                  registry, observation.link_map_addr, generation,
                  0x101000, 0x120000, NULL),
              KZT_GUEST_REGISTRY_CONFLICT);
    check_int("range.stale-generation",
              kzt_guest_registry_supplement_map_range(
                  registry, observation.link_map_addr, generation + 1,
                  0x100000, 0x120000, NULL),
              KZT_GUEST_REGISTRY_CONFLICT);
    check_int("range.retire", kzt_guest_registry_retire(
                  registry, observation.link_map_addr, generation), 0);
    check_int("range.dead-generation",
              kzt_guest_registry_supplement_map_range(
                  registry, observation.link_map_addr, generation,
                  0x100000, 0x120000, NULL),
              KZT_GUEST_REGISTRY_CONFLICT);
    kzt_guest_registry_destroy(&registry);
}

static void test_loader_handle_binds_exact_link_map_generation_and_namespace(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7400);
    kzt_guest_loader_identity_t published = { 0 };
    kzt_guest_loader_identity_t found = { 0 };
    kzt_guest_object_snapshot_t *snapshot;

    check_true("loader-identity.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("loader-identity.observe",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("loader-identity.publish",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9100, observation.link_map_addr, 7,
                  &published),
              0);
    check_uintptr("loader-identity.published-handle", published.handle,
                  0x9100);
    check_uintptr("loader-identity.published-link-map",
                  published.link_map_addr, observation.link_map_addr);
    check_ulong("loader-identity.published-generation",
                published.generation, 1);
    check_uintptr("loader-identity.published-namespace",
                  published.namespace_id, 7);
    check_true("loader-identity.handle-generation",
               published.handle_generation != 0);
    check_int("loader-identity.mark-resident",
              kzt_guest_registry_mark_loader_resident(
                  registry, &published),
              0);

    check_int("loader-identity.find",
              kzt_guest_registry_find_loader_identity(
                  registry, 0x9100, &found),
              0);
    check_uintptr("loader-identity.found-link-map", found.link_map_addr,
                  observation.link_map_addr);
    check_ulong("loader-identity.found-generation", found.generation, 1);
    check_uintptr("loader-identity.found-namespace", found.namespace_id, 7);

    check_int("loader-identity.reuse-live-handle",
              kzt_guest_registry_reuse_loader_identity(
                  registry, 0x9100, &published),
              0);
    check_int("loader-identity.first-close-keeps-reference",
              kzt_guest_registry_complete_loader_close(
                  registry, &published),
              KZT_GUEST_LOADER_CLOSE_REFERENCED);
    check_int("loader-identity.still-findable",
              kzt_guest_registry_find_loader_identity(
                  registry, 0x9100, &found),
              0);
    check_int("loader-identity.last-close-unproven",
              kzt_guest_registry_complete_loader_close(
                  registry, &published),
              KZT_GUEST_LOADER_CLOSE_UNLOAD_UNPROVEN);
    check_not_int("loader-identity.closed-handle-not-findable",
                  kzt_guest_registry_find_loader_identity(
                      registry, 0x9100, &found),
                  0);
    check_int("loader-identity.exact-resident-handle-rebound",
              kzt_guest_registry_reuse_loader_identity(
                  registry, 0x9100, &found),
              0);
    check_true("loader-identity.rebind-new-handle-generation",
               found.handle_generation != published.handle_generation);
    check_int("loader-identity.old-close-cannot-touch-rebind",
              kzt_guest_registry_complete_loader_close(
                  registry, &published),
              KZT_GUEST_LOADER_CLOSE_STALE);
    check_int("loader-identity.rebind-remains-findable",
              kzt_guest_registry_find_loader_identity(
                  registry, 0x9100, &found),
              0);
    check_int("loader-identity.rebind-close-unproven",
              kzt_guest_registry_complete_loader_close(registry, &found),
              KZT_GUEST_LOADER_CLOSE_UNLOAD_UNPROVEN);

    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_int("loader-identity.namespace-status",
              snapshot->namespace_id.status, KZT_GUEST_FIELD_OK);
    check_uintptr("loader-identity.namespace-value",
                  snapshot->namespace_id.value, 7);
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_registry_destroy(&registry);
}

static void test_unproven_unload_is_not_reused_without_resident_proof(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7440);
    kzt_guest_loader_identity_t identity = { 0 };
    kzt_guest_loader_identity_t reused = { 0 };

    check_true("loader-unproven.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("loader-unproven.observe",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("loader-unproven.publish",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9140, observation.link_map_addr, 7,
                  &identity),
              0);
    check_int("loader-unproven.close",
              kzt_guest_registry_complete_loader_close(
                  registry, &identity),
              KZT_GUEST_LOADER_CLOSE_UNLOAD_UNPROVEN);
    check_not_int("loader-unproven.reuse-rejected",
                  kzt_guest_registry_reuse_loader_identity(
                      registry, 0x9140, &reused),
                  0);
    kzt_guest_registry_destroy(&registry);
}

static void test_loader_symbol_source_is_exact_main_generation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t main_object = make_observation(0x7480);
    kzt_guest_object_observation_t other_object = make_observation(0x7490);
    kzt_guest_loader_identity_t published = { 0 };
    kzt_guest_loader_identity_t source = { 0 };
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = 0x101000,
        .load_bias = 0x100000,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
    };
    kzt_guest_dynamic_view_t found_view = { 0 };
    kzt_guest_field_status_t dynamic_status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long dynamic_revision = 0;
    kzt_guest_registry_source_lease_t lease = { 0 };

    other_object.load_bias.value += 0x200000;
    other_object.dynamic_addr.value += 0x200000;
    check_true("symbol-source.registry", registry != NULL);
    if (!registry) return;
    check_int("symbol-source.observe-main",
              kzt_guest_registry_observe(registry, &main_object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("symbol-source.publish-main",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9180, main_object.link_map_addr, 0, &published),
              0);
    check_int("symbol-source.dynamic-main",
              kzt_guest_registry_commit_dynamic_view(
                  registry, main_object.link_map_addr, published.generation,
                  &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("symbol-source.acquire-main",
              kzt_guest_registry_loader_symbol_source_acquire(
                  registry, 0x9180, &source, &found_view, &dynamic_status,
                  &dynamic_revision, &lease),
              0);
    check_uintptr("symbol-source.link-map", source.link_map_addr,
                  main_object.link_map_addr);
    check_ulong("symbol-source.generation", source.generation,
                published.generation);
    check_uintptr("symbol-source.namespace", source.namespace_id, 0);
    check_int("symbol-source.dynamic-status", dynamic_status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("symbol-source.dynamic-address", found_view.dynamic_addr,
                  view.dynamic_addr);
    check_ulong("symbol-source.dynamic-revision", dynamic_revision, 1);
    check_true("symbol-source.lease", lease.active);
    kzt_guest_registry_source_lease_release(&lease);

    source = (kzt_guest_loader_identity_t) { 0 };
    {
        const kzt_guest_loader_identity_t queried = {
            .handle = 0x91f0,
            .link_map_addr = main_object.link_map_addr,
            .namespace_id = 0,
        };

        check_int("symbol-source.exact-dlinfo-acquire",
                  kzt_guest_registry_loader_symbol_source_acquire_exact(
                      registry, &queried, &source, &found_view,
                      &dynamic_status, &dynamic_revision, &lease),
                  0);
        check_uintptr("symbol-source.exact-handle", source.handle,
                      queried.handle);
        check_uintptr("symbol-source.exact-link-map", source.link_map_addr,
                      queried.link_map_addr);
        check_ulong("symbol-source.exact-generation", source.generation,
                    published.generation);
        check_true("symbol-source.exact-lease", lease.active);
        kzt_guest_registry_source_lease_release(&lease);
    }
    {
        const kzt_guest_loader_identity_t wrong_namespace = {
            .handle = 0x91f0,
            .link_map_addr = main_object.link_map_addr,
            .namespace_id = 7,
        };

        check_not_int("symbol-source.exact-non-main-rejected",
                      kzt_guest_registry_loader_symbol_source_acquire_exact(
                          registry, &wrong_namespace, &source, &found_view,
                          &dynamic_status, &dynamic_revision, &lease),
                      0);
        check_true("symbol-source.exact-non-main-no-lease", !lease.active);
    }

    view.strsz.present = 1;
    view.strsz.value = 0x80;
    view.strsz.address_semantics = KZT_GUEST_DYNAMIC_SCALAR;
    check_int("symbol-source.dynamic-main-update",
              kzt_guest_registry_commit_dynamic_view(
                  registry, main_object.link_map_addr, published.generation,
                  &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("symbol-source.acquire-main-update",
              kzt_guest_registry_loader_symbol_source_acquire(
                  registry, 0x9180, &source, &found_view, &dynamic_status,
                  &dynamic_revision, &lease),
              0);
    check_ulong("symbol-source.dynamic-revision-update",
                dynamic_revision, 2);
    kzt_guest_registry_source_lease_release(&lease);

    check_int("symbol-source.observe-other",
              kzt_guest_registry_observe(registry, &other_object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("symbol-source.publish-other",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9190, other_object.link_map_addr, 7, &published),
              0);
    view.dynamic_addr = other_object.dynamic_addr.value;
    view.load_bias = other_object.load_bias.value;
    check_int("symbol-source.dynamic-other",
              kzt_guest_registry_commit_dynamic_view(
                  registry, other_object.link_map_addr, published.generation,
                  &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_not_int("symbol-source.non-main-rejected",
                  kzt_guest_registry_loader_symbol_source_acquire(
                      registry, 0x9190, &source, &found_view, &dynamic_status,
                      &dynamic_revision, &lease),
                  0);
    check_true("symbol-source.non-main-no-lease", !lease.active);

    check_int("symbol-source.retire-main",
              kzt_guest_registry_retire(
                  registry, main_object.link_map_addr, 1),
              0);
    check_not_int("symbol-source.retired-rejected",
                  kzt_guest_registry_loader_symbol_source_acquire(
                      registry, 0x9180, &source, &found_view, &dynamic_status,
                      &dynamic_revision, &lease),
                  0);
    check_true("symbol-source.retired-no-lease", !lease.active);
    {
        const kzt_guest_loader_identity_t retired = {
            .handle = 0x91f0,
            .link_map_addr = main_object.link_map_addr,
            .namespace_id = 0,
        };

        check_not_int("symbol-source.exact-retired-rejected",
                      kzt_guest_registry_loader_symbol_source_acquire_exact(
                          registry, &retired, &source, &found_view,
                          &dynamic_status, &dynamic_revision, &lease),
                      0);
        check_true("symbol-source.exact-retired-no-lease", !lease.active);
    }
    kzt_guest_registry_destroy(&registry);
}

static void test_source_lease_counter_overflow_is_rejected(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = make_observation(0x74a0);
    kzt_guest_loader_identity_t published = { 0 };
    kzt_guest_loader_identity_t identity = { 0 };
    const kzt_guest_loader_identity_t queried = {
        .handle = 0x91a0,
        .link_map_addr = 0x74a0,
        .namespace_id = 0,
    };
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = 0x101000,
        .load_bias = 0x100000,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
    };
    kzt_guest_dynamic_view_t found_view = { 0 };
    kzt_guest_field_status_t dynamic_status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long dynamic_revision = 0;
    kzt_guest_registry_source_lease_t anchor = { 0 };
    kzt_guest_registry_source_lease_t rejected = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };
    kzt_guest_registry_symbol_candidate_t candidate = { 0 };
    size_t cursor = 0;

    check_true("lease-overflow.registry", registry != NULL);
    if (!registry) return;
    check_int("lease-overflow.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("lease-overflow.publish-handle",
              kzt_guest_registry_publish_loader_identity(
                  registry, queried.handle, object.link_map_addr, 0,
                  &published),
              0);
    check_int("lease-overflow.dynamic",
              kzt_guest_registry_commit_dynamic_view(
                  registry, object.link_map_addr, published.generation,
                  &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("lease-overflow.anchor",
              kzt_guest_registry_source_lease_acquire(
                  registry, object.link_map_addr, published.generation, 0,
                  &anchor),
              0);
    check_int("lease-overflow.decision",
              kzt_guest_registry_patch_decision_lease_acquire(
                  &anchor, &decision),
              0);
    check_int("lease-overflow.force-max",
              kzt_guest_registry_test_set_active_source_leases(
                  registry, object.link_map_addr, published.generation,
                  ULONG_MAX),
              0);

    check_not_int("lease-overflow.direct-rejected",
                  kzt_guest_registry_source_lease_acquire(
                      registry, object.link_map_addr, published.generation,
                      0, &rejected),
                  0);
    check_true("lease-overflow.direct-cleared", !rejected.active);
    check_not_int("lease-overflow.handle-rejected",
                  kzt_guest_registry_loader_symbol_source_acquire(
                      registry, queried.handle, &identity, &found_view,
                      &dynamic_status, &dynamic_revision, &rejected),
                  0);
    check_true("lease-overflow.handle-cleared", !rejected.active);
    check_not_int("lease-overflow.exact-rejected",
                  kzt_guest_registry_loader_symbol_source_acquire_exact(
                      registry, &queried, &identity, &found_view,
                      &dynamic_status, &dynamic_revision, &rejected),
                  0);
    check_true("lease-overflow.exact-cleared", !rejected.active);
    check_not_int("lease-overflow.candidate-rejected",
                  kzt_guest_registry_symbol_candidate_acquire_next(
                      &decision, &cursor, &candidate),
                  1);
    check_true("lease-overflow.candidate-cleared",
               !candidate.lease.active);

    check_int("lease-overflow.restore-anchor",
              kzt_guest_registry_test_set_active_source_leases(
                  registry, object.link_map_addr, published.generation, 1),
              0);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    kzt_guest_registry_source_lease_release(&anchor);
    kzt_guest_registry_destroy(&registry);
}

static void test_loader_unload_retires_only_exact_namespace_and_generation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7500);
    kzt_guest_loader_identity_t old_identity = { 0 };
    kzt_guest_loader_identity_t new_identity = { 0 };
    kzt_guest_loader_identity_t wrong_identity;
    kzt_guest_object_snapshot_t *snapshot;

    check_true("loader-retire.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("loader-retire.observe-old",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("loader-retire.publish-old",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9200, observation.link_map_addr, 7,
                  &old_identity),
              0);

    wrong_identity = old_identity;
    wrong_identity.namespace_id = 8;
    check_not_int("loader-retire.reject-wrong-namespace",
                  kzt_guest_registry_retire_loader_identity(
                      registry, &wrong_identity),
                  0);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("loader-retire.wrong-namespace-generation-live",
                snapshot->generation, old_identity.generation);
    kzt_guest_object_snapshot_free(snapshot);

    check_int("loader-retire.exact-old",
              kzt_guest_registry_retire_loader_identity(
                  registry, &old_identity),
              0);
    observation.load_bias.value += 0x100000;
    observation.dynamic_addr.value += 0x100000;
    observation.path.value = "/guest/libreopened.so";
    observation.namespace_id.status = KZT_GUEST_FIELD_UNKNOWN;
    check_int("loader-retire.observe-reopen",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("loader-retire.publish-reopen",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9200, observation.link_map_addr, 9,
                  &new_identity),
              0);
    check_true("loader-retire.new-generation",
               new_identity.generation != old_identity.generation);
    check_not_int("loader-retire.reject-old-generation",
                  kzt_guest_registry_retire_loader_identity(
                      registry, &old_identity),
                  0);
    snapshot = find_snapshot(registry, observation.link_map_addr);
    check_ulong("loader-retire.reopen-generation-live",
                snapshot->generation, new_identity.generation);
    check_uintptr("loader-retire.reopen-namespace-live",
                  snapshot->namespace_id.value, 9);
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_registry_destroy(&registry);
}

static void test_loader_unload_prepares_before_unmap_and_can_cancel(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7580);
    kzt_guest_loader_identity_t identity = { 0 };
    kzt_guest_loader_identity_t found = { 0 };
    kzt_guest_registry_address_match_t match = { 0 };

    check_true("loader-prepare.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("loader-prepare.observe",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("loader-prepare.publish",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9280, observation.link_map_addr, 7,
                  &identity),
              0);
    check_int("loader-prepare.begin",
              kzt_guest_registry_begin_loader_unload(registry, &identity),
              0);
    check_not_int("loader-prepare.blocks-live-lookup",
                  kzt_guest_registry_find_live_object(
                      registry, observation.link_map_addr, &match),
                  0);
    check_int("loader-prepare.identity-remains-resolvable",
              kzt_guest_registry_find_loader_object_identity(
                  registry, observation.link_map_addr, &found),
              0);
    check_ulong("loader-prepare.identity-generation", found.generation,
                identity.generation);
    check_int("loader-prepare.cancel",
              kzt_guest_registry_cancel_loader_unload(registry, &identity),
              0);
    check_int("loader-prepare.live-after-cancel",
              kzt_guest_registry_find_live_object(
                  registry, observation.link_map_addr, &match),
              0);
    check_int("loader-prepare.begin-again",
              kzt_guest_registry_begin_loader_unload(registry, &identity),
              0);
    check_int("loader-prepare.finish",
              kzt_guest_registry_finish_loader_unload(registry, &identity),
              0);
    check_not_int("loader-prepare.dead-after-finish",
                  kzt_guest_registry_find_loader_object_identity(
                      registry, observation.link_map_addr, &found),
                  0);
    kzt_guest_registry_destroy(&registry);
}

static void test_namespace_evidence_supplements_exact_dependency(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t root = make_observation(0x7590);
    kzt_guest_object_observation_t dependency = make_observation(0x75a0);
    kzt_guest_loader_identity_t root_identity = { 0 };
    kzt_guest_object_snapshot_t *snapshot;

    root.namespace_id.status = KZT_GUEST_FIELD_UNKNOWN;
    dependency.namespace_id.status = KZT_GUEST_FIELD_UNKNOWN;
    dependency.load_bias.value += 0x200000;
    dependency.dynamic_addr.value += 0x200000;
    dependency.path.value = "/guest/libnamespace-dependency.so";
    check_true("namespace-supplement.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("namespace-supplement.observe-root",
              kzt_guest_registry_observe(registry, &root),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("namespace-supplement.observe-dependency",
              kzt_guest_registry_observe(registry, &dependency),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("namespace-supplement.publish-root",
              kzt_guest_registry_publish_loader_identity(
                  registry, 0x9290, root.link_map_addr, 7,
                  &root_identity),
              0);
    check_int("namespace-supplement.dependency",
              kzt_guest_registry_supplement_namespace(
                  registry, dependency.link_map_addr, 2, 7),
              KZT_GUEST_REGISTRY_UPDATED);
    snapshot = find_snapshot(registry, dependency.link_map_addr);
    check_int("namespace-supplement.status", snapshot->namespace_id.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("namespace-supplement.value", snapshot->namespace_id.value,
                  7);
    kzt_guest_object_snapshot_free(snapshot);
    check_int("namespace-supplement.conflict",
              kzt_guest_registry_supplement_namespace(
                  registry, dependency.link_map_addr, 2, 8),
              KZT_GUEST_REGISTRY_CONFLICT);
    kzt_guest_registry_destroy(&registry);
}

static void test_address_match_overlong_path_is_unknown(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7600);
    kzt_guest_registry_address_match_t match = { 0 };
    char path[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT + 32];

    memset(path, 'x', sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    observation.path.value = path;
    observation.namespace_id = (kzt_guest_scalar_field_t) {
        .value = 0,
        .status = KZT_GUEST_FIELD_OK,
    };
    check_true("long-match.registry", registry != NULL);
    if (!registry) {
        return;
    }
    check_int("long-match.observe",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("long-match.find-live",
              kzt_guest_registry_find_live_object(
                  registry, observation.link_map_addr, &match),
              0);
    check_int("long-match.path-status", match.path_status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_string("long-match.path-empty", match.path, "");
    kzt_guest_registry_destroy(&registry);
}

static void test_symbol_candidate_iteration_is_leased_and_compact(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t source = make_observation(0x7700);
    kzt_guest_object_observation_t owner = make_observation(0x7710);
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = 0x201000,
        .load_bias = 0x200000,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
    };
    kzt_guest_object_snapshot_t *snapshot;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision_lease = { 0 };
    kzt_guest_registry_symbol_candidate_t candidate = { 0 };
    unsigned long source_generation;
    unsigned long owner_generation;
    size_t cursor = 0;
    int count = 0;

    owner.load_bias.value += 0x100000;
    owner.dynamic_addr.value += 0x100000;
    source.namespace_id.status = KZT_GUEST_FIELD_OK;
    owner.namespace_id.status = KZT_GUEST_FIELD_OK;
    owner.path.value = "/lib/x86_64-linux-gnu/libdl.so.2";
    owner.soname.value = "libdl.so.2";
    owner.soname.status = KZT_GUEST_FIELD_OK;
    check_true("symbol-candidate.registry", registry != NULL);
    if (!registry) return;
    check_int("symbol-candidate.observe-source",
              kzt_guest_registry_observe(registry, &source),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("symbol-candidate.observe-owner",
              kzt_guest_registry_observe(registry, &owner),
              KZT_GUEST_REGISTRY_ADDED);
    snapshot = find_snapshot(registry, source.link_map_addr);
    source_generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    snapshot = find_snapshot(registry, owner.link_map_addr);
    owner_generation = snapshot->generation;
    kzt_guest_object_snapshot_free(snapshot);
    check_int("symbol-candidate.dynamic-source",
              kzt_guest_registry_commit_dynamic_view(
                  registry, source.link_map_addr, source_generation, &view),
              KZT_GUEST_REGISTRY_UPDATED);
    view.dynamic_addr = owner.dynamic_addr.value;
    view.load_bias = owner.load_bias.value;
    check_int("symbol-candidate.dynamic-owner",
              kzt_guest_registry_commit_dynamic_view(
                  registry, owner.link_map_addr, owner_generation, &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("symbol-candidate.source-lease",
              kzt_guest_registry_source_lease_acquire(
                  registry, source.link_map_addr, source_generation, 0,
                  &source_lease),
              0);
    check_not_int("symbol-candidate.requires-decision",
                  kzt_guest_registry_symbol_candidate_acquire_next(
                      &decision_lease, &cursor, &candidate),
                  1);
    check_int("symbol-candidate.decision-lease",
              kzt_guest_registry_patch_decision_lease_acquire(
                  &source_lease, &decision_lease),
              0);
    kzt_guest_registry_test_set_alloc_failure_after(0);
    while (kzt_guest_registry_symbol_candidate_acquire_next(
               &decision_lease, &cursor, &candidate) == 1) {
        check_true("symbol-candidate.lease-active", candidate.lease.active);
        check_true("symbol-candidate.exact-identity",
                   candidate.link_map_addr == candidate.lease.link_map_addr &&
                   candidate.generation == candidate.lease.generation &&
                   candidate.namespace_id == candidate.lease.namespace_id);
        if (candidate.link_map_addr == owner.link_map_addr) {
            check_string("symbol-candidate.path", candidate.path,
                         owner.path.value);
            check_string("symbol-candidate.soname", candidate.soname,
                         owner.soname.value);
            check_ulong("symbol-candidate.owner-generation",
                        candidate.generation, owner_generation);
        }
        ++count;
        kzt_guest_registry_symbol_candidate_release(&candidate);
    }
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_int("symbol-candidate.count", count, 2);
    check_true("symbol-candidate.release-zero", !candidate.lease.active);
    kzt_guest_registry_patch_decision_lease_release(&decision_lease);
    kzt_guest_registry_source_lease_release(&source_lease);
    kzt_guest_registry_destroy(&registry);
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
    test_cond_init_failure_is_clean();
    test_source_lease_acquire_release();
    test_retire_waits_for_source_lease();
    test_double_retire_cannot_kill_reused_generation();
    test_simultaneous_retire_has_one_owner();
    test_destroy_drains_waiter_and_inflight_api();
    test_destroyed_registry_rejects_new_observation();
    test_retired_address_gets_new_generation();
    test_lazy_resolver_publish_find_lifecycle();
    test_map_range_supplement_is_exact_and_allocation_free();
    test_loader_handle_binds_exact_link_map_generation_and_namespace();
    test_unproven_unload_is_not_reused_without_resident_proof();
    test_loader_symbol_source_is_exact_main_generation();
    test_source_lease_counter_overflow_is_rejected();
    test_loader_unload_retires_only_exact_namespace_and_generation();
    test_loader_unload_prepares_before_unmap_and_can_cancel();
    test_namespace_evidence_supplements_exact_dependency();
    test_address_match_overlong_path_is_unknown();
    test_symbol_candidate_iteration_is_leased_and_compact();

    if (failures) {
        fprintf(stderr, "kzt-guest-registry: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-guest-registry: all contract tests passed");
    return 0;
}
