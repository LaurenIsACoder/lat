#ifndef KZT_GUEST_REGISTRY_H
#define KZT_GUEST_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_dynamic_view.h"

typedef struct kzt_guest_registry kzt_guest_registry_t;

typedef struct kzt_guest_registry_source_lease {
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    int active;
} kzt_guest_registry_source_lease_t;

typedef enum kzt_guest_object_state {
    KZT_GUEST_OBJECT_DISCOVERED = 0,
    KZT_GUEST_OBJECT_PARSED,
    KZT_GUEST_OBJECT_WRAPPER_READY,
    KZT_GUEST_OBJECT_PATCHED,
    KZT_GUEST_OBJECT_UNLOADING,
    KZT_GUEST_OBJECT_DEAD,
} kzt_guest_object_state_t;

typedef enum kzt_guest_field_status {
    KZT_GUEST_FIELD_OK = 0,
    KZT_GUEST_FIELD_UNKNOWN,
    KZT_GUEST_FIELD_READ_ERROR,
    KZT_GUEST_FIELD_TRUNCATED,
    KZT_GUEST_FIELD_NOT_PARSED,
} kzt_guest_field_status_t;

typedef enum kzt_guest_registry_result {
    KZT_GUEST_REGISTRY_ADDED = 0,
    KZT_GUEST_REGISTRY_UNCHANGED,
    KZT_GUEST_REGISTRY_UPDATED,
    KZT_GUEST_REGISTRY_CONFLICT,
    KZT_GUEST_REGISTRY_DISABLED,
    KZT_GUEST_REGISTRY_ERROR,
    KZT_GUEST_REGISTRY_RESULT_COUNT,
} kzt_guest_registry_result_t;

typedef struct kzt_guest_scalar_field {
    uintptr_t value;
    kzt_guest_field_status_t status;
} kzt_guest_scalar_field_t;

typedef struct kzt_guest_string_field {
    const char *value;
    kzt_guest_field_status_t status;
} kzt_guest_string_field_t;

typedef struct kzt_guest_lazy_resolver {
    uintptr_t link_map_slot;
    uintptr_t resolver_slot;
    uintptr_t guest_link_map;
    uintptr_t guest_resolver;
    int valid;
} kzt_guest_lazy_resolver_t;

typedef struct kzt_guest_object_observation {
    uintptr_t link_map_addr;
    kzt_guest_scalar_field_t load_bias;
    kzt_guest_scalar_field_t dynamic_addr;
    kzt_guest_scalar_field_t map_start;
    kzt_guest_scalar_field_t map_end;
    kzt_guest_scalar_field_t namespace_id;
    kzt_guest_string_field_t path;
    kzt_guest_string_field_t soname;
    kzt_guest_field_status_t dynamic_view_status;
} kzt_guest_object_observation_t;

typedef struct kzt_guest_object_snapshot {
    uintptr_t link_map_addr;
    kzt_guest_scalar_field_t load_bias;
    kzt_guest_scalar_field_t dynamic_addr;
    kzt_guest_scalar_field_t map_start;
    kzt_guest_scalar_field_t map_end;
    kzt_guest_scalar_field_t namespace_id;
    kzt_guest_string_field_t path;
    kzt_guest_string_field_t soname;
    kzt_guest_field_status_t dynamic_view_status;
    kzt_guest_dynamic_view_t dynamic_view;
    kzt_guest_lazy_resolver_t lazy_resolver;
    kzt_guest_object_state_t state;
    unsigned long generation;
    unsigned long active_source_leases;
} kzt_guest_object_snapshot_t;

typedef struct kzt_guest_registry_dump {
    kzt_guest_object_snapshot_t *objects;
    size_t count;
} kzt_guest_registry_dump_t;

typedef struct kzt_guest_registry_diagnostics {
    unsigned long observations;
    unsigned long added;
    unsigned long unchanged;
    unsigned long updated;
    unsigned long conflicts;
    unsigned long disabled;
    unsigned long errors;
    unsigned long init_failures;
    unsigned long allocation_failures;
} kzt_guest_registry_diagnostics_t;

typedef struct kzt_guest_registry_diagnostic_config {
    int enabled;
    unsigned long throttle_limit;
} kzt_guest_registry_diagnostic_config_t;

typedef struct kzt_guest_registry_observation_diagnostic {
    int enabled;
    int emitted;
    kzt_guest_registry_result_t result;
    uintptr_t link_map_addr;
    unsigned long generation;
    unsigned long object_count;
    unsigned long result_observations;
    unsigned long result_suppressed;
    kzt_guest_registry_diagnostics_t counters;
} kzt_guest_registry_observation_diagnostic_t;

typedef struct kzt_guest_registry_event_summary {
    kzt_guest_registry_result_t result;
    unsigned long observed;
    unsigned long emitted;
    unsigned long suppressed;
    uintptr_t last_link_map_addr;
    unsigned long last_generation;
} kzt_guest_registry_event_summary_t;

typedef struct kzt_guest_registry_diagnostic_report {
    kzt_guest_registry_diagnostic_config_t config;
    kzt_guest_registry_diagnostics_t counters;
    kzt_guest_registry_event_summary_t events[KZT_GUEST_REGISTRY_RESULT_COUNT];
    size_t event_count;
} kzt_guest_registry_diagnostic_report_t;

typedef int (*kzt_guest_registry_dump_sink_fn)(const char *line,
                                               void *opaque);

kzt_guest_registry_t *kzt_guest_registry_init(void);
/* The owner must stop starting new registry calls before destroy begins.
 * Calls that have entered the API, including cond waiters and active source
 * leases, are drained before the mutex/condition and registry storage die. */
void kzt_guest_registry_destroy(kzt_guest_registry_t **registry);

#ifdef KZT_GUEST_REGISTRY_TEST
typedef void (*kzt_guest_registry_test_hook_fn)(void *opaque);
void kzt_guest_registry_test_set_after_api_enter(
    kzt_guest_registry_test_hook_fn hook, void *opaque);
void kzt_guest_registry_test_set_before_retire_wait(
    kzt_guest_registry_test_hook_fn hook, void *opaque);
void kzt_guest_registry_test_set_after_retire_wake(
    kzt_guest_registry_test_hook_fn hook, void *opaque);
void kzt_guest_registry_test_set_after_destroy_disable(
    kzt_guest_registry_test_hook_fn hook, void *opaque);
#endif

kzt_guest_registry_result_t kzt_guest_registry_observe(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *observation);

kzt_guest_registry_result_t kzt_guest_registry_observe_with_diagnostic(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *observation,
    kzt_guest_registry_observation_diagnostic_t *diagnostic);

int kzt_guest_registry_find_by_link_map(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_object_snapshot_t **snapshot);

int kzt_guest_registry_retire(kzt_guest_registry_t *registry,
                              uintptr_t link_map_addr,
                              unsigned long generation);
/* Defensive handoff for a violated single-retire protocol: wait for the
 * already-started exact generation to become DEAD instead of allowing its
 * binding owner to return before source leases drain. */
int kzt_guest_registry_wait_retired(kzt_guest_registry_t *registry,
                                    uintptr_t link_map_addr,
                                    unsigned long generation);

/* Pin an exact live (link_map, generation, namespace) source across a writer
 * transaction.  Only the main namespace is currently supported.  Retire has
 * a single owner: it rejects an already UNLOADING/DEAD generation, then waits
 * for every active lease before completing DEAD.  The guest loader therefore
 * cannot unmap source slots while a lease is held.  Guest memory must never be
 * accessed while the registry mutex is held. */
int kzt_guest_registry_source_lease_acquire(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id,
    kzt_guest_registry_source_lease_t *lease);
void kzt_guest_registry_source_lease_release(
    kzt_guest_registry_source_lease_t *lease);

kzt_guest_registry_result_t kzt_guest_registry_commit_dynamic_view(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    const kzt_guest_dynamic_view_t *view);

int kzt_guest_registry_find_dynamic_view(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_dynamic_view_t *view,
    kzt_guest_field_status_t *status,
    unsigned long *generation);

/* Resolver metadata is published only while the object is not callable.
 * The generation and namespace checks make stale/non-main observations fail
 * open without changing the guest resolver slots. */
int kzt_guest_registry_publish_lazy_resolver(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id,
    const kzt_guest_lazy_resolver_t *resolver);

int kzt_guest_registry_find_lazy_resolver(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id,
    kzt_guest_lazy_resolver_t *resolver);

int kzt_guest_registry_dump_snapshot(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_dump_t *dump);

int kzt_guest_registry_get_diagnostics(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_diagnostics_t *diagnostics);

int kzt_guest_registry_configure_diagnostics(
    kzt_guest_registry_t *registry,
    const kzt_guest_registry_diagnostic_config_t *config);

int kzt_guest_registry_get_diagnostic_report(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_diagnostic_report_t *report);

int kzt_guest_registry_note_diagnostic(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_result_t result,
    uintptr_t link_map_addr,
    kzt_guest_registry_observation_diagnostic_t *diagnostic);

int kzt_guest_registry_dump_text(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_dump_sink_fn sink,
    void *opaque);

void kzt_guest_object_snapshot_free(kzt_guest_object_snapshot_t *snapshot);
void kzt_guest_registry_dump_free(kzt_guest_registry_dump_t *dump);

#ifdef KZT_GUEST_REGISTRY_TEST
void kzt_guest_registry_test_set_alloc_failure_after(long allocations);
void kzt_guest_registry_test_set_dynamic_commit_failure_after(long commits);
void kzt_guest_registry_test_fail_next_cond_init(void);
#endif

#endif
