#ifndef KZT_GUEST_REGISTRY_H
#define KZT_GUEST_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_dynamic_view.h"

#define KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT 256

typedef struct kzt_guest_registry kzt_guest_registry_t;

typedef struct kzt_guest_loader_identity {
    uintptr_t handle;
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    unsigned long handle_generation;
} kzt_guest_loader_identity_t;

typedef enum kzt_guest_loader_close_result {
    KZT_GUEST_LOADER_CLOSE_REFERENCED = 0,
    KZT_GUEST_LOADER_CLOSE_UNLOAD_UNPROVEN,
    KZT_GUEST_LOADER_CLOSE_RETIRED,
    KZT_GUEST_LOADER_CLOSE_STALE,
} kzt_guest_loader_close_result_t;

typedef struct kzt_guest_registry_source_lease {
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    int active;
} kzt_guest_registry_source_lease_t;

/* Pins the Registry evidence used by one first-bind write transaction.  The
 * lease is derived from an already-held exact source lease; it prevents
 * Registry mutations, but never holds the Registry mutex across guest memory
 * access, page permission changes, or the slot CAS. */
typedef struct kzt_guest_registry_patch_decision_lease {
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    int active;
} kzt_guest_registry_patch_decision_lease_t;

typedef enum kzt_guest_object_state {
    KZT_GUEST_OBJECT_DISCOVERED = 0,
    KZT_GUEST_OBJECT_PARSED,
    KZT_GUEST_OBJECT_WRAPPER_READY,
    KZT_GUEST_OBJECT_PATCHED,
    KZT_GUEST_OBJECT_UNLOADING,
    KZT_GUEST_OBJECT_DEAD,
} kzt_guest_object_state_t;

/* Per-generation state for the narrow PLTGOT resolver injection transaction.
 * It is intentionally separate from the object lifecycle: an observation
 * remains live while one writer is preparing its guest-memory transaction. */
typedef enum kzt_guest_got_plt_injection_state {
    KZT_GUEST_GOT_PLT_INJECTION_NONE = 0,
    KZT_GUEST_GOT_PLT_INJECTION_APPLYING,
    KZT_GUEST_GOT_PLT_INJECTION_APPLIED,
} kzt_guest_got_plt_injection_state_t;

typedef enum kzt_guest_got_plt_injection_claim_result {
    KZT_GUEST_GOT_PLT_INJECTION_GRANTED = 0,
    KZT_GUEST_GOT_PLT_INJECTION_IN_PROGRESS,
    KZT_GUEST_GOT_PLT_INJECTION_ALREADY_APPLIED,
    KZT_GUEST_GOT_PLT_INJECTION_FAIL_OPEN,
} kzt_guest_got_plt_injection_claim_result_t;

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
    uintptr_t object_head;
    int registry_owned_head;
    int valid;
} kzt_guest_lazy_resolver_t;

typedef struct kzt_guest_registry_lazy_source {
    unsigned long generation;
    uintptr_t namespace_id;
    uintptr_t guest_resolver;
} kzt_guest_registry_lazy_source_t;

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
    unsigned long dynamic_view_revision;
    kzt_guest_lazy_resolver_t lazy_resolver;
    kzt_guest_got_plt_injection_state_t got_plt_injection_state;
    kzt_guest_object_state_t state;
    kzt_guest_object_state_t unload_previous_state;
    unsigned long generation;
    unsigned long active_source_leases;
} kzt_guest_object_snapshot_t;

/* A compact, caller-owned result for an address-range lookup.  It is copied
 * under the Registry mutex, so no Registry-owned pointer escapes the lock. */
typedef struct kzt_guest_registry_address_match {
    uintptr_t link_map_addr;
    uintptr_t map_start;
    uintptr_t map_end;
    uintptr_t namespace_id;
    unsigned long generation;
    kzt_guest_field_status_t soname_status;
    kzt_guest_field_status_t path_status;
    kzt_guest_field_status_t namespace_id_status;
    char soname[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    char path[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    size_t match_count;
} kzt_guest_registry_address_match_t;

typedef struct kzt_guest_registry_address_pair {
    kzt_guest_registry_address_match_t current;
    kzt_guest_registry_address_match_t expected;
} kzt_guest_registry_address_pair_t;

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
    unsigned long loader_identity_publications;
    unsigned long loader_close_referenced;
    unsigned long loader_close_unload_unproven;
    unsigned long loader_close_retired;
    unsigned long loader_close_stale;
    unsigned long loader_close_identity_missing;
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
void kzt_guest_registry_test_set_before_patch_decision_wait(
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

/* Completes the range evidence for one exact live generation without reading
 * guest memory again.  Existing reliable values are confirmed, never
 * overwritten; a disagreement or stale generation fails open as CONFLICT. */
kzt_guest_registry_result_t kzt_guest_registry_supplement_map_range(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t map_start,
    uintptr_t map_end,
    kzt_guest_registry_observation_diagnostic_t *diagnostic);

/* Publishes an exact LMID learned from guest dlinfo/r_debug namespace
 * membership for one already-observed live generation. */
kzt_guest_registry_result_t kzt_guest_registry_supplement_namespace(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id);

int kzt_guest_registry_find_by_link_map(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_object_snapshot_t **snapshot);

/* Resolves two guest addresses from one coherent Registry lock hold without
 * allocating a full dump.  Each match_count is zero, one, or greater than one
 * for not-found, unique, or ambiguous evidence respectively. */
int kzt_guest_registry_resolve_address_pair(
    kzt_guest_registry_t *registry,
    uintptr_t current_address,
    uintptr_t expected_address,
    kzt_guest_registry_address_pair_t *pair);

/* Copies one live object's identity evidence without a heap snapshot. */
int kzt_guest_registry_find_live_object(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_registry_address_match_t *match);

/* Binds one successful guest loader handle to the exact LINKMAP/LMID returned
 * by guest dlinfo.  Repeated opens of the same exact object are reference
 * counted; conflicting live identities fail open. */
int kzt_guest_registry_publish_loader_identity(
    kzt_guest_registry_t *registry,
    uintptr_t handle,
    uintptr_t link_map_addr,
    uintptr_t namespace_id,
    kzt_guest_loader_identity_t *identity);
int kzt_guest_registry_find_loader_identity(
    kzt_guest_registry_t *registry,
    uintptr_t handle,
    kzt_guest_loader_identity_t *identity);
/* Reuses an exact live handle binding without another guest dlinfo round trip.
 * Inactive bindings additionally require an exact RTLD_NODELETE resident
 * proof; a generic unload-unproven result is not sufficient. */
int kzt_guest_registry_reuse_loader_identity(
    kzt_guest_registry_t *registry,
    uintptr_t handle,
    kzt_guest_loader_identity_t *identity);
int kzt_guest_registry_mark_loader_resident(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
int kzt_guest_registry_loader_symbol_source_acquire(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity,
    kzt_guest_dynamic_view_t *dynamic_view,
    kzt_guest_field_status_t *dynamic_status,
    unsigned long *dynamic_revision,
    kzt_guest_registry_source_lease_t *lease);
/* Resolves a loader object while it is LIVE or pre-unmap UNLOADING. */
int kzt_guest_registry_find_loader_object_identity(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_loader_identity_t *identity);
kzt_guest_loader_close_result_t
kzt_guest_registry_complete_loader_close(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
void kzt_guest_registry_note_loader_close_identity_missing(
    kzt_guest_registry_t *registry);

/* Checks the exact live object identity under one Registry lock without
 * allocating or copying unrelated object metadata.  Returns 1 for an exact
 * match, 0 for a mismatch, and -1 when the Registry cannot answer. */
int kzt_guest_registry_matches_live_identity(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t load_bias,
    uintptr_t dynamic_addr,
    uintptr_t namespace_id);

int kzt_guest_registry_retire(kzt_guest_registry_t *registry,
                              uintptr_t link_map_addr,
                              unsigned long generation);
int kzt_guest_registry_retire_loader_identity(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
/* RT_DELETE closes lease admission before guest unmap.  RT_CONSISTENT then
 * either cancels unchanged objects or finishes only identities proven absent. */
int kzt_guest_registry_begin_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
int kzt_guest_registry_cancel_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
int kzt_guest_registry_finish_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity);
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

/* The source lease must remain active until this lease is released. */
int kzt_guest_registry_patch_decision_lease_acquire(
    const kzt_guest_registry_source_lease_t *source_lease,
    kzt_guest_registry_patch_decision_lease_t *lease);
void kzt_guest_registry_patch_decision_lease_release(
    kzt_guest_registry_patch_decision_lease_t *lease);

/* Claims the one PLTGOT injection transaction for the exact generation
 * protected by an active patch-decision lease.  The supplied Dynamic View
 * must be the Registry's complete, matching view; otherwise this returns
 * FAIL_OPEN without changing state.  No guest memory is accessed here. */
kzt_guest_got_plt_injection_claim_result_t
kzt_guest_registry_got_plt_injection_claim(
    const kzt_guest_registry_patch_decision_lease_t *lease,
    const kzt_guest_dynamic_view_t *view);

/* Completes a previously granted claim while the same decision lease remains
 * active.  A failed writer returns the generation to NONE so the legacy path
 * or a later observation can retry safely. */
int kzt_guest_registry_got_plt_injection_finish(
    const kzt_guest_registry_patch_decision_lease_t *lease,
    int applied);

/* Returns 1 for APPLYING/APPLIED, 0 for NONE, and -1 for stale, dead, or
 * unsupported identity evidence.  Legacy code uses this to avoid a duplicate
 * resolver-slot write while the new transaction owns the generation. */
int kzt_guest_registry_got_plt_injection_claimed(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id);

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

int kzt_guest_registry_dynamic_view_matches(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation, const kzt_guest_dynamic_view_t *view);

/* Resolver metadata is published only while the object is not callable.
 * The generation and namespace checks make stale/non-main observations fail
 * open without changing the guest resolver slots. */
int kzt_guest_registry_publish_lazy_resolver(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    unsigned long generation,
    uintptr_t namespace_id,
    const kzt_guest_lazy_resolver_t *resolver);

/* Copies the generation, namespace, and resolver needed by one PLT entry
 * under a single Registry lock without allocating a full object snapshot. */
int kzt_guest_registry_find_lazy_source(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_registry_lazy_source_t *source);

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
