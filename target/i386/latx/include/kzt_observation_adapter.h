#ifndef KZT_OBSERVATION_ADAPTER_H
#define KZT_OBSERVATION_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_link_map_reader.h"
#include "kzt_guest_dynamic.h"
#include "kzt_guest_dynamic_diagnostics.h"
#include "kzt_guest_registry.h"
#include "kzt_loader_callback_scope.h"

typedef struct kzt_guest_library_bindings kzt_guest_library_bindings_t;

typedef enum kzt_observation_adapter_result {
    KZT_OBSERVATION_ADAPTER_DISABLED = 0,
    KZT_OBSERVATION_ADAPTER_ADDED,
    KZT_OBSERVATION_ADAPTER_UNCHANGED,
    KZT_OBSERVATION_ADAPTER_UPDATED,
    KZT_OBSERVATION_ADAPTER_CONFLICT,
    KZT_OBSERVATION_ADAPTER_READER_FAILED,
    KZT_OBSERVATION_ADAPTER_REGISTRY_FAILED,
} kzt_observation_adapter_result_t;

typedef int (*kzt_observation_legacy_flow_fn)(uintptr_t link_map_addr,
                                             void *opaque);

typedef struct kzt_observation_adapter_dynamic_diagnostic {
    int attempted;
    int cache_hit;
    int parse_return;
    uintptr_t dynamic_addr;
    kzt_guest_dynamic_status_t status;
    kzt_guest_dynamic_error_t error;
    size_t entry_count;
    uintptr_t read_error_addr;
    int commit_attempted;
    kzt_guest_registry_result_t commit_result;
    int comparison_attempted;
    kzt_guest_dynamic_diagnostic_summary_t comparison;
    kzt_guest_registry_observation_diagnostic_t registry;
} kzt_observation_adapter_dynamic_diagnostic_t;

typedef struct kzt_observation_adapter_diagnostic {
    int enabled;
    int emitted;
    kzt_observation_adapter_result_t result;
    uintptr_t link_map_addr;
    kzt_guest_registry_observation_diagnostic_t registry;
    kzt_observation_adapter_dynamic_diagnostic_t dynamic;
} kzt_observation_adapter_diagnostic_t;

typedef void (*kzt_observation_adapter_diagnostic_fn)(
    const kzt_observation_adapter_diagnostic_t *diagnostic,
    void *opaque);

typedef struct kzt_observation_adapter_request {
    int enabled;
    int diagnostics_enabled;
    int dynamic_diagnostics_force_compare;
    uintptr_t link_map_addr;
    kzt_guest_registry_t *registry;
    kzt_guest_library_bindings_t *library_bindings;
    const kzt_guest_library_loader_scope_t *loader_scope;
    const kzt_guest_link_map_reader_ops_t *reader_ops;
    /* Caller-verified evidence.  Invalid or absent hints are ignored. */
    int namespace_id_present;
    uintptr_t namespace_id;
    int map_range_present;
    uintptr_t map_start;
    uintptr_t map_end;
    kzt_observation_legacy_flow_fn legacy_flow;
    void *legacy_opaque;
    kzt_observation_adapter_diagnostic_fn diagnostic;
    void *diagnostic_opaque;
} kzt_observation_adapter_request_t;

int kzt_observe_guest_object_from_callback(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t *result);

#endif
