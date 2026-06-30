#ifndef KZT_OBSERVATION_ADAPTER_H
#define KZT_OBSERVATION_ADAPTER_H

#include <stdint.h>

#include "kzt_guest_link_map_reader.h"
#include "kzt_guest_registry.h"

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

typedef struct kzt_observation_adapter_diagnostic {
    int enabled;
    int emitted;
    kzt_observation_adapter_result_t result;
    uintptr_t link_map_addr;
    kzt_guest_registry_observation_diagnostic_t registry;
} kzt_observation_adapter_diagnostic_t;

typedef void (*kzt_observation_adapter_diagnostic_fn)(
    const kzt_observation_adapter_diagnostic_t *diagnostic,
    void *opaque);

typedef struct kzt_observation_adapter_request {
    int enabled;
    int diagnostics_enabled;
    uintptr_t link_map_addr;
    kzt_guest_registry_t *registry;
    const kzt_guest_link_map_reader_ops_t *reader_ops;
    kzt_observation_legacy_flow_fn legacy_flow;
    void *legacy_opaque;
    kzt_observation_adapter_diagnostic_fn diagnostic;
    void *diagnostic_opaque;
} kzt_observation_adapter_request_t;

int kzt_observe_guest_object_from_callback(
    const kzt_observation_adapter_request_t *request,
    kzt_observation_adapter_result_t *result);

#endif
