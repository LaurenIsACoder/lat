#ifndef KZT_WRAPPER_PROBE_H
#define KZT_WRAPPER_PROBE_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_patch_planner.h"

typedef enum kzt_wrapper_probe_bridge_source {
    KZT_WRAPPER_PROBE_BRIDGE_NONE = 0,
    KZT_WRAPPER_PROBE_BRIDGE_CACHE,
    KZT_WRAPPER_PROBE_BRIDGE_ADD_BRIDGE,
} kzt_wrapper_probe_bridge_source_t;

typedef struct kzt_wrapper_probe_entry {
    const char *symbol_name;
    kzt_symbol_version_evidence_t symbol_version_evidence;
    const char *symbol_version;
    const char *wrapper_name;
    kzt_symbol_version_evidence_t wrapper_version_evidence;
    const char *wrapper_symbol_version;
    uintptr_t native_symbol;
} kzt_wrapper_probe_entry_t;

typedef struct kzt_wrapper_probe_manifest {
    int available;
    const char *manifest_name;
    const kzt_wrapper_probe_entry_t *entries;
    size_t entry_count;
} kzt_wrapper_probe_manifest_t;

typedef struct kzt_wrapper_probe_request {
    const char *symbol_name;
    kzt_symbol_version_evidence_t symbol_version_evidence;
    const char *symbol_version;
} kzt_wrapper_probe_request_t;

typedef struct kzt_wrapper_probe_bridge_request {
    const char *symbol_name;
    kzt_symbol_version_evidence_t symbol_version_evidence;
    const char *symbol_version;
    const char *wrapper_name;
    kzt_symbol_version_evidence_t wrapper_version_evidence;
    const char *wrapper_symbol_version;
    uintptr_t native_symbol;
} kzt_wrapper_probe_bridge_request_t;

typedef uintptr_t (*kzt_wrapper_probe_check_bridge_fn)(
    uintptr_t native_symbol, void *opaque);

typedef uintptr_t (*kzt_wrapper_probe_add_bridge_fn)(
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque);

typedef struct kzt_wrapper_probe_bridge_ops {
    kzt_wrapper_probe_check_bridge_fn check_bridge;
    kzt_wrapper_probe_add_bridge_fn add_bridge;
    void *opaque;
} kzt_wrapper_probe_bridge_ops_t;

typedef struct kzt_wrapper_probe_result {
    kzt_patch_wrapper_match_t wrapper_match;
    const char *wrapper_name;
    kzt_symbol_version_evidence_t wrapper_version_evidence;
    const char *wrapper_symbol_version;
    uintptr_t native_symbol;
    uintptr_t bridge_target;
    kzt_wrapper_probe_bridge_source_t bridge_source;
} kzt_wrapper_probe_result_t;

int kzt_wrapper_probe_minimal_manifest(
    const kzt_wrapper_probe_manifest_t *manifest,
    const kzt_wrapper_probe_request_t *request,
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops,
    kzt_wrapper_probe_result_t *result);

void kzt_wrapper_probe_apply_to_candidate(
    const kzt_wrapper_probe_result_t *probe,
    kzt_patch_candidate_t *candidate);

void kzt_wrapper_probe_apply_to_decision_request(
    const kzt_wrapper_probe_result_t *probe,
    kzt_patch_wrapper_match_t *wrapper_match,
    const char **wrapper_name,
    const char **wrapper_symbol_version,
    uintptr_t *bridge_target);

#endif
