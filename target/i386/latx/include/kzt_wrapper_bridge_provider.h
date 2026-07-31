#ifndef KZT_WRAPPER_BRIDGE_PROVIDER_H
#define KZT_WRAPPER_BRIDGE_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_library_binding.h"
#include "kzt_wrapper_probe.h"

typedef void (*kzt_wrapper_bridge_abi_wrapper_t)(uintptr_t fnc);

#define KZT_WRAPPER_BRIDGE_NATIVE_NAME_MAX 256

typedef struct kzt_wrapper_bridge_provider_match {
    const char *wrapper_name;
    char native_name[KZT_WRAPPER_BRIDGE_NATIVE_NAME_MAX];
    kzt_wrapper_bridge_abi_wrapper_t abi_wrapper;
    uintptr_t native_symbol;
    uintptr_t resolved_bridge_target;
    void *context_owner;
    void *wrapper_provider;
    void *native_lookup_handle;
    void *native_owner;
    void *bridge_owner;
    void *bridge_storage;
    int stack_bytes;
    int custom_wrapper;
    int resolved_bridge_exact;
    int wrapper_provider_lifetime_bound;
    int native_owner_lifetime_bound;
    int bridge_owner_lifetime_bound;
    const kzt_guest_library_handle_t *retained_provider_handle;
} kzt_wrapper_bridge_provider_match_t;

typedef int (*kzt_wrapper_bridge_provider_inspect_fn)(
    void *library, const char *symbol_name, const char *symbol_version,
    kzt_wrapper_bridge_provider_match_t *match, void *opaque);

typedef uintptr_t (*kzt_wrapper_bridge_provider_check_fn)(
    const kzt_wrapper_bridge_provider_match_t *match, void *opaque);

typedef uintptr_t (*kzt_wrapper_bridge_provider_add_fn)(
    const kzt_wrapper_bridge_provider_match_t *match,
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque);

typedef struct kzt_wrapper_bridge_provider_runtime_ops {
    kzt_wrapper_bridge_provider_inspect_fn inspect_library;
    kzt_wrapper_bridge_provider_check_fn check_bridge;
    kzt_wrapper_bridge_provider_add_fn add_bridge;
    void *opaque;
} kzt_wrapper_bridge_provider_runtime_ops_t;

typedef struct kzt_wrapper_bridge_provider {
    kzt_wrapper_probe_entry_t entry;
    kzt_wrapper_probe_manifest_t manifest;
    kzt_wrapper_probe_bridge_ops_t bridge_ops;
    kzt_wrapper_bridge_provider_match_t match;
    kzt_wrapper_bridge_provider_runtime_ops_t runtime_ops;
} kzt_wrapper_bridge_provider_t;

int kzt_wrapper_bridge_provider_prepare(
    kzt_wrapper_bridge_provider_t *provider, void *const *libraries,
    size_t library_count, const char *symbol_name,
    const char *symbol_version,
    const kzt_wrapper_bridge_provider_runtime_ops_t *runtime_ops);

int kzt_wrapper_bridge_provider_prepare_with_version_evidence(
    kzt_wrapper_bridge_provider_t *provider, void *const *libraries,
    size_t library_count, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    const kzt_wrapper_bridge_provider_runtime_ops_t *runtime_ops);

#endif
