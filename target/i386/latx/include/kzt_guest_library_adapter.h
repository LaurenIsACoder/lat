#ifndef KZT_GUEST_LIBRARY_ADAPTER_H
#define KZT_GUEST_LIBRARY_ADAPTER_H

#include <stdint.h>

#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"
#include "kzt_loader_callback_scope.h"

typedef struct box64context_s box64context_t;
typedef struct library_s library_t;

typedef struct kzt_guest_wrapper_source_proof {
    kzt_guest_registry_source_lease_t lease;
    kzt_guest_library_binding_key_t key;
} kzt_guest_wrapper_source_proof_t;

int kzt_guest_library_wrapper_source_acquire(
    box64context_t *context, uintptr_t link_map_addr,
    const char *requested_path, const char *wrapper_name,
    kzt_guest_wrapper_source_proof_t *proof);
void kzt_guest_library_wrapper_source_release(
    kzt_guest_wrapper_source_proof_t *proof);

/*
 * Run one guest dlopen while exposing its context-owned loader scope only to
 * callbacks caused by that invocation.  Scope setup failure is fail-open: the
 * guest call still runs and its original result is returned.
 */
uint64_t kzt_guest_library_run_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    uintptr_t function, void *filename, int flag,
    kzt_guest_library_loader_scope_t *call_scope);

/*
 * Publish the result of one completed guest dlopen, then close its scope.
 * A zero result, disabled publication, or invalid scope publishes nothing.
 */
void kzt_guest_library_finish_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *call_scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof, int publish);

/* Guest symbol lookup is authoritative.  These adapters only preserve the
 * guest ABI arguments and result; wrapper selection happens afterwards. */
uint64_t kzt_guest_library_run_dlsym(
    uintptr_t function, void *handle, void *symbol);
uint64_t kzt_guest_library_run_dlvsym(
    uintptr_t function, void *handle, void *symbol, const char *version);
uint64_t kzt_guest_library_run_dlerror(uintptr_t function);
int kzt_guest_library_run_dlclose(uintptr_t function, void *handle);
uint64_t kzt_guest_library_run_dlmopen(
    uintptr_t function, void *lmid, void *filename, int flag);
int kzt_guest_library_run_dlinfo(
    uintptr_t function, void *handle, int request, void *info);

/*
 * Replace a successful guest symbol result only when Registry and the exact
 * context-owned binding prove that its owner is a wrapped main-namespace
 * object with a matching bridge.  Missing or conflicting evidence preserves
 * the guest address.
 */
uintptr_t kzt_guest_library_select_symbol_result(
    box64context_t *context, uintptr_t guest_handle,
    uintptr_t guest_result, const char *symbol, const char *version);

/* Shared production adapter used by wrappedlibc, wrappedlibdl, and loader
 * callback paths whenever one operation owns both exact values. */
kzt_guest_library_binding_result_t kzt_guest_library_note_loader_pair(
    box64context_t *context, uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof);
kzt_guest_library_binding_result_t
kzt_guest_library_note_loader_pair_pending(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof);
kzt_guest_library_binding_result_t
kzt_guest_library_publish_loader_pair_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof);
void kzt_guest_library_publish_loader_observed_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr);

#endif
