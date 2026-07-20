#ifndef KZT_GUEST_LIBRARY_BINDING_H
#define KZT_GUEST_LIBRARY_BINDING_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "kzt_loader_callback_scope.h"

typedef struct library_s library_t;
typedef struct kzt_guest_registry kzt_guest_registry_t;
typedef struct kzt_guest_library_bindings kzt_guest_library_bindings_t;

/* Embedded in box64context_t.  This is the only lifetime gate for lookup:
 * context teardown closes it before waiting for lookup handles. */
typedef struct kzt_guest_library_access {
    pthread_mutex_t lock;
    kzt_guest_library_bindings_t *bindings;
    int accepting;
    int initialized;
} kzt_guest_library_access_t;

typedef enum kzt_guest_library_object_type {
    KZT_GUEST_LIBRARY_OBJECT_MAIN = 0,
    KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
    KZT_GUEST_LIBRARY_OBJECT_EMULATED,
    KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED,
} kzt_guest_library_object_type_t;

typedef enum kzt_guest_library_namespace_kind {
    KZT_GUEST_LIBRARY_NAMESPACE_MAIN = 0,
    KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT,
    KZT_GUEST_LIBRARY_NAMESPACE_UNSUPPORTED,
} kzt_guest_library_namespace_kind_t;

typedef enum kzt_guest_library_binding_state {
    KZT_GUEST_LIBRARY_BINDING_LIVE = 0,
    KZT_GUEST_LIBRARY_BINDING_UNLOADING,
    KZT_GUEST_LIBRARY_BINDING_DEAD,
} kzt_guest_library_binding_state_t;

typedef enum kzt_guest_library_binding_result {
    KZT_GUEST_LIBRARY_BINDING_ADDED = 0,
    KZT_GUEST_LIBRARY_BINDING_UNCHANGED,
    KZT_GUEST_LIBRARY_BINDING_PENDING,
    KZT_GUEST_LIBRARY_BINDING_CANCELLED,
    KZT_GUEST_LIBRARY_BINDING_RETIRE_OWNED,
    KZT_GUEST_LIBRARY_BINDING_CONFLICT,
    KZT_GUEST_LIBRARY_BINDING_DISABLED,
    KZT_GUEST_LIBRARY_BINDING_ERROR,
} kzt_guest_library_binding_result_t;

typedef struct kzt_guest_library_binding_key {
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
} kzt_guest_library_binding_key_t;

typedef struct kzt_guest_library_handle {
    kzt_guest_library_bindings_t *bindings;
    void *entry;
    library_t *library;
    kzt_guest_library_object_type_t object_type;
} kzt_guest_library_handle_t;

typedef struct kzt_guest_library_callback_access {
    kzt_guest_library_bindings_t *bindings;
    uintptr_t link_map_addr;
    void *gate;
    int fallback;
} kzt_guest_library_callback_access_t;

kzt_guest_library_bindings_t *kzt_guest_library_bindings_init(void);
void kzt_guest_library_bindings_begin_teardown(
    kzt_guest_library_bindings_t *bindings);
void kzt_guest_library_bindings_destroy(kzt_guest_library_bindings_t **bindings);

int kzt_guest_library_access_init(kzt_guest_library_access_t *access);
void kzt_guest_library_access_begin_teardown(
    kzt_guest_library_access_t *access);
void kzt_guest_library_access_destroy(kzt_guest_library_access_t *access);

/* Libraries must be tracked before they become visible to loader users.  If
 * tracking cannot be established, exact binding remains disabled for that
 * library and the legacy loader continues unchanged. */
int kzt_guest_library_track(kzt_guest_library_bindings_t *bindings,
                            library_t *library);
int kzt_guest_library_reactivate(kzt_guest_library_bindings_t *bindings,
                                 library_t *library);

/* Guest loader calls are synchronous.  A context-local scope proves that a
 * callback came from a loader invocation issued after an older address was
 * closed.  note_pair only prepares a scope-local pair and never makes it
 * visible to lookup; publish_pair commits it after the loader succeeds.
 * Ending a scope without publication cancels every prepared pair. */
int kzt_guest_library_loader_scope_begin(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_scope_t *scope);
void kzt_guest_library_loader_scope_end(
    kzt_guest_library_loader_scope_t *scope);
kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_note_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type);
kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type);
kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_observed(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr);

/* Pins one link_map address before the callback's first guest-memory read and
 * through dynamic parsing, legacy processing, and diagnostics.  Unload closes
 * that address under the same lock and waits for every admitted callback.
 * A closed address rejects late callbacks before any guest work. */
int kzt_guest_library_callback_access_begin(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    kzt_guest_library_callback_access_t *access);
int kzt_guest_library_callback_access_begin_scoped(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    const kzt_guest_library_loader_scope_t *scope,
    kzt_guest_library_callback_access_t *access);
void kzt_guest_library_callback_access_end(
    kzt_guest_library_callback_access_t *access);

/* Record the exact pair produced by one causal loader operation.  This never
 * searches by name/path/SONAME.  A pair remains pending until registry
 * observation supplies its generation, so either arrival order works. */
kzt_guest_library_binding_result_t kzt_guest_library_note_exact_pair(
    kzt_guest_library_bindings_t *bindings,
    uintptr_t link_map_addr,
    library_t *library,
    kzt_guest_library_object_type_t object_type);

/* The caller must use only the exact (address, library) returned by one
 * successfully completed guest loader operation.  This causal publication
 * may reopen an address whose replacement is now known valid. */
kzt_guest_library_binding_result_t kzt_guest_library_publish_loader_pair(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    library_t *library, kzt_guest_library_object_type_t object_type);

/* Publish successful registry evidence to the exact-pair handshake.  WI-254
 * intentionally supports only ordinary shared objects in LM_ID_BASE.  Main
 * executable objects and non-main namespaces fail open. */
kzt_guest_library_binding_result_t kzt_guest_library_note_observation(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key);

kzt_guest_library_binding_result_t kzt_guest_library_bind(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key,
    library_t *library,
    kzt_guest_library_object_type_t object_type);

/* Production lookup must enter through the box64context-owned access object.
 * The raw lookup is exposed only for binding white-box tests, where the test
 * owns and stops all callers before destroying bindings. */
int kzt_guest_library_access_lookup(
    kzt_guest_library_access_t *access,
    const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle);
#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
int kzt_guest_library_lookup(kzt_guest_library_bindings_t *bindings,
                             const kzt_guest_library_binding_key_t *key,
                             kzt_guest_library_handle_t *handle);
#endif
void kzt_guest_library_handle_release(kzt_guest_library_handle_t *handle);

/* Closes attachment under the bindings lock, retires exact registry
 * generations without that lock, then waits for acquired lookup handles.
 * guest_link_map_hint identifies only this library's unclaimed observation;
 * a missing hint leaves unclaimed observations live rather than guessing.
 * This is the only permitted order: access -> bindings for lookup entry;
 * registry is never entered while bindings is held; handle release takes only
 * bindings. */
void kzt_guest_library_unbind(kzt_guest_library_bindings_t *bindings,
                              kzt_guest_registry_t *registry,
                              library_t *library,
                              uintptr_t guest_link_map_hint);
void kzt_guest_library_inactivate(kzt_guest_library_bindings_t *bindings,
                                  kzt_guest_registry_t *registry,
                                  library_t *library,
                                  uintptr_t guest_link_map_hint);

#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
typedef void (*kzt_guest_library_binding_test_retire_fn)(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key,
    library_t *library, int from_observation, void *opaque);
typedef void (*kzt_guest_library_binding_test_lifecycle_wait_fn)(
    kzt_guest_library_bindings_t *bindings, library_t *library,
    void *opaque);

void kzt_guest_library_binding_test_set_alloc_failure_after(long allocations);
void kzt_guest_library_binding_test_set_before_registry_retire(
    kzt_guest_library_binding_test_retire_fn hook, void *opaque);
void kzt_guest_library_binding_test_set_before_lifecycle_wait(
    kzt_guest_library_binding_test_lifecycle_wait_fn hook, void *opaque);
int kzt_guest_library_binding_test_snapshot(
    kzt_guest_library_bindings_t *bindings, library_t *library,
    kzt_guest_library_binding_state_t *lifecycle_state,
    size_t *active_pending, size_t *live_entries);
int kzt_guest_library_binding_test_get_diagnostics(
    kzt_guest_library_bindings_t *bindings,
    unsigned long *registry_missing,
    unsigned long *retire_unprovable);
#endif

#endif
