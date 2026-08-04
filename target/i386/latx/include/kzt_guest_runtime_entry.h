#ifndef KZT_GUEST_RUNTIME_ENTRY_H
#define KZT_GUEST_RUNTIME_ENTRY_H

#include <stdint.h>

#include "kzt_guest_runtime_entry_state.h"

typedef struct box64context_s box64context_t;
typedef struct dlprivate_s dlprivate_t;
typedef struct CPUX86State CPUX86State;

uintptr_t kzt_guest_runtime_entry_load(
    const box64context_t *context, kzt_guest_runtime_entry_id_t entry);

uintptr_t kzt_guest_runtime_entry_ensure(
    dlprivate_t *dl, kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_resolver_fn resolver, void *opaque);
uintptr_t kzt_guest_runtime_entry_for_guest_branch(
    box64context_t *context, kzt_guest_runtime_entry_id_t entry);
int kzt_guest_runtime_entry_acquire(
    box64context_t *context, kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_scope_t *scope);
void kzt_guest_runtime_entry_release(
    kzt_guest_runtime_entry_scope_t *scope);

uintptr_t kzt_runtime_guest_entry_or_abort(
    CPUX86State *env, kzt_guest_runtime_entry_id_t entry);

#endif
