#ifndef KZT_GUEST_RUNTIME_ENTRY_STATE_H
#define KZT_GUEST_RUNTIME_ENTRY_STATE_H

#include <stdint.h>

#include "kzt_guest_dl_state.h"

typedef uintptr_t (*kzt_guest_runtime_entry_resolver_fn)(
    const char *symbol, void *opaque);

typedef struct kzt_guest_runtime_entry_scope_s {
    kzt_guest_dl_entry_state_t *state;
    uintptr_t address;
} kzt_guest_runtime_entry_scope_t;

static inline uintptr_t kzt_guest_runtime_entry_state_load(
    const kzt_guest_dl_entry_state_t *state,
    kzt_guest_runtime_entry_id_t entry)
{
    if (!state || entry < 0 || entry >= KZT_GUEST_RUNTIME_ENTRY_COUNT ||
        !(__atomic_load_n(&state->lifecycle, __ATOMIC_ACQUIRE) &
          KZT_GUEST_DL_LIFECYCLE_OPEN)) {
        return 0;
    }
    return __atomic_load_n(
        &state->runtime_entries[entry], __ATOMIC_ACQUIRE);
}

int kzt_guest_dl_entry_state_enter(kzt_guest_dl_entry_state_t *state);
void kzt_guest_dl_entry_state_leave_locked(
    kzt_guest_dl_entry_state_t *state);

int kzt_guest_runtime_entry_state_publish(
    kzt_guest_dl_entry_state_t *state,
    const uintptr_t entries[KZT_GUEST_RUNTIME_ENTRY_COUNT]);

uintptr_t kzt_guest_runtime_entry_state_ensure(
    kzt_guest_dl_entry_state_t *state,
    kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_resolver_fn resolver, void *opaque);
int kzt_guest_runtime_entry_state_acquire(
    kzt_guest_dl_entry_state_t *state,
    kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_scope_t *scope);
void kzt_guest_runtime_entry_state_release(
    kzt_guest_runtime_entry_scope_t *scope);
void kzt_guest_runtime_entry_state_begin_teardown(
    kzt_guest_dl_entry_state_t *state);

#endif
