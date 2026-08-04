#include "qemu/osdep.h"

#include "box64context.h"
#include "kzt_guest_runtime_entry.h"

uintptr_t kzt_guest_runtime_entry_load(
    const box64context_t *context, kzt_guest_runtime_entry_id_t entry)
{
    const dlprivate_t *dl = context ? context->dlprivate : NULL;

    if (!dl || entry < 0 || entry >= KZT_GUEST_RUNTIME_ENTRY_COUNT) {
        return 0;
    }
    return kzt_guest_runtime_entry_state_load(
        &dl->guest_dl_entries, entry);
}

uintptr_t kzt_guest_runtime_entry_ensure(
    dlprivate_t *dl, kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_resolver_fn resolver, void *opaque)
{
    return dl ? kzt_guest_runtime_entry_state_ensure(
                    &dl->guest_dl_entries, entry, resolver, opaque)
              : 0;
}

uintptr_t kzt_guest_runtime_entry_for_guest_branch(
    box64context_t *context, kzt_guest_runtime_entry_id_t entry)
{
    return kzt_guest_runtime_entry_load(context, entry);
}

int kzt_guest_runtime_entry_acquire(
    box64context_t *context, kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_scope_t *scope)
{
    kzt_guest_dl_entry_state_t *state;

    if (!context || !context->dlprivate || !scope) {
        return -1;
    }
    state = &context->dlprivate->guest_dl_entries;
    return kzt_guest_runtime_entry_state_acquire(state, entry, scope);
}

void kzt_guest_runtime_entry_release(
    kzt_guest_runtime_entry_scope_t *scope)
{
    kzt_guest_runtime_entry_state_release(scope);
}
