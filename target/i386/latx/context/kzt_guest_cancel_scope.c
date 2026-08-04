#include "qemu/osdep.h"

#include <pthread.h>

#include "callback.h"
#include "kzt_guest_cancel_scope.h"

void kzt_guest_cancel_scope_begin(
    box64context_t *context, kzt_guest_cancel_scope_t *scope)
{
    if (!scope) {
        return;
    }
    *scope = (kzt_guest_cancel_scope_t) { 0 };
    if (kzt_guest_runtime_entry_acquire(
            context, KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE,
            &scope->runtime) != 0) {
        return;
    }
    scope->switched = RunFunctionWithState(
        scope->runtime.address, 2, PTHREAD_CANCEL_ASYNCHRONOUS,
        &scope->oldtype) == 0;
    if (!scope->switched) {
        kzt_guest_runtime_entry_release(&scope->runtime);
    }
}

void kzt_guest_cancel_scope_end(kzt_guest_cancel_scope_t *scope)
{
    if (!scope || !scope->switched) {
        return;
    }
    scope->switched = 0;
    (void)RunFunctionWithState(
        scope->runtime.address, 2, scope->oldtype, NULL);
    kzt_guest_runtime_entry_release(&scope->runtime);
}

void kzt_guest_cancel_scope_cleanup(void *opaque)
{
    kzt_guest_cancel_scope_t *scope = opaque;

    if (!scope) {
        return;
    }
    scope->switched = 0;
    kzt_guest_runtime_entry_release(&scope->runtime);
}
