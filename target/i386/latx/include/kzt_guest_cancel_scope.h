#ifndef KZT_GUEST_CANCEL_SCOPE_H
#define KZT_GUEST_CANCEL_SCOPE_H

#include "kzt_guest_runtime_entry.h"

typedef struct kzt_guest_cancel_scope {
    kzt_guest_runtime_entry_scope_t runtime;
    int oldtype;
    int switched;
} kzt_guest_cancel_scope_t;

void kzt_guest_cancel_scope_begin(
    box64context_t *context, kzt_guest_cancel_scope_t *scope);
void kzt_guest_cancel_scope_end(kzt_guest_cancel_scope_t *scope);
void kzt_guest_cancel_scope_cleanup(void *opaque);

#endif
