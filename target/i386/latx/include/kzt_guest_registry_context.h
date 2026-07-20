#ifndef KZT_GUEST_REGISTRY_CONTEXT_H
#define KZT_GUEST_REGISTRY_CONTEXT_H

#include <pthread.h>

#include "kzt_guest_registry.h"

typedef struct kzt_guest_registry_context {
    kzt_guest_registry_t *registry;
    int state;
    uintptr_t main_namespace_head;
} kzt_guest_registry_context_t;

/* The caller owns the surrounding context lifetime.  The context lock is
 * used only for first publication and teardown; established lookups use an
 * atomic fast path and registry calls never run while the context lock is
 * held. */
kzt_guest_registry_t *kzt_guest_registry_context_get(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock);

void kzt_guest_registry_context_destroy(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock);

int kzt_guest_registry_context_get_main_namespace_head(
    const kzt_guest_registry_context_t *context,
    uintptr_t *head);

int kzt_guest_registry_context_confirm_main_namespace_head(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock,
    uintptr_t head);

int kzt_guest_registry_context_has_main_namespace_evidence(
    const kzt_guest_registry_context_t *context,
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t load_bias,
    uintptr_t dynamic_addr);

#endif
