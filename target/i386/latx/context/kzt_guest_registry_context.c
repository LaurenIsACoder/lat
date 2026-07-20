#include "kzt_guest_registry_context.h"

enum kzt_guest_registry_context_state {
    KZT_GUEST_REGISTRY_CONTEXT_UNINITIALIZED = 0,
    KZT_GUEST_REGISTRY_CONTEXT_READY,
    KZT_GUEST_REGISTRY_CONTEXT_UNAVAILABLE,
    KZT_GUEST_REGISTRY_CONTEXT_DESTROYING,
};

kzt_guest_registry_t *kzt_guest_registry_context_get(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock)
{
    kzt_guest_registry_t *registry;
    int state;

    if (!context || !context_lock) {
        return NULL;
    }

    state = __atomic_load_n(&context->state, __ATOMIC_ACQUIRE);
    if (state == KZT_GUEST_REGISTRY_CONTEXT_READY) {
        return __atomic_load_n(&context->registry, __ATOMIC_ACQUIRE);
    }
    if (state != KZT_GUEST_REGISTRY_CONTEXT_UNINITIALIZED) {
        return NULL;
    }

    pthread_mutex_lock(context_lock);
    state = __atomic_load_n(&context->state, __ATOMIC_RELAXED);
    if (state == KZT_GUEST_REGISTRY_CONTEXT_UNINITIALIZED) {
        registry = kzt_guest_registry_init();
        __atomic_store_n(&context->registry, registry, __ATOMIC_RELEASE);
        __atomic_store_n(
            &context->state,
            registry ? KZT_GUEST_REGISTRY_CONTEXT_READY :
                       KZT_GUEST_REGISTRY_CONTEXT_UNAVAILABLE,
            __ATOMIC_RELEASE);
    } else {
        registry = state == KZT_GUEST_REGISTRY_CONTEXT_READY ?
            __atomic_load_n(&context->registry, __ATOMIC_ACQUIRE) : NULL;
    }
    pthread_mutex_unlock(context_lock);
    return registry;
}

void kzt_guest_registry_context_destroy(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock)
{
    kzt_guest_registry_t *registry;

    if (!context || !context_lock) {
        return;
    }

    pthread_mutex_lock(context_lock);
    __atomic_store_n(&context->state,
                     KZT_GUEST_REGISTRY_CONTEXT_DESTROYING,
                     __ATOMIC_RELEASE);
    registry = __atomic_exchange_n(&context->registry, NULL,
                                   __ATOMIC_ACQ_REL);
    __atomic_store_n(&context->main_namespace_head, 0, __ATOMIC_RELEASE);
    pthread_mutex_unlock(context_lock);

    kzt_guest_registry_destroy(&registry);
}

int kzt_guest_registry_context_get_main_namespace_head(
    const kzt_guest_registry_context_t *context,
    uintptr_t *head)
{
    uintptr_t value;

    if (head) {
        *head = 0;
    }
    if (!context || !head ||
        __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) ==
            KZT_GUEST_REGISTRY_CONTEXT_DESTROYING) {
        return -1;
    }
    value = __atomic_load_n(&context->main_namespace_head,
                            __ATOMIC_ACQUIRE);
    if (!value) {
        return -1;
    }
    *head = value;
    return 0;
}

int kzt_guest_registry_context_confirm_main_namespace_head(
    kzt_guest_registry_context_t *context,
    pthread_mutex_t *context_lock,
    uintptr_t head)
{
    uintptr_t current;
    int result = -1;

    if (!context || !context_lock || !head) {
        return -1;
    }

    pthread_mutex_lock(context_lock);
    if (__atomic_load_n(&context->state, __ATOMIC_RELAXED) !=
        KZT_GUEST_REGISTRY_CONTEXT_DESTROYING) {
        current = __atomic_load_n(&context->main_namespace_head,
                                  __ATOMIC_RELAXED);
        if (!current || current == head) {
            __atomic_store_n(&context->main_namespace_head, head,
                             __ATOMIC_RELEASE);
            result = 0;
        }
    }
    pthread_mutex_unlock(context_lock);
    return result;
}

int kzt_guest_registry_context_has_main_namespace_evidence(
    const kzt_guest_registry_context_t *context,
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t load_bias,
    uintptr_t dynamic_addr)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;
    uintptr_t main_head = 0;
    int matches = 0;

    if (!registry || !link_map_addr || !dynamic_addr ||
        kzt_guest_registry_context_get_main_namespace_head(
            context, &main_head) != 0 || !main_head) {
        return 0;
    }
    if (kzt_guest_registry_find_by_link_map(
            registry, link_map_addr, &snapshot) == 0 && snapshot &&
        snapshot->load_bias.status == KZT_GUEST_FIELD_OK &&
        snapshot->load_bias.value == load_bias &&
        snapshot->dynamic_addr.status == KZT_GUEST_FIELD_OK &&
        snapshot->dynamic_addr.value == dynamic_addr &&
        snapshot->namespace_id.status == KZT_GUEST_FIELD_OK &&
        snapshot->namespace_id.value == 0) {
        matches = 1;
    }
    kzt_guest_object_snapshot_free(snapshot);
    return matches;
}
