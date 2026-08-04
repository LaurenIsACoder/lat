#include "kzt_xcb_connection_guard.h"

#include <pthread.h>
#include <stddef.h>
#include <string.h>

#define KZT_XCB_ACTIVE_LEASE_DEPTH 8

typedef struct kzt_xcb_pending_guard {
    kzt_xcb_connection_map_t *map;
    kzt_xcb_connection_lease_t lease;
    int valid;
} kzt_xcb_pending_guard_t;

typedef struct kzt_xcb_thread_leases {
    kzt_xcb_pending_guard_t pending;
    kzt_xcb_connection_lease_t active[KZT_XCB_ACTIVE_LEASE_DEPTH];
    size_t active_count;
    int registered;
} kzt_xcb_thread_leases_t;

static pthread_once_t kzt_xcb_thread_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t kzt_xcb_thread_key;
static int kzt_xcb_thread_key_status = -1;
static __thread kzt_xcb_thread_leases_t kzt_xcb_thread_leases;

static int kzt_xcb_cancel_disable(void)
{
    int old_state = PTHREAD_CANCEL_ENABLE;

    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
    return old_state;
}

static void kzt_xcb_cancel_restore(int old_state)
{
    (void)pthread_setcancelstate(old_state, NULL);
}

static void kzt_xcb_release_lease(
    const kzt_xcb_connection_lease_t *lease)
{
    if (lease && lease->_map && lease->native && lease->guest) {
        kzt_xcb_connection_map_release_pair(
            lease->_map, lease->native, lease->guest);
    }
}

static void kzt_xcb_thread_leases_destroy(void *opaque)
{
    kzt_xcb_thread_leases_t *state = opaque;

    if (!state) {
        return;
    }
    state->registered = 0;
    if (state->pending.valid) {
        kzt_xcb_release_lease(&state->pending.lease);
    }
    while (state->active_count) {
        kzt_xcb_release_lease(&state->active[--state->active_count]);
    }
    memset(state, 0, sizeof(*state));
}

static void kzt_xcb_thread_key_init(void)
{
    kzt_xcb_thread_key_status = pthread_key_create(
        &kzt_xcb_thread_key, kzt_xcb_thread_leases_destroy);
}

static int kzt_xcb_thread_leases_register(
    kzt_xcb_thread_leases_t *state)
{
    (void)pthread_once(&kzt_xcb_thread_key_once, kzt_xcb_thread_key_init);
    if (kzt_xcb_thread_key_status != 0) {
        return -1;
    }
    if (!state->registered) {
        if (pthread_setspecific(kzt_xcb_thread_key, state) != 0) {
            return -1;
        }
        state->registered = 1;
    }
    return 0;
}

static void kzt_xcb_pending_release(kzt_xcb_thread_leases_t *state)
{
    if (!state->pending.valid) {
        return;
    }
    kzt_xcb_release_lease(&state->pending.lease);
    memset(&state->pending, 0, sizeof(state->pending));
}

static int kzt_xcb_active_push(
    kzt_xcb_thread_leases_t *state,
    const kzt_xcb_connection_lease_t *lease)
{
    if (state->active_count == KZT_XCB_ACTIVE_LEASE_DEPTH) {
        return -1;
    }
    state->active[state->active_count++] = *lease;
    return 0;
}

void kzt_xcb_connection_guard_cancel(void)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    int old_state = kzt_xcb_cancel_disable();

    kzt_xcb_pending_release(state);
    kzt_xcb_cancel_restore(old_state);
}

int kzt_xcb_connection_guard_prepare(
    kzt_xcb_connection_map_t *map, void *guest)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    kzt_xcb_pending_guard_t *pending = &state->pending;
    int old_state = kzt_xcb_cancel_disable();
    int result = -1;

    if (kzt_xcb_thread_leases_register(state) != 0) {
        goto out;
    }
    kzt_xcb_pending_release(state);
    if (map && guest &&
        kzt_xcb_connection_map_acquire_by_guest(
            map, guest, &pending->lease) == 0) {
        pending->map = map;
        pending->valid = 1;
        result = 0;
    }
out:
    kzt_xcb_cancel_restore(old_state);
    return result;
}

int kzt_xcb_connection_guard_take(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    kzt_xcb_pending_guard_t *pending = &state->pending;
    int old_state = kzt_xcb_cancel_disable();
    int result = -1;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!map || !guest || !lease || !pending->valid ||
        pending->map != map || pending->lease.guest != guest) {
        goto out;
    }
    if (kzt_xcb_thread_leases_register(state) != 0 ||
        kzt_xcb_active_push(state, &pending->lease) != 0) {
        goto out;
    }
    *lease = pending->lease;
    memset(pending, 0, sizeof(*pending));
    result = 0;
out:
    kzt_xcb_cancel_restore(old_state);
    return result;
}

int kzt_xcb_connection_guard_acquire(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    kzt_xcb_pending_guard_t *pending = &state->pending;
    kzt_xcb_connection_lease_t acquired = { 0 };
    int old_state = kzt_xcb_cancel_disable();
    int result = -1;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!map || !guest || !lease ||
        kzt_xcb_thread_leases_register(state) != 0) {
        goto out;
    }
    if (state->active_count == KZT_XCB_ACTIVE_LEASE_DEPTH) {
        kzt_xcb_pending_release(state);
        goto out;
    }
    if (pending->valid) {
        if (pending->map != map || pending->lease.guest != guest) {
            kzt_xcb_pending_release(state);
            goto out;
        }
        acquired = pending->lease;
        memset(pending, 0, sizeof(*pending));
    } else if (kzt_xcb_connection_map_acquire_by_guest(
                   map, guest, &acquired) != 0) {
        goto out;
    }
    if (kzt_xcb_active_push(state, &acquired) != 0) {
        kzt_xcb_release_lease(&acquired);
        goto out;
    }
    *lease = acquired;
    result = 0;
out:
    kzt_xcb_cancel_restore(old_state);
    return result;
}

int kzt_xcb_connection_guard_release(
    kzt_xcb_connection_map_t *map, void *native, void *guest)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    kzt_xcb_connection_lease_t lease;
    size_t index;
    int old_state = kzt_xcb_cancel_disable();
    int result = -1;

    if (!map || !native || !guest) {
        goto out;
    }
    for (index = state->active_count; index; --index) {
        lease = state->active[index - 1];
        if (lease._map != map || lease.native != native ||
            lease.guest != guest) {
            continue;
        }
        --state->active_count;
        if (index - 1 != state->active_count) {
            memmove(&state->active[index - 1], &state->active[index],
                    (state->active_count - (index - 1)) *
                        sizeof(state->active[0]));
        }
        memset(&state->active[state->active_count], 0,
               sizeof(state->active[0]));
        kzt_xcb_release_lease(&lease);
        result = 0;
        break;
    }
out:
    kzt_xcb_cancel_restore(old_state);
    return result;
}

int kzt_xcb_connection_guard_active_lease(
    kzt_xcb_connection_map_t *map, void *native, void *guest,
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_thread_leases_t *state = &kzt_xcb_thread_leases;
    size_t index;
    int old_state = kzt_xcb_cancel_disable();
    int result = -1;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!map || !native || !guest || !lease) {
        goto out;
    }
    for (index = state->active_count; index; --index) {
        if (state->active[index - 1]._map == map &&
            state->active[index - 1].native == native &&
            state->active[index - 1].guest == guest) {
            *lease = state->active[index - 1];
            result = 0;
            break;
        }
    }
out:
    kzt_xcb_cancel_restore(old_state);
    return result;
}
