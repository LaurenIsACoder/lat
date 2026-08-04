#include "kzt_guest_runtime_entry_state.h"

#include <pthread.h>
#include <sched.h>

static const char *const kzt_guest_runtime_entry_symbols[] = {
    [KZT_GUEST_RUNTIME_FREE] = "free",
    [KZT_GUEST_RUNTIME_REALLOC] = "realloc",
    [KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE] = "pthread_setcanceltype",
};

int kzt_guest_dl_entry_state_enter(kzt_guest_dl_entry_state_t *state)
{
    unsigned int lifecycle;

    if (!state) {
        return -1;
    }
    lifecycle = __atomic_load_n(&state->lifecycle, __ATOMIC_ACQUIRE);
    for (;;) {
        if (!(lifecycle & KZT_GUEST_DL_LIFECYCLE_OPEN) ||
            (lifecycle & KZT_GUEST_DL_LIFECYCLE_USERS) ==
                KZT_GUEST_DL_LIFECYCLE_USERS) {
            return -1;
        }
        if (__atomic_compare_exchange_n(
                &state->lifecycle, &lifecycle, lifecycle + 1, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            return 0;
        }
    }
}

void kzt_guest_dl_entry_state_leave_locked(
    kzt_guest_dl_entry_state_t *state)
{
    unsigned int previous = __atomic_fetch_sub(
        &state->lifecycle, 1, __ATOMIC_RELEASE);

    if ((previous & KZT_GUEST_DL_LIFECYCLE_USERS) == 1) {
        pthread_cond_broadcast(&state->ready);
    }
}

static void kzt_guest_runtime_entry_slow_leave(
    kzt_guest_dl_entry_state_t *state)
{
    if (state->slow_users) {
        --state->slow_users;
    }
    pthread_cond_broadcast(&state->ready);
}

uintptr_t kzt_guest_runtime_entry_state_ensure(
    kzt_guest_dl_entry_state_t *state,
    kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_resolver_fn resolver, void *opaque)
{
    uintptr_t address;
    unsigned int bit;

    if (!state || !resolver || entry < 0 ||
        entry >= KZT_GUEST_RUNTIME_ENTRY_COUNT ||
        kzt_guest_dl_entry_state_enter(state) != 0) {
        return 0;
    }

    bit = 1U << entry;
    pthread_mutex_lock(&state->mutex);
    if (state->teardown) {
        kzt_guest_dl_entry_state_leave_locked(state);
        pthread_mutex_unlock(&state->mutex);
        return 0;
    }
    ++state->slow_users;
    for (;;) {
        address = kzt_guest_runtime_entry_state_load(state, entry);
        if (address || state->teardown) {
            kzt_guest_runtime_entry_slow_leave(state);
            kzt_guest_dl_entry_state_leave_locked(state);
            pthread_mutex_unlock(&state->mutex);
            return state->teardown ? 0 : address;
        }
        if (!(state->runtime_initializing & bit)) {
            state->runtime_initializing |= bit;
            state->runtime_initializers[entry] = pthread_self();
            break;
        }
        if (pthread_equal(
                state->runtime_initializers[entry], pthread_self())) {
            kzt_guest_runtime_entry_slow_leave(state);
            kzt_guest_dl_entry_state_leave_locked(state);
            pthread_mutex_unlock(&state->mutex);
            return 0;
        }
        pthread_cond_wait(&state->ready, &state->mutex);
    }
    pthread_mutex_unlock(&state->mutex);

    address = resolver(kzt_guest_runtime_entry_symbols[entry], opaque);

    pthread_mutex_lock(&state->mutex);
    if (!state->teardown && address) {
        uintptr_t expected = 0;

        (void)__atomic_compare_exchange_n(
            &state->runtime_entries[entry], &expected, address, 0,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
    }
    state->runtime_initializing &= ~bit;
    address = state->teardown
                  ? 0
                  : kzt_guest_runtime_entry_state_load(state, entry);
    kzt_guest_runtime_entry_slow_leave(state);
    kzt_guest_dl_entry_state_leave_locked(state);
    pthread_mutex_unlock(&state->mutex);
    return address;
}

int kzt_guest_runtime_entry_state_publish(
    kzt_guest_dl_entry_state_t *state,
    const uintptr_t entries[KZT_GUEST_RUNTIME_ENTRY_COUNT])
{
    int entry;
    int result = -1;

    if (!entries || kzt_guest_dl_entry_state_enter(state) != 0) {
        return -1;
    }
    pthread_mutex_lock(&state->mutex);
    if (!state->teardown) {
        for (entry = 0; entry < KZT_GUEST_RUNTIME_ENTRY_COUNT; ++entry) {
            if (!entries[entry]) {
                goto out;
            }
        }
        for (entry = 0; entry < KZT_GUEST_RUNTIME_ENTRY_COUNT; ++entry) {
            __atomic_store_n(
                &state->runtime_entries[entry], entries[entry],
                __ATOMIC_RELEASE);
        }
        result = 0;
    }
out:
    kzt_guest_dl_entry_state_leave_locked(state);
    pthread_mutex_unlock(&state->mutex);
    return result;
}

int kzt_guest_runtime_entry_state_acquire(
    kzt_guest_dl_entry_state_t *state,
    kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_scope_t *scope)
{
    uintptr_t address;

    if (scope) {
        *scope = (kzt_guest_runtime_entry_scope_t) { 0 };
    }
    if (!state || !scope || entry < 0 ||
        entry >= KZT_GUEST_RUNTIME_ENTRY_COUNT ||
        kzt_guest_dl_entry_state_enter(state) != 0) {
        return -1;
    }
    pthread_mutex_lock(&state->mutex);
    address = state->teardown
                  ? 0
                  : kzt_guest_runtime_entry_state_load(state, entry);
    if (address) {
        ++state->runtime_users;
        scope->state = state;
        scope->address = address;
    }
    kzt_guest_dl_entry_state_leave_locked(state);
    pthread_mutex_unlock(&state->mutex);
    return address ? 0 : -1;
}

void kzt_guest_runtime_entry_state_release(
    kzt_guest_runtime_entry_scope_t *scope)
{
    kzt_guest_dl_entry_state_t *state;

    if (!scope || !(state = scope->state)) {
        return;
    }
    pthread_mutex_lock(&state->mutex);
    if (state->runtime_users) {
        --state->runtime_users;
    }
    pthread_cond_broadcast(&state->ready);
    pthread_mutex_unlock(&state->mutex);
    *scope = (kzt_guest_runtime_entry_scope_t) { 0 };
}

void kzt_guest_runtime_entry_state_begin_teardown(
    kzt_guest_dl_entry_state_t *state)
{
    unsigned int lifecycle;
    int entry;

    if (!state) {
        return;
    }
    lifecycle = __atomic_load_n(&state->lifecycle, __ATOMIC_ACQUIRE);
    for (;;) {
        unsigned int closing;

        if (!(lifecycle & KZT_GUEST_DL_LIFECYCLE_OPEN)) {
            while (lifecycle & KZT_GUEST_DL_LIFECYCLE_CLOSING) {
                sched_yield();
                lifecycle = __atomic_load_n(
                    &state->lifecycle, __ATOMIC_ACQUIRE);
            }
            return;
        }
        closing = (lifecycle & KZT_GUEST_DL_LIFECYCLE_USERS) |
                  KZT_GUEST_DL_LIFECYCLE_CLOSING;
        if (__atomic_compare_exchange_n(
                &state->lifecycle, &lifecycle, closing, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            break;
        }
    }
    pthread_mutex_lock(&state->mutex);
    state->teardown = 1;
    pthread_cond_broadcast(&state->ready);
    while (state->initializing || state->slow_users ||
           state->runtime_users ||
           (__atomic_load_n(&state->lifecycle, __ATOMIC_ACQUIRE) &
            KZT_GUEST_DL_LIFECYCLE_USERS)) {
        pthread_cond_wait(&state->ready, &state->mutex);
    }
    for (entry = 0; entry < KZT_GUEST_RUNTIME_ENTRY_COUNT; ++entry) {
        __atomic_store_n(
            &state->runtime_entries[entry], 0, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&state->mutex);
    __atomic_store_n(&state->lifecycle, 0, __ATOMIC_RELEASE);
}
