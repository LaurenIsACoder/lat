#ifndef KZT_GUEST_DL_API_H
#define KZT_GUEST_DL_API_H

#include <stdint.h>

#include "box64context.h"
#include "kzt_guest_registry.h"
#include "kzt_loader_callback_scope.h"

typedef struct kzt_guest_dl_symbol_result_s {
    uintptr_t value;
    int forward_to_guest_caller;
} kzt_guest_dl_symbol_result_t;

typedef struct kzt_guest_dlerror_result_s {
    char *value;
    int forward_to_guest_caller;
} kzt_guest_dlerror_result_t;

void kzt_guest_dl_api_clear_error(kzt_guest_dlerror_state_t *state);

extern __thread uintptr_t kzt_guest_dlerror_fast_result_tls;

static inline uintptr_t kzt_guest_dl_api_current_fast_result(void)
{
    return kzt_guest_dlerror_fast_result_tls;
}

static inline void kzt_guest_dl_api_set_slow_required(
    kzt_guest_dlerror_state_t *state, int required)
{
    if (!state) {
        return;
    }
    state->dlerror_slow_required = required;
    if (state->dlerror_fast_result_mirror) {
        *state->dlerror_fast_result_mirror = state->dlerror_fast_result;
    }
}

static inline int kzt_guest_dl_api_dlerror_needs_slow_path(
    const kzt_guest_dlerror_state_t *state)
{
    return !state || state->dlerror_fast_result;
}

static inline int kzt_guest_dl_api_begin_call(
    kzt_guest_dlerror_state_t *state)
{
    int was_clean = state && !state->dlerror_fast_result;

    kzt_guest_dl_api_clear_error(state);
    return was_clean;
}

static inline void kzt_guest_dl_api_finish_success(
    kzt_guest_dlerror_state_t *state, int was_clean)
{
    if (state && was_clean) {
        kzt_guest_dl_api_set_slow_required(state, 0);
    }
}

void kzt_guest_dl_api_bind_current_thread(kzt_guest_dlerror_state_t *state);

void kzt_guest_dl_api_free_errors(kzt_guest_dlerror_state_t *state);
int kzt_guest_dl_api_entry_state_init(dlprivate_t *dl);
void kzt_guest_dl_api_entry_state_destroy(dlprivate_t *dl);
static inline const kzt_guest_dl_entries_t *
kzt_guest_dl_api_load_entries(dlprivate_t *dl)
{
    return dl ? __atomic_load_n(
                    &dl->guest_dl_entries.published, __ATOMIC_ACQUIRE) : NULL;
}
static inline uintptr_t kzt_guest_dl_api_load_dlerror_hint(dlprivate_t *dl)
{
    return dl ? __atomic_load_n(
                    &dl->guest_dl_entries.observed_dlerror,
                    __ATOMIC_RELAXED) : 0;
}
const kzt_guest_dl_entries_t *kzt_guest_dl_api_ensure_entries(
    dlprivate_t *dl, kzt_guest_dl_entries_resolver_fn resolver, void *opaque,
    kzt_guest_dl_entries_t *fallback, int *published_now);
const kzt_guest_dl_entries_t *kzt_guest_dl_api_ensure_entries_prepared(
    dlprivate_t *dl, kzt_guest_dl_entries_resolver_fn resolver,
    kzt_guest_dl_entries_prepare_fn prepare, void *opaque,
    kzt_guest_dl_entries_t *fallback, int *published_now);
uintptr_t kzt_guest_dl_api_load_dlerror_entry(dlprivate_t *dl);
int kzt_guest_dl_api_publish_dlerror_entry(
    dlprivate_t *dl, const char *symbol, uintptr_t guest_entry,
    int custom_wrapper);

uint64_t kzt_guest_dl_api_dlopen(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    const kzt_guest_dl_entries_t *entries,
    kzt_guest_dlerror_state_t *error_state,
    const void *filename, int flag);
int kzt_guest_dl_api_dlclose(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    const kzt_guest_dl_entries_t *entries, void *handle);
int kzt_guest_dl_api_publish_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity);
int kzt_guest_dl_api_prepare_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity);
int kzt_guest_dl_api_cancel_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity);
uint64_t kzt_guest_dl_api_dlmopen(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *lmid, void *filename, int flag);
kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *handle, void *symbol);
kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlvsym(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *handle, void *symbol, const char *version);
kzt_guest_dlerror_result_t kzt_guest_dl_api_dlerror(
    kzt_guest_dlerror_state_t *state, uintptr_t guest_dlerror);
int kzt_guest_dl_api_dlinfo(
    const kzt_guest_dl_entries_t *entries,
    void *handle, int request, void *info);

#endif
