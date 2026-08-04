#include "kzt_guest_dl_api.h"

#include <string.h>

#include "box64context.h"
#include "debug.h"
#include "elfloader.h"
#include "kzt_guest_library_adapter.h"
#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"
#include "kzt_guest_runtime_entry_state.h"
#include "kzt_lifecycle_diagnostics.h"
#ifdef CONFIG_LATX_KZT
#include "kzt_jump_slot_production.h"
#endif
#include "librarian.h"
#include "library.h"
#include "library_private.h"

void kzt_guest_dl_api_bind_current_thread(kzt_guest_dlerror_state_t *state)
{
    if (!state) {
        kzt_guest_dlerror_fast_result_tls = 1;
        return;
    }
    state->dlerror_fast_result_mirror =
        &kzt_guest_dlerror_fast_result_tls;
    kzt_guest_dlerror_fast_result_tls = state->dlerror_fast_result;
}

#define KZT_GUEST_RTLD_NEXT ((void *)~0ULL)
#define KZT_GUEST_RTLD_NODELETE 0x1000
#define KZT_GUEST_RTLD_DI_LMID 1
#define KZT_GUEST_RTLD_DI_LINKMAP 2

static int kzt_guest_dl_entries_complete(
    const kzt_guest_dl_entries_t *entries)
{
    return entries && entries->dlopen && entries->dlmopen &&
           entries->dlsym && entries->dlclose && entries->dladdr &&
           entries->dladdr1 && entries->dlinfo && entries->dlvsym &&
           entries->dlerror;
}

int kzt_guest_dl_api_entry_state_init(dlprivate_t *dl)
{
    kzt_guest_dl_entry_state_t *state;

    if (!dl) {
        return -1;
    }
    state = &dl->guest_dl_entries;
    if (state->initialized) {
        return 0;
    }
    memset(state, 0, sizeof(*state));
    if (pthread_mutex_init(&state->mutex, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&state->ready, NULL) != 0) {
        pthread_mutex_destroy(&state->mutex);
        return -1;
    }
    __atomic_store_n(
        &state->lifecycle, KZT_GUEST_DL_LIFECYCLE_OPEN,
        __ATOMIC_RELEASE);
    __atomic_store_n(&state->initialized, 1, __ATOMIC_RELEASE);
    return 0;
}

static void kzt_guest_dl_entry_slow_leave(
    kzt_guest_dl_entry_state_t *state)
{
    if (state->slow_users) {
        --state->slow_users;
    }
    pthread_cond_broadcast(&state->ready);
}

const kzt_guest_dl_entries_t *kzt_guest_dl_api_ensure_entries_prepared(
    dlprivate_t *dl, kzt_guest_dl_entries_resolver_fn resolver,
    kzt_guest_dl_entries_prepare_fn prepare, void *opaque,
    kzt_guest_dl_entries_t *fallback, int *published_now)
{
    kzt_guest_dl_entry_state_t *state;
    const kzt_guest_dl_entries_t *published;
    kzt_guest_dl_entries_t local = { 0 };
    kzt_guest_dl_entries_t *candidate = NULL;
    uintptr_t observed_dlerror;
    int prepared = 1;
    int resolved;

    if (published_now) {
        *published_now = 0;
    }
    if (!dl || !resolver || !fallback) {
        return NULL;
    }
    state = &dl->guest_dl_entries;
    if (kzt_guest_dl_entry_state_enter(state) != 0) {
        return NULL;
    }
    published = kzt_guest_dl_api_load_entries(dl);
    if (published) {
        pthread_mutex_lock(&state->mutex);
        kzt_guest_dl_entry_state_leave_locked(state);
        pthread_mutex_unlock(&state->mutex);
        return published;
    }
    memset(fallback, 0, sizeof(*fallback));

    pthread_mutex_lock(&state->mutex);
    if (state->teardown) {
        kzt_guest_dl_entry_state_leave_locked(state);
        pthread_mutex_unlock(&state->mutex);
        return NULL;
    }
    ++state->slow_users;
    for (;;) {
        published = kzt_guest_dl_api_load_entries(dl);
        if (published || state->teardown) {
            kzt_guest_dl_entry_slow_leave(state);
            kzt_guest_dl_entry_state_leave_locked(state);
            pthread_mutex_unlock(&state->mutex);
            return published;
        }
        if (!state->initializing) {
            state->initializing = 1;
            state->initializer = pthread_self();
            state->initializer_valid = 1;
            break;
        }
        if (state->initializer_valid &&
            pthread_equal(state->initializer, pthread_self())) {
            kzt_guest_dl_entry_slow_leave(state);
            kzt_guest_dl_entry_state_leave_locked(state);
            pthread_mutex_unlock(&state->mutex);
            return NULL;
        }
        pthread_cond_wait(&state->ready, &state->mutex);
    }
    pthread_mutex_unlock(&state->mutex);

    resolved = resolver(&local, opaque);
    *fallback = local;
    if (resolved == 0 && kzt_guest_dl_entries_complete(&local)) {
        candidate = box_malloc(sizeof(*candidate));
        if (candidate) {
            *candidate = local;
        }
    }

    pthread_mutex_lock(&state->mutex);
    observed_dlerror = __atomic_load_n(
        &state->observed_dlerror, __ATOMIC_RELAXED);
    if (!state->teardown && candidate &&
        (!observed_dlerror || observed_dlerror == candidate->dlerror)) {
        if (!observed_dlerror) {
            __atomic_store_n(
                &state->observed_dlerror, candidate->dlerror,
                __ATOMIC_RELEASE);
        }
        if (prepare) {
            pthread_mutex_unlock(&state->mutex);
            prepared = prepare(candidate, opaque) == 0;
            pthread_mutex_lock(&state->mutex);
        }
        observed_dlerror = __atomic_load_n(
            &state->observed_dlerror, __ATOMIC_RELAXED);
        if (!state->teardown && prepared &&
            observed_dlerror == candidate->dlerror) {
            __atomic_store_n(
                &state->published, candidate, __ATOMIC_RELEASE);
            if (published_now) {
                *published_now = 1;
            }
            candidate = NULL;
        }
    }
    state->initializing = 0;
    state->initializer_valid = 0;
    published = kzt_guest_dl_api_load_entries(dl);
    kzt_guest_dl_entry_slow_leave(state);
    kzt_guest_dl_entry_state_leave_locked(state);
    pthread_mutex_unlock(&state->mutex);
    box_free(candidate);
    return published ? published : fallback;
}

const kzt_guest_dl_entries_t *kzt_guest_dl_api_ensure_entries(
    dlprivate_t *dl, kzt_guest_dl_entries_resolver_fn resolver, void *opaque,
    kzt_guest_dl_entries_t *fallback, int *published_now)
{
    return kzt_guest_dl_api_ensure_entries_prepared(
        dl, resolver, NULL, opaque, fallback, published_now);
}

void kzt_guest_dl_api_entry_state_begin_teardown(dlprivate_t *dl)
{
    kzt_guest_dl_entry_state_t *state;
    kzt_guest_dl_entries_t *published;

    if (!dl) {
        return;
    }
    state = &dl->guest_dl_entries;
    kzt_guest_runtime_entry_state_begin_teardown(state);
    published = __atomic_exchange_n(
        &state->published, NULL, __ATOMIC_ACQ_REL);
    box_free(published);
}

void kzt_guest_dl_api_entry_state_destroy(dlprivate_t *dl)
{
    kzt_guest_dl_entry_state_t *state;

    if (!dl || !__atomic_exchange_n(
                   &dl->guest_dl_entries.initialized, 0,
                   __ATOMIC_ACQ_REL)) {
        return;
    }
    state = &dl->guest_dl_entries;
    kzt_guest_dl_api_entry_state_begin_teardown(dl);
    pthread_cond_destroy(&state->ready);
    pthread_mutex_destroy(&state->mutex);
    memset(state, 0, sizeof(*state));
}

#ifdef CONFIG_LATX_KZT
extern int option_kzt;
extern int wine_option_kzt;

static int kzt_guest_dl_api_enabled(void)
{
    return option_kzt || wine_option_kzt;
}

static void kzt_guest_dl_api_discard_internal_error(
    const kzt_guest_dl_entries_t *entries)
{
    if (entries && entries->dlerror) {
        (void)kzt_guest_library_run_dlerror(entries->dlerror);
    }
}

static int kzt_guest_dl_api_query_identity(
    const kzt_guest_dl_entries_t *entries, uintptr_t handle,
    kzt_guest_loader_identity_t *identity)
{
    uintptr_t link_map_addr = 0;
    uintptr_t namespace_id = 0;

    if (identity) {
        memset(identity, 0, sizeof(*identity));
    }
    if (!entries || !handle || !identity || !entries->dlinfo ||
        !kzt_guest_dl_api_enabled()) {
        return -1;
    }
    if (kzt_guest_library_run_dlinfo(
            entries->dlinfo, (void *)handle,
            KZT_GUEST_RTLD_DI_LINKMAP, &link_map_addr) != 0) {
        kzt_guest_dl_api_discard_internal_error(entries);
        return -1;
    }
    if (!link_map_addr) {
        return -1;
    }
    if (kzt_guest_library_run_dlinfo(
            entries->dlinfo, (void *)handle,
            KZT_GUEST_RTLD_DI_LMID, &namespace_id) != 0) {
        kzt_guest_dl_api_discard_internal_error(entries);
        return -1;
    }

    identity->handle = handle;
    identity->link_map_addr = link_map_addr;
    identity->namespace_id = namespace_id;
    return 0;
}
#endif

#ifdef CONFIG_LATX_KZT
static int kzt_guest_dl_api_prepare_prebind_target(
    uintptr_t target, void *opaque)
{
    (void)opaque;
    return KztPrebindTargetTbPrepare(target);
}
#endif

static void kzt_guest_dl_api_finish_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *call_scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof, int publish)
{
#ifdef CONFIG_LATX_KZT
    if (call_scope && call_scope->prebind_refresh_pending) {
        uint64_t refresh_start = kzt_lifecycle_diagnostics_enabled()
                                     ? kzt_lifecycle_diagnostics_now()
                                     : 0;

        kzt_production_lazy_prebind_refresh(
            context, kzt_guest_dl_api_prepare_prebind_target, NULL);
        if (refresh_start) {
            kzt_lifecycle_diagnostics_add(
                KZT_LIFECYCLE_SCOPED_PREBIND_REFRESH,
                kzt_lifecycle_diagnostics_now() - refresh_start);
        }
        call_scope->prebind_refresh_pending = 0;
    }
#endif
    kzt_guest_library_finish_dlopen_scoped(
        context, call_scope, link_map_addr, library, proof, publish);
}

int kzt_guest_dl_api_publish_dlerror_entry(
    dlprivate_t *dl, const char *symbol, uintptr_t guest_entry,
    int custom_wrapper)
{
    kzt_guest_dl_entry_state_t *state;
    const kzt_guest_dl_entries_t *entries;
    uintptr_t expected = 0;
    int result;

    if (!dl || !symbol || strcmp(symbol, "dlerror") != 0 ||
        !guest_entry || !custom_wrapper) {
        return -1;
    }
    state = &dl->guest_dl_entries;
    if (state->initialized) {
        pthread_mutex_lock(&state->mutex);
        if (state->teardown) {
            pthread_mutex_unlock(&state->mutex);
            return -1;
        }
    }
    entries = kzt_guest_dl_api_load_entries(dl);
    if (entries && entries->dlerror != guest_entry) {
        result = -1;
    } else if (__atomic_compare_exchange_n(
            &dl->guest_dl_entries.observed_dlerror, &expected, guest_entry, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        result = 0;
    } else {
        result = expected == guest_entry ? 0 : -1;
    }
    if (state->initialized) {
        pthread_mutex_unlock(&state->mutex);
    }
    return result;
}

uintptr_t kzt_guest_dl_api_load_dlerror_entry(dlprivate_t *dl)
{
    const kzt_guest_dl_entries_t *entries;
    uintptr_t observed;

    if (!dl) {
        return 0;
    }
    observed = __atomic_load_n(
        &dl->guest_dl_entries.observed_dlerror, __ATOMIC_RELAXED);
    if (observed) {
        return observed;
    }
    entries = kzt_guest_dl_api_load_entries(dl);
    return entries ? entries->dlerror : 0;
}

static void kzt_guest_dl_api_capture_guest_error(
    const kzt_guest_dl_entries_t *entries,
    kzt_guest_dlerror_state_t *state)
{
    const char *guest_error;
    const char fallback[] = "guest dlopen failed";
    char *captured;
    size_t length;
    uintptr_t guest_dlerror = entries ? entries->dlerror : 0;

    guest_error = NULL;
    if (guest_dlerror) {
        guest_error = (const char *)(uintptr_t)kzt_guest_library_run_dlerror(
            guest_dlerror);
    }
    if (!guest_error) {
        guest_error = fallback;
    }
    length = strlen(guest_error) + 1;
    captured = box_malloc(length);
    if (!captured) {
        return;
    }
    memcpy(captured, guest_error, length);
    box_free(state->last_error);
    state->last_error = captured;
    state->last_error_guest_consumed = guest_dlerror != 0;
}

void kzt_guest_dl_api_clear_error(kzt_guest_dlerror_state_t *state)
{
    if (!state) {
        return;
    }
    box_free(state->last_error);
    state->last_error = NULL;
    box_free(state->last_error_returned);
    state->last_error_returned = NULL;
    state->last_error_guest_consumed = 0;
    kzt_guest_dl_api_set_slow_required(state, 1);
}

void kzt_guest_dl_api_free_errors(kzt_guest_dlerror_state_t *state)
{
    if (!state) {
        return;
    }
    box_free(state->last_error);
    box_free(state->last_error_returned);
    memset(state, 0, sizeof(*state));
}

uint64_t kzt_guest_dl_api_dlopen(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    const kzt_guest_dl_entries_t *entries,
    kzt_guest_dlerror_state_t *error_state,
    const void *filename, int flag)
{
    kzt_guest_library_loader_scope_t call_scope = { 0 };
    kzt_guest_wrapper_source_proof_t source_proof = { 0 };
    const char *path = filename;
    const char *name;
    library_t *library = NULL;
    uint64_t guest_handle;
    uint64_t timing_start = 0;
    uintptr_t exact_link_map = 0;
    int have_exact_identity = 0;
    int is_local;
    int bind_now;
    int source_proven = 0;
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_binding_result_t binding_claim =
        KZT_GUEST_LIBRARY_BINDING_ERROR;
#endif

#ifdef CONFIG_LATX_KZT
    (void)kzt_production_lazy_prebind_invalidate(
        context, KZT_LAZY_PREBIND_MUTATION_DLOPEN);
#endif
    if (kzt_lifecycle_diagnostics_enabled()) {
        timing_start = kzt_lifecycle_diagnostics_now();
    }
    guest_handle = kzt_guest_library_run_dlopen_scoped(
        context, thread_scope, entries->dlopen,
        (void *)filename, flag, &call_scope);
    if (timing_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_GUEST_DLOPEN,
            kzt_lifecycle_diagnostics_now() - timing_start);
        timing_start = kzt_lifecycle_diagnostics_now();
    }
    if (!guest_handle) {
        kzt_guest_dl_api_finish_dlopen_scoped(
            context, &call_scope, 0, NULL, NULL, 0);
        kzt_guest_dl_api_capture_guest_error(entries, error_state);
        if (timing_start) {
            kzt_lifecycle_diagnostics_add(
                KZT_LIFECYCLE_DLOPEN_FINISH,
                kzt_lifecycle_diagnostics_now() - timing_start);
        }
        return guest_handle;
    }

#ifdef CONFIG_LATX_KZT
    if (!kzt_guest_dl_api_enabled()) {
        exact_link_map = guest_handle;
        have_exact_identity = 1;
    } else {
        kzt_guest_loader_identity_t identity;
        kzt_guest_registry_t *registry =
            KztGuestRegistryForContext(context);

        if (registry &&
            (kzt_guest_registry_reuse_loader_identity(
                 registry, guest_handle, &identity) == 0 ||
             (kzt_guest_dl_api_query_identity(
                  entries, guest_handle, &identity) == 0 &&
              kzt_guest_registry_publish_loader_identity(
                  registry, identity.handle, identity.link_map_addr,
                  identity.namespace_id, &identity) == 0))) {
            exact_link_map = identity.link_map_addr;
            have_exact_identity = 1;
            if (flag & KZT_GUEST_RTLD_NODELETE) {
                (void)kzt_guest_registry_mark_loader_resident(
                    registry, &identity);
            }
        }
    }
#else
    exact_link_map = guest_handle;
    have_exact_identity = 1;
#endif

    if (!path) {
        kzt_guest_dl_api_finish_dlopen_scoped(
            context, &call_scope, exact_link_map, NULL,
            NULL, have_exact_identity);
        if (timing_start) {
            kzt_lifecycle_diagnostics_add(
                KZT_LIFECYCLE_DLOPEN_FINISH,
                kzt_lifecycle_diagnostics_now() - timing_start);
        }
        return guest_handle;
    }
    name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (!FindLibIsWrapped((char *)name)) {
        kzt_guest_dl_api_finish_dlopen_scoped(
            context, &call_scope, exact_link_map, NULL,
            NULL, have_exact_identity);
        if (timing_start) {
            kzt_lifecycle_diagnostics_add(
                KZT_LIFECYCLE_DLOPEN_FINISH,
                kzt_lifecycle_diagnostics_now() - timing_start);
        }
        return guest_handle;
    }

    context->deferedInit = 1;
    is_local = (flag & 0x100) ? 0 : 1;
    bind_now = (flag & 0x2) ? 1 : 0;
    source_proven = have_exact_identity &&
        (!kzt_guest_dl_api_enabled() ||
         kzt_guest_library_wrapper_source_acquire(
             context, exact_link_map, path, name, &source_proof) == 0);
    if (have_exact_identity && source_proven && AddNeededLibWithLibrary(
            NULL, NULL, NULL, is_local, bind_now, name, context,
            &library) == 0 &&
        library) {
        if (library->type != LIB_WRAPPED) {
            library = NULL;
        }
#ifdef CONFIG_LATX_KZT
        if (library && kzt_guest_dl_api_enabled()) {
            binding_claim = kzt_guest_library_note_loader_pair(
                context, exact_link_map, library, &source_proof);
            if (binding_claim != KZT_GUEST_LIBRARY_BINDING_ADDED &&
                binding_claim != KZT_GUEST_LIBRARY_BINDING_UNCHANGED) {
                library = NULL;
            }
        }
#endif
    }
    if (library) {
        library->x86linkmap =
            (struct link_map *)(uintptr_t)exact_link_map;
    }
    kzt_guest_dl_api_finish_dlopen_scoped(
        context, &call_scope, exact_link_map, library,
        library ? &source_proof : NULL, have_exact_identity);
    kzt_guest_library_wrapper_source_release(&source_proof);
    if (timing_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_DLOPEN_FINISH,
            kzt_lifecycle_diagnostics_now() - timing_start);
    }
    return guest_handle;
}

int kzt_guest_dl_api_dlclose(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    const kzt_guest_dl_entries_t *entries, void *handle)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_registry_t *registry = NULL;
    kzt_guest_loader_identity_t identity = { 0 };
    kzt_guest_library_loader_quiescence_writer_t writer = { 0 };
    int have_exact_identity = 0;
    int kzt_enabled = 0;
#endif
    int guest_result;
    uint64_t timing_start = 0;

#ifdef CONFIG_LATX_KZT
    if (context) {
        kzt_enabled = kzt_guest_dl_api_enabled();
        if (kzt_enabled) {
            (void)kzt_guest_library_loader_quiescence_writer_begin(
                KztGuestLibraryBindingsForContext(context), &writer);
        }
        (void)kzt_production_lazy_prebind_invalidate(
            context, KZT_LAZY_PREBIND_MUTATION_DLCLOSE);
        if (kzt_enabled) {
            registry = KztGuestRegistryForContext(context);
            have_exact_identity = registry &&
                kzt_guest_registry_find_loader_identity(
                    registry, (uintptr_t)handle, &identity) == 0;
        }
    }
#else
    (void)context;
#endif
    (void)thread_scope;
    if (kzt_lifecycle_diagnostics_enabled()) {
        timing_start = kzt_lifecycle_diagnostics_now();
    }
    guest_result = kzt_guest_library_run_dlclose(
        entries->dlclose, handle);
    if (timing_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_GUEST_DLCLOSE,
            kzt_lifecycle_diagnostics_now() - timing_start);
    }
    if (guest_result != 0) {
        goto out;
    }

#ifdef CONFIG_LATX_KZT
    if (have_exact_identity) {
        (void)kzt_guest_registry_complete_loader_close(
            registry, &identity);
    } else if (registry) {
        kzt_guest_registry_note_loader_close_identity_missing(registry);
    }
#endif

out:
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_loader_quiescence_writer_end(&writer);
#endif
    return guest_result;
}

#ifdef CONFIG_LATX_KZT
static void kzt_guest_dl_api_cleanup_exact_library(
    library_t *library, void *opaque)
{
    uintptr_t link_map_addr = (uintptr_t)opaque;

    if (!library) {
        return;
    }
    library->active = 0;
    if ((uintptr_t)library->x86linkmap == link_map_addr) {
        library->x86linkmap = NULL;
    }
}
#endif

int kzt_guest_dl_api_publish_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_registry_t *registry;
    kzt_guest_loader_identity_t current = { 0 };
    kzt_guest_lazy_resolver_t lazy_resolver = { 0 };
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t binding = { 0 };
    uint64_t retire_start;
    int retire_result;

    if (!context || !identity || !identity->link_map_addr ||
        !identity->generation || !kzt_guest_dl_api_enabled()) {
        return -1;
    }
    registry = KztGuestRegistryForContext(context);
    if (!registry ||
        kzt_guest_registry_find_loader_object_identity(
            registry, identity->link_map_addr, &current) != 0 ||
        current.generation != identity->generation ||
        current.namespace_id != identity->namespace_id) {
        return -1;
    }
    (void)kzt_guest_registry_find_lazy_resolver(
        registry, identity->link_map_addr, identity->generation,
        identity->namespace_id, &lazy_resolver);
    retire_start = kzt_lifecycle_diagnostics_enabled()
                       ? kzt_lifecycle_diagnostics_now()
                       : 0;
    retire_result = kzt_guest_registry_finish_loader_unload(
        registry, identity);
    if (retire_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_REGISTRY_RETIRE,
            kzt_lifecycle_diagnostics_now() - retire_start);
    }
    if (retire_result != 0) {
        return -1;
    }

    key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = identity->link_map_addr,
        .generation = identity->generation,
        .namespace_id = identity->namespace_id,
        .namespace_kind = identity->namespace_id == 0
                              ? KZT_GUEST_LIBRARY_NAMESPACE_MAIN
                              : KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT,
    };
    if (KztGuestLibraryLookupForContext(
            context, &key, &binding) == 0 &&
        binding.object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
        binding.library) {
        if (kzt_guest_library_cleanup_exact_handle(
                &binding, kzt_guest_dl_api_cleanup_exact_library,
                (void *)identity->link_map_addr) != 0) {
            kzt_guest_library_handle_release(&binding);
        }
    } else {
        kzt_guest_library_handle_release(&binding);
    }
    if (lazy_resolver.registry_owned_head) {
        KztPerObjectGotPltRelease(lazy_resolver.object_head);
    }
    return 0;
#else
    (void)context;
    (void)identity;
    return -1;
#endif
}

int kzt_guest_dl_api_prepare_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_registry_t *registry;
    kzt_lazy_prebind_identity_t prebind_identity;

    if (!context || !identity || !identity->link_map_addr ||
        !identity->generation || !kzt_guest_dl_api_enabled() ||
        !(registry = KztGuestRegistryForContext(context)) ||
        kzt_guest_registry_begin_loader_unload(registry, identity) != 0) {
        return -1;
    }
    if (identity->namespace_id == 0) {
        prebind_identity = (kzt_lazy_prebind_identity_t) {
            .link_map_addr = identity->link_map_addr,
            .generation = identity->generation,
            .namespace_id = identity->namespace_id,
        };
        if (kzt_production_lazy_prebind_retire(
                context, &prebind_identity) != 0) {
            /* Registry quiescence is the safety boundary.  Auxiliary
             * prebind cleanup failure must not reopen lease admission before
             * the loader reaches RT_CONSISTENT. */
        }
    }
    return 0;
#else
    (void)context;
    (void)identity;
    return -1;
#endif
}

int kzt_guest_dl_api_cancel_unload(
    box64context_t *context,
    const kzt_guest_loader_identity_t *identity)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_registry_t *registry;

    if (!context || !identity || !kzt_guest_dl_api_enabled() ||
        !(registry = KztGuestRegistryForContext(context))) {
        return -1;
    }
    return kzt_guest_registry_cancel_loader_unload(registry, identity);
#else
    (void)context;
    (void)identity;
    return -1;
#endif
}

uint64_t kzt_guest_dl_api_dlmopen(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *lmid, void *filename, int flag)
{
#ifdef CONFIG_LATX_KZT
    if (context) {
        (void)kzt_production_lazy_prebind_invalidate(
            context, KZT_LAZY_PREBIND_MUTATION_DLMOPEN);
    }
#endif
    uint64_t result = kzt_guest_library_run_dlmopen(
        entries->dlmopen, lmid, filename, flag);

#ifdef CONFIG_LATX_KZT
    if (result && kzt_guest_dl_api_enabled()) {
        kzt_guest_loader_identity_t identity;
        kzt_guest_registry_t *registry =
            KztGuestRegistryForContext(context);

        if (kzt_guest_dl_api_query_identity(entries, result, &identity) == 0 &&
            registry) {
            (void)kzt_guest_registry_publish_loader_identity(
                registry, identity.handle, identity.link_map_addr,
                identity.namespace_id, &identity);
        }
    }
#else
    (void)context;
#endif
    return result;
}

kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *handle, void *symbol)
{
    kzt_guest_dl_symbol_result_t result = { 0 };
    kzt_guest_loader_identity_t queried_identity = { 0 };
    kzt_guest_loader_identity_t known_identity = { 0 };
    const kzt_guest_loader_identity_t *identity_hint = NULL;
    uintptr_t guest_result;

    if (handle == KZT_GUEST_RTLD_NEXT) {
        result.forward_to_guest_caller = 1;
        return result;
    }
    guest_result = kzt_guest_library_run_dlsym(
        entries->dlsym, handle, symbol);
#ifdef CONFIG_LATX_KZT
    if (guest_result && context && handle && kzt_guest_dl_api_enabled()) {
        kzt_guest_registry_t *registry = KztGuestRegistryForContext(context);

        if (registry && kzt_guest_registry_find_loader_identity(
                            registry, (uintptr_t)handle,
                            &known_identity) != 0 &&
            kzt_guest_dl_api_query_identity(
                entries, (uintptr_t)handle, &queried_identity) == 0) {
            identity_hint = &queried_identity;
        }
    }
#endif
    result.value = kzt_guest_library_select_symbol_result_with_identity(
        context, (uintptr_t)handle, identity_hint, guest_result,
        (const char *)symbol, NULL);
    return result;
}

kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlvsym(
    box64context_t *context, const kzt_guest_dl_entries_t *entries,
    void *handle, void *symbol, const char *version)
{
    kzt_guest_dl_symbol_result_t result = { 0 };
    kzt_guest_loader_identity_t queried_identity = { 0 };
    kzt_guest_loader_identity_t known_identity = { 0 };
    const kzt_guest_loader_identity_t *identity_hint = NULL;
    uintptr_t guest_result;

    if (handle == KZT_GUEST_RTLD_NEXT) {
        result.forward_to_guest_caller = 1;
        return result;
    }
    guest_result = kzt_guest_library_run_dlvsym(
        entries->dlvsym, handle, symbol, version);
#ifdef CONFIG_LATX_KZT
    if (guest_result && context && handle && kzt_guest_dl_api_enabled()) {
        kzt_guest_registry_t *registry = KztGuestRegistryForContext(context);

        if (registry && kzt_guest_registry_find_loader_identity(
                            registry, (uintptr_t)handle,
                            &known_identity) != 0 &&
            kzt_guest_dl_api_query_identity(
                entries, (uintptr_t)handle, &queried_identity) == 0) {
            identity_hint = &queried_identity;
        }
    }
#endif
    result.value = kzt_guest_library_select_symbol_result_with_identity(
        context, (uintptr_t)handle, identity_hint, guest_result,
        (const char *)symbol, version);
    return result;
}

kzt_guest_dlerror_result_t kzt_guest_dl_api_dlerror(
    kzt_guest_dlerror_state_t *state, uintptr_t guest_dlerror,
    int guest_route_may_have_pending_error)
{
    kzt_guest_dlerror_result_t result = { 0 };

    if (state && state->last_error) {
        if (!state->last_error_guest_consumed && guest_dlerror) {
            (void)kzt_guest_library_run_dlerror(
                guest_dlerror);
            state->last_error_guest_consumed = 1;
        }
        box_free(state->last_error_returned);
        state->last_error_returned = state->last_error;
        state->last_error = NULL;
        result.value = state->last_error_returned;
        return result;
    }
    if (state && state->last_error_returned) {
        box_free(state->last_error_returned);
        state->last_error_returned = NULL;
        if (state->last_error_guest_consumed) {
            state->last_error_guest_consumed = 0;
            kzt_guest_dl_api_set_slow_required(state, 0);
            if (!guest_route_may_have_pending_error) {
                return result;
            }
        }
    }
    if (state && !state->dlerror_slow_required &&
        !guest_route_may_have_pending_error) {
        return result;
    }
    result.forward_to_guest_caller = 1;
    return result;
}

int kzt_guest_dl_api_dlinfo(
    const kzt_guest_dl_entries_t *entries,
    void *handle, int request, void *info)
{
    return kzt_guest_library_run_dlinfo(
        entries->dlinfo, handle, request, info);
}
