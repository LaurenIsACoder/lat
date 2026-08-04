#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/elfloader.h"
#include "target/i386/latx/include/kzt_guest_dl_api.h"
#include "target/i386/latx/include/kzt_guest_dl_init.h"
#include "target/i386/latx/include/kzt_guest_runtime_entry.h"
#include "target/i386/latx/include/kzt_guest_library_adapter.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/kzt_jump_slot_production.h"
#include "target/i386/latx/include/librarian.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

__thread uintptr_t kzt_guest_dlerror_fast_result_tls;

int option_kzt = 1;
int wine_option_kzt;
elfheader_t *tryLoadElfFromFileForContext(
    box64context_t *context, const char *name);
void freeElfFromFile(elfheader_t **header);

#define CHECK(label, condition)                                              \
    do {                                                                     \
        if (!(condition)) {                                                  \
            fprintf(stderr, "%s: FAIL\n", label);                            \
            exit(EXIT_FAILURE);                                              \
        }                                                                    \
    } while (0)

static uintptr_t seen_function;
static void *seen_handle;
static void *seen_symbol;
static const char *seen_version;
static void *seen_lmid;
static void *seen_filename;
static void *seen_info;
static int seen_flag;
static int seen_request;
static int dlsym_calls;
static int dlvsym_calls;
static int dlerror_calls;
static int dlopen_calls;
static int dlclose_calls;
static int dlmopen_calls;
static int dlinfo_calls;
static int dlinfo_identity_enabled;
static uintptr_t dlinfo_link_map;
static uintptr_t dlinfo_lmid;
static int prebind_invalidate_calls;
static int prebind_retire_calls;
static int prebind_retire_result;
static int writer_begin_calls;
static int writer_end_calls;
static int writer_active;
static void *dlclose_handles[4];
static uintptr_t dlopen_result;
static int dlclose_result;
static uintptr_t guest_result;
static uintptr_t selected_result;
static uintptr_t seen_dlsym_function;
static char guest_error[] = "guest error";
static int wrapper_known;
static int attach_result;
static int attach_calls;
static int source_proof_result;
static int source_proof_acquire_calls;
static int source_proof_release_calls;
static kzt_guest_library_binding_result_t binding_claim_result;
static int binding_claim_calls;
static int finish_calls;
static int finish_publish;
static library_t *finish_library;
static uintptr_t finish_link_map;
static int registry_match_enabled;
static kzt_guest_registry_address_match_t registry_match;
static int registry_identity_publish_calls;
static int registry_identity_reuse_calls;
static int registry_identity_resident_calls;
static uintptr_t registry_identity_handle;
static uintptr_t registry_identity_link_map;
static uintptr_t registry_identity_namespace;
static int selector_identity_required = -1;
static int registry_close_complete_calls;
static kzt_guest_loader_close_result_t registry_close_result;
static int registry_close_identity_missing_calls;
static int registry_unload_begin_calls;
static int registry_unload_cancel_calls;
static int binding_lookup_result;
static library_t *binding_library;
static kzt_guest_library_object_type_t binding_object_type;
static int binding_release_calls;
static int inactive_calls;
static int retire_calls;
static uintptr_t retired_link_map;
static unsigned long retired_generation;
static int registry_token;
static int binding_token;
static library_t attached_library;
static pthread_mutex_t close_race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t close_race_ready = PTHREAD_COND_INITIALIZER;
static int close_race_enabled;
static int close_race_guest_closes;
static int close_race_retire_claimed;
static int close_race_wait_calls;
static pthread_mutex_t error_race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t error_race_ready = PTHREAD_COND_INITIALIZER;
static int error_race_enabled;
static int error_race_phase;
static __thread const char *thread_guest_error;
static pthread_mutex_t entry_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t entry_init_ready = PTHREAD_COND_INITIALIZER;
static int entry_init_paused;
static int entry_init_release;
static int entry_reader_checked;
static int entry_resolver_calls;
static int entry_retry_attempts;
static int entry_hint_attempts;
static int entry_recursive_attempted;
static int entry_recursive_result;
static int entry_destroy_started;
static int entry_destroy_done;
static int default_entry_pause;
static int default_entry_libc_calls;
static int default_entry_libdl_calls;
static int default_entry_path_calls;
static int default_entry_header_frees;
static box64context_t *default_entry_contexts[2];
static int default_entry_context_calls[2];
static int default_entry_context_path_present[2];
static int runtime_dlsym_error_model;
static int runtime_dlsym_error_pending;
static int default_entry_incomplete;
const char *interp_prefix = "/guest-root";

typedef struct runtime_entry_resolver_state {
    pthread_mutex_t mutex;
    pthread_cond_t ready;
    const char *expected_symbol;
    uintptr_t result;
    int failures;
    int calls;
    int pause;
    int paused;
    int release;
} runtime_entry_resolver_state_t;

typedef struct runtime_entry_race {
    dlprivate_t *dl;
    kzt_guest_runtime_entry_id_t entry;
    runtime_entry_resolver_state_t *resolver;
    uintptr_t result;
} runtime_entry_race_t;

typedef struct dlerror_publish_race {
    dlprivate_t *dl;
    uintptr_t entry;
    int result;
} dlerror_publish_race_t;

typedef struct dlclose_race {
    box64context_t *context;
    kzt_guest_library_loader_scope_t *thread_scope;
    const kzt_guest_dl_entries_t *entries;
    void *handle;
    int result;
} dlclose_race_t;

typedef struct dlerror_isolation_race {
    box64context_t *context;
    kzt_guest_library_loader_scope_t scope;
    dlprivate_t *dl;
    const kzt_guest_dl_entries_t *entries;
    kzt_guest_dlerror_state_t error_state;
    const char *error;
    char observed[32];
    int forward_to_guest_caller;
    int first;
    int clear_before_read;
} dlerror_isolation_race_t;

typedef struct dlentry_init_race {
    dlprivate_t *dl;
    const kzt_guest_dl_entries_t *result;
    kzt_guest_dl_entries_t fallback;
    kzt_guest_dl_entries_t snapshot;
    int saw_table_before_release;
} dlentry_init_race_t;

typedef struct dlentry_destroy_race {
    dlprivate_t *dl;
} dlentry_destroy_race_t;

typedef struct default_dlentry_race {
    box64context_t *context;
    const kzt_guest_dl_entries_t *result;
    kzt_guest_dl_entries_t fallback;
} default_dlentry_race_t;

static void *publish_dlerror_entry(void *opaque)
{
    dlerror_publish_race_t *race = opaque;

    race->result = kzt_guest_dl_api_publish_dlerror_entry(
        race->dl, "dlerror", race->entry, 1);
    return NULL;
}

static void *close_guest_library(void *opaque)
{
    dlclose_race_t *race = opaque;

    race->result = kzt_guest_dl_api_dlclose(
        race->context, race->thread_scope, race->entries, race->handle);
    return NULL;
}

static void *isolate_guest_dlerror(void *opaque)
{
    dlerror_isolation_race_t *race = opaque;
    kzt_guest_dlerror_result_t result;

    thread_guest_error = race->error;
    if (!race->first) {
        pthread_mutex_lock(&error_race_lock);
        while (error_race_phase < 1) {
            pthread_cond_wait(&error_race_ready, &error_race_lock);
        }
        pthread_mutex_unlock(&error_race_lock);
    }

    (void)kzt_guest_dl_api_dlopen(
        race->context, &race->scope, race->entries, &race->error_state,
        "libwi979.so", 2);

    pthread_mutex_lock(&error_race_lock);
    error_race_phase = race->first ? 1 : 2;
    pthread_cond_broadcast(&error_race_ready);
    if (race->first) {
        while (error_race_phase < 2) {
            pthread_cond_wait(&error_race_ready, &error_race_lock);
        }
    }
    pthread_mutex_unlock(&error_race_lock);

    if (race->clear_before_read) {
        kzt_guest_dl_api_clear_error(&race->error_state);
    }
    result = kzt_guest_dl_api_dlerror(
        &race->error_state,
        kzt_guest_dl_api_load_dlerror_entry(race->dl), 0);
    race->forward_to_guest_caller = result.forward_to_guest_caller;
    snprintf(race->observed, sizeof(race->observed), "%s",
             result.value ? result.value : "<empty>");

    if (race->first) {
        pthread_mutex_lock(&error_race_lock);
        error_race_phase = 3;
        pthread_cond_broadcast(&error_race_ready);
        pthread_mutex_unlock(&error_race_lock);
    } else {
        pthread_mutex_lock(&error_race_lock);
        while (error_race_phase < 3) {
            pthread_cond_wait(&error_race_ready, &error_race_lock);
        }
        pthread_mutex_unlock(&error_race_lock);
    }
    thread_guest_error = NULL;
    return NULL;
}

static int resolve_guest_dl_entries(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    (void)opaque;
    __atomic_add_fetch(&entry_resolver_calls, 1, __ATOMIC_RELAXED);
    entries->dlopen = 0x8100;
    entries->dlmopen = 0x8110;
    entries->dlsym = 0x8120;
    entries->dlclose = 0x8130;

    pthread_mutex_lock(&entry_init_lock);
    entry_init_paused = 1;
    pthread_cond_broadcast(&entry_init_ready);
    while (!entry_init_release) {
        pthread_cond_wait(&entry_init_ready, &entry_init_lock);
    }
    pthread_mutex_unlock(&entry_init_lock);

    entries->dladdr = 0x8140;
    entries->dladdr1 = 0x8150;
    entries->dlinfo = 0x8160;
    entries->dlvsym = 0x8170;
    entries->dlerror = 0x8180;
    return 0;
}

static void *initialize_guest_dl_entries(void *opaque)
{
    dlentry_init_race_t *race = opaque;

    race->result = kzt_guest_dl_api_ensure_entries(
        race->dl, resolve_guest_dl_entries, NULL, &race->fallback, NULL);
    if (race->result) {
        race->snapshot = *race->result;
    }
    return NULL;
}

static void *read_guest_dl_entries(void *opaque)
{
    dlentry_init_race_t *race = opaque;
    const kzt_guest_dl_entries_t *visible =
        kzt_guest_dl_api_load_entries(race->dl);

    race->saw_table_before_release = visible != NULL;
    if (visible) {
        race->snapshot = *visible;
    }
    pthread_mutex_lock(&entry_init_lock);
    entry_reader_checked = 1;
    pthread_cond_broadcast(&entry_init_ready);
    pthread_mutex_unlock(&entry_init_lock);

    race->result = kzt_guest_dl_api_ensure_entries(
        race->dl, resolve_guest_dl_entries, NULL, &race->fallback, NULL);
    if (race->result) {
        race->snapshot = *race->result;
    }
    return NULL;
}

static void fill_guest_dl_entries(kzt_guest_dl_entries_t *entries)
{
    *entries = (kzt_guest_dl_entries_t) {
        .dlopen = 0x8200,
        .dlmopen = 0x8210,
        .dlsym = 0x8220,
        .dlclose = 0x8230,
        .dladdr = 0x8240,
        .dladdr1 = 0x8250,
        .dlinfo = 0x8260,
        .dlvsym = 0x8270,
        .dlerror = 0x8280,
    };
}

static int resolve_guest_dl_entries_with_retry(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    int attempt = ++entry_retry_attempts;

    (void)opaque;
    fill_guest_dl_entries(entries);
    if (attempt == 1) {
        entries->dlerror = 0;
        return -1;
    }
    return 0;
}

static int resolve_guest_dl_entries_against_hint(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    int attempt = ++entry_hint_attempts;

    (void)opaque;
    fill_guest_dl_entries(entries);
    if (attempt > 1) {
        entries->dlerror = 0x8290;
    }
    return 0;
}

static int resolve_guest_dl_entries_recursively(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    dlprivate_t *dl = opaque;
    kzt_guest_dl_entries_t fallback = { 0 };

    entry_recursive_attempted = 1;
    entry_recursive_result =
        kzt_guest_dl_api_ensure_entries(
            dl, resolve_guest_dl_entries_recursively, dl, &fallback,
            NULL) != NULL;
    fill_guest_dl_entries(entries);
    return 0;
}

static void *destroy_guest_dl_entries(void *opaque)
{
    dlentry_destroy_race_t *race = opaque;

    __atomic_store_n(&entry_destroy_started, 1, __ATOMIC_RELEASE);
    kzt_guest_dl_api_entry_state_begin_teardown(race->dl);
    __atomic_store_n(&entry_destroy_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static uintptr_t resolve_runtime_entry(const char *symbol, void *opaque)
{
    runtime_entry_resolver_state_t *state = opaque;
    int call;

    CHECK("runtime resolver exact symbol",
          strcmp(symbol, state->expected_symbol) == 0);
    pthread_mutex_lock(&state->mutex);
    call = ++state->calls;
    if (state->pause) {
        state->paused = 1;
        pthread_cond_broadcast(&state->ready);
        while (!state->release) {
            pthread_cond_wait(&state->ready, &state->mutex);
        }
    }
    pthread_mutex_unlock(&state->mutex);
    return call <= state->failures ? 0 : state->result;
}

static void *resolve_runtime_entry_in_thread(void *opaque)
{
    runtime_entry_race_t *race = opaque;

    race->result = kzt_guest_runtime_entry_ensure(
        race->dl, race->entry, resolve_runtime_entry, race->resolver);
    return NULL;
}

static int wait_for_runtime_slow_users(
    dlprivate_t *dl, unsigned int minimum)
{
    int attempt;

    for (attempt = 0; attempt < 100000; ++attempt) {
        unsigned int users;

        pthread_mutex_lock(&dl->guest_dl_entries.mutex);
        users = dl->guest_dl_entries.slow_users;
        pthread_mutex_unlock(&dl->guest_dl_entries.mutex);
        if (users >= minimum) {
            return 0;
        }
        sched_yield();
    }
    return -1;
}

static void runtime_entry_resolver_state_init(
    runtime_entry_resolver_state_t *state, const char *symbol,
    uintptr_t result)
{
    memset(state, 0, sizeof(*state));
    CHECK("runtime resolver mutex initializes",
          pthread_mutex_init(&state->mutex, NULL) == 0);
    CHECK("runtime resolver condition initializes",
          pthread_cond_init(&state->ready, NULL) == 0);
    state->expected_symbol = symbol;
    state->result = result;
}

static void runtime_entry_resolver_state_destroy(
    runtime_entry_resolver_state_t *state)
{
    pthread_cond_destroy(&state->ready);
    pthread_mutex_destroy(&state->mutex);
}

elfheader_t* tryLoadElfFromFileForContext(
    box64context_t *context, const char *name)
{
    int context_index = context == default_entry_contexts[0] ? 0 : 1;

    CHECK("default resolver receives owning context",
          context == default_entry_contexts[context_index]);
    ++default_entry_context_calls[context_index];
    if (strcmp(name, "libc.so.6") == 0) {
        ++default_entry_libc_calls;
        return (elfheader_t *)(uintptr_t)(1 + context_index * 2);
    }
    CHECK("default resolver requests libdl", strcmp(name, "libdl.so.2") == 0);
    ++default_entry_libdl_calls;
    return (elfheader_t *)(uintptr_t)(2 + context_index * 2);
}

void freeElfFromFile(elfheader_t **header)
{
    CHECK("default resolver frees a loaded header", header && *header);
    ++default_entry_header_frees;
    *header = NULL;
}

void ResetSpecialCaseElf(
    elfheader_t *header, const char **names, int name_count,
    void **resolved, int *resolved_count)
{
    uintptr_t header_id = (uintptr_t)header;
    int second_context = header_id >= 3;
    int is_libc = header_id == 1 || header_id == 3;
    int begin = is_libc ? 0 : 4;
    int end = is_libc ? name_count : 9;
    uintptr_t base = second_context ? 0xa000 : 0x9000;

    CHECK("default resolver symbol count", name_count == 12);
    for (int i = begin; i < end; ++i) {
        if (is_libc && i >= 4 && i < 9) {
            continue;
        }
        CHECK("default resolver symbol name", names[i] && names[i][0]);
        if (default_entry_incomplete && i == 8) {
            continue;
        }
        if (!resolved[i]) {
            resolved[i] = (void *)(base + i * 0x10);
            ++*resolved_count;
        }
    }
    if (is_libc && default_entry_pause) {
        pthread_mutex_lock(&entry_init_lock);
        entry_init_paused = 1;
        pthread_cond_broadcast(&entry_init_ready);
        while (!entry_init_release) {
            pthread_cond_wait(&entry_init_ready, &entry_init_lock);
        }
        pthread_mutex_unlock(&entry_init_lock);
    }
}

void PrependList(path_collection_t *collection, const char *list, int folder)
{
    int context_index =
        collection == &default_entry_contexts[0]->box64_ld_lib ? 0 : 1;

    CHECK("default resolver path collection", collection != NULL);
    CHECK("default resolver owns path collection",
          collection == &default_entry_contexts[context_index]->box64_ld_lib);
    CHECK("default resolver hwcap path", strstr(list, "x86-64-v2") != NULL);
    CHECK("default resolver path kind", folder == 1);
    ++default_entry_path_calls;
    default_entry_context_path_present[context_index] = 1;
}

int FindInCollection(const char *path, path_collection_t *collection)
{
    int context_index =
        collection == &default_entry_contexts[0]->box64_ld_lib ? 0 : 1;

    CHECK("default resolver path lookup collection", collection != NULL);
    CHECK("default resolver path lookup owner",
          collection == &default_entry_contexts[context_index]->box64_ld_lib);
    CHECK("default resolver path lookup", strstr(path, "x86-64-v2") != NULL);
    return default_entry_context_path_present[context_index];
}

static void *initialize_default_guest_dl_entries(void *opaque)
{
    default_dlentry_race_t *race = opaque;

    race->result = kzt_guest_dl_init_entries(
        race->context, &race->fallback);
    return NULL;
}

uint64_t kzt_guest_library_run_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    uintptr_t function, void *filename, int flag,
    kzt_guest_library_loader_scope_t *call_scope)
{
    CHECK("dlopen context", context != NULL);
    CHECK("dlopen thread scope", thread_scope != NULL);
    if (close_race_enabled) {
        call_scope->identity = 41;
        __atomic_add_fetch(&dlopen_calls, 1, __ATOMIC_RELAXED);
        return dlopen_result;
    }
    if (error_race_enabled) {
        call_scope->identity = 41;
        return 0;
    }
    seen_function = function;
    seen_filename = filename;
    seen_flag = flag;
    call_scope->identity = 41;
    ++dlopen_calls;
    return dlopen_result;
}

void kzt_guest_library_finish_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *call_scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof, int publish)
{
    CHECK("finish context", context != NULL);
    CHECK("finish scope", call_scope->identity == 41);
    if (close_race_enabled || error_race_enabled) {
        return;
    }
    finish_link_map = link_map_addr;
    finish_library = library;
    finish_publish = publish;
    if (library && option_kzt) {
        CHECK("finish wrapped proof", proof && proof->lease.active &&
              proof->key.link_map_addr == link_map_addr);
    }
    ++finish_calls;
}

int FindLibIsWrapped(char *name)
{
    CHECK("wrapper name", strcmp(name, "libwi979.so") == 0);
    return wrapper_known;
}

int AddNeededLibWithLibrary(
    lib_t *maplib, needed_libs_t *neededlibs, library_t *deplib,
    int local, int bindnow, const char *path, box64context_t *context,
    library_t **exact_library)
{
    CHECK("attach maplib", maplib == NULL);
    CHECK("attach neededlibs", neededlibs == NULL);
    CHECK("attach dependency", deplib == NULL);
    CHECK("attach local", local == 1);
    CHECK("attach bind now", bindnow == 1);
    CHECK("attach path", strcmp(path, "libwi979.so") == 0);
    CHECK("attach context", context != NULL);
    ++attach_calls;
    *exact_library = attach_result ? NULL : &attached_library;
    return attach_result;
}

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(
    box64context_t *context)
{
    CHECK("claim context", context != NULL);
    return (kzt_guest_library_bindings_t *)&binding_token;
}

int kzt_guest_library_loader_quiescence_writer_begin(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_quiescence_writer_t *writer)
{
    CHECK("writer bindings",
          bindings == (kzt_guest_library_bindings_t *)&binding_token);
    CHECK("writer token", writer != NULL);
    memset(writer, 0, sizeof(*writer));
    writer->bindings = bindings;
    writer->cookie = 1;
    __atomic_add_fetch(&writer_begin_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&writer_active, 1, __ATOMIC_RELAXED);
    return 0;
}

void kzt_guest_library_loader_quiescence_writer_end(
    kzt_guest_library_loader_quiescence_writer_t *writer)
{
    if (!writer || !writer->bindings) return;
    CHECK("writer release bindings",
          writer->bindings ==
              (kzt_guest_library_bindings_t *)&binding_token);
    CHECK("writer release active",
          __atomic_load_n(&writer_active, __ATOMIC_RELAXED) > 0);
    __atomic_sub_fetch(&writer_active, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&writer_end_calls, 1, __ATOMIC_RELAXED);
    memset(writer, 0, sizeof(*writer));
}

kzt_guest_library_binding_result_t kzt_guest_library_note_loader_pair(
    box64context_t *context, uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof)
{
    CHECK("claim context", context != NULL);
    CHECK("claim exact key",
          proof && proof->lease.active && proof->key.link_map_addr ==
                     (dlinfo_identity_enabled ? dlinfo_link_map
                                              : dlopen_result) &&
              proof->key.link_map_addr == link_map_addr &&
              proof->key.generation == 17 &&
              proof->key.namespace_id == 0 &&
              proof->key.namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN);
    CHECK("claim exact library", library == &attached_library);
    ++binding_claim_calls;
    return binding_claim_result;
}

int kzt_guest_library_wrapper_source_acquire(
    box64context_t *context, uintptr_t link_map_addr,
    const char *requested_path, const char *wrapper_name,
    kzt_guest_wrapper_source_proof_t *proof)
{
    CHECK("source proof context", context != NULL);
    CHECK("source proof link map", link_map_addr != 0);
    CHECK("source proof requested path", requested_path != NULL);
    CHECK("source proof wrapper name", wrapper_name != NULL);
    ++source_proof_acquire_calls;
    memset(proof, 0, sizeof(*proof));
    if (source_proof_result != 0) {
        return source_proof_result;
    }
    proof->lease.active = 1;
    proof->key.link_map_addr = link_map_addr;
    proof->key.generation = 17;
    proof->key.namespace_id = 0;
    proof->key.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN;
    return 0;
}

void kzt_guest_library_wrapper_source_release(
    kzt_guest_wrapper_source_proof_t *proof)
{
    CHECK("source proof release", proof != NULL);
    if (proof->lease.active) {
        ++source_proof_release_calls;
    }
    memset(proof, 0, sizeof(*proof));
}

uint64_t kzt_guest_library_run_dlsym(
    uintptr_t function, void *handle, void *symbol)
{
    seen_dlsym_function = function;
    seen_function = function;
    seen_handle = handle;
    seen_symbol = symbol;
    ++dlsym_calls;
    if (runtime_dlsym_error_model) {
        runtime_dlsym_error_pending = guest_result == 0;
    }
    return guest_result;
}

uint64_t kzt_guest_library_run_dlvsym(
    uintptr_t function, void *handle, void *symbol, const char *version)
{
    seen_function = function;
    seen_handle = handle;
    seen_symbol = symbol;
    seen_version = version;
    ++dlvsym_calls;
    return guest_result;
}

uint64_t kzt_guest_library_run_dlerror(uintptr_t function)
{
    if (runtime_dlsym_error_model) {
        int pending = runtime_dlsym_error_pending;

        runtime_dlsym_error_pending = 0;
        seen_function = function;
        ++dlerror_calls;
        return pending ? (uintptr_t)guest_error : 0;
    }
    if (thread_guest_error) {
        __atomic_add_fetch(&dlerror_calls, 1, __ATOMIC_RELAXED);
        return (uintptr_t)thread_guest_error;
    }
    if (close_race_enabled) {
        __atomic_add_fetch(&dlerror_calls, 1, __ATOMIC_RELAXED);
        return (uintptr_t)guest_error;
    }
    seen_function = function;
    ++dlerror_calls;
    return (uintptr_t)guest_error;
}

int kzt_guest_library_run_dlclose(uintptr_t function, void *handle)
{
    int call_index;

    if (close_race_enabled) {
        call_index = __atomic_fetch_add(&dlclose_calls, 1, __ATOMIC_RELAXED);
    } else {
        call_index = dlclose_calls++;
    }
    if (!close_race_enabled) {
        seen_function = function;
    }
    if (!close_race_enabled && call_index < 4) {
        dlclose_handles[call_index] = handle;
    }
    if (close_race_enabled && handle == (void *)(uintptr_t)0x9000) {
        pthread_mutex_lock(&close_race_lock);
        ++close_race_guest_closes;
        if (close_race_guest_closes == 2) {
            pthread_cond_broadcast(&close_race_ready);
        } else {
            while (close_race_guest_closes < 2) {
                pthread_cond_wait(&close_race_ready, &close_race_lock);
            }
        }
        pthread_mutex_unlock(&close_race_lock);
    }
    return dlclose_result;
}

uint64_t kzt_guest_library_run_dlmopen(
    uintptr_t function, void *lmid, void *filename, int flag)
{
    seen_function = function;
    seen_lmid = lmid;
    seen_filename = filename;
    seen_flag = flag;
    ++dlmopen_calls;
    return guest_result;
}

int kzt_guest_library_run_dlinfo(
    uintptr_t function, void *handle, int request, void *info)
{
    seen_function = function;
    seen_handle = handle;
    seen_request = request;
    seen_info = info;
    ++dlinfo_calls;
    if (dlinfo_identity_enabled < 0) {
        return -1;
    }
    if (dlinfo_identity_enabled) {
        if (request == 2) {
            *(uintptr_t *)info = dlinfo_link_map;
            return 0;
        }
        if (request == 1) {
            *(uintptr_t *)info = dlinfo_lmid;
            return 0;
        }
        return -1;
    }
    if (request == 2) {
        *(uintptr_t *)info = (uintptr_t)handle;
        return 0;
    }
    if (request == 1) {
        *(uintptr_t *)info = 0;
        return 0;
    }
    return (int)guest_result;
}

uintptr_t kzt_guest_library_select_symbol_result(
    box64context_t *context, uintptr_t guest_handle,
    uintptr_t actual_guest_result, const char *symbol, const char *version)
{
    CHECK("selector context", context != NULL);
    CHECK("selector handle", guest_handle == (uintptr_t)seen_handle);
    CHECK("selector guest result", actual_guest_result == guest_result);
    CHECK("selector symbol", symbol == (const char *)seen_symbol);
    CHECK("selector version", version == seen_version);
    return selected_result;
}

uintptr_t kzt_guest_library_select_symbol_result_with_identity(
    box64context_t *context, uintptr_t guest_handle,
    const kzt_guest_loader_identity_t *queried_identity,
    uintptr_t actual_guest_result, const char *symbol, const char *version)
{
    if (selector_identity_required >= 0) {
        CHECK("selector exact identity presence",
              (queried_identity != NULL) == selector_identity_required);
    }
    if (queried_identity) {
        CHECK("selector exact identity handle",
              queried_identity->handle == guest_handle);
        CHECK("selector exact identity link map",
              queried_identity->link_map_addr == dlinfo_link_map);
        CHECK("selector exact identity namespace",
              queried_identity->namespace_id == dlinfo_lmid);
    }
    return kzt_guest_library_select_symbol_result(
        context, guest_handle, actual_guest_result, symbol, version);
}

kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    CHECK("registry context", context != NULL);
    return (kzt_guest_registry_t *)&registry_token;
}

kzt_lazy_prebind_scope_t *KztLazyPrebindScopeForContext(
    box64context_t *context)
{
    CHECK("prebind scope context", context != NULL);
    return NULL;
}

int kzt_production_lazy_prebind_invalidate(
    box64context_t *context, kzt_lazy_prebind_mutation_t mutation)
{
    CHECK("prebind invalidate context", context != NULL);
    CHECK("prebind invalidate mutation",
          mutation == KZT_LAZY_PREBIND_MUTATION_DLOPEN ||
              mutation == KZT_LAZY_PREBIND_MUTATION_DLCLOSE ||
              mutation == KZT_LAZY_PREBIND_MUTATION_DLMOPEN);
    ++prebind_invalidate_calls;
    return 0;
}

int kzt_production_lazy_prebind_retire(
    box64context_t *context,
    const kzt_lazy_prebind_identity_t *identity)
{
    CHECK("prebind retire context", context != NULL);
    CHECK("prebind retire identity", identity != NULL &&
          identity->link_map_addr == registry_match.link_map_addr &&
          identity->generation == registry_match.generation &&
          identity->namespace_id == registry_match.namespace_id);
    ++prebind_retire_calls;
    return prebind_retire_result;
}

void kzt_production_lazy_prebind_refresh(
    box64context_t *context,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque)
{
    CHECK("prebind refresh context", context != NULL);
    CHECK("prebind refresh target prepare", target_prepare != NULL);
    (void)target_prepare_opaque;
}

int KztPrebindTargetTbPrepare(uintptr_t target)
{
    return target ? 0 : -1;
}

int kzt_guest_registry_find_live_object(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    kzt_guest_registry_address_match_t *match)
{
    CHECK("registry token", registry == (kzt_guest_registry_t *)&registry_token);
    if (!registry_match_enabled ||
        link_map_addr != registry_match.link_map_addr) {
        memset(match, 0, sizeof(*match));
        return -1;
    }
    *match = registry_match;
    return 0;
}

int kzt_guest_registry_publish_loader_identity(
    kzt_guest_registry_t *registry, uintptr_t handle,
    uintptr_t link_map_addr, uintptr_t namespace_id,
    kzt_guest_loader_identity_t *identity)
{
    CHECK("publish identity registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    ++registry_identity_publish_calls;
    registry_identity_handle = handle;
    registry_identity_link_map = link_map_addr;
    registry_identity_namespace = namespace_id;
    *identity = (kzt_guest_loader_identity_t) {
        .handle = handle,
        .link_map_addr = link_map_addr,
        .generation = 17,
        .namespace_id = namespace_id,
    };
    return 0;
}

int kzt_guest_registry_find_loader_identity(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity)
{
    CHECK("find identity registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    if (!registry_match_enabled ||
        handle != registry_match.link_map_addr) {
        memset(identity, 0, sizeof(*identity));
        return -1;
    }
    *identity = (kzt_guest_loader_identity_t) {
        .handle = handle,
        .link_map_addr = registry_match.link_map_addr,
        .generation = registry_match.generation,
        .namespace_id = registry_match.namespace_id,
    };
    return 0;
}

int kzt_guest_registry_reuse_loader_identity(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity)
{
    ++registry_identity_reuse_calls;
    return kzt_guest_registry_find_loader_identity(
        registry, handle, identity);
}

int kzt_guest_registry_mark_loader_resident(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("mark resident registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("mark resident exact identity",
          identity != NULL && identity->handle != 0 &&
              identity->link_map_addr != 0);
    ++registry_identity_resident_calls;
    return 0;
}

int kzt_guest_registry_find_loader_object_identity(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    kzt_guest_loader_identity_t *identity)
{
    CHECK("find loader object registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    if (!registry_match_enabled ||
        link_map_addr != registry_match.link_map_addr) {
        memset(identity, 0, sizeof(*identity));
        return -1;
    }
    *identity = (kzt_guest_loader_identity_t) {
        .link_map_addr = link_map_addr,
        .generation = registry_match.generation,
        .namespace_id = registry_match.namespace_id,
    };
    return 0;
}

int kzt_guest_registry_begin_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("begin unload registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("begin unload exact identity",
          identity->link_map_addr == registry_match.link_map_addr &&
              identity->generation == registry_match.generation &&
              identity->namespace_id == registry_match.namespace_id);
    ++registry_unload_begin_calls;
    return 0;
}

int kzt_guest_registry_cancel_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("cancel unload registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("cancel unload exact identity",
          identity->link_map_addr == registry_match.link_map_addr &&
              identity->generation == registry_match.generation &&
              identity->namespace_id == registry_match.namespace_id);
    ++registry_unload_cancel_calls;
    return 0;
}

kzt_guest_loader_close_result_t
kzt_guest_registry_complete_loader_close(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("complete close registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("complete close exact identity",
          identity->link_map_addr == registry_match.link_map_addr &&
              identity->generation == registry_match.generation &&
              identity->namespace_id == registry_match.namespace_id);
    ++registry_close_complete_calls;
    return registry_close_result;
}

void kzt_guest_registry_note_loader_close_identity_missing(
    kzt_guest_registry_t *registry)
{
    CHECK("missing close identity registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    ++registry_close_identity_missing_calls;
}

int KztGuestLibraryLookupForContext(
    box64context_t *context,
    const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    CHECK("binding context", context != NULL);
    CHECK("binding link map",
          key->link_map_addr == registry_match.link_map_addr);
    CHECK("binding generation",
          key->generation == registry_match.generation);
    CHECK("binding namespace",
          key->namespace_id == registry_match.namespace_id);
    if (binding_lookup_result != 0) {
        return binding_lookup_result;
    }
    handle->bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1;
    handle->entry = (void *)(uintptr_t)1;
    handle->library = binding_library;
    handle->object_type = binding_object_type;
    return 0;
}

void kzt_guest_library_handle_release(kzt_guest_library_handle_t *handle)
{
    if (handle->entry) {
        __atomic_add_fetch(&binding_release_calls, 1, __ATOMIC_RELAXED);
    }
    memset(handle, 0, sizeof(*handle));
}

int kzt_guest_library_cleanup_exact_handle(
    kzt_guest_library_handle_t *handle,
    kzt_guest_library_exact_cleanup_fn cleanup,
    void *opaque)
{
    CHECK("cleanup exact pinned handle", handle != NULL && handle->entry &&
          handle->library == binding_library);
    CHECK("cleanup exact callback", cleanup != NULL);
    cleanup(handle->library, opaque);
    ++binding_release_calls;
    ++inactive_calls;
    memset(handle, 0, sizeof(*handle));
    return 0;
}

void InactiveLibrary(library_t *library)
{
    CHECK("inactive exact library", library == binding_library);
    __atomic_add_fetch(&inactive_calls, 1, __ATOMIC_RELAXED);
}

int kzt_guest_registry_retire(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation)
{
    CHECK("retire registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    if (!close_race_enabled) {
        retired_link_map = link_map_addr;
        retired_generation = generation;
    }
    __atomic_add_fetch(&retire_calls, 1, __ATOMIC_RELAXED);
    if (close_race_enabled) {
        int winner;

        pthread_mutex_lock(&close_race_lock);
        winner = !close_race_retire_claimed;
        close_race_retire_claimed = 1;
        pthread_mutex_unlock(&close_race_lock);
        return winner ? 0 : -1;
    }
    return 0;
}

int kzt_guest_registry_retire_loader_identity(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("retire loader namespace",
          identity->namespace_id == registry_match.namespace_id);
    return kzt_guest_registry_retire(
        registry, identity->link_map_addr, identity->generation);
}

int kzt_guest_registry_finish_loader_unload(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("finish unload namespace",
          identity->namespace_id == registry_match.namespace_id);
    return kzt_guest_registry_retire(
        registry, identity->link_map_addr, identity->generation);
}

int kzt_guest_registry_wait_retired(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation)
{
    CHECK("wait retired registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("wait retired identity",
          link_map_addr == registry_match.link_map_addr &&
              generation == registry_match.generation);
    __atomic_add_fetch(&close_race_wait_calls, 1, __ATOMIC_RELAXED);
    return 0;
}

int kzt_guest_registry_find_lazy_resolver(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation, uintptr_t namespace_id,
    kzt_guest_lazy_resolver_t *resolver)
{
    CHECK("lazy resolver registry",
          registry == (kzt_guest_registry_t *)&registry_token);
    CHECK("lazy resolver identity",
          link_map_addr == registry_match.link_map_addr &&
              generation == registry_match.generation &&
              namespace_id == registry_match.namespace_id);
    memset(resolver, 0, sizeof(*resolver));
    return -1;
}

void KztPerObjectGotPltRelease(uintptr_t object_head)
{
    CHECK("runtime head not released by legacy dl-api fixture",
          object_head == 0);
}

static void reset_calls(void)
{
    seen_function = 0;
    seen_dlsym_function = 0;
    seen_handle = NULL;
    seen_symbol = NULL;
    seen_version = NULL;
    seen_lmid = NULL;
    seen_filename = NULL;
    seen_info = NULL;
    seen_flag = 0;
    seen_request = 0;
    dlsym_calls = 0;
    dlvsym_calls = 0;
    dlerror_calls = 0;
    dlopen_calls = 0;
    dlclose_calls = 0;
    memset(dlclose_handles, 0, sizeof(dlclose_handles));
    dlmopen_calls = 0;
    dlinfo_calls = 0;
    dlinfo_identity_enabled = 0;
    dlinfo_link_map = 0;
    dlinfo_lmid = 0;
    prebind_invalidate_calls = 0;
    prebind_retire_calls = 0;
    prebind_retire_result = 0;
    writer_begin_calls = 0;
    writer_end_calls = 0;
    writer_active = 0;
    attach_calls = 0;
    source_proof_result = 0;
    source_proof_acquire_calls = 0;
    source_proof_release_calls = 0;
    binding_claim_result = KZT_GUEST_LIBRARY_BINDING_ADDED;
    binding_claim_calls = 0;
    memset(&attached_library, 0, sizeof(attached_library));
    attached_library.type = LIB_WRAPPED;
    finish_calls = 0;
    finish_publish = 0;
    finish_library = NULL;
    finish_link_map = 0;
    dlopen_result = 0;
    dlclose_result = 0;
    guest_result = 0;
    selected_result = 0;
    wrapper_known = 0;
    attach_result = 0;
    registry_match_enabled = 0;
    memset(&registry_match, 0, sizeof(registry_match));
    registry_identity_publish_calls = 0;
    registry_identity_reuse_calls = 0;
    registry_identity_resident_calls = 0;
    registry_identity_handle = 0;
    registry_identity_link_map = 0;
    registry_identity_namespace = 0;
    selector_identity_required = -1;
    registry_close_complete_calls = 0;
    registry_close_result = KZT_GUEST_LOADER_CLOSE_UNLOAD_UNPROVEN;
    registry_close_identity_missing_calls = 0;
    registry_unload_begin_calls = 0;
    registry_unload_cancel_calls = 0;
    binding_lookup_result = -1;
    binding_library = NULL;
    binding_object_type = KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED;
    binding_release_calls = 0;
    inactive_calls = 0;
    retire_calls = 0;
    retired_link_map = 0;
    retired_generation = 0;
    close_race_enabled = 0;
    close_race_guest_closes = 0;
    close_race_retire_claimed = 0;
    close_race_wait_calls = 0;
    error_race_enabled = 0;
    error_race_phase = 0;
    runtime_dlsym_error_model = 0;
    runtime_dlsym_error_pending = 0;
}

static void set_exact_match(uintptr_t link_map_addr, uintptr_t namespace_id)
{
    registry_match_enabled = 1;
    registry_match.link_map_addr = link_map_addr;
    registry_match.generation = 17;
    registry_match.namespace_id = namespace_id;
    registry_match.namespace_id_status = KZT_GUEST_FIELD_OK;
    registry_match.path_status = KZT_GUEST_FIELD_OK;
    registry_match.match_count = 1;
    strcpy(registry_match.path, "/guest/libwi980.so");
}

int main(void)
{
    box64context_t context = { 0 };
    dlprivate_t dl = { 0 };
    kzt_guest_dlerror_state_t error_state = { 0 };
    kzt_guest_dlerror_state_t fast_error_state = { 0 };
    uintptr_t fast_error_mirror = 0;
    dlerror_publish_race_t races[2];
    pthread_t race_threads[2];
    dlclose_race_t close_races[2];
    pthread_t close_threads[2];
    dlerror_isolation_race_t error_races[2];
    pthread_t error_threads[2];
    dlentry_init_race_t entry_races[2] = { 0 };
    pthread_t entry_threads[2];
    dlprivate_t destroy_dl = { 0 };
    dlprivate_t runtime_dl_a = { 0 };
    dlprivate_t runtime_dl_b = { 0 };
    dlentry_destroy_race_t destroy_race = { .dl = &destroy_dl };
    dlentry_init_race_t destroy_init_race = { .dl = &destroy_dl };
    pthread_t destroy_threads[2];
    pthread_t runtime_threads[2];
    runtime_entry_resolver_state_t runtime_resolver_a;
    runtime_entry_resolver_state_t runtime_resolver_b;
    runtime_entry_race_t runtime_races[2];
    kzt_guest_runtime_entry_scope_t runtime_scope = { 0 };
    box64context_t runtime_context_a = { .dlprivate = &runtime_dl_a };
    box64context_t runtime_context_b = { .dlprivate = &runtime_dl_b };
    uintptr_t runtime_entries[KZT_GUEST_RUNTIME_ENTRY_COUNT] = {
        0xa610, 0xa620, 0xa630,
    };
    dlprivate_t default_dl = { 0 };
    dlprivate_t default_dl_b = { 0 };
    box64context_t default_context = { .dlprivate = &default_dl };
    box64context_t default_context_b = { .dlprivate = &default_dl_b };
    default_dlentry_race_t default_races[2] = {
        { .context = &default_context },
        { .context = &default_context },
    };
    pthread_t default_threads[2];
    library_t library = { 0 };
    kzt_guest_library_loader_scope_t thread_scope = { 0 };
    kzt_guest_dl_symbol_result_t symbol_result;
    kzt_guest_dlerror_result_t error_result;
    char symbol[] = "wi964_symbol";
    char version[] = "WI964_1.0";
    char filename[] = "libwi964.so";
    char info[16] = { 0 };
    kzt_guest_dl_entries_t direct_entries = {
        .dlsym = 0x1010,
        .dlvsym = 0x1020,
        .dlerror = 0x1030,
        .dlmopen = 0x1040,
        .dlinfo = 0x1050,
        .dlclose = 0x1060,
        .dlopen = 0x1070,
        .dladdr = 0x1080,
        .dladdr1 = 0x1090,
    };

    default_entry_contexts[0] = &default_context;
    default_entry_contexts[1] = &default_context_b;

    fast_error_state.dlerror_fast_result_mirror = &fast_error_mirror;
    fast_error_state.dlerror_slow_required = 1;
    fast_error_mirror = fast_error_state.dlerror_fast_result;
    CHECK("explicit unknown dlerror state remains conservative",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    fast_error_state.dlerror_slow_required = 0;
    CHECK("initialized clean dlerror state skips slow path",
          !kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    CHECK("guest call remembers a clean predecessor",
          kzt_guest_dl_api_begin_call(&fast_error_state));
    CHECK("guest call starts conservatively",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state) &&
              fast_error_mirror != 0);
    kzt_guest_dl_api_finish_success(&fast_error_state, 1);
    CHECK("successful guest call preserves known clean state",
          !kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state) &&
              fast_error_mirror == 0);
    fast_error_state.dlerror_slow_required = 1;
    CHECK("guest call remembers an unknown predecessor",
          !kzt_guest_dl_api_begin_call(&fast_error_state));
    kzt_guest_dl_api_finish_success(&fast_error_state, 0);
    CHECK("success cannot promote an unknown predecessor",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    fast_error_state.dlerror_slow_required = 0;
    fast_error_state.last_error = (char *)(uintptr_t)1;
    fast_error_state.dlerror_slow_required = 1;
    CHECK("pending dlerror requires slow path",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    fast_error_state.last_error = NULL;
    fast_error_state.last_error_returned = (char *)(uintptr_t)1;
    CHECK("returned dlerror cache requires slow path",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    fast_error_state.last_error_returned = NULL;
    fast_error_state.guest_dlerror_entry = 0x1234;
    kzt_guest_dl_api_clear_error(&fast_error_state);
    CHECK("CLEARERR preserves thread guest dlerror entry",
          fast_error_state.guest_dlerror_entry == 0x1234);
    CHECK("CLEARERR makes guest dlerror state conservative",
          kzt_guest_dl_api_dlerror_needs_slow_path(&fast_error_state));
    kzt_guest_dl_api_free_errors(&fast_error_state);
    CHECK("thread teardown clears guest dlerror entry",
          fast_error_state.guest_dlerror_entry == 0);

    reset_calls();
    dlopen_result = 0x2000;
    dlinfo_identity_enabled = 1;
    dlinfo_link_map = 0x2080;
    CHECK("unwrapped dlopen result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0x2000);
    CHECK("unwrapped guest call", dlopen_calls == 1);
    CHECK("unwrapped no attach", attach_calls == 0);
    CHECK("unwrapped finish", finish_calls == 1 && finish_publish);
    CHECK("unwrapped observed only", finish_library == NULL);
    CHECK("unwrapped exact dlinfo calls", dlinfo_calls == 2);
    CHECK("unwrapped exact link map", finish_link_map == 0x2080);
    CHECK("unwrapped exact identity published",
          registry_identity_publish_calls == 1 &&
              registry_identity_handle == 0x2000 &&
              registry_identity_link_map == 0x2080 &&
              registry_identity_namespace == 0);
    CHECK("unwrapped invalidates prebind", prebind_invalidate_calls == 1);

    reset_calls();
    dlopen_result = 0x2040;
    dlinfo_identity_enabled = 1;
    dlinfo_link_map = 0x20c0;
    CHECK("nodelete dlopen result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 0x1002) == 0x2040);
    CHECK("nodelete exact identity marked resident",
          registry_identity_publish_calls == 1 &&
              registry_identity_resident_calls == 1);

    reset_calls();
    dlopen_result = 0x2000;
    registry_match_enabled = 1;
    registry_match.link_map_addr = 0x2000;
    registry_match.generation = 17;
    registry_match.namespace_id = 0;
    CHECK("live duplicate dlopen result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0x2000);
    CHECK("live duplicate reuses exact identity",
          registry_identity_reuse_calls == 1 && dlinfo_calls == 0 &&
              registry_identity_publish_calls == 0 &&
              finish_link_map == 0x2000 && finish_publish);

    reset_calls();
    option_kzt = 0;
    dlopen_result = 0x2500;
    CHECK("disabled KZT dlopen result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0x2500);
    CHECK("disabled KZT skips identity dlinfo", dlinfo_calls == 0);
    CHECK("disabled KZT preserves old publication",
          finish_calls == 1 && finish_publish &&
              finish_link_map == 0x2500);
    CHECK("disabled KZT skips Registry identity",
          registry_identity_publish_calls == 0);
    option_kzt = 1;

    reset_calls();
    dlopen_result = 0x2580;
    dlinfo_identity_enabled = -1;
    CHECK("identity probe failure preserves successful dlopen",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0x2580);
    CHECK("identity probe failure is bounded", dlinfo_calls == 1);
    CHECK("identity probe failure consumes internal loader error",
          dlerror_calls == 1);
    CHECK("identity probe failure does not publish guessed identity",
          registry_identity_publish_calls == 0 && !finish_publish);

    reset_calls();
    dlopen_result = 0x2000;
    CHECK("noload global result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 0x104) == 0x2000);
    CHECK("noload global invalidates prebind",
          prebind_invalidate_calls == 1);

    reset_calls();
    wrapper_known = 1;
    dlopen_result = 0x2100;
    CHECK("wrapped dlopen result",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "/guest/libwi979.so", 2) == 0x2100);
    CHECK("wrapped guest first", dlopen_calls == 1);
    CHECK("wrapped attach", attach_calls == 1);
    CHECK("wrapped source proof held and released",
          source_proof_acquire_calls == 1 && source_proof_release_calls == 1);
    CHECK("wrapped exact pair", finish_library != NULL);
    CHECK("wrapped guest handle stored",
          finish_library->x86linkmap ==
              (struct link_map *)(uintptr_t)0x2100);

    reset_calls();
    wrapper_known = 1;
    binding_claim_result = KZT_GUEST_LIBRARY_BINDING_CONFLICT;
    attached_library.x86linkmap =
        (struct link_map *)(uintptr_t)0x2100;
    dlopen_result = 0x2140;
    CHECK("conflicting wrapped source preserves guest handle",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "/usr/lib/libwi979.so", 2) == 0x2140);
    CHECK("conflicting wrapped source claims before mutation",
          binding_claim_calls == 1);
    CHECK("conflicting wrapped source remains observed only",
          finish_library == NULL && finish_publish);
    CHECK("conflicting wrapped source keeps first producer owner",
          attached_library.x86linkmap ==
              (struct link_map *)(uintptr_t)0x2100);

    reset_calls();
    wrapper_known = 1;
    attached_library.type = LIB_EMULATED;
    attached_library.x86linkmap =
        (struct link_map *)(uintptr_t)0x2100;
    dlopen_result = 0x2160;
    CHECK("emulated basename collision preserves guest handle",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "/usr/lib/libwi979.so", 2) == 0x2160);
    CHECK("emulated basename collision skips wrapped claim",
          binding_claim_calls == 0);
    CHECK("emulated basename collision remains observed only",
          finish_library == NULL && finish_publish);
    CHECK("emulated basename collision keeps producer state",
          attached_library.x86linkmap ==
              (struct link_map *)(uintptr_t)0x2100);

    reset_calls();
    wrapper_known = 1;
    source_proof_result = -1;
    dlopen_result = 0x2180;
    CHECK("unproven wrapped source preserves guest handle",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "/tmp/libwi979.so", 2) == 0x2180);
    CHECK("unproven wrapped source does not materialize", attach_calls == 0);
    CHECK("unproven wrapped source remains observed only",
          finish_library == NULL && finish_publish);

    reset_calls();
    wrapper_known = 1;
    attach_result = 1;
    dlopen_result = 0x2200;
    CHECK("attach failure preserves guest",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0x2200);
    CHECK("attach failure observed", finish_library == NULL);

    reset_calls();
    wrapper_known = 1;
    dlopen_result = 0;
    CHECK("guest failure preserved",
          kzt_guest_dl_api_dlopen(
              &context, &thread_scope, &direct_entries, &error_state,
              "libwi979.so", 2) == 0);
    CHECK("guest failure skips attach", attach_calls == 0);
    CHECK("guest failure cancels scope",
          finish_calls == 1 && !finish_publish && finish_link_map == 0);
    CHECK("guest failure captures guest error", dlerror_calls == 1);
    error_result = kzt_guest_dl_api_dlerror(
        &error_state, kzt_guest_dl_api_load_dlerror_entry(&dl), 0);
    CHECK("captured guest error returned",
          error_result.value &&
              strcmp(error_result.value, guest_error) == 0 &&
              !error_result.forward_to_guest_caller);
    error_result = kzt_guest_dl_api_dlerror(
        &error_state, kzt_guest_dl_api_load_dlerror_entry(&dl), 0);
    CHECK("captured guest error is one-shot",
          !error_result.value && !error_result.forward_to_guest_caller);
    CHECK("consumed guest error stays on clean path", dlerror_calls == 1);
    error_state.last_error_returned = strdup("prior wrapper error");
    CHECK("cached error test allocation",
          error_state.last_error_returned != NULL);
    error_state.last_error_guest_consumed = 1;
    error_state.dlerror_slow_required = 1;
    error_result = kzt_guest_dl_api_dlerror(
        &error_state, kzt_guest_dl_api_load_dlerror_entry(&dl), 1);
    CHECK("guest route can report an error after a cached error was consumed",
          !error_result.value && error_result.forward_to_guest_caller);
    kzt_guest_dl_api_clear_error(&error_state);

    reset_calls();
    error_race_enabled = 1;
    error_races[0] = (dlerror_isolation_race_t) {
        .context = &context,
        .dl = &dl,
        .entries = &direct_entries,
        .error = "thread A error",
        .first = 1,
    };
    error_races[1] = (dlerror_isolation_race_t) {
        .context = &context,
        .dl = &dl,
        .entries = &direct_entries,
        .error = "thread B error",
    };
    CHECK("dlerror isolation first thread starts",
          pthread_create(&error_threads[0], NULL, isolate_guest_dlerror,
                         &error_races[0]) == 0);
    CHECK("dlerror isolation second thread starts",
          pthread_create(&error_threads[1], NULL, isolate_guest_dlerror,
                         &error_races[1]) == 0);
    CHECK("dlerror isolation first thread joins",
          pthread_join(error_threads[0], NULL) == 0);
    CHECK("dlerror isolation second thread joins",
          pthread_join(error_threads[1], NULL) == 0);
    error_race_enabled = 0;
    CHECK("dlerror isolation preserves first error",
          strcmp(error_races[0].observed, error_races[0].error) == 0 &&
              !error_races[0].forward_to_guest_caller);
    CHECK("dlerror isolation preserves second error",
          strcmp(error_races[1].observed, error_races[1].error) == 0 &&
              !error_races[1].forward_to_guest_caller);
    kzt_guest_dl_api_clear_error(&error_races[0].error_state);
    kzt_guest_dl_api_clear_error(&error_races[1].error_state);

    reset_calls();
    error_race_enabled = 1;
    error_races[0] = (dlerror_isolation_race_t) {
        .context = &context,
        .dl = &dl,
        .entries = &direct_entries,
        .error = "thread A cleared error",
        .first = 1,
        .clear_before_read = 1,
    };
    error_races[1] = (dlerror_isolation_race_t) {
        .context = &context,
        .dl = &dl,
        .entries = &direct_entries,
        .error = "thread B retained error",
    };
    CHECK("dlerror clear isolation first thread starts",
          pthread_create(&error_threads[0], NULL, isolate_guest_dlerror,
                         &error_races[0]) == 0);
    CHECK("dlerror clear isolation second thread starts",
          pthread_create(&error_threads[1], NULL, isolate_guest_dlerror,
                         &error_races[1]) == 0);
    CHECK("dlerror clear isolation first thread joins",
          pthread_join(error_threads[0], NULL) == 0);
    CHECK("dlerror clear isolation second thread joins",
          pthread_join(error_threads[1], NULL) == 0);
    error_race_enabled = 0;
    CHECK("CLEARERR empties only the calling thread",
          strcmp(error_races[0].observed, "<empty>") == 0 &&
              error_races[0].forward_to_guest_caller);
    CHECK("CLEARERR preserves the other thread error",
          strcmp(error_races[1].observed, error_races[1].error) == 0 &&
              !error_races[1].forward_to_guest_caller);
    kzt_guest_dl_api_clear_error(&error_races[0].error_state);
    kzt_guest_dl_api_clear_error(&error_races[1].error_state);

    reset_calls();
    guest_result = 0x2010;
    selected_result = 0x3010;
    registry_match_enabled = 1;
    registry_match.link_map_addr = 0x9000;
    registry_match.generation = 1;
    registry_match.namespace_id = 0;
    symbol_result = kzt_guest_dl_api_dlsym(
        &context, &direct_entries, (void *)(uintptr_t)0x9000, symbol);
    CHECK("direct dlsym call", dlsym_calls == 1);
    CHECK("direct dlsym function", seen_function == 0x1010);
    CHECK("direct dlsym handle", seen_handle == (void *)(uintptr_t)0x9000);
    CHECK("direct dlsym result", symbol_result.value == 0x3010);
    CHECK("direct dlsym no forward", !symbol_result.forward_to_guest_caller);

    reset_calls();
    guest_result = 0x2020;
    selected_result = 0x3020;
    registry_match_enabled = 1;
    registry_match.link_map_addr = 1;
    registry_match.generation = 1;
    registry_match.namespace_id = 0;
    symbol_result = kzt_guest_dl_api_dlsym(
        &context, &direct_entries, (void *)(uintptr_t)1, symbol);
    CHECK("opaque low dlsym call", dlsym_calls == 1);
    CHECK("opaque low dlsym handle preserved",
          seen_handle == (void *)(uintptr_t)1);
    CHECK("opaque low dlsym result", symbol_result.value == 0x3020);

    reset_calls();
    guest_result = 0x2028;
    selected_result = 0x3028;
    dlinfo_identity_enabled = 1;
    dlinfo_link_map = 0x2098;
    dlinfo_lmid = 0;
    selector_identity_required = 1;
    symbol_result = kzt_guest_dl_api_dlsym(
        &context, &direct_entries, (void *)(uintptr_t)0x9028, symbol);
    CHECK("unpublished handle queries exact dlinfo", dlinfo_calls == 2);
    CHECK("unpublished handle selected result",
          symbol_result.value == selected_result);

    reset_calls();
    symbol_result = kzt_guest_dl_api_dlsym(
        &context, &direct_entries, (void *)~0ULL, symbol);
    CHECK("RTLD_NEXT forwards", symbol_result.forward_to_guest_caller);
    CHECK("RTLD_NEXT does not call adapter", dlsym_calls == 0);

    reset_calls();
    reset_calls();
    guest_result = 0x2030;
    selected_result = 0x3030;
    registry_match_enabled = 1;
    registry_match.link_map_addr = 1;
    registry_match.generation = 1;
    registry_match.namespace_id = 0;
    symbol_result = kzt_guest_dl_api_dlvsym(
        &context, &direct_entries, (void *)(uintptr_t)1, symbol, version);
    CHECK("dlvsym call", dlvsym_calls == 1);
    CHECK("dlvsym handle preserved", seen_handle == (void *)(uintptr_t)1);
    CHECK("dlvsym version", seen_version == version);
    CHECK("dlvsym result", symbol_result.value == 0x3030);

    reset_calls();
    guest_result = 0x2040;
    dlinfo_identity_enabled = 1;
    dlinfo_link_map = 0x2090;
    dlinfo_lmid = 7;
    CHECK("dlmopen result",
          kzt_guest_dl_api_dlmopen(
              &context, &direct_entries, (void *)(uintptr_t)7,
              filename, 3) == 0x2040);
    CHECK("dlmopen call", dlmopen_calls == 1);
    CHECK("dlmopen namespace", seen_lmid == (void *)(uintptr_t)7);
    CHECK("dlmopen filename", seen_filename == filename);
    CHECK("dlmopen flag", seen_flag == 3);
    CHECK("dlmopen exact dlinfo calls", dlinfo_calls == 2);
    CHECK("dlmopen exact identity published",
          registry_identity_publish_calls == 1 &&
              registry_identity_handle == 0x2040 &&
              registry_identity_link_map == 0x2090 &&
              registry_identity_namespace == 7);

    reset_calls();
    guest_result = 17;
    CHECK("dlinfo result",
          kzt_guest_dl_api_dlinfo(
              &direct_entries, (void *)(uintptr_t)1, 9, info) == 17);
    CHECK("dlinfo call", dlinfo_calls == 1);
    CHECK("dlinfo handle preserved", seen_handle == (void *)(uintptr_t)1);
    CHECK("dlinfo request", seen_request == 9);
    CHECK("dlinfo info", seen_info == info);

    reset_calls();
    dlclose_result = -7;
    CHECK("guest dlclose failure preserved",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == -7);
    CHECK("guest dlclose failure called once", dlclose_calls == 1);
    CHECK("guest dlclose failure handle",
          dlclose_handles[0] == (void *)(uintptr_t)0x9000);
    CHECK("guest dlclose failure skips probe", dlopen_calls == 0);
    CHECK("guest dlclose failure releases writer",
          writer_begin_calls == 1 && writer_end_calls == 1 &&
              writer_active == 0);

    reset_calls();
    CHECK("dlclose without identity succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("dlclose without identity called once", dlclose_calls == 1);
    CHECK("dlclose without identity skips probe", dlopen_calls == 0);
    CHECK("dlclose without identity keeps metadata",
          inactive_calls == 0 && retire_calls == 0);
    CHECK("dlclose without identity records diagnostic",
          registry_close_identity_missing_calls == 1);

    reset_calls();
    set_exact_match(0x9000, 0);
    dlopen_result = 0x9200;
    registry_close_result = KZT_GUEST_LOADER_CLOSE_REFERENCED;
    CHECK("referenced object close succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("referenced object is not pathname-probed", dlopen_calls == 0);
    CHECK("referenced object guest close called once", dlclose_calls == 1);
    CHECK("referenced object remains live",
          inactive_calls == 0 && retire_calls == 0);
    CHECK("referenced object completes exact handle close",
          registry_close_complete_calls == 1);

    reset_calls();
    set_exact_match(0x9000, 0);
    CHECK("pathname miss close succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("pathname miss is not unload proof",
          inactive_calls == 0 && retire_calls == 0);

    reset_calls();
    set_exact_match(0x9000, 0);
    binding_lookup_result = 0;
    binding_library = &library;
    binding_object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED;
    library.x86linkmap = (struct link_map *)(uintptr_t)0x9000;
    CHECK("unloaded wrapper close succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("pathname miss does not consume guest error", dlerror_calls == 0);
    CHECK("pathname miss keeps wrapper binding",
          binding_release_calls == 0 && inactive_calls == 0);
    CHECK("pathname miss keeps guest link map",
          library.x86linkmap == (struct link_map *)(uintptr_t)0x9000);
    CHECK("pathname miss keeps exact generation live", retire_calls == 0);

    {
        kzt_guest_loader_identity_t unload = {
            .handle = 0x9000,
            .link_map_addr = 0x9000,
            .generation = 17,
            .namespace_id = 0,
        };

        CHECK("exact unload prepare",
              kzt_guest_dl_api_prepare_unload(&context, &unload) == 0);
        CHECK("exact unload prepare closes Registry admission",
              registry_unload_begin_calls == 1);
        CHECK("exact unload prepare retires prebind",
              prebind_retire_calls == 1);
        CHECK("exact unload event retires wrapper",
              kzt_guest_dl_api_publish_unload(&context, &unload) == 0);
        CHECK("exact unload event does not repeat prebind retire",
              prebind_retire_calls == 1);
        CHECK("exact unload event retires registry", retire_calls == 1);
        CHECK("exact unload event releases binding",
              binding_release_calls == 1);
        CHECK("exact unload event inactivates wrapper", inactive_calls == 1);
        CHECK("exact unload event clears link map", library.x86linkmap == NULL);
    }

    reset_calls();
    set_exact_match(0x9000, 7);
    {
        kzt_guest_loader_identity_t retained = {
            .link_map_addr = 0x9000,
            .generation = 17,
            .namespace_id = 7,
        };

        CHECK("retained identity prepares",
              kzt_guest_dl_api_prepare_unload(&context, &retained) == 0);
        CHECK("retained identity cancels",
              kzt_guest_dl_api_cancel_unload(&context, &retained) == 0);
        CHECK("retained identity does not finish",
              registry_unload_begin_calls == 1 &&
                  registry_unload_cancel_calls == 1 && retire_calls == 0 &&
                  prebind_retire_calls == 0);
    }

    reset_calls();
    set_exact_match(0x9000, 0);
    prebind_retire_result = -1;
    {
        kzt_guest_loader_identity_t quiesced = {
            .link_map_addr = 0x9000,
            .generation = 17,
            .namespace_id = 0,
        };

        CHECK("prebind failure keeps unload prepared",
              kzt_guest_dl_api_prepare_unload(&context, &quiesced) == 0);
        CHECK("prebind failure does not reopen Registry admission",
              registry_unload_begin_calls == 1 &&
                  registry_unload_cancel_calls == 0);
        CHECK("prebind failure can cancel at consistent",
              kzt_guest_dl_api_cancel_unload(&context, &quiesced) == 0);
    }

    reset_calls();
    set_exact_match(0x9000, 0);
    CHECK("unbound object close succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("unbound object stays live without unload fact", retire_calls == 0);

    reset_calls();
    set_exact_match(0x9000, 0);
    binding_lookup_result = 0;
    binding_library = &library;
    binding_object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED;
    library.x86linkmap = (struct link_map *)(uintptr_t)0x9000;
    close_race_enabled = 1;
    close_races[0] = (dlclose_race_t) {
        .context = &context,
        .thread_scope = &thread_scope,
        .entries = &direct_entries,
        .handle = (void *)(uintptr_t)0x9000,
        .result = -1,
    };
    close_races[1] = close_races[0];
    CHECK("close race first thread starts",
          pthread_create(&close_threads[0], NULL, close_guest_library,
                         &close_races[0]) == 0);
    CHECK("close race second thread starts",
          pthread_create(&close_threads[1], NULL, close_guest_library,
                         &close_races[1]) == 0);
    CHECK("close race first thread joins",
          pthread_join(close_threads[0], NULL) == 0);
    CHECK("close race second thread joins",
          pthread_join(close_threads[1], NULL) == 0);
    close_race_enabled = 0;
    CHECK("close race both guest closes succeed",
          close_races[0].result == 0 && close_races[1].result == 0);
    CHECK("close race does not probe pathname",
          __atomic_load_n(&dlopen_calls, __ATOMIC_RELAXED) == 0);
    CHECK("close race keeps metadata without unload fact",
          __atomic_load_n(&retire_calls, __ATOMIC_RELAXED) == 0 &&
              __atomic_load_n(&inactive_calls, __ATOMIC_RELAXED) == 0 &&
              __atomic_load_n(&binding_release_calls, __ATOMIC_RELAXED) == 0 &&
              library.x86linkmap == (struct link_map *)(uintptr_t)0x9000);

    reset_calls();
    set_exact_match(0x9000, 7);
    guest_result = 0x9300;
    CHECK("namespace object close succeeds",
          kzt_guest_dl_api_dlclose(
              &context, &thread_scope, &direct_entries,
              (void *)(uintptr_t)0x9000) == 0);
    CHECK("namespace close does not probe pathname", dlmopen_calls == 0);
    CHECK("namespace close calls guest once", dlclose_calls == 1);
    CHECK("namespace object remains live",
          inactive_calls == 0 && retire_calls == 0);

    __atomic_store_n(
        &dl.guest_dl_entries.observed_dlerror, 0, __ATOMIC_RELEASE);
    CHECK("dlerror entry starts empty",
          kzt_guest_dl_api_load_dlerror_entry(&dl) == 0);
    CHECK("dlerror inline hint starts empty",
          kzt_guest_dl_api_load_dlerror_hint(&dl) == 0);
    CHECK("dlerror entry rejects wrong symbol",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlsym", 0x7010, 1) != 0);
    CHECK("dlerror entry rejects plain wrapper",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0x7010, 0) != 0);
    CHECK("dlerror entry rejects zero",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0, 1) != 0);
    CHECK("dlerror entry publishes exact guest target",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0x7010, 1) == 0);
    CHECK("dlerror entry loads published target",
          kzt_guest_dl_api_load_dlerror_entry(&dl) == 0x7010);
    CHECK("dlerror inline hint loads published target",
          kzt_guest_dl_api_load_dlerror_hint(&dl) == 0x7010);
    CHECK("dlerror entry same target is idempotent",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0x7010, 1) == 0);
    CHECK("dlerror entry rejects conflict",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0x7020, 1) != 0);
    CHECK("dlerror entry conflict preserves original",
          kzt_guest_dl_api_load_dlerror_entry(&dl) == 0x7010);

    __atomic_store_n(
        &dl.guest_dl_entries.observed_dlerror, 0, __ATOMIC_RELEASE);
    races[0] = (dlerror_publish_race_t) {
        .dl = &dl,
        .entry = 0x7030,
        .result = -1,
    };
    races[1] = (dlerror_publish_race_t) {
        .dl = &dl,
        .entry = 0x7040,
        .result = -1,
    };
    CHECK("dlerror concurrent publisher one starts",
          pthread_create(
              &race_threads[0], NULL, publish_dlerror_entry,
              &races[0]) == 0);
    CHECK("dlerror concurrent publisher two starts",
          pthread_create(
              &race_threads[1], NULL, publish_dlerror_entry,
              &races[1]) == 0);
    CHECK("dlerror concurrent publisher one joins",
          pthread_join(race_threads[0], NULL) == 0);
    CHECK("dlerror concurrent publisher two joins",
          pthread_join(race_threads[1], NULL) == 0);
    CHECK("dlerror concurrent publication has one winner",
          (races[0].result == 0) != (races[1].result == 0));
    CHECK("dlerror concurrent publication preserves winner",
          kzt_guest_dl_api_load_dlerror_entry(&dl) ==
              (races[0].result == 0 ? races[0].entry : races[1].entry));

    CHECK("guest dl entry state initializes",
          kzt_guest_dl_api_entry_state_init(&dl) == 0);
    entry_init_paused = 0;
    entry_init_release = 0;
    entry_reader_checked = 0;
    entry_resolver_calls = 0;
    entry_races[0].dl = &dl;
    entry_races[1].dl = &dl;
    CHECK("guest dl initializer starts",
          pthread_create(&entry_threads[0], NULL,
                         initialize_guest_dl_entries,
                         &entry_races[0]) == 0);
    pthread_mutex_lock(&entry_init_lock);
    while (!entry_init_paused) {
        pthread_cond_wait(&entry_init_ready, &entry_init_lock);
    }
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("guest dl concurrent reader starts",
          pthread_create(&entry_threads[1], NULL, read_guest_dl_entries,
                         &entry_races[1]) == 0);
    pthread_mutex_lock(&entry_init_lock);
    while (!entry_reader_checked) {
        pthread_cond_wait(&entry_init_ready, &entry_init_lock);
    }
    CHECK("guest dl table is hidden while resolver is paused",
          !entry_races[1].saw_table_before_release);
    entry_init_release = 1;
    pthread_cond_broadcast(&entry_init_ready);
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("guest dl initializer joins",
          pthread_join(entry_threads[0], NULL) == 0);
    CHECK("guest dl concurrent reader joins",
          pthread_join(entry_threads[1], NULL) == 0);
    CHECK("guest dl entries resolve once", entry_resolver_calls == 1);
    CHECK("guest dl threads share one published table",
          entry_races[0].result &&
              entry_races[0].result == entry_races[1].result);
    CHECK("guest dl published table is complete",
          entry_races[0].snapshot.dlopen == 0x8100 &&
              entry_races[0].snapshot.dlmopen == 0x8110 &&
              entry_races[0].snapshot.dlsym == 0x8120 &&
              entry_races[0].snapshot.dlclose == 0x8130 &&
              entry_races[0].snapshot.dladdr == 0x8140 &&
              entry_races[0].snapshot.dladdr1 == 0x8150 &&
              entry_races[0].snapshot.dlinfo == 0x8160 &&
              entry_races[0].snapshot.dlvsym == 0x8170 &&
              entry_races[0].snapshot.dlerror == 0x8180);
    kzt_guest_dl_api_entry_state_destroy(&dl);

    CHECK("guest dl retry state initializes",
          kzt_guest_dl_api_entry_state_init(&dl) == 0);
    entry_retry_attempts = 0;
    memset(&entry_races[0], 0, sizeof(entry_races[0]));
    entry_races[0].dl = &dl;
    entry_races[0].result = kzt_guest_dl_api_ensure_entries(
        &dl, resolve_guest_dl_entries_with_retry, NULL,
        &entry_races[0].fallback, NULL);
    CHECK("incomplete guest dl table is not published",
          kzt_guest_dl_api_load_entries(&dl) == NULL);
    CHECK("incomplete guest dl table remains usable only as fallback",
          entry_races[0].result == &entry_races[0].fallback &&
              entry_races[0].fallback.dlopen == 0x8200 &&
              entry_races[0].fallback.dlerror == 0);
    entry_races[0].result = kzt_guest_dl_api_ensure_entries(
        &dl, resolve_guest_dl_entries_with_retry, NULL,
        &entry_races[0].fallback, NULL);
    CHECK("guest dl initialization retries after incomplete result",
          entry_retry_attempts == 2 && entry_races[0].result &&
              entry_races[0].result != &entry_races[0].fallback &&
              entry_races[0].result->dlerror == 0x8280);
    for (int i = 0; i < 1000; ++i) {
        CHECK("steady guest dl table stays published",
              kzt_guest_dl_api_ensure_entries(
                  &dl, resolve_guest_dl_entries_with_retry, NULL,
                  &entry_races[0].fallback, NULL) == entry_races[0].result);
    }
    CHECK("steady guest dl calls do not resolve again",
          entry_retry_attempts == 2);
    kzt_guest_dl_api_entry_state_destroy(&dl);

    CHECK("guest dl hint conflict state initializes",
          kzt_guest_dl_api_entry_state_init(&dl) == 0);
    CHECK("guest dl hint publishes before table initialization",
          kzt_guest_dl_api_publish_dlerror_entry(
              &dl, "dlerror", 0x8290, 1) == 0);
    entry_hint_attempts = 0;
    entry_races[0].result = kzt_guest_dl_api_ensure_entries(
        &dl, resolve_guest_dl_entries_against_hint, NULL,
        &entry_races[0].fallback, NULL);
    CHECK("guest dl hint conflict rejects complete table publication",
          entry_hint_attempts == 1 &&
              kzt_guest_dl_api_load_entries(&dl) == NULL &&
              entry_races[0].result == &entry_races[0].fallback &&
              entry_races[0].fallback.dlerror == 0x8280);
    entry_races[0].result = kzt_guest_dl_api_ensure_entries(
        &dl, resolve_guest_dl_entries_against_hint, NULL,
        &entry_races[0].fallback, NULL);
    CHECK("guest dl hint conflict retries and publishes matching table",
          entry_hint_attempts == 2 && entry_races[0].result &&
              entry_races[0].result != &entry_races[0].fallback &&
              entry_races[0].result->dlerror == 0x8290 &&
              kzt_guest_dl_api_load_dlerror_entry(&dl) == 0x8290);
    kzt_guest_dl_api_entry_state_destroy(&dl);

    CHECK("guest dl recursive state initializes",
          kzt_guest_dl_api_entry_state_init(&dl) == 0);
    entry_recursive_attempted = 0;
    entry_recursive_result = -1;
    entry_races[0].result = kzt_guest_dl_api_ensure_entries(
        &dl, resolve_guest_dl_entries_recursively, &dl,
        &entry_races[0].fallback, NULL);
    CHECK("recursive guest dl initialization fails open",
          entry_recursive_attempted && entry_recursive_result == 0);
    CHECK("outer guest dl initialization still publishes",
          entry_races[0].result &&
              entry_races[0].result->dlerror == 0x8280);
    kzt_guest_dl_api_entry_state_destroy(&dl);

    CHECK("guest dl destroy state initializes",
          kzt_guest_dl_api_entry_state_init(&destroy_dl) == 0);
    entry_init_paused = 0;
    entry_init_release = 0;
    entry_destroy_started = 0;
    entry_destroy_done = 0;
    CHECK("guest dl destroy initializer starts",
          pthread_create(&destroy_threads[0], NULL,
                         initialize_guest_dl_entries,
                         &destroy_init_race) == 0);
    pthread_mutex_lock(&entry_init_lock);
    while (!entry_init_paused) {
        pthread_cond_wait(&entry_init_ready, &entry_init_lock);
    }
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("guest dl destroy thread starts",
          pthread_create(&destroy_threads[1], NULL,
                         destroy_guest_dl_entries, &destroy_race) == 0);
    while (!__atomic_load_n(&entry_destroy_started, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }
    CHECK("guest dl destroy waits for in-flight resolver",
          !__atomic_load_n(&entry_destroy_done, __ATOMIC_ACQUIRE));
    pthread_mutex_lock(&entry_init_lock);
    entry_init_release = 1;
    pthread_cond_broadcast(&entry_init_ready);
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("guest dl destroy initializer joins",
          pthread_join(destroy_threads[0], NULL) == 0);
    CHECK("guest dl destroy thread joins",
          pthread_join(destroy_threads[1], NULL) == 0);
    CHECK("guest dl destroy completes after resolver",
          __atomic_load_n(&entry_destroy_done, __ATOMIC_ACQUIRE));
    CHECK("guest dl teardown prevents publication",
          destroy_init_race.result == &destroy_init_race.fallback);
    kzt_guest_dl_api_entry_state_destroy(&destroy_dl);

    CHECK("default guest dl state initializes",
          kzt_guest_dl_api_entry_state_init(&default_dl) == 0);
    default_entry_pause = 1;
    default_entry_libc_calls = 0;
    default_entry_libdl_calls = 0;
    default_entry_path_calls = 0;
    default_entry_header_frees = 0;
    memset(default_entry_context_calls, 0,
           sizeof(default_entry_context_calls));
    memset(default_entry_context_path_present, 0,
           sizeof(default_entry_context_path_present));
    default_entry_incomplete = 0;
    entry_init_paused = 0;
    entry_init_release = 0;
    CHECK("default guest dl libc caller starts",
          pthread_create(&default_threads[0], NULL,
                         initialize_default_guest_dl_entries,
                         &default_races[0]) == 0);
    pthread_mutex_lock(&entry_init_lock);
    while (!entry_init_paused) {
        pthread_cond_wait(&entry_init_ready, &entry_init_lock);
    }
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("default guest dl libdl caller starts",
          pthread_create(&default_threads[1], NULL,
                         initialize_default_guest_dl_entries,
                         &default_races[1]) == 0);
    pthread_mutex_lock(&entry_init_lock);
    entry_init_release = 1;
    pthread_cond_broadcast(&entry_init_ready);
    pthread_mutex_unlock(&entry_init_lock);
    CHECK("default guest dl libc caller joins",
          pthread_join(default_threads[0], NULL) == 0);
    CHECK("default guest dl libdl caller joins",
          pthread_join(default_threads[1], NULL) == 0);
    CHECK("default guest dl resolver runs once",
          default_entry_libc_calls == 1 && default_entry_libdl_calls == 1 &&
              default_entry_path_calls == 1);
    CHECK("default guest dl resolver frees transient headers",
          default_entry_header_frees == 2);
    CHECK("default guest dl callers share complete table",
          default_races[0].result &&
              default_races[0].result == default_races[1].result &&
              default_races[0].result->dlopen == 0x9000 &&
              default_races[0].result->dlerror == 0x9080);
    CHECK("default initialization publishes runtime entries",
          kzt_guest_runtime_entry_for_guest_branch(
              &default_context, KZT_GUEST_RUNTIME_FREE) == 0x9090 &&
              kzt_guest_runtime_entry_for_guest_branch(
                  &default_context, KZT_GUEST_RUNTIME_REALLOC) == 0x90a0 &&
              kzt_guest_runtime_entry_for_guest_branch(
                  &default_context,
                  KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE) == 0x90b0);
    reset_calls();
    runtime_dlsym_error_model = 1;
    runtime_dlsym_error_pending = 1;
    CHECK("runtime lookup does not consume an older guest error",
          kzt_guest_runtime_entry_for_guest_branch(
              &default_context, KZT_GUEST_RUNTIME_FREE) == 0x9090 &&
              dlsym_calls == 0 && dlerror_calls == 0 &&
              kzt_guest_library_run_dlerror(0x9080) ==
                  (uintptr_t)guest_error &&
              dlerror_calls == 1);
    runtime_dlsym_error_model = 0;
    default_entry_pause = 0;
    for (int i = 0; i < 1000; ++i) {
        CHECK("default guest dl steady table remains published",
              kzt_guest_dl_entries_for_call(
                  &default_context, &default_races[0].fallback) ==
                  default_races[0].result);
    }
    CHECK("default guest dl steady calls skip resolution",
          default_entry_libc_calls == 1 && default_entry_libdl_calls == 1 &&
              default_entry_path_calls == 1);
    kzt_guest_dl_api_entry_state_destroy(&default_dl);

    CHECK("second-context guest dl state initializes",
          kzt_guest_dl_api_entry_state_init(&default_dl_b) == 0);
    default_entry_libc_calls = 0;
    default_entry_libdl_calls = 0;
    default_entry_path_calls = 0;
    default_entry_header_frees = 0;
    default_entry_context_calls[0] = 0;
    default_entry_context_calls[1] = 0;
    default_entry_context_path_present[1] = 0;
    default_races[1].context = &default_context_b;
    default_races[1].result = kzt_guest_dl_entries_for_call(
        &default_context_b, &default_races[1].fallback);
    CHECK("second context resolves through its own path collection",
          default_races[1].result &&
              default_races[1].result->dlopen == 0xa000 &&
              default_races[1].result->dlerror == 0xa080 &&
              default_entry_context_calls[0] == 0 &&
              default_entry_context_calls[1] == 2 &&
              default_entry_path_calls == 1);
    kzt_guest_dl_api_entry_state_destroy(&default_dl_b);

    CHECK("default guest dl failure resource state initializes",
          kzt_guest_dl_api_entry_state_init(&default_dl) == 0);
    default_entry_libc_calls = 0;
    default_entry_libdl_calls = 0;
    default_entry_path_calls = 0;
    default_entry_header_frees = 0;
    default_entry_context_path_present[0] = 0;
    default_entry_incomplete = 1;
    for (int i = 0; i < 100; ++i) {
        default_races[0].result = kzt_guest_dl_entries_for_call(
            &default_context, &default_races[0].fallback);
        CHECK("default guest dl incomplete retry stays private",
              default_races[0].result == &default_races[0].fallback &&
                  kzt_guest_dl_api_load_entries(&default_dl) == NULL);
    }
    CHECK("default guest dl incomplete retries release resources",
          default_entry_libc_calls == 100 &&
              default_entry_libdl_calls == 100 &&
              default_entry_header_frees == 200 &&
              default_entry_path_calls == 1);
    default_entry_incomplete = 0;
    default_races[0].result = kzt_guest_dl_entries_for_call(
        &default_context, &default_races[0].fallback);
    CHECK("default guest dl recovery publishes after resource-stable retries",
          default_races[0].result &&
              default_races[0].result != &default_races[0].fallback &&
              default_entry_libc_calls == 101 &&
              default_entry_libdl_calls == 101 &&
              default_entry_header_frees == 202 &&
              default_entry_path_calls == 1);
    kzt_guest_dl_api_entry_state_destroy(&default_dl);

    CHECK("runtime entry state A initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_a) == 0);
    runtime_entry_resolver_state_init(
        &runtime_resolver_a, "free", 0xa100);
    runtime_resolver_a.failures = 1;
    CHECK("runtime entry failure is not cached",
          kzt_guest_runtime_entry_ensure(
              &runtime_dl_a, KZT_GUEST_RUNTIME_FREE,
              resolve_runtime_entry, &runtime_resolver_a) == 0 &&
              kzt_guest_runtime_entry_load(
                  &runtime_context_a, KZT_GUEST_RUNTIME_FREE) == 0);
    CHECK("runtime entry retries and publishes a valid address",
          kzt_guest_runtime_entry_ensure(
              &runtime_dl_a, KZT_GUEST_RUNTIME_FREE,
              resolve_runtime_entry, &runtime_resolver_a) == 0xa100 &&
              runtime_resolver_a.calls == 2);
    CHECK("runtime entry fast path is an atomic cached load",
          kzt_guest_runtime_entry_load(
              &runtime_context_a, KZT_GUEST_RUNTIME_FREE) == 0xa100);

    runtime_entry_resolver_state_init(
        &runtime_resolver_b, "realloc", 0xa200);
    CHECK("runtime entries cache independently",
          kzt_guest_runtime_entry_ensure(
              &runtime_dl_a, KZT_GUEST_RUNTIME_REALLOC,
              resolve_runtime_entry, &runtime_resolver_b) == 0xa200 &&
              kzt_guest_runtime_entry_load(
                  &runtime_context_a, KZT_GUEST_RUNTIME_FREE) == 0xa100 &&
              runtime_resolver_a.calls == 2 &&
              runtime_resolver_b.calls == 1);
    runtime_entry_resolver_state_destroy(&runtime_resolver_a);
    runtime_entry_resolver_state_destroy(&runtime_resolver_b);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_a);

    CHECK("runtime concurrent state initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_a) == 0);
    runtime_entry_resolver_state_init(
        &runtime_resolver_a, "pthread_setcanceltype", 0xa300);
    runtime_resolver_a.pause = 1;
    runtime_races[0] = (runtime_entry_race_t) {
        .dl = &runtime_dl_a,
        .entry = KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE,
        .resolver = &runtime_resolver_a,
    };
    runtime_races[1] = runtime_races[0];
    CHECK("runtime first resolver starts",
          pthread_create(&runtime_threads[0], NULL,
                         resolve_runtime_entry_in_thread,
                         &runtime_races[0]) == 0);
    pthread_mutex_lock(&runtime_resolver_a.mutex);
    while (!runtime_resolver_a.paused) {
        pthread_cond_wait(
            &runtime_resolver_a.ready, &runtime_resolver_a.mutex);
    }
    pthread_mutex_unlock(&runtime_resolver_a.mutex);
    CHECK("runtime concurrent waiter starts",
          pthread_create(&runtime_threads[1], NULL,
                         resolve_runtime_entry_in_thread,
                         &runtime_races[1]) == 0);
    CHECK("runtime concurrent waiter enters state gate",
          wait_for_runtime_slow_users(&runtime_dl_a, 2) == 0);
    CHECK("runtime entry remains hidden until nonzero publication",
          kzt_guest_runtime_entry_load(
              &runtime_context_a,
              KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE) == 0);
    pthread_mutex_lock(&runtime_resolver_a.mutex);
    runtime_resolver_a.release = 1;
    pthread_cond_broadcast(&runtime_resolver_a.ready);
    pthread_mutex_unlock(&runtime_resolver_a.mutex);
    CHECK("runtime resolver thread joins",
          pthread_join(runtime_threads[0], NULL) == 0);
    CHECK("runtime waiter thread joins",
          pthread_join(runtime_threads[1], NULL) == 0);
    CHECK("runtime concurrent first resolution publishes once",
          runtime_resolver_a.calls == 1 &&
              runtime_races[0].result == 0xa300 &&
              runtime_races[1].result == 0xa300);
    runtime_entry_resolver_state_destroy(&runtime_resolver_a);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_a);

    CHECK("runtime isolated state A initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_a) == 0);
    CHECK("runtime isolated state B initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_b) == 0);
    runtime_entry_resolver_state_init(
        &runtime_resolver_a, "free", 0xa410);
    runtime_entry_resolver_state_init(
        &runtime_resolver_b, "free", 0xa420);
    CHECK("runtime contexts publish isolated addresses",
          kzt_guest_runtime_entry_ensure(
              &runtime_dl_a, KZT_GUEST_RUNTIME_FREE,
              resolve_runtime_entry, &runtime_resolver_a) == 0xa410 &&
              kzt_guest_runtime_entry_ensure(
              &runtime_dl_b, KZT_GUEST_RUNTIME_FREE,
              resolve_runtime_entry, &runtime_resolver_b) == 0xa420 &&
              kzt_guest_runtime_entry_load(
                  &runtime_context_a, KZT_GUEST_RUNTIME_FREE) == 0xa410 &&
              kzt_guest_runtime_entry_load(
                  &runtime_context_b, KZT_GUEST_RUNTIME_FREE) == 0xa420);
    runtime_entry_resolver_state_destroy(&runtime_resolver_a);
    runtime_entry_resolver_state_destroy(&runtime_resolver_b);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_a);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_b);

    CHECK("runtime pinned state initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_a) == 0);
    CHECK("runtime pinned entries publish",
          kzt_guest_runtime_entry_state_publish(
              &runtime_dl_a.guest_dl_entries, runtime_entries) == 0);
    CHECK("runtime pinned scope acquires",
          kzt_guest_runtime_entry_acquire(
              &runtime_context_a,
              KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE,
              &runtime_scope) == 0 && runtime_scope.address == 0xa630);
    entry_destroy_started = 0;
    entry_destroy_done = 0;
    destroy_race.dl = &runtime_dl_a;
    CHECK("runtime pinned teardown starts",
          pthread_create(&runtime_threads[0], NULL,
                         destroy_guest_dl_entries, &destroy_race) == 0);
    while (!__atomic_load_n(&entry_destroy_started, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }
    for (;;) {
        int teardown;

        pthread_mutex_lock(&runtime_dl_a.guest_dl_entries.mutex);
        teardown = runtime_dl_a.guest_dl_entries.teardown;
        pthread_mutex_unlock(&runtime_dl_a.guest_dl_entries.mutex);
        if (teardown) {
            break;
        }
        sched_yield();
    }
    CHECK("runtime pinned teardown waits",
          !__atomic_load_n(&entry_destroy_done, __ATOMIC_ACQUIRE));
    kzt_guest_runtime_entry_release(&runtime_scope);
    CHECK("runtime pinned teardown joins",
          pthread_join(runtime_threads[0], NULL) == 0 &&
          __atomic_load_n(&entry_destroy_done, __ATOMIC_ACQUIRE));
    CHECK("runtime pinned teardown clears entries",
          runtime_dl_a.guest_dl_entries.runtime_entries[
              KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE] == 0);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_a);

    CHECK("runtime teardown state initializes",
          kzt_guest_dl_api_entry_state_init(&runtime_dl_a) == 0);
    runtime_entry_resolver_state_init(
        &runtime_resolver_a, "realloc", 0xa500);
    runtime_resolver_a.pause = 1;
    runtime_races[0] = (runtime_entry_race_t) {
        .dl = &runtime_dl_a,
        .entry = KZT_GUEST_RUNTIME_REALLOC,
        .resolver = &runtime_resolver_a,
    };
    CHECK("runtime teardown resolver starts",
          pthread_create(&runtime_threads[0], NULL,
                         resolve_runtime_entry_in_thread,
                         &runtime_races[0]) == 0);
    pthread_mutex_lock(&runtime_resolver_a.mutex);
    while (!runtime_resolver_a.paused) {
        pthread_cond_wait(
            &runtime_resolver_a.ready, &runtime_resolver_a.mutex);
    }
    pthread_mutex_unlock(&runtime_resolver_a.mutex);
    entry_destroy_started = 0;
    entry_destroy_done = 0;
    destroy_race.dl = &runtime_dl_a;
    CHECK("runtime teardown destroy starts",
          pthread_create(&runtime_threads[1], NULL,
                         destroy_guest_dl_entries, &destroy_race) == 0);
    while (!__atomic_load_n(&entry_destroy_started, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }
    for (;;) {
        int teardown;

        pthread_mutex_lock(&runtime_dl_a.guest_dl_entries.mutex);
        teardown = runtime_dl_a.guest_dl_entries.teardown;
        pthread_mutex_unlock(&runtime_dl_a.guest_dl_entries.mutex);
        if (teardown) {
            break;
        }
        sched_yield();
    }
    CHECK("runtime teardown waits for resolver",
          !__atomic_load_n(&entry_destroy_done, __ATOMIC_ACQUIRE));
    pthread_mutex_lock(&runtime_resolver_a.mutex);
    runtime_resolver_a.release = 1;
    pthread_cond_broadcast(&runtime_resolver_a.ready);
    pthread_mutex_unlock(&runtime_resolver_a.mutex);
    CHECK("runtime teardown resolver joins",
          pthread_join(runtime_threads[0], NULL) == 0);
    CHECK("runtime teardown destroy joins",
          pthread_join(runtime_threads[1], NULL) == 0);
    CHECK("runtime teardown blocks late publication",
          runtime_races[0].result == 0 &&
              runtime_dl_a.guest_dl_entries.runtime_entries[
                  KZT_GUEST_RUNTIME_REALLOC] == 0);
    kzt_guest_dl_api_entry_state_destroy(&runtime_dl_a);
    runtime_entry_resolver_state_destroy(&runtime_resolver_a);

    kzt_guest_dl_api_clear_error(&error_state);
    kzt_guest_dl_api_free_errors(&error_state);
    printf("kzt guest dl API tests: PASS\n");
    return EXIT_SUCCESS;
}
