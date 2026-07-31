#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/kzt_guest_dl_api.h"
#include "target/i386/latx/include/kzt_guest_library_adapter.h"
#include "target/i386/latx/include/kzt_guest_library_binding.h"
#include "target/i386/latx/include/kzt_jump_slot_production.h"
#include "target/i386/latx/include/kzt_lifecycle_diagnostics.h"

int option_kzt = 1;
int wine_option_kzt;

typedef struct dlclose_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int guest_entered;
    int allow_guest_return;
    int close_bookkeeping_entered;
    int allow_close_bookkeeping_return;
} dlclose_sync_t;

typedef struct dlclose_thread_arg {
    box64context_t *context;
    const kzt_guest_dl_entries_t *entries;
    kzt_guest_library_loader_scope_t thread_scope;
    void *handle;
    int result;
} dlclose_thread_arg_t;

static dlclose_sync_t sync_state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};
static int failures;
static int prebind_invalidations;
static int identity_lookups;
static int close_bookkeeping_calls;
static int guest_return_value;

#define CHECK(name, expr)                                                      \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s\n", name);                               \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

static struct timespec deadline_after_seconds(time_t seconds)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += seconds;
    return deadline;
}

static int wait_for_flag(int *flag)
{
    struct timespec deadline = deadline_after_seconds(10);

    pthread_mutex_lock(&sync_state.lock);
    while (!*flag) {
        int result = pthread_cond_timedwait(
            &sync_state.cond, &sync_state.lock, &deadline);

        if (result != 0) {
            pthread_mutex_unlock(&sync_state.lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&sync_state.lock);
    return 0;
}

static int guest_entered(void)
{
    int entered;

    pthread_mutex_lock(&sync_state.lock);
    entered = sync_state.guest_entered;
    pthread_mutex_unlock(&sync_state.lock);
    return entered;
}

static int wait_for_writer_or_guest(
    kzt_guest_library_bindings_t *bindings, unsigned int *waiters)
{
    struct timespec start;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;
        struct timespec delay = { .tv_nsec = 1000000L };

        if (kzt_guest_library_binding_test_loader_state(
                bindings, NULL, waiters, NULL, NULL) != 0) {
            return -1;
        }
        if (*waiters || guest_entered()) {
            return 0;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 10) {
            return -1;
        }
        nanosleep(&delay, NULL);
    }
}

static void release_guest_call(void)
{
    pthread_mutex_lock(&sync_state.lock);
    sync_state.allow_guest_return = 1;
    pthread_cond_broadcast(&sync_state.cond);
    pthread_mutex_unlock(&sync_state.lock);
}

static void release_close_bookkeeping(void)
{
    pthread_mutex_lock(&sync_state.lock);
    sync_state.allow_close_bookkeeping_return = 1;
    pthread_cond_broadcast(&sync_state.cond);
    pthread_mutex_unlock(&sync_state.lock);
}

static void check_reader_rejected(
    const char *name, kzt_guest_library_bindings_t *bindings)
{
    kzt_guest_library_loader_quiescence_lease_t late = { 0 };
    int result = kzt_guest_library_loader_quiescence_try_acquire(
        bindings, &late);

    CHECK(name, result != 0);
    if (result == 0) {
        kzt_guest_library_loader_quiescence_release(&late);
    }
}

static void *run_dlclose_thread(void *opaque)
{
    dlclose_thread_arg_t *arg = opaque;

    arg->result = kzt_guest_dl_api_dlclose(
        arg->context, &arg->thread_scope, arg->entries, arg->handle);
    return NULL;
}

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(
    box64context_t *context)
{
    return context ? context->kzt_guest_library_access.bindings : NULL;
}

kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    return context ? (kzt_guest_registry_t *)(uintptr_t)0x1 : NULL;
}

int kzt_guest_registry_find_loader_identity(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity)
{
    CHECK("identity registry", registry == (kzt_guest_registry_t *)0x1);
    CHECK("identity handle", handle == 0x9000);
    ++identity_lookups;
    *identity = (kzt_guest_loader_identity_t) {
        .handle = handle,
        .link_map_addr = 0x9100,
        .generation = 17,
        .namespace_id = 0,
    };
    return 0;
}

kzt_guest_loader_close_result_t kzt_guest_registry_complete_loader_close(
    kzt_guest_registry_t *registry,
    const kzt_guest_loader_identity_t *identity)
{
    CHECK("close registry", registry == (kzt_guest_registry_t *)0x1);
    CHECK("close identity",
          identity && identity->link_map_addr == 0x9100 &&
              identity->generation == 17 && identity->namespace_id == 0);
    ++close_bookkeeping_calls;
    pthread_mutex_lock(&sync_state.lock);
    sync_state.close_bookkeeping_entered = 1;
    pthread_cond_broadcast(&sync_state.cond);
    while (!sync_state.allow_close_bookkeeping_return) {
        pthread_cond_wait(&sync_state.cond, &sync_state.lock);
    }
    pthread_mutex_unlock(&sync_state.lock);
    return KZT_GUEST_LOADER_CLOSE_REFERENCED;
}

void kzt_guest_registry_note_loader_close_identity_missing(
    kzt_guest_registry_t *registry)
{
    (void)registry;
    CHECK("exact identity unexpectedly missing", 0);
}

int kzt_production_lazy_prebind_invalidate(
    box64context_t *context, kzt_lazy_prebind_mutation_t mutation)
{
    CHECK("prebind context", context != NULL);
    CHECK("prebind mutation", mutation == KZT_LAZY_PREBIND_MUTATION_DLCLOSE);
    ++prebind_invalidations;
    return 0;
}

int kzt_lifecycle_diagnostics_enabled(void)
{
    return 0;
}

uint64_t kzt_lifecycle_diagnostics_now(void)
{
    return 0;
}

void kzt_lifecycle_diagnostics_add(
    kzt_lifecycle_diagnostic_stage_t stage, uint64_t duration_ns)
{
    (void)stage;
    (void)duration_ns;
}

int kzt_guest_library_run_dlclose(uintptr_t function, void *handle)
{
    CHECK("guest function", function == 0x1060);
    CHECK("guest handle", handle == (void *)(uintptr_t)0x9000);
    pthread_mutex_lock(&sync_state.lock);
    sync_state.guest_entered = 1;
    pthread_cond_broadcast(&sync_state.cond);
    while (!sync_state.allow_guest_return) {
        pthread_cond_wait(&sync_state.cond, &sync_state.lock);
    }
    pthread_mutex_unlock(&sync_state.lock);
    return guest_return_value;
}

int main(void)
{
    box64context_t context = { 0 };
    kzt_guest_library_bindings_t *bindings =
        kzt_guest_library_bindings_init();
    kzt_guest_library_loader_quiescence_lease_t reader = { 0 };
    kzt_guest_library_loader_quiescence_lease_t after = { 0 };
    kzt_guest_dl_entries_t entries = { .dlclose = 0x1060 };
    dlclose_thread_arg_t arg = {
        .context = &context,
        .entries = &entries,
        .handle = (void *)(uintptr_t)0x9000,
        .result = -1,
    };
    pthread_t thread;
    unsigned int waiters = 0;

    CHECK("bindings init", bindings != NULL);
    if (!bindings) {
        return EXIT_FAILURE;
    }
    context.kzt_guest_library_access.bindings = bindings;
    CHECK("initial reader acquire",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &reader) == 0);
    CHECK("dlclose thread create",
          pthread_create(&thread, NULL, run_dlclose_thread, &arg) == 0);

    CHECK("writer or guest becomes observable",
          wait_for_writer_or_guest(bindings, &waiters) == 0);
    CHECK("guest dlclose waits for existing reader", !guest_entered());
    CHECK("dlclose registers writer admission gate", waiters == 1);
    check_reader_rejected("waiting writer rejects new reader", bindings);

    kzt_guest_library_loader_quiescence_release(&reader);
    CHECK("guest dlclose enters after reader release",
          wait_for_flag(&sync_state.guest_entered) == 0);
    check_reader_rejected("guest dlclose keeps writer active", bindings);

    release_guest_call();
    CHECK("close bookkeeping entered",
          wait_for_flag(&sync_state.close_bookkeeping_entered) == 0);
    check_reader_rejected("close bookkeeping keeps writer active", bindings);

    release_close_bookkeeping();
    CHECK("dlclose thread join", pthread_join(thread, NULL) == 0);
    CHECK("guest result preserved", arg.result == 0);
    CHECK("prebind invalidated once", prebind_invalidations == 1);
    CHECK("identity read once", identity_lookups == 1);
    CHECK("close bookkeeping once", close_bookkeeping_calls == 1);
    CHECK("reader admission reopens after dlclose",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &after) == 0);
    kzt_guest_library_loader_quiescence_release(&after);

    pthread_mutex_lock(&sync_state.lock);
    sync_state.guest_entered = 0;
    sync_state.allow_guest_return = 0;
    pthread_mutex_unlock(&sync_state.lock);
    guest_return_value = -7;
    arg.result = 0;
    CHECK("failing dlclose thread create",
          pthread_create(&thread, NULL, run_dlclose_thread, &arg) == 0);
    CHECK("failing guest dlclose enters",
          wait_for_flag(&sync_state.guest_entered) == 0);
    check_reader_rejected("failing guest dlclose keeps writer active",
                          bindings);
    release_guest_call();
    CHECK("failing dlclose thread join", pthread_join(thread, NULL) == 0);
    CHECK("failing guest result preserved", arg.result == -7);
    CHECK("failing close skips bookkeeping", close_bookkeeping_calls == 1);
    CHECK("failing close releases writer",
          kzt_guest_library_loader_quiescence_try_acquire(
              bindings, &after) == 0);
    kzt_guest_library_loader_quiescence_release(&after);

    context.kzt_guest_library_access.bindings = NULL;
    kzt_guest_library_bindings_destroy(&bindings);
    pthread_cond_destroy(&sync_state.cond);
    pthread_mutex_destroy(&sync_state.lock);
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return EXIT_FAILURE;
    }
    puts("guest dlclose quiescence: PASS");
    return EXIT_SUCCESS;
}
