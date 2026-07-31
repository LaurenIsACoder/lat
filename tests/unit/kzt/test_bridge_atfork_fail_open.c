#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge.h"
#include "target/i386/latx/include/elfloader.h"
#include "target/i386/latx/include/khash.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"
#include "target/i386/latx/include/librarian_private.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

#define FIXTURE_SYMBOL "uname"
#define FIXTURE_VERSION "GLIBC_2.36"

box64context_t *my_context;
int relocation_log;
int kzt_registry_diagnostics;

KHASH_MAP_IMPL_STR(symbolmap, wrapper_t)
KHASH_MAP_IMPL_STR(symbol2map, symbol2_t)

typedef struct bridge_hold_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int entered;
    int release;
} bridge_hold_sync_t;

typedef struct bridge_hold_worker {
    bridge_t *bridge;
    bridge_hold_sync_t *sync;
} bridge_hold_worker_t;

typedef struct runtime_fixture {
    box64context_t context;
    lib_t scope;
    library_t provider;
    library_t *libraries[1];
    void *native_symbol;
    uintptr_t bridge_target;
} runtime_fixture_t;

elfheader_t *FindElfAddress(box64context_t *context, uintptr_t address)
{
    (void)context;
    (void)address;
    return NULL;
}

static void wrapper(uintptr_t fnc)
{
    (void)fnc;
}

static void bridge_hold_hook(void *opaque)
{
    bridge_hold_sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    sync->entered = 1;
    pthread_cond_broadcast(&sync->cond);
    while (!sync->release) {
        pthread_cond_wait(&sync->cond, &sync->lock);
    }
    pthread_mutex_unlock(&sync->lock);
}

static void *bridge_hold_main(void *opaque)
{
    bridge_hold_worker_t *worker = opaque;

    (void)AddCheckBridge(worker->bridge, wrapper, (void *)0x410000, 0,
                         "held-across-fork");
    return NULL;
}

static int bridge_hold_sync_init(bridge_hold_sync_t *sync)
{
    memset(sync, 0, sizeof(*sync));
    return pthread_mutex_init(&sync->lock, NULL) ||
           pthread_cond_init(&sync->cond, NULL) ? -1 : 0;
}

static void bridge_hold_sync_destroy(bridge_hold_sync_t *sync)
{
    pthread_cond_destroy(&sync->cond);
    pthread_mutex_destroy(&sync->lock);
}

static int bridge_hold_wait(bridge_hold_sync_t *sync)
{
    struct timespec deadline;
    int status = 0;

    clock_gettime(CLOCK_REALTIME, &deadline);
    ++deadline.tv_sec;
    pthread_mutex_lock(&sync->lock);
    while (!sync->entered && status == 0) {
        status = pthread_cond_timedwait(&sync->cond, &sync->lock, &deadline);
    }
    pthread_mutex_unlock(&sync->lock);
    return status == 0 ? 0 : -1;
}

static void bridge_hold_release(bridge_hold_sync_t *sync)
{
    pthread_mutex_lock(&sync->lock);
    sync->release = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
}

static int runtime_fixture_init(runtime_fixture_t *fixture, bridge_t *bridge)
{
    static char libc_name[] = "libc.so.6";
    khint_t key;
    int inserted;

    memset(fixture, 0, sizeof(*fixture));
    fixture->libraries[0] = &fixture->provider;
    fixture->scope.libraries = fixture->libraries;
    fixture->scope.libsz = 1;
    fixture->scope.context = &fixture->context;
    fixture->context.maplib = &fixture->scope;
    fixture->provider.name = libc_name;
    fixture->provider.path = libc_name;
    fixture->provider.type = LIB_WRAPPED;
    fixture->provider.active = 1;
    fixture->provider.context = &fixture->context;
    fixture->provider.priv.w.bridge = bridge;
    fixture->provider.priv.w.lib = dlopen(libc_name, RTLD_LAZY | RTLD_LOCAL);
    if (!fixture->provider.priv.w.lib) {
        return -1;
    }
    fixture->provider.symbolmap = kh_init(symbolmap);
    if (!fixture->provider.symbolmap) {
        dlclose(fixture->provider.priv.w.lib);
        fixture->provider.priv.w.lib = NULL;
        return -1;
    }
    key = kh_put(symbolmap, fixture->provider.symbolmap, FIXTURE_SYMBOL,
                 &inserted);
    if (inserted == -1 || key == kh_end(fixture->provider.symbolmap)) {
        kh_destroy(symbolmap, fixture->provider.symbolmap);
        dlclose(fixture->provider.priv.w.lib);
        memset(fixture, 0, sizeof(*fixture));
        return -1;
    }
    kh_value(fixture->provider.symbolmap, key) = wrapper;
    fixture->native_symbol = dlvsym(fixture->provider.priv.w.lib,
                                    FIXTURE_SYMBOL, FIXTURE_VERSION);
    fixture->bridge_target = AddCheckBridge(
        bridge, wrapper, fixture->native_symbol, 0, FIXTURE_SYMBOL);
    if (!fixture->native_symbol || !fixture->bridge_target ||
        CheckBridged(bridge, fixture->native_symbol) != fixture->bridge_target) {
        kh_destroy(symbolmap, fixture->provider.symbolmap);
        dlclose(fixture->provider.priv.w.lib);
        memset(fixture, 0, sizeof(*fixture));
        return -1;
    }
    return 0;
}

static void runtime_fixture_destroy(runtime_fixture_t *fixture)
{
    if (fixture->provider.symbolmap) {
        kh_destroy(symbolmap, fixture->provider.symbolmap);
    }
    if (fixture->provider.priv.w.lib) {
        dlclose(fixture->provider.priv.w.lib);
    }
}

static int capture_atfork_diagnostic(bridge_t **bridge, char *diagnostic,
                                     size_t diagnostic_capacity)
{
    int diagnostic_pipe[2];
    int saved_stderr;
    ssize_t diagnostic_size;

    if (pipe(diagnostic_pipe) != 0) {
        return -1;
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0 || dup2(diagnostic_pipe[1], STDERR_FILENO) < 0) {
        close(diagnostic_pipe[0]);
        close(diagnostic_pipe[1]);
        if (saved_stderr >= 0) {
            close(saved_stderr);
        }
        return -1;
    }
    close(diagnostic_pipe[1]);
    *bridge = NewBridge();
    fflush(stderr);
    if (dup2(saved_stderr, STDERR_FILENO) < 0) {
        close(saved_stderr);
        close(diagnostic_pipe[0]);
        return -1;
    }
    close(saved_stderr);
    diagnostic_size = read(diagnostic_pipe[0], diagnostic,
                           diagnostic_capacity - 1);
    close(diagnostic_pipe[0]);
    if (diagnostic_size < 0) {
        return -1;
    }
    diagnostic[diagnostic_size] = '\0';
    return 0;
}

int main(int argc, char **argv)
{
    char diagnostic[512] = { 0 };
    bridge_hold_sync_t sync;
    bridge_hold_worker_t worker;
    kzt_wrapper_bridge_provider_t provider;
    runtime_fixture_t fixture;
    pthread_t holder;
    bridge_t *bridge = NULL;
    pid_t pid;
    int child_status = -1;
    int failed = 0;

    if (argc == 2 && strcmp(argv[1], "--diagnostics-off") == 0) {
        kzt_registry_diagnostics = 0;
        if (capture_atfork_diagnostic(
                &bridge, diagnostic, sizeof(diagnostic)) != 0 || !bridge) {
            fprintf(stderr, "cannot initialize diagnostics-off fixture\n");
            return 1;
        }
        if (diagnostic[0]) {
            fprintf(stderr, "atfork fallback diagnostic ignored gate: %s\n",
                    diagnostic);
            failed = 1;
        }
        FreeBridge(&bridge);
        return failed ? 1 : 0;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--diagnostics-off]\n", argv[0]);
        return 2;
    }

    kzt_registry_diagnostics = 1;
    if (capture_atfork_diagnostic(&bridge, diagnostic, sizeof(diagnostic)) != 0 ||
        !bridge) {
        fprintf(stderr, "cannot initialize bridge failure fixture\n");
        return 1;
    }
    if (!strstr(diagnostic, "kzt_bridge_fallback") ||
        !strstr(diagnostic, "reason=atfork_registration_failed")) {
        fprintf(stderr, "structured atfork fallback diagnostic missing: %s\n",
                diagnostic);
        failed = 1;
    }
    if (bridge_hold_sync_init(&sync) != 0 ||
        runtime_fixture_init(&fixture, bridge) != 0) {
        fprintf(stderr, "cannot initialize real-fork fixture\n");
        FreeBridge(&bridge);
        return 1;
    }
    worker = (bridge_hold_worker_t) { bridge, &sync };
    bridge_test_set_after_check_hook(bridge_hold_hook, &sync);
    if (pthread_create(&holder, NULL, bridge_hold_main, &worker) != 0 ||
        bridge_hold_wait(&sync) != 0) {
        fprintf(stderr, "bridge holder did not acquire the bridge lock\n");
        bridge_hold_release(&sync);
        bridge_test_set_after_check_hook(NULL, NULL);
        runtime_fixture_destroy(&fixture);
        FreeBridge(&bridge);
        bridge_hold_sync_destroy(&sync);
        return 1;
    }

    pid = fork();
    if (pid == 0) {
        int status;

        alarm(2);
        memset(&provider, 0, sizeof(provider));
        status = kzt_rela_runtime_wrapper_provider_prepare(
            &fixture.context, &fixture.provider, fixture.bridge_target,
            FIXTURE_SYMBOL, FIXTURE_VERSION, &provider);
        _exit(status == 0 && !provider.manifest.available &&
                      !provider.bridge_ops.check_bridge &&
                      !provider.bridge_ops.add_bridge ? 0 : 2);
    }
    if (pid < 0 || waitpid(pid, &child_status, 0) != pid) {
        fprintf(stderr, "real fork failed\n");
        failed = 1;
    }

    bridge_hold_release(&sync);
    if (pthread_join(holder, NULL) != 0) {
        fprintf(stderr, "cannot join bridge holder\n");
        failed = 1;
    }
    bridge_test_set_after_check_hook(NULL, NULL);
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr,
                "KZT child did not fail open while bridge lock was inherited: "
                "status=%d\n",
                child_status);
        failed = 1;
    }

    runtime_fixture_destroy(&fixture);
    FreeBridge(&bridge);
    bridge_hold_sync_destroy(&sync);
    return failed ? 1 : 0;
}
