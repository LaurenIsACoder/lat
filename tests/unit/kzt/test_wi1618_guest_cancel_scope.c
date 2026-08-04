#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "callback.h"
#include "kzt_guest_cancel_scope.h"

#define CHECK(label, condition)                                             \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s: FAIL\n", label);                        \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

static uintptr_t published_address;
static uintptr_t called_address[4];
static int called_type[4];
static int call_count;
static int acquire_calls;
static int release_calls;
static int call_result;

uint64_t RunFunctionWithState(uintptr_t function, int nargs, ...)
{
    va_list args;
    int type;
    int *oldtype;

    CHECK("cancel call argument count", nargs == 2);
    va_start(args, nargs);
    type = va_arg(args, int);
    oldtype = va_arg(args, int *);
    va_end(args);
    called_address[call_count] = function;
    called_type[call_count] = type;
    ++call_count;
    if (!call_result && oldtype) {
        *oldtype = 17;
    }
    return call_result;
}

int kzt_guest_runtime_entry_acquire(
    box64context_t *context, kzt_guest_runtime_entry_id_t entry,
    kzt_guest_runtime_entry_scope_t *scope)
{
    (void)context;
    ++acquire_calls;
    *scope = (kzt_guest_runtime_entry_scope_t) { 0 };
    if (entry != KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE ||
        !published_address) {
        return -1;
    }
    scope->state = (kzt_guest_dl_entry_state_t *)(uintptr_t)1;
    scope->address = published_address;
    return 0;
}

void kzt_guest_runtime_entry_release(
    kzt_guest_runtime_entry_scope_t *scope)
{
    if (scope && scope->state) {
        ++release_calls;
        *scope = (kzt_guest_runtime_entry_scope_t) { 0 };
    }
}

static void reset_state(void)
{
    published_address = 0xa100;
    call_count = 0;
    acquire_calls = 0;
    release_calls = 0;
    call_result = 0;
}

static void test_normal_return_uses_pinned_entry(void)
{
    kzt_guest_cancel_scope_t scope = { 0 };

    reset_state();
    kzt_guest_cancel_scope_begin((box64context_t *)(uintptr_t)1, &scope);
    CHECK("cancel begin acquires once",
          acquire_calls == 1 && scope.switched && scope.oldtype == 17);
    CHECK("cancel begin uses published entry",
          call_count == 1 && called_address[0] == 0xa100);
    published_address = 0xb200;
    kzt_guest_cancel_scope_end(&scope);
    CHECK("cancel end does not reacquire", acquire_calls == 1);
    CHECK("cancel end uses same pinned entry",
          call_count == 2 && called_address[1] == 0xa100 &&
          called_type[1] == 17);
    CHECK("cancel end releases scope",
          release_calls == 1 && !scope.runtime.state && !scope.switched);
}

static void test_switch_failure_releases_entry(void)
{
    kzt_guest_cancel_scope_t scope = { 0 };

    reset_state();
    call_result = 1;
    kzt_guest_cancel_scope_begin((box64context_t *)(uintptr_t)1, &scope);
    CHECK("cancel failure releases scope",
          acquire_calls == 1 && release_calls == 1 &&
          !scope.runtime.state && !scope.switched);
    kzt_guest_cancel_scope_end(&scope);
    CHECK("cancel failure does not restore", call_count == 1);
}

static void test_cancel_cleanup_releases_entry(void)
{
    kzt_guest_cancel_scope_t scope = { 0 };

    reset_state();
    kzt_guest_cancel_scope_begin((box64context_t *)(uintptr_t)1, &scope);
    kzt_guest_cancel_scope_cleanup(&scope);
    CHECK("cancel cleanup releases without restore",
          acquire_calls == 1 && release_calls == 1 && call_count == 1 &&
          !scope.runtime.state && !scope.switched);
    kzt_guest_cancel_scope_cleanup(&scope);
    CHECK("cancel cleanup is idempotent", release_calls == 1);
}

int main(void)
{
    test_normal_return_uses_pinned_entry();
    test_switch_failure_releases_entry();
    test_cancel_cleanup_releases_entry();
    puts("wi1618-guest-cancel-scope: PASS");
    return EXIT_SUCCESS;
}
