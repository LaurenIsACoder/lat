#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define GUARDED_THREAD_COUNT 16

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge.h"
#include "target/i386/latx/include/bridge_private.h"
#include "target/i386/latx/include/elfloader.h"

box64context_t *my_context;
int relocation_log;
int kzt_registry_diagnostics;

elfheader_t *FindElfAddress(box64context_t *context, uintptr_t address)
{
    (void)context;
    (void)address;
    return NULL;
}

static int failures;

static void wrapper(uintptr_t fnc)
{
    (void)fnc;
}

static void other_wrapper(uintptr_t fnc)
{
    (void)fnc;
}

static void check_true(const char *name, int value)
{
    if (!value) {
        fprintf(stderr, "%s: false\n", name);
        ++failures;
    }
}

static void test_layout_stays_compatible(void)
{
    check_true("layout.size", sizeof(onebridge_t) == 32);
    check_true("layout.CC", offsetof(onebridge_t, CC) == 0);
    check_true("layout.S", offsetof(onebridge_t, S) == 1);
    check_true("layout.C", offsetof(onebridge_t, C) == 2);
    check_true("layout.w", offsetof(onebridge_t, w) == 3);
    check_true("layout.f", offsetof(onebridge_t, f) == 11);
    check_true("layout.C3", offsetof(onebridge_t, C3) == 19);
    check_true("layout.N", offsetof(onebridge_t, N) == 20);
    check_true("layout.fallback",
               offsetof(onebridge_t, guest_fallback_target) == 22);
    check_true("layout.guard", offsetof(onebridge_t, guard_kind) == 30);
}

static void test_guarded_bridge_semantic_reuse(void)
{
    bridge_t *bridge = NewBridge();
    void *native = (void *)(uintptr_t)0x410000;
    uintptr_t base;
    uintptr_t same;
    uintptr_t other_fallback;
    uintptr_t other_wrapper_bridge;
    uintptr_t other_native;
    uintptr_t other_stack_bytes;
    onebridge_t *entry;

    check_true("guarded.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    base = AddGuardedBridge(bridge, wrapper, native, 0, "xcb_flush",
                            0x510000,
                            KZT_BRIDGE_GUARD_XCB_CONNECTION);
    same = AddGuardedBridge(bridge, wrapper, native, 0, "different-name",
                            0x510000,
                            KZT_BRIDGE_GUARD_XCB_CONNECTION);
    other_fallback = AddGuardedBridge(
        bridge, wrapper, native, 0, "xcb_flush", 0x520000,
        KZT_BRIDGE_GUARD_XCB_CONNECTION);
    other_wrapper_bridge = AddGuardedBridge(
        bridge, other_wrapper, native, 0, "xcb_flush", 0x510000,
        KZT_BRIDGE_GUARD_XCB_CONNECTION);
    other_native = AddGuardedBridge(
        bridge, wrapper, (void *)(uintptr_t)0x410008, 0, "xcb_flush",
        0x510000, KZT_BRIDGE_GUARD_XCB_CONNECTION);
    other_stack_bytes = AddGuardedBridge(
        bridge, wrapper, native, 4, "xcb_flush", 0x510000,
        KZT_BRIDGE_GUARD_XCB_CONNECTION);
    entry = (onebridge_t *)base;

    check_true("guarded.base", base != 0);
    check_true("guarded.same-semantic-key", same == base);
    check_true("guarded.other-fallback", other_fallback != base);
    check_true("guarded.other-wrapper", other_wrapper_bridge != base);
    check_true("guarded.other-native", other_native != base);
    check_true("guarded.other-stack-bytes", other_stack_bytes != base);
    check_true("guarded.other-guard-rejected",
               AddGuardedBridge(bridge, wrapper, native, 0, "xcb_flush",
                                0x510000, KZT_BRIDGE_GUARD_NONE) == 0);
    check_true("guarded.unique-count",
               bridge_test_guarded_count(bridge) == 5);
    check_true("guarded.not-mapped", CheckBridged(bridge, native) == 0);
    check_true("guarded.native-hidden", GetNativeFnc(base) == NULL);
    check_true("guarded.bridge-preserved",
               GetNativeFncOrFnc(base) == (void *)base);
    if (entry) {
        check_true("guarded.wrapper", entry->w == wrapper);
        check_true("guarded.native", entry->f == (uintptr_t)native);
        check_true("guarded.fallback",
                   entry->guest_fallback_target == 0x510000);
        check_true("guarded.kind",
                   entry->guard_kind ==
                       KZT_BRIDGE_GUARD_XCB_CONNECTION);
    }
    FreeBridge(&bridge);
}

static void test_normal_bridge_deduplication_is_unchanged(void)
{
    bridge_t *bridge = NewBridge();
    void *native = (void *)(uintptr_t)0x420000;
    uintptr_t guarded;
    uintptr_t first;
    uintptr_t second;
    uintptr_t guarded_again;
    onebridge_t *entry;

    check_true("normal.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    guarded = AddGuardedBridge(bridge, wrapper, native, 0, "guarded",
                               0x520000,
                               KZT_BRIDGE_GUARD_XCB_CONNECTION);
    check_true("normal.guarded-created", guarded != 0);
    check_true("normal.guarded-not-mapped",
               CheckBridged(bridge, native) == 0);
    first = AddCheckBridge(bridge, wrapper, native, 0, "normal");
    second = AddCheckBridge(bridge, wrapper, native, 0, "normal");
    guarded_again = AddGuardedBridge(
        bridge, wrapper, native, 0, "guarded-again", 0x520000,
        KZT_BRIDGE_GUARD_XCB_CONNECTION);
    entry = (onebridge_t *)first;

    check_true("normal.first", first != 0);
    check_true("normal.separate-from-guarded", first != guarded);
    check_true("normal.deduplicated", first == second);
    check_true("normal.guarded-still-deduplicated",
               guarded_again == guarded);
    check_true("normal.guarded-count",
               bridge_test_guarded_count(bridge) == 1);
    check_true("normal.mapped", CheckBridged(bridge, native) == first);
    check_true("normal.native-visible", GetNativeFnc(first) == native);
    check_true("normal.native-unwrapped", GetNativeFncOrFnc(first) == native);
    if (entry) {
        check_true("normal.no-fallback", entry->guest_fallback_target == 0);
        check_true("normal.no-guard",
                   entry->guard_kind == KZT_BRIDGE_GUARD_NONE);
    }
    FreeBridge(&bridge);
}

typedef struct guarded_start_gate_s {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int ready;
    int start;
} guarded_start_gate_t;

typedef struct guarded_worker_s {
    bridge_t *bridge;
    guarded_start_gate_t *gate;
    uintptr_t result;
} guarded_worker_t;

static void *guarded_worker_main(void *opaque)
{
    guarded_worker_t *worker = opaque;

    pthread_mutex_lock(&worker->gate->lock);
    ++worker->gate->ready;
    pthread_cond_broadcast(&worker->gate->cond);
    while (!worker->gate->start) {
        pthread_cond_wait(&worker->gate->cond, &worker->gate->lock);
    }
    pthread_mutex_unlock(&worker->gate->lock);
    worker->result = AddGuardedBridge(
        worker->bridge, wrapper, (void *)(uintptr_t)0x440000, 0,
        "xcb_connection_has_error", 0x540000,
        KZT_BRIDGE_GUARD_XCB_CONNECTION);
    return NULL;
}

static void test_guarded_bridge_concurrent_reuse(void)
{
    bridge_t *bridge = NewBridge();
    guarded_start_gate_t gate;
    guarded_worker_t workers[GUARDED_THREAD_COUNT];
    pthread_t threads[GUARDED_THREAD_COUNT];
    int created = 0;
    int i;

    check_true("concurrent.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    gate.ready = 0;
    gate.start = 0;
    check_true("concurrent.mutex-init",
               pthread_mutex_init(&gate.lock, NULL) == 0);
    check_true("concurrent.cond-init",
               pthread_cond_init(&gate.cond, NULL) == 0);
    for (i = 0; i < GUARDED_THREAD_COUNT; ++i) {
        workers[i] = (guarded_worker_t) {
            .bridge = bridge,
            .gate = &gate,
            .result = 0,
        };
        if (pthread_create(&threads[i], NULL, guarded_worker_main,
                           &workers[i]) != 0) {
            check_true("concurrent.thread-create", 0);
            break;
        }
        ++created;
    }
    pthread_mutex_lock(&gate.lock);
    while (gate.ready < created) {
        pthread_cond_wait(&gate.cond, &gate.lock);
    }
    gate.start = 1;
    pthread_cond_broadcast(&gate.cond);
    pthread_mutex_unlock(&gate.lock);
    for (i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
    }
    check_true("concurrent.all-created",
               created == GUARDED_THREAD_COUNT);
    if (created > 0) {
        check_true("concurrent.nonzero", workers[0].result != 0);
        for (i = 1; i < created; ++i) {
            check_true("concurrent.same-result",
                       workers[i].result == workers[0].result);
        }
    }
    check_true("concurrent.single-entry",
               bridge_test_guarded_count(bridge) == 1);
    pthread_cond_destroy(&gate.cond);
    pthread_mutex_destroy(&gate.lock);
    FreeBridge(&bridge);
}

static void test_invalid_guarded_bridge_is_rejected(void)
{
    bridge_t *bridge = NewBridge();
    void *native = (void *)(uintptr_t)0x430000;

    check_true("invalid.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    check_true("invalid.bridge",
               AddGuardedBridge(NULL, wrapper, native, 0, "invalid",
                                0x530000,
                                KZT_BRIDGE_GUARD_XCB_CONNECTION) == 0);
    check_true("invalid.wrapper",
               AddGuardedBridge(bridge, NULL, native, 0, "invalid",
                                0x530000,
                                KZT_BRIDGE_GUARD_XCB_CONNECTION) == 0);
    check_true("invalid.native",
               AddGuardedBridge(bridge, wrapper, NULL, 0, "invalid",
                                0x530000,
                                KZT_BRIDGE_GUARD_XCB_CONNECTION) == 0);
    check_true("invalid.fallback",
               AddGuardedBridge(bridge, wrapper, native, 0, "invalid", 0,
                                KZT_BRIDGE_GUARD_XCB_CONNECTION) == 0);
    check_true("invalid.none",
               AddGuardedBridge(bridge, wrapper, native, 0, "invalid",
                                0x530000, KZT_BRIDGE_GUARD_NONE) == 0);
    check_true("invalid.unknown",
               AddGuardedBridge(bridge, wrapper, native, 0, "invalid",
                                0x530000,
                                (kzt_bridge_guard_kind_t)2) == 0);
    check_true("invalid.no-map", CheckBridged(bridge, native) == 0);
    FreeBridge(&bridge);
}

int main(void)
{
    test_layout_stays_compatible();
    test_guarded_bridge_semantic_reuse();
    test_normal_bridge_deduplication_is_unchanged();
    test_guarded_bridge_concurrent_reuse();
    test_invalid_guarded_bridge_is_rejected();
    if (failures) {
        fprintf(stderr, "kzt-wi1572-guarded-bridge: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("kzt-wi1572-guarded-bridge: ok");
    return 0;
}
