#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge.h"
#include "target/i386/latx/include/elfloader.h"
#include "target/i386/latx/include/khash.h"

#define SYMBOL_COUNT 512
#define THREAD_COUNT 8
#define ALTERNATE_STRESS_ENTRIES 2048
#define ALTERNATE_READER_THREADS 4
#define ALTERNATE_WRITER_THREADS 4
#define BENCHMARK_ROUNDS 30
#define BENCHMARK_QUERIES 4096
#define BENCHMARK_REPEAT 32
#define BRIDGE_GATE_BENCHMARK_REPEAT 1000000

KHASH_MAP_INIT_INT64(alternate_benchmark, uintptr_t)

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

static uint64_t monotonic_ns(void);

static void check_true(const char *name, int value)
{
    if (!value) {
        fprintf(stderr, "%s: false\n", name);
        ++failures;
    }
}

typedef struct sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int entered;
    int second_started;
    int release;
    int done;
} sync_t;

typedef struct bridge_worker {
    bridge_t *bridge;
    void *symbol;
    uintptr_t result;
    sync_t *sync;
    int force_add;
    int automatic_add;
    int second;
} bridge_worker_t;

typedef struct alternate_worker {
    void *address;
    void *alternate;
} alternate_worker_t;

typedef struct alternate_reader_worker {
    uintptr_t first;
    uintptr_t count;
    int same_offset;
    int failures;
} alternate_reader_worker_t;

typedef struct alternate_writer_range {
    uintptr_t first;
    uintptr_t count;
    uintptr_t stride;
    int same_offset;
} alternate_writer_range_t;

typedef struct fork_worker {
    bridge_t *bridge;
    sync_t *sync;
    int child_status;
} fork_worker_t;

typedef struct free_bridge_worker {
    bridge_t **bridge;
} free_bridge_worker_t;

typedef struct fork_after_free_worker {
    sync_t *sync;
    int child_status;
} fork_after_free_worker_t;

typedef struct parallel_worker {
    bridge_worker_t *workers;
    size_t start;
} parallel_worker_t;

static void wrapper(uintptr_t fnc)
{
    (void)fnc;
}

static uintptr_t alternate_test_address(uintptr_t base, uintptr_t index,
                                        int same_offset)
{
    return same_offset ? base + (index << 16) : base + index * 16;
}

static int sync_init(sync_t *sync)
{
    memset(sync, 0, sizeof(*sync));
    return pthread_mutex_init(&sync->lock, NULL) ||
           pthread_cond_init(&sync->cond, NULL) ? -1 : 0;
}

static void sync_destroy(sync_t *sync)
{
    pthread_cond_destroy(&sync->cond);
    pthread_mutex_destroy(&sync->lock);
}

static int sync_wait_for(sync_t *sync, int *value, int expected,
                         long timeout_ms)
{
    struct timespec deadline;
    int result = 0;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += (timeout_ms % 1000) * 1000 * 1000;
    deadline.tv_sec += timeout_ms / 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&sync->lock);
    while (*value < expected) {
        int status = pthread_cond_timedwait(&sync->cond, &sync->lock,
                                            &deadline);
        if (status != 0) {
            result = -1;
            break;
        }
    }
    pthread_mutex_unlock(&sync->lock);
    return result;
}

static void after_check_hook(void *opaque)
{
    sync_t *sync = opaque;

    pthread_mutex_lock(&sync->lock);
    if (!sync->entered) {
        sync->entered = 1;
        pthread_cond_broadcast(&sync->cond);
        while (!sync->release) {
            pthread_cond_wait(&sync->cond, &sync->lock);
        }
    }
    pthread_mutex_unlock(&sync->lock);
}

static void *bridge_worker_main(void *opaque)
{
    bridge_worker_t *worker = opaque;

    if (worker->sync && worker->second) {
        pthread_mutex_lock(&worker->sync->lock);
        worker->sync->second_started = 1;
        pthread_cond_broadcast(&worker->sync->cond);
        pthread_mutex_unlock(&worker->sync->lock);
    }
    if (worker->force_add) {
        worker->result = AddBridge(worker->bridge, wrapper, worker->symbol,
                                   0, "force");
    } else if (worker->automatic_add) {
        worker->result = AddAutomaticBridge(worker->bridge, wrapper,
                                            worker->symbol, 0);
    } else {
        worker->result = AddCheckBridge(worker->bridge, wrapper,
                                        worker->symbol, 0, "check");
    }
    if (worker->sync) {
        pthread_mutex_lock(&worker->sync->lock);
        ++worker->sync->done;
        pthread_cond_broadcast(&worker->sync->cond);
        pthread_mutex_unlock(&worker->sync->lock);
    }
    return NULL;
}

static void *alternate_writer_range_main(void *opaque)
{
    alternate_writer_range_t *worker = opaque;
    uintptr_t i;

    for (i = worker->first; i < worker->count; i += worker->stride) {
        uintptr_t address = alternate_test_address(0x800000, i,
                                                   worker->same_offset);
        addAlternate((void *)address, (void *)(address + 8));
    }
    return NULL;
}

static void *alternate_worker_main(void *opaque)
{
    alternate_worker_t *worker = opaque;

    addAlternate(worker->address, worker->alternate);
    return NULL;
}

static void *alternate_reader_worker_main(void *opaque)
{
    alternate_reader_worker_t *worker = opaque;
    uintptr_t i;

    for (i = 0; i < 200000; ++i) {
        uintptr_t address = alternate_test_address(
            worker->first, i % worker->count, worker->same_offset);
        void *result = getAlternate((void *)address);

        if (result != (void *)address &&
            result != (void *)(address + 8)) {
            ++worker->failures;
        }
    }
    return NULL;
}

static void *fork_worker_main(void *opaque)
{
    fork_worker_t *worker = opaque;
    pid_t pid;
    int status = -1;

    pthread_mutex_lock(&worker->sync->lock);
    ++worker->sync->done;
    pthread_cond_broadcast(&worker->sync->cond);
    pthread_mutex_unlock(&worker->sync->lock);
    pid = fork();
    if (pid == 0) {
        alarm(2);
        if (getAlternate((void *)0x700000) != (void *)0x700008) {
            _exit(1);
        }
        if (!AddAutomaticBridge(worker->bridge, wrapper, (void *)0x420000,
                                0) ||
            getAlternate((void *)0x420000) == (void *)0x420000) {
            _exit(2);
        }
        _exit(0);
    }
    if (pid > 0 && waitpid(pid, &status, 0) == pid) {
        worker->child_status = status;
    }
    return NULL;
}

static void *free_bridge_worker_main(void *opaque)
{
    free_bridge_worker_t *worker = opaque;

    FreeBridge(worker->bridge);
    return NULL;
}

static void *fork_after_free_worker_main(void *opaque)
{
    fork_after_free_worker_t *worker = opaque;
    pid_t pid;
    int status = -1;

    pthread_mutex_lock(&worker->sync->lock);
    worker->sync->second_started = 1;
    pthread_cond_broadcast(&worker->sync->cond);
    pthread_mutex_unlock(&worker->sync->lock);
    pid = fork();
    if (pid == 0) {
        bridge_t *fresh;

        alarm(2);
        fresh = NewBridge();
        if (!fresh || !AddCheckBridge(fresh, wrapper, (void *)0x430000,
                                      0, "fork-after-free")) {
            _exit(1);
        }
        FreeBridge(&fresh);
        _exit(0);
    }
    if (pid > 0 && waitpid(pid, &status, 0) == pid) {
        worker->child_status = status;
    }
    pthread_mutex_lock(&worker->sync->lock);
    ++worker->sync->done;
    pthread_cond_broadcast(&worker->sync->cond);
    pthread_mutex_unlock(&worker->sync->lock);
    return NULL;
}

static void *parallel_worker_main(void *opaque)
{
    parallel_worker_t *worker = opaque;
    size_t i;

    for (i = worker->start; i < SYMBOL_COUNT; i += THREAD_COUNT) {
        bridge_worker_main(&worker->workers[i]);
    }
    return NULL;
}

static void test_add_check_is_one_critical_section(void)
{
    bridge_t *bridge = NewBridge();
    bridge_worker_t first;
    bridge_worker_t second;
    pthread_t first_thread;
    pthread_t second_thread;
    sync_t sync;

    check_true("atomic.new", bridge != NULL);
    if (!bridge || sync_init(&sync) != 0) {
        FreeBridge(&bridge);
        return;
    }
    first = (bridge_worker_t) { bridge, (void *)0x410000, 0, &sync, 0, 0, 0 };
    second = (bridge_worker_t) { bridge, (void *)0x410000, 0, &sync, 0, 0, 1 };
    bridge_test_set_after_check_hook(after_check_hook, &sync);
    check_true("atomic.first.create",
               pthread_create(&first_thread, NULL, bridge_worker_main, &first) == 0);
    check_true("atomic.first.checked", sync_wait_for(&sync, &sync.entered, 1, 1000) == 0);
    check_true("atomic.second.create",
               pthread_create(&second_thread, NULL, bridge_worker_main, &second) == 0);
    check_true("atomic.second-started",
               sync_wait_for(&sync, &sync.second_started, 1, 1000) == 0);
    check_true("atomic.lock-held-across-check-add",
               bridge_test_lock_is_held(bridge));
    pthread_mutex_lock(&sync.lock);
    check_true("atomic.first-stopped-after-check", sync.entered == 1);
    check_true("atomic.second-not-complete-before-release", sync.done == 0);
    pthread_mutex_unlock(&sync.lock);
    pthread_mutex_lock(&sync.lock);
    sync.release = 1;
    pthread_cond_broadcast(&sync.cond);
    pthread_mutex_unlock(&sync.lock);
    check_true("atomic.first.join", pthread_join(first_thread, NULL) == 0);
    check_true("atomic.second.join", pthread_join(second_thread, NULL) == 0);
    check_true("atomic.same-trampoline", first.result && first.result == second.result);
    check_true("atomic.map", CheckBridged(bridge, (void *)0x410000) == first.result);
    bridge_test_set_after_check_hook(NULL, NULL);
    FreeBridge(&bridge);
    sync_destroy(&sync);
}

static void test_parallel_bricks_and_resize(void)
{
    bridge_t *bridge = NewBridge();
    bridge_worker_t workers[SYMBOL_COUNT];
    pthread_t threads[THREAD_COUNT];
    parallel_worker_t parallel[THREAD_COUNT];
    size_t i;

    check_true("resize.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    for (i = 0; i < SYMBOL_COUNT; ++i) {
        workers[i] = (bridge_worker_t) {
            bridge, (void *)(uintptr_t)(0x500000 + i * 16), 0, NULL,
            0, 0, 0
        };
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        parallel[i] = (parallel_worker_t) { workers, i };
        check_true("resize.create", pthread_create(&threads[i], NULL,
                                                     parallel_worker_main,
                                                     &parallel[i]) == 0);
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        check_true("resize.join", pthread_join(threads[i], NULL) == 0);
    }
    for (i = 0; i < SYMBOL_COUNT; ++i) {
        size_t j;
        check_true("resize.add-check", workers[i].result != 0);
        check_true("resize.lookup", CheckBridged(bridge, workers[i].symbol) ==
                   workers[i].result);
        for (j = 0; j < i; ++j) {
            check_true("resize.unique-slot", workers[i].result != workers[j].result);
        }
    }
    FreeBridge(&bridge);
}

static void test_add_bridge_keeps_force_create_semantics(void)
{
    bridge_t *bridge = NewBridge();
    bridge_worker_t workers[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    size_t i;

    check_true("force.new", bridge != NULL);
    if (!bridge) {
        return;
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        workers[i] = (bridge_worker_t) {
            bridge, (void *)0x610000, 0, NULL, 1, 0, 0
        };
        check_true("force.create", pthread_create(&threads[i], NULL,
                                                    bridge_worker_main,
                                                    &workers[i]) == 0);
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        size_t j;
        check_true("force.join", pthread_join(threads[i], NULL) == 0);
        check_true("force.result", workers[i].result != 0);
        for (j = 0; j < i; ++j) {
            check_true("force.unique-slot", workers[i].result != workers[j].result);
        }
    }
    check_true("force.map-published", CheckBridged(bridge, (void *)0x610000) != 0);
    FreeBridge(&bridge);
}

static void test_fork_waits_for_live_bridge_operation(void)
{
    bridge_t *bridge = NewBridge();
    bridge_worker_t held;
    fork_worker_t forker;
    pthread_t held_thread;
    pthread_t fork_thread;
    sync_t sync;
    struct timespec pause = { 0, 100 * 1000 * 1000 };

    check_true("fork.new", bridge != NULL);
    if (!bridge || sync_init(&sync) != 0) {
        FreeBridge(&bridge);
        return;
    }
    held = (bridge_worker_t) { bridge, (void *)0x410000, 0, &sync, 0, 1, 0 };
    forker = (fork_worker_t) { bridge, &sync, -1 };
    addAlternate((void *)0x700000, (void *)0x700008);
    bridge_test_set_after_check_hook(after_check_hook, &sync);
    check_true("fork.held.create", pthread_create(&held_thread, NULL,
                                                    bridge_worker_main,
                                                    &held) == 0);
    check_true("fork.held.locked", sync_wait_for(&sync, &sync.entered, 1, 1000) == 0);
    check_true("fork.create", pthread_create(&fork_thread, NULL,
                                               fork_worker_main, &forker) == 0);
    check_true("fork.started", sync_wait_for(&sync, &sync.done, 1, 1000) == 0);
    nanosleep(&pause, NULL);
    pthread_mutex_lock(&sync.lock);
    sync.release = 1;
    pthread_cond_broadcast(&sync.cond);
    pthread_mutex_unlock(&sync.lock);
    check_true("fork.held.join", pthread_join(held_thread, NULL) == 0);
    check_true("fork.join", pthread_join(fork_thread, NULL) == 0);
    check_true("fork.child-smoke", WIFEXITED(forker.child_status) &&
               WEXITSTATUS(forker.child_status) == 0);
    bridge_test_set_after_check_hook(NULL, NULL);
    FreeBridge(&bridge);
    sync_destroy(&sync);
}

static void test_fork_waits_for_bridge_free(void)
{
    bridge_t *bridge = NewBridge();
    free_bridge_worker_t freer = { .bridge = &bridge };
    fork_after_free_worker_t forker;
    pthread_t free_thread;
    pthread_t fork_thread;
    sync_t sync;
    struct timespec pause = { 0, 100 * 1000 * 1000 };

    check_true("fork-free.new", bridge != NULL);
    if (!bridge || sync_init(&sync) != 0) {
        FreeBridge(&bridge);
        return;
    }
    forker = (fork_after_free_worker_t) { .sync = &sync, .child_status = -1 };
    bridge_test_set_before_free_hook(after_check_hook, &sync);
    check_true("fork-free.free-create",
               pthread_create(&free_thread, NULL, free_bridge_worker_main,
                              &freer) == 0);
    check_true("fork-free.free-locked",
               sync_wait_for(&sync, &sync.entered, 1, 1000) == 0);
    check_true("fork-free.fork-create",
               pthread_create(&fork_thread, NULL, fork_after_free_worker_main,
                              &forker) == 0);
    check_true("fork-free.fork-started",
               sync_wait_for(&sync, &sync.second_started, 1, 1000) == 0);
    nanosleep(&pause, NULL);
    pthread_mutex_lock(&sync.lock);
    check_true("fork-free.fork-waits", sync.done == 0);
    sync.release = 1;
    pthread_cond_broadcast(&sync.cond);
    pthread_mutex_unlock(&sync.lock);
    check_true("fork-free.free-join", pthread_join(free_thread, NULL) == 0);
    check_true("fork-free.pointer-cleared", bridge == NULL);
    check_true("fork-free.fork-join", pthread_join(fork_thread, NULL) == 0);
    check_true("fork-free.child-smoke", WIFEXITED(forker.child_status) &&
               WEXITSTATUS(forker.child_status) == 0);
    bridge_test_set_before_free_hook(NULL, NULL);
    sync_destroy(&sync);
}

static void test_alternate_first_publication(void)
{
    alternate_worker_t workers[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    void *address = (void *)0x710000;
    void *published;
    uint64_t start;
    size_t i;

    cleanAlternate();
    start = monotonic_ns();
    for (i = 0; i < THREAD_COUNT; ++i) {
        workers[i] = (alternate_worker_t) {
            address, (void *)(uintptr_t)(0x720000 + i * 16)
        };
        check_true("alternate.create", pthread_create(&threads[i], NULL,
                                                        alternate_worker_main,
                                                        &workers[i]) == 0);
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        check_true("alternate.join", pthread_join(threads[i], NULL) == 0);
    }
    published = getAlternate(address);
    printf("alternate-first-publication threads=%d elapsed_ns=%llu\n",
           THREAD_COUNT, (unsigned long long)(monotonic_ns() - start));
    check_true("alternate.published", published != address);
    addAlternate(address, (void *)0x730000);
    check_true("alternate.first-wins", getAlternate(address) == published);
    cleanAlternate();
}

static void test_alternate_readers_and_stress(int same_offset)
{
    alternate_writer_range_t writers[ALTERNATE_WRITER_THREADS];
    alternate_reader_worker_t readers[ALTERNATE_READER_THREADS];
    pthread_t writer_threads[ALTERNATE_WRITER_THREADS];
    pthread_t reader_threads[ALTERNATE_READER_THREADS];
    size_t i;

    cleanAlternate();
    for (i = 0; i < 64; ++i) {
        uintptr_t address = alternate_test_address(0x800000, i, same_offset);
        addAlternate((void *)address, (void *)(address + 8));
    }
    for (i = 0; i < ALTERNATE_READER_THREADS; ++i) {
        readers[i] = (alternate_reader_worker_t) {
            .first = 0x800000,
            .count = ALTERNATE_STRESS_ENTRIES,
            .same_offset = same_offset,
        };
        check_true("alternate.resize.reader-create",
                   pthread_create(&reader_threads[i], NULL,
                                  alternate_reader_worker_main,
                                  &readers[i]) == 0);
    }
    for (i = 0; i < ALTERNATE_WRITER_THREADS; ++i) {
        writers[i] = (alternate_writer_range_t) {
            .first = 64 + i,
            .count = ALTERNATE_STRESS_ENTRIES,
            .stride = ALTERNATE_WRITER_THREADS,
            .same_offset = same_offset,
        };
        check_true("alternate.resize.writer-create",
                   pthread_create(&writer_threads[i], NULL,
                                  alternate_writer_range_main,
                                  &writers[i]) == 0);
    }
    for (i = 0; i < ALTERNATE_WRITER_THREADS; ++i) {
        check_true("alternate.resize.writer-join",
                   pthread_join(writer_threads[i], NULL) == 0);
    }
    for (i = 0; i < ALTERNATE_READER_THREADS; ++i) {
        check_true("alternate.resize.reader-join",
                   pthread_join(reader_threads[i], NULL) == 0);
        check_true("alternate.resize.reader-values", readers[i].failures == 0);
    }
    for (i = 0; i < ALTERNATE_STRESS_ENTRIES; ++i) {
        uintptr_t address = alternate_test_address(0x800000, i, same_offset);

        check_true("alternate.resize.present",
                   getAlternate((void *)address) == (void *)(address + 8));
    }
    cleanAlternate();
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;
}

static volatile uintptr_t benchmark_sink;
static int bridge_gate_baseline_state = 1;

static uint64_t benchmark_next(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return a < b ? -1 : a > b;
}

static void benchmark_summary(const char *table, size_t entries,
                              const char *pattern, const uint64_t *samples,
                              size_t operations)
{
    uint64_t sorted[BENCHMARK_ROUNDS];
    uint64_t bootstrap[1000];
    uint64_t state = UINT64_C(0x3f4a9d1b7c2e5109);
    size_t i;

    memcpy(sorted, samples, sizeof(sorted));
    qsort(sorted, BENCHMARK_ROUNDS, sizeof(sorted[0]), compare_u64);
    for (i = 0; i < sizeof(bootstrap) / sizeof(bootstrap[0]); ++i) {
        uint64_t total = 0;
        size_t j;

        for (j = 0; j < BENCHMARK_ROUNDS; ++j) {
            total += samples[benchmark_next(&state) % BENCHMARK_ROUNDS];
        }
        bootstrap[i] = total / BENCHMARK_ROUNDS;
    }
    qsort(bootstrap, sizeof(bootstrap) / sizeof(bootstrap[0]),
          sizeof(bootstrap[0]), compare_u64);
    printf("alternate-workset table=%s entries=%zu pattern=%s median_ns_op=%llu throughput_mops=%.2f ci95_ns_op=%llu:%llu\n",
           table, entries, pattern,
           (unsigned long long)(sorted[BENCHMARK_ROUNDS / 2] / operations),
           1000.0 * operations / sorted[BENCHMARK_ROUNDS / 2],
           (unsigned long long)(bootstrap[25] / operations),
           (unsigned long long)(bootstrap[974] / operations));
}

static uint64_t benchmark_median_total(const uint64_t *samples)
{
    uint64_t sorted[BENCHMARK_ROUNDS];

    memcpy(sorted, samples, sizeof(sorted));
    qsort(sorted, BENCHMARK_ROUNDS, sizeof(sorted[0]), compare_u64);
    return sorted[BENCHMARK_ROUNDS / 2];
}

static __attribute__((noinline)) int benchmark_bridge_gate_baseline(void)
{
    return __atomic_load_n(&bridge_gate_baseline_state, __ATOMIC_ACQUIRE);
}

static uint64_t benchmark_bridge_gate_baseline_run(void)
{
    uintptr_t result = 0;
    uint64_t start = monotonic_ns();
    size_t i;

    for (i = 0; i < BRIDGE_GATE_BENCHMARK_REPEAT; ++i) {
        result += benchmark_bridge_gate_baseline();
    }
    benchmark_sink ^= result;
    return monotonic_ns() - start;
}

static uint64_t benchmark_bridge_gate_run(void)
{
    uintptr_t result = 0;
    uint64_t start = monotonic_ns();
    size_t i;

    for (i = 0; i < BRIDGE_GATE_BENCHMARK_REPEAT; ++i) {
        result += BridgeForkProtectionAvailable();
    }
    benchmark_sink ^= result;
    return monotonic_ns() - start;
}

static void test_bridge_gate_benchmark(void)
{
    uint64_t baseline_samples[BENCHMARK_ROUNDS];
    uint64_t gate_samples[BENCHMARK_ROUNDS];
    uint64_t baseline_median;
    uint64_t gate_median;
    uint64_t limit;
    size_t i;

    check_true("bridge-gate.available", BridgeForkProtectionAvailable());
    for (i = 0; i < BENCHMARK_ROUNDS; ++i) {
        if (i & 1) {
            gate_samples[i] = benchmark_bridge_gate_run();
            baseline_samples[i] = benchmark_bridge_gate_baseline_run();
        } else {
            baseline_samples[i] = benchmark_bridge_gate_baseline_run();
            gate_samples[i] = benchmark_bridge_gate_run();
        }
    }
    baseline_median = benchmark_median_total(baseline_samples);
    gate_median = benchmark_median_total(gate_samples);
    limit = baseline_median + BRIDGE_GATE_BENCHMARK_REPEAT * 5;
    printf("bridge-gate-performance baseline_median_total_ns=%llu "
           "gate_median_total_ns=%llu limit_total_ns=%llu "
           "gate_ns_op=%llu result=%s\n",
           (unsigned long long)baseline_median,
           (unsigned long long)gate_median,
           (unsigned long long)limit,
           (unsigned long long)(gate_median /
                                BRIDGE_GATE_BENCHMARK_REPEAT),
           gate_median <= limit ? "PASS" : "FAIL");
    check_true("bridge-gate.performance", gate_median <= limit);
}

static void benchmark_check_gate(size_t entries, const char *label,
                                 int same_offset,
                                 const uint64_t *old_samples,
                                 const uint64_t *new_samples)
{
    const uint64_t operations = BENCHMARK_QUERIES * BENCHMARK_REPEAT;
    uint64_t old_median = benchmark_median_total(old_samples);
    uint64_t new_median = benchmark_median_total(new_samples);
    uint64_t limit;

    if (same_offset) {
        limit = old_median;
    } else if (entries == 0) {
        limit = old_median + operations * 2;
    } else {
        limit = old_median + old_median * 5 / 100;
    }
    printf("alternate-gate entries=%zu pattern=%s old_median_total_ns=%llu new_median_total_ns=%llu limit_total_ns=%llu result=%s\n",
           entries, label, (unsigned long long)old_median,
           (unsigned long long)new_median, (unsigned long long)limit,
           new_median <= limit ? "PASS" : "FAIL");
    check_true("benchmark.performance-gate", new_median <= limit);
}

static __attribute__((noinline)) uintptr_t benchmark_old_lookup(
    kh_alternate_benchmark_t *table, uintptr_t address)
{
    khint_t key = kh_get(alternate_benchmark, table, address);

    return key == kh_end(table) ? address : kh_value(table, key);
}

static uint64_t benchmark_old(kh_alternate_benchmark_t *table,
                              const uintptr_t *queries)
{
    uint64_t start = monotonic_ns();
    size_t i;

    for (i = 0; i < BENCHMARK_QUERIES * BENCHMARK_REPEAT; ++i) {
        uintptr_t address = queries[i % BENCHMARK_QUERIES];
        benchmark_sink ^= benchmark_old_lookup(table, address);
    }
    return monotonic_ns() - start;
}

static uint64_t benchmark_new(const uintptr_t *queries)
{
    uint64_t start = monotonic_ns();
    size_t i;

    for (i = 0; i < BENCHMARK_QUERIES * BENCHMARK_REPEAT; ++i) {
        benchmark_sink ^= (uintptr_t)getAlternate(
            (void *)queries[i % BENCHMARK_QUERIES]);
    }
    return monotonic_ns() - start;
}

static void benchmark_alternate_workset(size_t entries, const char *pattern,
                                        int same_offset)
{
    kh_alternate_benchmark_t *old = kh_init(alternate_benchmark);
    uintptr_t queries[BENCHMARK_QUERIES];
    uint64_t old_samples[BENCHMARK_ROUNDS];
    uint64_t new_samples[BENCHMARK_ROUNDS];
    uint64_t state = UINT64_C(0x6d2b79f5a41e308c);
    char label[32];
    size_t i;

    cleanAlternate();
    check_true("benchmark.old-init", old != NULL);
    for (i = 0; old && i < entries; ++i) {
        uintptr_t address = alternate_test_address(
            same_offset ? 0x10000000 : 0xa00000, i, same_offset);
        int inserted;
        khint_t key = kh_put(alternate_benchmark, old, address, &inserted);

        kh_value(old, key) = address + 8;
        addAlternate((void *)address, (void *)(address + 8));
    }
    for (i = 0; i < BENCHMARK_QUERIES; ++i) {
        int hit = entries && (!strcmp(pattern, "hit") ||
                              (!strcmp(pattern, "miss99") && i % 100 == 0));
        queries[i] = hit ? alternate_test_address(
                         same_offset ? 0x10000000 : 0xa00000,
                         benchmark_next(&state) % entries,
                         same_offset) : alternate_test_address(
                         same_offset ? 0x20000000 : 0xb00000,
                         benchmark_next(&state) % 4096,
                         same_offset);
        if (!hit) {
            check_true("benchmark.miss-not-found",
                       getAlternate((void *)queries[i]) ==
                       (void *)queries[i]);
        }
    }
    for (i = BENCHMARK_QUERIES; i > 1; --i) {
        size_t j = benchmark_next(&state) % i;
        uintptr_t value = queries[i - 1];

        queries[i - 1] = queries[j];
        queries[j] = value;
    }
    for (i = 0; i < BENCHMARK_ROUNDS; ++i) {
        if (i & 1) {
            new_samples[i] = benchmark_new(queries);
            old_samples[i] = benchmark_old(old, queries);
        } else {
            old_samples[i] = benchmark_old(old, queries);
            new_samples[i] = benchmark_new(queries);
        }
        snprintf(label, sizeof(label), "%s%s",
                 same_offset ? "high-offset-" : "", pattern);
        printf("alternate-round entries=%zu pattern=%s round=%zu old_ns_op=%llu new_ns_op=%llu\n",
               entries, label, i,
               (unsigned long long)(old_samples[i] /
                                    (BENCHMARK_QUERIES * BENCHMARK_REPEAT)),
               (unsigned long long)(new_samples[i] /
                                    (BENCHMARK_QUERIES * BENCHMARK_REPEAT)));
    }
    snprintf(label, sizeof(label), "%s%s",
             same_offset ? "high-offset-" : "", pattern);
    benchmark_summary("old-khash", entries, label, old_samples,
                      BENCHMARK_QUERIES * BENCHMARK_REPEAT);
    benchmark_summary("new-fixed-append-only", entries, label, new_samples,
                      BENCHMARK_QUERIES * BENCHMARK_REPEAT);
    benchmark_check_gate(entries, label, same_offset, old_samples, new_samples);
    if (old) {
        kh_destroy(alternate_benchmark, old);
    }
    cleanAlternate();
}

static void test_alternate_lookup_benchmark(void)
{
    static const size_t sizes[] = { 0, 64, 512, 2048 };
    static const char *const patterns[] = { "hit", "miss", "miss99" };
    cpu_set_t allowed;
    cpu_set_t chosen;
    size_t i;
    size_t j;

    CPU_ZERO(&allowed);
    check_true("benchmark.get-affinity", sched_getaffinity(0, sizeof(allowed),
                                                             &allowed) == 0);
    for (i = 0; i < CPU_SETSIZE && !CPU_ISSET(i, &allowed); ++i) {
    }
    check_true("benchmark.cpu-available", i < CPU_SETSIZE);
    if (i < CPU_SETSIZE) {
        CPU_ZERO(&chosen);
        CPU_SET(i, &chosen);
        check_true("benchmark.set-affinity", sched_setaffinity(
                       0, sizeof(chosen), &chosen) == 0);
    }
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        for (j = 0; j < sizeof(patterns) / sizeof(patterns[0]); ++j) {
            benchmark_alternate_workset(sizes[i], patterns[j], 0);
        }
    }
    benchmark_alternate_workset(2048, "hit", 1);
    benchmark_alternate_workset(2048, "miss", 1);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--benchmark")) {
        test_bridge_gate_benchmark();
        test_alternate_lookup_benchmark();
        return failures ? 1 : 0;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--benchmark]\n", argv[0]);
        return 2;
    }
    test_add_check_is_one_critical_section();
    test_parallel_bricks_and_resize();
    test_add_bridge_keeps_force_create_semantics();
    test_fork_waits_for_live_bridge_operation();
    test_fork_waits_for_bridge_free();
    test_alternate_first_publication();
    test_alternate_readers_and_stress(0);
    test_alternate_readers_and_stress(1);
    return failures ? 1 : 0;
}
