#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_rela_diagnostics.h"

static int failures;
static int tests_run;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %lu expected %lu\n", name, got, expected);
    ++failures;
}

static void check_string(const char *name, const char *got,
                         const char *expected)
{
    if (got && expected && strcmp(got, expected) == 0) {
        return;
    }

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

typedef struct capture_sink {
    int calls;
    int fail;
    char line[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];
} capture_sink_t;

#define THROTTLE_THREADS 12
#define THROTTLE_ITERATIONS 200
#define SNAPSHOT_READERS 4
#define ADAPTER_THREADS 10
#define ADAPTER_ITERATIONS 50

static int wait_for_barrier(pthread_barrier_t *barrier)
{
    int ret = pthread_barrier_wait(barrier);

    return ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : ret;
}

static int capture_line(const char *line, size_t line_length, void *opaque)
{
    capture_sink_t *capture = opaque;
    size_t copy_length;

    ++capture->calls;
    copy_length = line_length;
    if (copy_length >= sizeof(capture->line)) {
        copy_length = sizeof(capture->line) - 1;
    }
    memcpy(capture->line, line, copy_length);
    capture->line[copy_length] = '\0';
    return capture->fail ? -1 : 0;
}

typedef struct throttle_worker {
    kzt_rela_diagnostic_throttle_t *throttle;
    pthread_barrier_t *barrier;
    unsigned long admitted;
    unsigned long suppressed;
    unsigned long errors;
} throttle_worker_t;

static void *throttle_worker_main(void *opaque)
{
    throttle_worker_t *worker = opaque;
    int i;

    if (wait_for_barrier(worker->barrier) != 0) {
        ++worker->errors;
        return NULL;
    }

    for (i = 0; i < THROTTLE_ITERATIONS; ++i) {
        int result =
            kzt_rela_diagnostic_throttle_try_admit(worker->throttle);

        if (result > 0) {
            ++worker->admitted;
        } else if (result == 0) {
            ++worker->suppressed;
        } else {
            ++worker->errors;
        }
    }
    return NULL;
}

typedef struct snapshot_reader {
    kzt_rela_diagnostic_throttle_t *throttle;
    unsigned long capacity;
    unsigned int *done;
    unsigned long snapshots;
    unsigned long errors;
} snapshot_reader_t;

static void *snapshot_reader_main(void *opaque)
{
    snapshot_reader_t *reader = opaque;

    do {
        kzt_rela_diagnostic_throttle_snapshot_t snapshot;

        if (kzt_rela_diagnostic_throttle_snapshot(
                reader->throttle, &snapshot) != 0) {
            ++reader->errors;
            continue;
        }
        ++reader->snapshots;
        if (snapshot.capacity != reader->capacity ||
            snapshot.admitted > snapshot.capacity ||
            (snapshot.admitted < snapshot.capacity &&
             snapshot.suppressed != 0)) {
            ++reader->errors;
        }
    } while (__atomic_load_n(reader->done, __ATOMIC_ACQUIRE) == 0);

    return NULL;
}

typedef struct atomic_sink {
    unsigned long calls;
} atomic_sink_t;

static int count_line_atomically(const char *line, size_t line_length,
                                 void *opaque)
{
    atomic_sink_t *sink = opaque;

    (void)line;
    (void)line_length;
    __atomic_fetch_add(&sink->calls, 1, __ATOMIC_RELAXED);
    return 0;
}

typedef struct adapter_worker {
    const kzt_rela_immediate_candidate_request_t *request;
    const kzt_rela_immediate_writer_result_t *writer_result;
    kzt_rela_diagnostic_throttle_t *throttle;
    pthread_barrier_t *barrier;
    atomic_sink_t *sink;
    unsigned long emitted;
    unsigned long suppressed;
    unsigned long errors;
} adapter_worker_t;

static void *adapter_worker_main(void *opaque)
{
    adapter_worker_t *worker = opaque;
    int i;

    if (wait_for_barrier(worker->barrier) != 0) {
        ++worker->errors;
        return NULL;
    }

    for (i = 0; i < ADAPTER_ITERATIONS; ++i) {
        kzt_rela_immediate_diagnostic_result_t result;
        char buffer[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];
        kzt_rela_immediate_diagnostic_input_t input = {
            .mode = KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
            .request = worker->request,
            .result = worker->writer_result,
            .legacy_fallback = 0,
            .throttle = worker->throttle,
            .buffer = buffer,
            .buffer_size = sizeof(buffer),
            .sink = count_line_atomically,
            .sink_opaque = worker->sink,
        };

        if (kzt_rela_immediate_diagnostic_emit(&input, &result) != 0) {
            ++worker->errors;
        } else if (result.status == KZT_RELA_DIAGNOSTIC_EMIT_EMITTED) {
            ++worker->emitted;
        } else if (result.status == KZT_RELA_DIAGNOSTIC_EMIT_SUPPRESSED) {
            ++worker->suppressed;
        } else {
            ++worker->errors;
        }
    }
    return NULL;
}

static kzt_rela_immediate_candidate_request_t base_request(const char *path)
{
    kzt_rela_immediate_candidate_request_t request;

    memset(&request, 0, sizeof(request));
    request.source.known = 1;
    request.source.link_map_addr = 0x110000;
    request.source.map_start = 0x400000;
    request.source.map_end = 0x410000;
    request.source.generation = 17;
    request.source.soname = "libdiag.so";
    request.source.path = path;
    request.current_owner.known = 1;
    request.current_owner.link_map_addr = 0x220000;
    request.current_owner.generation = 23;
    request.owner_match = KZT_PATCH_OWNER_MATCH;
    request.wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH;
    request.native_bridge_target = 0x660000;
    request.slot_addr = 0x550000;
    request.slot_current_value_present = 1;
    request.slot_current_value = 0x440000;
    request.symbol_name = "diag_symbol";
    request.version = "DIAG_1.0";
    return request;
}

static kzt_rela_immediate_writer_result_t base_result(
    const kzt_rela_immediate_candidate_request_t *request)
{
    kzt_rela_immediate_writer_result_t result;
    kzt_patch_decision_t *decision;

    memset(&result, 0, sizeof(result));
    result.planner_called = 1;
    result.writer_called = 1;
    result.skip_legacy_write = 1;
    result.plan.status = KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED;
    result.plan.reason = KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE;
    result.plan.candidate_present = 1;
    result.plan.decision_present = 1;

    decision = &result.plan.decision;
    decision->kind = KZT_PATCH_DECISION_APPROVED;
    decision->reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE;
    decision->allow_native_bridge = 1;
    decision->source = request->source;
    decision->current_owner = request->current_owner;
    decision->owner_match = request->owner_match;
    decision->wrapper_match = request->wrapper_match;
    decision->bridge_target = request->native_bridge_target;
    decision->slot_addr = request->slot_addr;
    decision->slot_current_value_present = 1;
    decision->slot_current_value = request->slot_current_value;
    decision->symbol_name = request->symbol_name;
    decision->version = request->version;

    result.record.valid = 1;
    result.record.decision_kind = decision->kind;
    result.record.decision_reason = decision->reason;
    result.record.result = KZT_PATCH_SPIKE_RESULT_APPLIED;
    result.record.failure = KZT_PATCH_SPIKE_FAILURE_NONE;
    result.record.action = KZT_PATCH_SPIKE_ACTION_USE_NATIVE_BRIDGE;
    result.record.skip_legacy_write = 1;
    result.record.writer_called = 1;
    return result;
}

static kzt_rela_immediate_diagnostic_input_t base_input(
    kzt_rela_diagnostic_mode_t mode,
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_immediate_writer_result_t *writer_result,
    kzt_rela_diagnostic_throttle_t *throttle,
    char *buffer,
    size_t buffer_size,
    capture_sink_t *capture)
{
    return (kzt_rela_immediate_diagnostic_input_t) {
        .mode = mode,
        .request = request,
        .result = writer_result,
        .legacy_fallback = 1,
        .throttle = throttle,
        .buffer = buffer,
        .buffer_size = buffer_size,
        .sink = capture_line,
        .sink_opaque = capture,
    };
}

static void test_modes_gate_output_and_writer_fields(void)
{
    kzt_rela_immediate_candidate_request_t request =
        base_request("/guest/libdiag.so");
    kzt_rela_immediate_writer_result_t writer_result =
        base_result(&request);
    kzt_rela_diagnostic_throttle_t throttle;
    kzt_rela_diagnostic_throttle_snapshot_t snapshot;
    kzt_rela_immediate_diagnostic_result_t result;
    capture_sink_t capture = { 0 };
    char buffer[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];
    kzt_rela_immediate_diagnostic_input_t input;

    ++tests_run;
    check_int("mode.default.flags",
              kzt_rela_diagnostic_mode_from_flags(0, 0),
              KZT_RELA_DIAGNOSTIC_MODE_DEFAULT);
    check_int("mode.write-only.flags",
              kzt_rela_diagnostic_mode_from_flags(0, 1),
              KZT_RELA_DIAGNOSTIC_MODE_WRITE_ENABLED_ONLY);
    check_int("mode.diagnostics.flags",
              kzt_rela_diagnostic_mode_from_flags(1, 0),
              KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS);
    check_int("mode.combined.flags",
              kzt_rela_diagnostic_mode_from_flags(1, 1),
              KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED);
    check_int("mode.throttle.init",
              kzt_rela_diagnostic_throttle_init(&throttle, 8), 0);

    input = base_input(KZT_RELA_DIAGNOSTIC_MODE_DEFAULT, &request,
                       &writer_result, &throttle, buffer, sizeof(buffer),
                       &capture);
    check_int("mode.default.emit",
              kzt_rela_immediate_diagnostic_emit(&input, &result), 0);
    check_int("mode.default.status", result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_DISABLED);

    input.mode = KZT_RELA_DIAGNOSTIC_MODE_WRITE_ENABLED_ONLY;
    check_int("mode.write-only.emit",
              kzt_rela_immediate_diagnostic_emit(&input, &result), 0);
    check_int("mode.write-only.status", result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_DISABLED);
    check_int("mode.closed.sink", capture.calls, 0);

    input.mode = KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS;
    check_int("mode.diagnostics.emit",
              kzt_rela_immediate_diagnostic_emit(&input, &result), 0);
    check_int("mode.diagnostics.status", result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_EMITTED);
    check_int("mode.diagnostics.domain", result.record.reason_domain,
              KZT_RELA_DIAGNOSTIC_REASON_PLANNER);
    check_string("mode.diagnostics.writer", result.record.writer_result,
                 "NOT_RECORDED");
    check_int("mode.diagnostics.fallback", result.record.legacy_fallback, 1);

    input.mode = KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED;
    input.legacy_fallback = 0;
    check_int("mode.combined.emit",
              kzt_rela_immediate_diagnostic_emit(&input, &result), 0);
    check_int("mode.combined.status", result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_EMITTED);
    check_int("mode.combined.domain", result.record.reason_domain,
              KZT_RELA_DIAGNOSTIC_REASON_WRITER);
    check_string("mode.combined.writer", result.record.writer_result,
                 "APPLIED");
    check_int("mode.combined.fallback", result.record.legacy_fallback, 0);
    check_int("mode.open.sink", capture.calls, 2);

    check_int("mode.snapshot",
              kzt_rela_diagnostic_throttle_snapshot(&throttle, &snapshot),
              0);
    check_ulong("mode.snapshot.admitted", snapshot.admitted, 2);
    check_ulong("mode.snapshot.suppressed", snapshot.suppressed, 0);
}

static void test_record_copies_fields_before_formatting(void)
{
    char source_path[] = "/guest/libdiag-copy.so";
    kzt_rela_immediate_candidate_request_t request =
        base_request(source_path);
    kzt_rela_immediate_writer_result_t writer_result =
        base_result(&request);
    kzt_rela_diagnostic_record_t record;
    char line[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];

    ++tests_run;
    check_int("fields.record",
              kzt_rela_immediate_diagnostic_record(
                  KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
                  &request, &writer_result, 0, &record),
              0);
    source_path[7] = 'X';
    check_int("fields.format",
              kzt_rela_diagnostic_format(&record, line, sizeof(line)),
              KZT_RELA_DIAGNOSTIC_FORMAT_OK);
    check_true("fields.source",
               strstr(line, "source=/guest/libdiag-copy.so") != NULL);
    check_true("fields.source-link-map",
               strstr(line, "source_link_map=0x110000") != NULL);
    check_true("fields.current-owner",
               strstr(line, "current_owner=0x220000") != NULL);
    check_true("fields.source-generation",
               strstr(line, "source_generation=17") != NULL);
    check_true("fields.current-owner-generation",
               strstr(line, "current_owner_generation=23") != NULL);
    check_true("fields.owner-match",
               strstr(line, "owner_match=MATCH") != NULL);
    check_true("fields.wrapper-match",
               strstr(line, "wrapper_match=VERSION_MATCH") != NULL);
    check_true("fields.bridge-target",
               strstr(line, "bridge_target=0x660000") != NULL);
    check_true("fields.symbol",
               strstr(line, "symbol=diag_symbol") != NULL);
    check_true("fields.version",
               strstr(line, "version=DIAG_1.0") != NULL);
    check_true("fields.reason-domain",
               strstr(line, "reason_domain=writer") != NULL);
    check_true("fields.reason", strstr(line, "reason=NONE") != NULL);
    check_true("fields.decision",
               strstr(line, "decision=APPROVED") != NULL);
    check_true("fields.writer-result",
               strstr(line, "writer_result=APPLIED") != NULL);
    check_true("fields.legacy-fallback",
               strstr(line, "legacy_fallback=0") != NULL);
}

static void test_candidate_reason_domain_is_preserved(void)
{
    kzt_rela_immediate_candidate_request_t request =
        base_request("/guest/libcandidate.so");
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_rela_diagnostic_record_t record;

    ++tests_run;
    memset(&writer_result, 0, sizeof(writer_result));
    writer_result.planner_called = 1;
    writer_result.plan.status = KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN;
    writer_result.plan.reason =
        KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SLOT;

    check_int("candidate.record",
              kzt_rela_immediate_diagnostic_record(
                  KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS,
                  &request, &writer_result, 1, &record),
              0);
    check_int("candidate.domain", record.reason_domain,
              KZT_RELA_DIAGNOSTIC_REASON_CANDIDATE);
    check_string("candidate.reason", record.reason, "MISSING_SLOT");
    check_string("candidate.decision", record.decision, "FAIL_OPEN");
    check_string("candidate.writer", record.writer_result, "NOT_RECORDED");
    check_int("candidate.fallback", record.legacy_fallback, 1);
}

/*
 * This unit only proves that diagnostic failures preserve the snapshots and
 * slot visible to this adapter. Production probe/writer isolation belongs in
 * the later wiring test where those call paths can be observed.
 */
static void test_diagnostic_failures_preserve_caller_inputs(void)
{
    uintptr_t slot = 0x440000;
    kzt_rela_immediate_candidate_request_t request =
        base_request("/guest/libfail-open.so");
    kzt_rela_immediate_writer_result_t writer_result =
        base_result(&request);
    kzt_rela_immediate_candidate_request_t request_before;
    kzt_rela_immediate_writer_result_t writer_before;
    kzt_rela_diagnostic_record_t record;
    kzt_rela_diagnostic_throttle_t throttle;
    kzt_rela_immediate_diagnostic_result_t emit_result;
    capture_sink_t capture = { 0 };
    char tiny[32];
    char buffer[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];
    kzt_rela_immediate_diagnostic_input_t input;

    ++tests_run;
    request.slot_addr = (uintptr_t)&slot;
    writer_result.plan.decision.slot_addr = request.slot_addr;
    request_before = request;
    writer_before = writer_result;

    check_int("failure.record",
              kzt_rela_immediate_diagnostic_record(
                  KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
                  &request, &writer_result, 1, &record),
              0);
    check_int("failure.format.truncated",
              kzt_rela_diagnostic_format(&record, tiny, sizeof(tiny)),
              KZT_RELA_DIAGNOSTIC_FORMAT_TRUNCATED);
    check_int("failure.format.nul", tiny[sizeof(tiny) - 1], '\0');

    check_int("failure.throttle.init",
              kzt_rela_diagnostic_throttle_init(&throttle, 4), 0);
    input = base_input(
        KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
        &request, &writer_result, &throttle, tiny, sizeof(tiny), &capture);
    check_int("failure.emit.truncated",
              kzt_rela_immediate_diagnostic_emit(&input, &emit_result), 0);
    check_int("failure.emit.truncated.status", emit_result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_FORMAT_TRUNCATED);
    check_int("failure.emit.truncated.sink", capture.calls, 0);

    input.buffer = buffer;
    input.buffer_size = sizeof(buffer);
    capture.fail = 1;
    check_int("failure.emit.sink",
              kzt_rela_immediate_diagnostic_emit(&input, &emit_result), 0);
    check_int("failure.emit.sink.status", emit_result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_SINK_FAILED);
    check_int("failure.emit.sink.calls", capture.calls, 1);

    memset(&throttle, 0, sizeof(throttle));
    capture.fail = 0;
    input.throttle = &throttle;
    check_int("failure.emit.throttle",
              kzt_rela_immediate_diagnostic_emit(&input, &emit_result), 0);
    check_int("failure.emit.throttle.status", emit_result.status,
              KZT_RELA_DIAGNOSTIC_EMIT_THROTTLE_FAILED);
    check_int("failure.emit.throttle.sink", capture.calls, 1);

    check_true("failure.request.unchanged",
               memcmp(&request, &request_before, sizeof(request)) == 0);
    check_true("failure.writer.unchanged",
               memcmp(&writer_result, &writer_before,
                      sizeof(writer_result)) == 0);
    check_ulong("failure.slot.unchanged", (unsigned long)slot, 0x440000);
}

static void test_fixed_capacity_throttle_is_concurrency_safe(void)
{
    static const unsigned long total =
        THROTTLE_THREADS * THROTTLE_ITERATIONS;
    static const unsigned long capacity =
        THROTTLE_THREADS * THROTTLE_ITERATIONS / 2;
    kzt_rela_diagnostic_throttle_t throttle;
    kzt_rela_diagnostic_throttle_snapshot_t snapshot;
    pthread_barrier_t barrier;
    pthread_t threads[THROTTLE_THREADS];
    pthread_t readers[SNAPSHOT_READERS];
    throttle_worker_t workers[THROTTLE_THREADS];
    snapshot_reader_t snapshot_readers[SNAPSHOT_READERS];
    unsigned int readers_done = 0;
    unsigned long admitted = 0;
    unsigned long suppressed = 0;
    unsigned long errors = 0;
    int i;

    ++tests_run;
    check_int("throttle.concurrent.init",
              kzt_rela_diagnostic_throttle_init(&throttle, capacity), 0);
    check_int("throttle.barrier.init",
              pthread_barrier_init(&barrier, NULL, THROTTLE_THREADS), 0);
    memset(workers, 0, sizeof(workers));
    memset(snapshot_readers, 0, sizeof(snapshot_readers));
    for (i = 0; i < SNAPSHOT_READERS; ++i) {
        snapshot_readers[i].throttle = &throttle;
        snapshot_readers[i].capacity = capacity;
        snapshot_readers[i].done = &readers_done;
        check_int("throttle.reader.create",
                  pthread_create(&readers[i], NULL, snapshot_reader_main,
                                 &snapshot_readers[i]),
                  0);
    }
    for (i = 0; i < THROTTLE_THREADS; ++i) {
        workers[i].throttle = &throttle;
        workers[i].barrier = &barrier;
        check_int("throttle.thread.create",
                  pthread_create(&threads[i], NULL, throttle_worker_main,
                                 &workers[i]),
                  0);
    }
    for (i = 0; i < THROTTLE_THREADS; ++i) {
        check_int("throttle.thread.join", pthread_join(threads[i], NULL), 0);
        admitted += workers[i].admitted;
        suppressed += workers[i].suppressed;
        errors += workers[i].errors;
    }
    __atomic_store_n(&readers_done, 1U, __ATOMIC_RELEASE);
    for (i = 0; i < SNAPSHOT_READERS; ++i) {
        check_int("throttle.reader.join", pthread_join(readers[i], NULL), 0);
        check_true("throttle.reader.snapshots",
                   snapshot_readers[i].snapshots != 0);
        errors += snapshot_readers[i].errors;
    }
    check_int("throttle.barrier.destroy",
              pthread_barrier_destroy(&barrier), 0);

    check_ulong("throttle.concurrent.admitted", admitted, capacity);
    check_ulong("throttle.concurrent.suppressed", suppressed,
                total - capacity);
    check_ulong("throttle.concurrent.errors", errors, 0);
    check_int("throttle.concurrent.snapshot",
              kzt_rela_diagnostic_throttle_snapshot(&throttle, &snapshot),
              0);
    check_ulong("throttle.snapshot.capacity", snapshot.capacity, capacity);
    check_ulong("throttle.snapshot.admitted", snapshot.admitted, capacity);
    check_ulong("throttle.snapshot.suppressed", snapshot.suppressed,
                total - capacity);

    check_int("throttle.saturation.init",
              kzt_rela_diagnostic_throttle_init(&throttle, 0), 0);
    throttle.suppressed = ULONG_MAX;
    check_int("throttle.saturation.admit",
              kzt_rela_diagnostic_throttle_try_admit(&throttle), 0);
    check_int("throttle.saturation.snapshot",
              kzt_rela_diagnostic_throttle_snapshot(&throttle, &snapshot),
              0);
    check_ulong("throttle.saturation.suppressed",
                snapshot.suppressed, ULONG_MAX);
}

static void test_concurrent_adapter_has_exact_suppression_count(void)
{
    static const unsigned long capacity = 29;
    static const unsigned long total = ADAPTER_THREADS * ADAPTER_ITERATIONS;
    kzt_rela_immediate_candidate_request_t request =
        base_request("/guest/libadapter-concurrent.so");
    kzt_rela_immediate_writer_result_t writer_result =
        base_result(&request);
    kzt_rela_diagnostic_throttle_t throttle;
    kzt_rela_diagnostic_throttle_snapshot_t snapshot;
    pthread_barrier_t barrier;
    pthread_t threads[ADAPTER_THREADS];
    adapter_worker_t workers[ADAPTER_THREADS];
    atomic_sink_t sink = { 0 };
    unsigned long emitted = 0;
    unsigned long suppressed = 0;
    unsigned long errors = 0;
    int i;

    ++tests_run;
    check_int("adapter.concurrent.init",
              kzt_rela_diagnostic_throttle_init(&throttle, capacity), 0);
    check_int("adapter.barrier.init",
              pthread_barrier_init(&barrier, NULL, ADAPTER_THREADS), 0);
    memset(workers, 0, sizeof(workers));
    for (i = 0; i < ADAPTER_THREADS; ++i) {
        workers[i].request = &request;
        workers[i].writer_result = &writer_result;
        workers[i].throttle = &throttle;
        workers[i].barrier = &barrier;
        workers[i].sink = &sink;
        check_int("adapter.thread.create",
                  pthread_create(&threads[i], NULL, adapter_worker_main,
                                 &workers[i]),
                  0);
    }
    for (i = 0; i < ADAPTER_THREADS; ++i) {
        check_int("adapter.thread.join", pthread_join(threads[i], NULL), 0);
        emitted += workers[i].emitted;
        suppressed += workers[i].suppressed;
        errors += workers[i].errors;
    }
    check_int("adapter.barrier.destroy",
              pthread_barrier_destroy(&barrier), 0);

    check_ulong("adapter.concurrent.emitted", emitted, capacity);
    check_ulong("adapter.concurrent.suppressed", suppressed,
                total - capacity);
    check_ulong("adapter.concurrent.errors", errors, 0);
    check_ulong("adapter.concurrent.sink",
                __atomic_load_n(&sink.calls, __ATOMIC_RELAXED), capacity);
    check_int("adapter.concurrent.snapshot",
              kzt_rela_diagnostic_throttle_snapshot(&throttle, &snapshot),
              0);
    check_ulong("adapter.snapshot.admitted", snapshot.admitted, capacity);
    check_ulong("adapter.snapshot.suppressed", snapshot.suppressed,
                total - capacity);
}

int main(void)
{
    test_modes_gate_output_and_writer_fields();
    test_record_copies_fields_before_formatting();
    test_candidate_reason_domain_is_preserved();
    test_diagnostic_failures_preserve_caller_inputs();
    test_fixed_capacity_throttle_is_concurrency_safe();
    test_concurrent_adapter_has_exact_suppression_count();

    if (failures) {
        fprintf(stderr,
                "kzt-wi238-structured-diagnostics-gate: %d failure(s)\n",
                failures);
        return 1;
    }

    printf("kzt-wi238-structured-diagnostics-gate: %d tests passed\n",
           tests_run);
    return 0;
}
