#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "target/i386/latx/include/kzt_lazy_binding.h"
#include "target/i386/latx/include/kzt_lazy_diagnostics.h"

static int failures;

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

static void check_contains(const char *name, const char *text,
                           const char *needle)
{
    if (text && needle && strstr(text, needle)) {
        return;
    }

    fprintf(stderr, "%s: \"%s\" missing \"%s\"\n", name,
            text ? text : "(null)", needle ? needle : "(null)");
    ++failures;
}

typedef struct capture_sink {
    int calls;
    int fail;
    char line[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
} capture_sink_t;

static int capture_line(const char *line, size_t line_length, void *opaque)
{
    capture_sink_t *capture = opaque;
    size_t copy_length = line_length;

    ++capture->calls;
    if (copy_length >= sizeof(capture->line)) {
        copy_length = sizeof(capture->line) - 1;
    }
    memcpy(capture->line, line, copy_length);
    capture->line[copy_length] = '\0';
    return capture->fail ? -1 : 0;
}

static kzt_lazy_binding_pending_t base_pending(void)
{
    kzt_lazy_binding_pending_t pending;

    memset(&pending, 0, sizeof(pending));
    pending.armed = 1;
    pending.slot_addr = 0x71000018;
    pending.unresolved_stub = 0x72000020;
    strcpy(pending.symbol_storage, "realloc");
    pending.symbol = pending.symbol_storage;
    strcpy(pending.version_storage, "GLIBC_2.2.5");
    pending.version = pending.version_storage;
    return pending;
}

static kzt_lazy_binding_result_t base_result(void)
{
    kzt_lazy_binding_result_t result;

    memset(&result, 0, sizeof(result));
    result.status = KZT_LAZY_BINDING_NATIVE_APPLIED;
    result.reason = KZT_LAZY_BINDING_REASON_NATIVE_APPLIED;
    result.slot_before = 0x73000030;
    result.slot_after = 0x74000040;
    result.selected_target = 0x74000040;
    return result;
}

static void test_emit_disabled_skips_format_and_sink(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    capture_sink_t capture = { 0 };
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input = {
        .enabled = 0,
        .pending = &pending,
        .binding_result = &binding_result,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = capture_line,
        .sink_opaque = &capture,
    };
    kzt_lazy_diagnostic_emit_result_t emit_result;

    memset(buffer, 'X', sizeof(buffer));
    check_int("disabled.emit",
              kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
    check_int("disabled.status", emit_result.status,
              KZT_LAZY_DIAGNOSTIC_EMIT_DISABLED);
    check_int("disabled.sink", capture.calls, 0);
    check_int("disabled.record", emit_result.record_present, 0);
    check_int("disabled.buffer-untouched", buffer[0], 'X');
}

static void test_native_applied_records_schema_one(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    capture_sink_t capture = { 0 };
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input = {
        .enabled = 1,
        .pending = &pending,
        .binding_result = &binding_result,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = capture_line,
        .sink_opaque = &capture,
    };
    kzt_lazy_diagnostic_emit_result_t emit_result;

    check_int("native.emit",
              kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
    check_int("native.status", emit_result.status,
              KZT_LAZY_DIAGNOSTIC_EMIT_EMITTED);
    check_int("native.record", emit_result.record_present, 1);
    check_ulong("native.schema", emit_result.record.schema, 1);
    check_string("native.symbol", emit_result.record.symbol, "realloc");
    check_string("native.first-route",
                 emit_result.record.first_execution_route, "guest");
    check_string("native.route-status",
                 emit_result.record.completion_route_status,
                 "NATIVE_APPLIED");
    check_ulong("native.slot-before", emit_result.record.slot_before,
                pending.unresolved_stub);
    check_ulong("native.slot-after-guest",
                emit_result.record.slot_after_guest,
                binding_result.slot_before);
    check_ulong("native.second-target",
                emit_result.record.selected_second_target,
                binding_result.slot_after);
    check_string("native.reason", emit_result.record.reason,
                 "NATIVE_APPLIED");
    check_int("native.sink", capture.calls, 1);
    check_contains("native.line.schema", capture.line, "schema=1");
    check_contains("native.line.symbol", capture.line, "symbol=realloc");
    check_contains("native.line.route", capture.line,
                   "completion_route_status=NATIVE_APPLIED");
    check_contains("native.line.before", capture.line,
                   "slot_before=0x72000020");
    check_contains("native.line.after-guest", capture.line,
                   "slot_after_guest=0x73000030");
    check_contains("native.line.second-target", capture.line,
                   "selected_second_target=0x74000040");
}

static void test_slot_unchanged_uses_stable_status_name(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    capture_sink_t capture = { 0 };
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input = {
        .enabled = 1,
        .pending = &pending,
        .binding_result = &binding_result,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = capture_line,
        .sink_opaque = &capture,
    };
    kzt_lazy_diagnostic_emit_result_t emit_result;

    binding_result.status = KZT_LAZY_BINDING_GUEST_PRESERVED;
    binding_result.reason = KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED;
    binding_result.slot_before = pending.unresolved_stub;
    binding_result.slot_after = pending.unresolved_stub;
    check_int("slot-unchanged.emit",
              kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
    check_string("slot-unchanged.status",
                 emit_result.record.completion_route_status,
                 "SLOT_UNCHANGED");
    check_string("slot-unchanged.reason", emit_result.record.reason,
                 "SLOT_UNCHANGED");
}

static void test_missing_version_uses_stable_status_name(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    capture_sink_t capture = { 0 };
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input = {
        .enabled = 1,
        .pending = &pending,
        .binding_result = &binding_result,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = capture_line,
        .sink_opaque = &capture,
    };
    kzt_lazy_diagnostic_emit_result_t emit_result;

    pending.version = NULL;
    pending.version_storage[0] = '\0';
    binding_result.status = KZT_LAZY_BINDING_GUEST_PRESERVED;
    binding_result.reason = KZT_LAZY_BINDING_REASON_MISSING_VERSION;
    binding_result.slot_after = binding_result.slot_before;
    check_int("missing-version.emit",
              kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
    check_string("missing-version.status",
                 emit_result.record.completion_route_status,
                 "MISSING_VERSION");
    check_string("missing-version.reason", emit_result.record.reason,
                 "MISSING_VERSION");
}

static void test_cas_mismatch_uses_final_competitor_target(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    capture_sink_t capture = { 0 };
    char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    kzt_lazy_diagnostic_input_t input = {
        .enabled = 1,
        .pending = &pending,
        .binding_result = &binding_result,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = capture_line,
        .sink_opaque = &capture,
    };
    kzt_lazy_diagnostic_emit_result_t emit_result;

    binding_result.status = KZT_LAZY_BINDING_CAS_MISMATCH;
    binding_result.reason = KZT_LAZY_BINDING_REASON_CAS_MISMATCH;
    binding_result.slot_after = 0x75000050;
    binding_result.selected_target = 0x76000060;
    check_int("cas.emit",
              kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
    check_string("cas.status", emit_result.record.completion_route_status,
                 "CAS_MISMATCH");
    check_ulong("cas.second-target",
                emit_result.record.selected_second_target,
                0x75000050);
    check_contains("cas.line.second-target", capture.line,
                   "selected_second_target=0x75000050");
}

static void test_transaction_failure_statuses_are_explicit(void)
{
    const struct {
        kzt_lazy_binding_status_t status;
        kzt_lazy_binding_reason_t reason;
        const char *name;
    } cases[] = {
        {
            KZT_LAZY_BINDING_WRITE_ROLLED_BACK,
            KZT_LAZY_BINDING_REASON_WRITE_ROLLED_BACK,
            "WRITE_ROLLED_BACK",
        },
        {
            KZT_LAZY_BINDING_UNRECOVERABLE,
            KZT_LAZY_BINDING_REASON_UNRECOVERABLE,
            "UNRECOVERABLE",
        },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        kzt_lazy_binding_pending_t pending = base_pending();
        kzt_lazy_binding_result_t binding_result = base_result();
        capture_sink_t capture = { 0 };
        char buffer[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
        kzt_lazy_diagnostic_input_t input = {
            .enabled = 1,
            .pending = &pending,
            .binding_result = &binding_result,
            .buffer = buffer,
            .buffer_size = sizeof(buffer),
            .sink = capture_line,
            .sink_opaque = &capture,
        };
        kzt_lazy_diagnostic_emit_result_t emit_result;

        binding_result.status = cases[i].status;
        binding_result.reason = cases[i].reason;
        check_int("transaction-diagnostic.emit",
                  kzt_lazy_diagnostics_emit(&input, &emit_result), 0);
        check_string("transaction-diagnostic.status",
                     emit_result.record.completion_route_status,
                     cases[i].name);
        check_string("transaction-diagnostic.reason",
                     emit_result.record.reason, cases[i].name);
        check_contains("transaction-diagnostic.line", capture.line,
                       cases[i].name);
    }
}

static void test_production_emit_writes_stderr(void)
{
    kzt_lazy_binding_pending_t pending = base_pending();
    kzt_lazy_binding_result_t binding_result = base_result();
    kzt_lazy_diagnostic_emit_result_t emit_result;
    int saved_stderr;
    int pipefd[2];
    char output[KZT_LAZY_DIAGNOSTIC_LINE_LIMIT];
    ssize_t count;

    check_int("production.pipe", pipe(pipefd), 0);
    saved_stderr = dup(STDERR_FILENO);
    check_true("production.saved-stderr", saved_stderr >= 0);
    check_true("production.redirect",
               dup2(pipefd[1], STDERR_FILENO) >= 0);
    close(pipefd[1]);

    check_int("production.enabled.emit",
              kzt_lazy_diagnostics_emit_production(
                  &pending, &binding_result, &emit_result),
              0);
    check_int("production.enabled.status", emit_result.status,
              KZT_LAZY_DIAGNOSTIC_EMIT_EMITTED);

    fflush(stderr);
    check_true("production.restore", dup2(saved_stderr, STDERR_FILENO) >= 0);
    close(saved_stderr);

    count = read(pipefd[0], output, sizeof(output) - 1);
    check_true("production.read", count > 0);
    if (count > 0) {
        output[count] = '\0';
        check_contains("production.output.schema", output, "schema=1");
        check_contains("production.output.symbol", output, "symbol=realloc");
    }
    close(pipefd[0]);
}

int main(void)
{
    test_emit_disabled_skips_format_and_sink();
    test_native_applied_records_schema_one();
    test_slot_unchanged_uses_stable_status_name();
    test_missing_version_uses_stable_status_name();
    test_cas_mismatch_uses_final_competitor_target();
    test_transaction_failure_statuses_are_explicit();
    test_production_emit_writes_stderr();

    if (failures) {
        fprintf(stderr, "kzt-wi256-lazy-diagnostics: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("KZT WI-256 lazy diagnostics: PASS");
    return 0;
}
