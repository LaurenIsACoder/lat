#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_wrapper_probe.h"

static int failures;

typedef struct fake_bridge_state {
    uintptr_t cached_native_symbol;
    uintptr_t cached_bridge_target;
    uintptr_t next_bridge_target;
    int check_calls;
    int add_calls;
    kzt_wrapper_probe_bridge_request_t last_request;
} fake_bridge_state_t;

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

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got,
            expected);
    ++failures;
}

static void check_str(const char *name, const char *got,
                      const char *expected)
{
    if (got && expected && !strcmp(got, expected)) {
        return;
    }
    if (!got && !expected) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static uintptr_t fake_check_bridge(uintptr_t native_symbol, void *opaque)
{
    fake_bridge_state_t *state = opaque;

    ++state->check_calls;
    if (native_symbol == state->cached_native_symbol) {
        return state->cached_bridge_target;
    }

    return 0;
}

static uintptr_t fake_add_bridge(
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque)
{
    fake_bridge_state_t *state = opaque;

    ++state->add_calls;
    state->last_request = *request;
    return state->next_bridge_target;
}

static kzt_wrapper_probe_bridge_ops_t fake_bridge_ops(
    fake_bridge_state_t *state)
{
    return (kzt_wrapper_probe_bridge_ops_t) {
        .check_bridge = fake_check_bridge,
        .add_bridge = fake_add_bridge,
        .opaque = state,
    };
}

static const kzt_wrapper_probe_entry_t base_entries[] = {
    {
        .symbol_name = "gtk_widget_show",
        .symbol_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .symbol_version = "GTK_3.0",
        .wrapper_name = "wrappedgtk3",
        .wrapper_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .wrapper_symbol_version = "GTK_3.0",
        .native_symbol = 0x7100001000,
    },
    {
        .symbol_name = "gtk_widget_hide",
        .symbol_version = NULL,
        .wrapper_name = "wrappedgtk3",
        .wrapper_symbol_version = NULL,
        .native_symbol = 0x7100002000,
    },
    {
        .symbol_name = "gtk_widget_destroy",
        .symbol_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .symbol_version = "GTK_3.0",
        .wrapper_name = "wrappedgtk3",
        .wrapper_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .wrapper_symbol_version = "GTK_3.0",
        .native_symbol = 0,
    },
    {
        .symbol_name = "gtk_widget_queue_draw",
        .symbol_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .symbol_version = "GTK_3.0",
        .wrapper_name = "wrappedgtk3",
        .wrapper_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .wrapper_symbol_version = "GTK_3.0",
        .native_symbol = 0x7100003000,
    },
    {
        .symbol_name = "gtk_widget_unversioned",
        .symbol_version_evidence =
            KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
        .symbol_version = NULL,
        .wrapper_name = "wrappedgtk3",
        .wrapper_version_evidence =
            KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
        .wrapper_symbol_version = NULL,
        .native_symbol = 0x7100004000,
    },
};

static kzt_wrapper_probe_manifest_t base_manifest(void)
{
    return (kzt_wrapper_probe_manifest_t) {
        .available = 1,
        .manifest_name = "wrappedgtk3",
        .entries = base_entries,
        .entry_count = sizeof(base_entries) / sizeof(base_entries[0]),
    };
}

static kzt_wrapper_probe_request_t request_for(const char *name,
                                               const char *version)
{
    return (kzt_wrapper_probe_request_t) {
        .symbol_name = name,
        .symbol_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .symbol_version = version,
    };
}

static void test_no_manifest_keeps_probe_unavailable(void)
{
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_show", "GTK_3.0");
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {0};
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    manifest.available = 0;
    check_int("no_manifest.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("no_manifest.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_NO_MANIFEST);
    check_str("no_manifest.wrapper", result.wrapper_name, NULL);
    check_ulong("no_manifest.bridge", result.bridge_target, 0);
    check_int("no_manifest.check_calls", state.check_calls, 0);
    check_int("no_manifest.add_calls", state.add_calls, 0);
}

static void test_no_wrapper_distinguishes_missing_symbol(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_missing", "GTK_3.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {0};
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("no_wrapper.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("no_wrapper.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_NO_WRAPPER);
    check_ulong("no_wrapper.native", result.native_symbol, 0);
    check_ulong("no_wrapper.bridge", result.bridge_target, 0);
    check_int("no_wrapper.add_calls", state.add_calls, 0);
}

static void test_symbol_only_does_not_create_safe_bridge(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_hide", "GTK_3.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .next_bridge_target = 0x7200001000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("symbol_only.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("symbol_only.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_SYMBOL_ONLY);
    check_str("symbol_only.wrapper", result.wrapper_name, "wrappedgtk3");
    check_str("symbol_only.version", result.wrapper_symbol_version, NULL);
    check_ulong("symbol_only.native", result.native_symbol, 0x7100002000);
    check_ulong("symbol_only.bridge", result.bridge_target, 0);
    check_int("symbol_only.check_calls", state.check_calls, 0);
    check_int("symbol_only.add_calls", state.add_calls, 0);
}

static void test_version_mismatch_keeps_bridge_empty(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_show", "GTK_4.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .next_bridge_target = 0x7200001000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("version_mismatch.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("version_mismatch.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MISMATCH);
    check_str("version_mismatch.wrapper", result.wrapper_name,
              "wrappedgtk3");
    check_str("version_mismatch.version", result.wrapper_symbol_version,
              "GTK_3.0");
    check_ulong("version_mismatch.bridge", result.bridge_target, 0);
    check_int("version_mismatch.add_calls", state.add_calls, 0);
}

static void test_version_match_creates_bridge_from_explicit_callback(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_show", "GTK_3.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .next_bridge_target = 0x7200001000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("version_match.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("version_match.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_str("version_match.wrapper", result.wrapper_name,
              "wrappedgtk3");
    check_str("version_match.version", result.wrapper_symbol_version,
              "GTK_3.0");
    check_ulong("version_match.native", result.native_symbol,
                0x7100001000);
    check_ulong("version_match.bridge", result.bridge_target,
                0x7200001000);
    check_int("version_match.bridge_source", result.bridge_source,
              KZT_WRAPPER_PROBE_BRIDGE_ADD_BRIDGE);
    check_int("version_match.check_calls", state.check_calls, 1);
    check_int("version_match.add_calls", state.add_calls, 1);
    check_str("version_match.bridge_request.name",
              state.last_request.symbol_name, "gtk_widget_show");
    check_str("version_match.bridge_request.version",
              state.last_request.symbol_version, "GTK_3.0");
    check_ulong("version_match.bridge_request.native",
                state.last_request.native_symbol, 0x7100001000);
}

static void test_confirmed_unversioned_match_creates_bridge(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_unversioned", NULL);
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .next_bridge_target = 0x7200004000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    request.symbol_version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    check_int("unversioned.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("unversioned.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_UNVERSIONED_MATCH);
    check_int("unversioned.wrapper-evidence",
              result.wrapper_version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
    check_str("unversioned.version", result.wrapper_symbol_version, NULL);
    check_ulong("unversioned.bridge", result.bridge_target, 0x7200004000);
    check_int("unversioned.add-calls", state.add_calls, 1);
    check_int("unversioned.bridge-request-evidence",
              state.last_request.symbol_version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
}

static void test_unknown_and_error_evidence_do_not_probe_bridge(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_result_t result;
    kzt_symbol_version_evidence_t evidence[] = {
        KZT_SYMBOL_VERSION_UNKNOWN,
        KZT_SYMBOL_VERSION_ERROR,
    };
    size_t i;

    for (i = 0; i < sizeof(evidence) / sizeof(evidence[0]); ++i) {
        kzt_wrapper_probe_request_t request =
            request_for("gtk_widget_show", "GTK_3.0");
        fake_bridge_state_t state = {
            .next_bridge_target = 0x7200001000,
        };
        kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

        request.symbol_version_evidence = evidence[i];
        check_int("untrusted.call",
                  kzt_wrapper_probe_minimal_manifest(
                      &manifest, &request, &ops, &result), 0);
        check_int("untrusted.match", result.wrapper_match,
                  KZT_PATCH_WRAPPER_VERSION_MISMATCH);
        check_int("untrusted.no-check", state.check_calls, 0);
        check_int("untrusted.no-add", state.add_calls, 0);
    }
}

static void test_bridge_zero_preserves_fail_open_input(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_destroy", "GTK_3.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .next_bridge_target = 0x7200001000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("bridge_zero.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("bridge_zero.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("bridge_zero.native", result.native_symbol, 0);
    check_ulong("bridge_zero.bridge", result.bridge_target, 0);
    check_int("bridge_zero.source", result.bridge_source,
              KZT_WRAPPER_PROBE_BRIDGE_NONE);
    check_int("bridge_zero.check_calls", state.check_calls, 0);
    check_int("bridge_zero.add_calls", state.add_calls, 0);
}

static void test_bridge_cache_reuse_does_not_add_duplicate_bridge(void)
{
    kzt_wrapper_probe_manifest_t manifest = base_manifest();
    kzt_wrapper_probe_request_t request =
        request_for("gtk_widget_queue_draw", "GTK_3.0");
    kzt_wrapper_probe_result_t result;
    fake_bridge_state_t state = {
        .cached_native_symbol = 0x7100003000,
        .cached_bridge_target = 0x7200003000,
        .next_bridge_target = 0x7200004000,
    };
    kzt_wrapper_probe_bridge_ops_t ops = fake_bridge_ops(&state);

    check_int("bridge_cache.call",
              kzt_wrapper_probe_minimal_manifest(&manifest, &request,
                                                 &ops, &result), 0);
    check_int("bridge_cache.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("bridge_cache.bridge", result.bridge_target,
                0x7200003000);
    check_int("bridge_cache.source", result.bridge_source,
              KZT_WRAPPER_PROBE_BRIDGE_CACHE);
    check_int("bridge_cache.check_calls", state.check_calls, 1);
    check_int("bridge_cache.add_calls", state.add_calls, 0);
}

int main(void)
{
    test_no_manifest_keeps_probe_unavailable();
    test_no_wrapper_distinguishes_missing_symbol();
    test_symbol_only_does_not_create_safe_bridge();
    test_version_mismatch_keeps_bridge_empty();
    test_version_match_creates_bridge_from_explicit_callback();
    test_confirmed_unversioned_match_creates_bridge();
    test_unknown_and_error_evidence_do_not_probe_bridge();
    test_bridge_zero_preserves_fail_open_input();
    test_bridge_cache_reuse_does_not_add_duplicate_bridge();

    if (failures) {
        fprintf(stderr, "kzt-wrapper-probe failures: %d\n", failures);
        return 1;
    }

    puts("kzt-wrapper-probe: ok");
    return 0;
}
