#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_wrapper_bridge_provider.h"

static int failures;

typedef struct fake_library {
    int inspect_status;
    const char *name;
    uintptr_t native_symbol;
    uintptr_t bridge_target;
    uintptr_t add_target;
    uintptr_t post_add_target;
    uintptr_t guest_fallback_target;
    kzt_bridge_guard_kind_t guard_kind;
    int bridge_exact;
    int guarded_absent_from_map;
    int lifetime_bound;
    int inspect_calls;
    int check_calls;
    int add_calls;
} fake_library_t;

static void fake_wrapper(uintptr_t fnc)
{
    (void)fnc;
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }
    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_ulong(const char *name, uintptr_t got, uintptr_t expected)
{
    if (got == expected) {
        return;
    }
    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static int fake_inspect(
    void *library, const char *symbol_name, const char *symbol_version,
    kzt_wrapper_bridge_provider_match_t *match, void *opaque)
{
    fake_library_t *lib = library;

    (void)opaque;
    ++lib->inspect_calls;
    if (lib->inspect_status <= 0) {
        return lib->inspect_status;
    }
    if (strcmp(symbol_name, "gtk_widget_show") != 0 ||
        (symbol_version && strcmp(symbol_version, "GTK_3.0") != 0)) {
        return -1;
    }

    match->wrapper_name = lib->name;
    snprintf(match->native_name, sizeof(match->native_name), "%s",
             symbol_name);
    match->abi_wrapper = fake_wrapper;
    match->native_symbol = lib->native_symbol;
    match->resolved_bridge_target = lib->bridge_target;
    match->context_owner = lib;
    match->wrapper_provider = lib;
    match->native_lookup_handle = lib;
    match->native_owner = lib;
    match->bridge_owner = lib;
    match->bridge_storage = lib;
    match->resolved_bridge_exact = lib->bridge_exact;
    match->wrapper_provider_lifetime_bound = lib->lifetime_bound;
    match->native_owner_lifetime_bound = lib->lifetime_bound;
    match->bridge_owner_lifetime_bound = lib->lifetime_bound;
    match->guest_fallback_target = lib->guest_fallback_target;
    match->guard_kind = lib->guard_kind;
    return 1;
}

static uintptr_t fake_check(
    const kzt_wrapper_bridge_provider_match_t *match, void *opaque)
{
    fake_library_t *lib = match->bridge_owner;

    (void)opaque;
    ++lib->check_calls;
    return lib->bridge_target;
}

static uintptr_t fake_add(
    const kzt_wrapper_bridge_provider_match_t *match,
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque)
{
    fake_library_t *lib = match->bridge_owner;

    (void)opaque;
    if (request->native_symbol != lib->native_symbol) {
        return 0;
    }
    ++lib->add_calls;
    if (!lib->guarded_absent_from_map) {
        lib->bridge_target = lib->post_add_target ? lib->post_add_target :
                                                   lib->add_target;
    }
    return lib->add_target;
}

static kzt_wrapper_bridge_provider_runtime_ops_t fake_ops(void)
{
    return (kzt_wrapper_bridge_provider_runtime_ops_t) {
        .inspect_library = fake_inspect,
        .check_bridge = fake_check,
        .add_bridge = fake_add,
    };
}

static void test_exact_unique_candidate_builds_temporary_provider(void)
{
    fake_library_t skipped = { .inspect_status = 0 };
    fake_library_t exact = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0x72000000,
        .bridge_exact = 1,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &skipped, &exact, &exact };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_result_t result;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = "gtk_widget_show",
        .symbol_version = "GTK_3.0",
    };

    ops.add_bridge = NULL;

    check_int("exact.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 3, request.symbol_name,
                  request.symbol_version, &ops),
              1);
    check_int("exact.duplicate-inspected-once", exact.inspect_calls, 1);
    check_int("exact.probe",
              kzt_wrapper_probe_minimal_manifest(
                  &provider.manifest, &request, &provider.bridge_ops,
                  &result),
              0);
    check_int("exact.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("exact.native", result.native_symbol, 0x71000000);
    check_ulong("exact.bridge", result.bridge_target, 0x72000000);
    check_int("exact.check", exact.check_calls, 1);
    check_int("exact.no-add", exact.add_calls, 0);
    check_int("exact.add-disabled",
              provider.bridge_ops.add_bridge == NULL, 1);
    check_int("exact.bound-owner",
              provider.match.bridge_owner == &exact, 1);
}

static void test_unversioned_query_failure_and_ambiguity_fail_open(void)
{
    fake_library_t exact_a = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0x72000000,
        .bridge_exact = 1,
        .lifetime_bound = 1,
    };
    fake_library_t exact_b = {
        .inspect_status = 1,
        .name = "libgtk-shadow.so.0",
        .native_symbol = 0x71001000,
        .bridge_target = 0x72001000,
        .bridge_exact = 1,
        .lifetime_bound = 1,
    };
    fake_library_t failed = { .inspect_status = -1 };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    void *one[] = { &exact_a };
    void *ambiguous[] = { &exact_a, &exact_b };
    void *query_failed[] = { &exact_a, &failed };

    check_int("unversioned.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, one, 1, "gtk_widget_show", NULL, &ops),
              0);
    check_int("unversioned.no-query", exact_a.inspect_calls, 0);

    check_int("ambiguous.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, ambiguous, 2, "gtk_widget_show",
                  "GTK_3.0", &ops),
              0);
    check_int("ambiguous.unavailable", provider.manifest.available, 0);

    check_int("query-failed.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, query_failed, 2, "gtk_widget_show",
                  "GTK_3.0", &ops),
              0);
    check_int("query-failed.unavailable", provider.manifest.available, 0);
}

static void test_confirmed_unversioned_provider_is_probeable(void)
{
    fake_library_t exact = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0x72000000,
        .bridge_exact = 1,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &exact };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = "gtk_widget_show",
        .symbol_version_evidence =
            KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
        .symbol_version = NULL,
    };
    kzt_wrapper_probe_result_t result;

    ops.add_bridge = NULL;
    check_int("confirmed-unversioned.prepare",
              kzt_wrapper_bridge_provider_prepare_with_version_evidence(
                  &provider, libraries, 1, request.symbol_name,
                  request.symbol_version_evidence, request.symbol_version,
                  &ops),
              1);
    check_int("confirmed-unversioned.inspected", exact.inspect_calls, 1);
    check_int("confirmed-unversioned.probe",
              kzt_wrapper_probe_minimal_manifest(
                  &provider.manifest, &request, &provider.bridge_ops,
                  &result),
              0);
    check_int("confirmed-unversioned.match", result.wrapper_match,
              KZT_PATCH_WRAPPER_UNVERSIONED_MATCH);
    check_ulong("confirmed-unversioned.bridge", result.bridge_target,
                exact.bridge_target);
}

static void test_missing_lifetime_binding_fails_open(void)
{
    fake_library_t unbound = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0x72000000,
        .bridge_exact = 1,
        .lifetime_bound = 0,
    };
    void *libraries[] = { &unbound };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;

    check_int("unbound.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 1, "gtk_widget_show",
                  "GTK_3.0", &ops),
              0);
    check_int("unbound.unavailable", provider.manifest.available, 0);
}

static void test_bridge_abi_conflict_fails_open_without_add(void)
{
    fake_library_t conflict = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0x72000000,
        .bridge_exact = 0,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &conflict };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;

    check_int("conflict.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 1, "gtk_widget_show",
                  "GTK_3.0", &ops),
              0);
    check_int("conflict.unavailable", provider.manifest.available, 0);
    check_int("conflict.no-add", conflict.add_calls, 0);
}

static void test_missing_bridge_is_created_then_rechecked(void)
{
    fake_library_t missing = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0,
        .add_target = 0x72000000,
        .bridge_exact = 0,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &missing };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_result_t result;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = "gtk_widget_show",
        .symbol_version = "GTK_3.0",
    };

    check_int("missing.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 1, request.symbol_name,
                  request.symbol_version, &ops),
              1);
    check_int("missing.probe",
              kzt_wrapper_probe_minimal_manifest(
                  &provider.manifest, &request, &provider.bridge_ops,
                  &result),
              0);
    check_ulong("missing.bridge", result.bridge_target, 0x72000000);
    check_int("missing.bridge-source", result.bridge_source,
              KZT_WRAPPER_PROBE_BRIDGE_ADD_BRIDGE);
    check_int("missing.check-twice", missing.check_calls, 2);
    check_int("missing.add-once", missing.add_calls, 1);
}

static void test_created_bridge_must_match_recheck(void)
{
    fake_library_t inexact = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .bridge_target = 0,
        .add_target = 0x72000000,
        .post_add_target = 0x73000000,
        .bridge_exact = 0,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &inexact };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_result_t result;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = "gtk_widget_show",
        .symbol_version = "GTK_3.0",
    };

    check_int("inexact-created.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 1, request.symbol_name,
                  request.symbol_version, &ops),
              1);
    check_int("inexact-created.probe",
              kzt_wrapper_probe_minimal_manifest(
                  &provider.manifest, &request, &provider.bridge_ops,
                  &result),
              0);
    check_ulong("inexact-created.no-bridge", result.bridge_target, 0);
    check_int("inexact-created.add-once", inexact.add_calls, 1);
}

static void test_guarded_created_bridge_does_not_require_map_recheck(void)
{
    fake_library_t guarded = {
        .inspect_status = 1,
        .name = "libgtk-3.so.0",
        .native_symbol = 0x71000000,
        .add_target = 0x72000000,
        .guest_fallback_target = 0x73000000,
        .guard_kind = KZT_BRIDGE_GUARD_XCB_CONNECTION,
        .guarded_absent_from_map = 1,
        .lifetime_bound = 1,
    };
    void *libraries[] = { &guarded };
    kzt_wrapper_bridge_provider_runtime_ops_t ops = fake_ops();
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_result_t result;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = "gtk_widget_show",
        .symbol_version = "GTK_3.0",
    };

    check_int("guarded.prepare",
              kzt_wrapper_bridge_provider_prepare(
                  &provider, libraries, 1, request.symbol_name,
                  request.symbol_version, &ops),
              1);
    check_int("guarded.probe",
              kzt_wrapper_probe_minimal_manifest(
                  &provider.manifest, &request, &provider.bridge_ops,
                  &result),
              0);
    check_ulong("guarded.bridge", result.bridge_target,
                guarded.add_target);
    check_int("guarded.bridge-source", result.bridge_source,
              KZT_WRAPPER_PROBE_BRIDGE_ADD_BRIDGE);
    check_int("guarded.initial-check-only", guarded.check_calls, 1);
    check_int("guarded.add-once", guarded.add_calls, 1);
    check_ulong("guarded.map-remains-empty", guarded.bridge_target, 0);
}

int main(void)
{
    test_exact_unique_candidate_builds_temporary_provider();
    test_unversioned_query_failure_and_ambiguity_fail_open();
    test_confirmed_unversioned_provider_is_probeable();
    test_missing_lifetime_binding_fails_open();
    test_bridge_abi_conflict_fails_open_without_add();
    test_missing_bridge_is_created_then_rechecked();
    test_created_bridge_must_match_recheck();
    test_guarded_created_bridge_does_not_require_map_recheck();

    if (failures) {
        fprintf(stderr, "kzt-wrapper-bridge-provider: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("kzt-wrapper-bridge-provider: ok");
    return 0;
}
