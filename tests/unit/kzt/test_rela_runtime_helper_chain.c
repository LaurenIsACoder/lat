#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge_private.h"
#include "target/i386/latx/include/khash.h"
#include "target/i386/latx/include/kzt_bridge_exact.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/kzt_rela_immediate_candidate.h"
#include "target/i386/latx/include/kzt_rela_request_enricher.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"
#include "target/i386/latx/include/librarian_private.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

#define FIXTURE_SYMBOL "uname"
#define FIXTURE_VERSION "GLIBC_2.36"

/* This test calls the runtime adapter, enricher, and writer helpers directly.
   It is a helper-chain test, not a full RelocateElfRELA E2E test, and it does
   not model or claim coverage of the production legacy-store path. */

static int failures;
static int fixture_not_applicable;

KHASH_MAP_IMPL_STR(symbolmap, wrapper_t)
KHASH_MAP_IMPL_STR(symbol2map, symbol2_t)

static void fixture_iFp(uintptr_t fnc)
{
    (void)fnc;
}

typedef struct fixture_bridge_map {
    void *native_symbol;
    uintptr_t target;
    int check_calls;
} fixture_bridge_map_t;

typedef struct runtime_fixture {
    box64context_t context;
    lib_t scope;
    library_t library;
    fixture_bridge_map_t bridge_map;
    onebridge_t bridge_entry;
    uintptr_t native_symbol;
} runtime_fixture_t;

enum fixture_setup_status {
    FIXTURE_SETUP_ERROR = -1,
    FIXTURE_SETUP_OK = 0,
    FIXTURE_SETUP_SKIP = 1,
};

uintptr_t CheckBridged(bridge_t *bridge, void *fnc);

uintptr_t CheckBridged(bridge_t *bridge, void *fnc)
{
    fixture_bridge_map_t *map = (fixture_bridge_map_t *)bridge;

    if (!map) {
        return 0;
    }
    ++map->check_calls;
    if (!fnc || fnc != map->native_symbol) {
        return 0;
    }
    return map->target;
}

typedef struct guarded_slot {
    uintptr_t value;
    uintptr_t canary;
} guarded_slot_t;

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

static kzt_guest_object_observation_t observation(
    uintptr_t link_map_addr, uintptr_t map_start, uintptr_t map_end,
    const char *name)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { name, KZT_GUEST_FIELD_OK },
        .soname = { name, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_registry_t *helper_chain_registry(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t source = observation(
        0x1000, 0x70000000, 0x70010000, "librequester.so");
    kzt_guest_object_observation_t owner = observation(
        0x2000, 0x71000000, 0x71010000, "libowner.so");
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = 0x70001000,
        .load_bias = 0x70000000,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 1,
        .has_null = 1,
    };

    check_int("registry.source",
              kzt_guest_registry_observe(registry, &source),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("registry.owner",
              kzt_guest_registry_observe(registry, &owner),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("registry.dynamic",
              kzt_guest_registry_commit_dynamic_view(
                  registry, source.link_map_addr, 1, &view),
              KZT_GUEST_REGISTRY_UPDATED);
    return registry;
}

static kzt_rela_immediate_candidate_request_t request_for(
    guarded_slot_t *slot, uintptr_t legacy_target, const char *version)
{
    return (kzt_rela_immediate_candidate_request_t) {
        .relocation_type = R_X86_64_JUMP_SLOT,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 3,
        .entry_addr = 0x70002000,
        .source = {
            .known = 1,
            .map_start = 0x70000000,
            .map_end = 0x70010000,
            .soname = "librequester.so",
            .path = "/guest/librequester.so",
        },
        .dynamic_addr = 0x70001000,
        .load_bias = 0x70000000,
        .slot_addr = (uintptr_t)&slot->value,
        .slot_current_value_present = 1,
        .slot_current_value = slot->value,
        .expected_guest_target = 0x71000020,
        .legacy_target = legacy_target,
        .symbol_index = 7,
        .symbol_name = FIXTURE_SYMBOL,
        .version = version,
    };
}

static void runtime_fixture_destroy(runtime_fixture_t *fixture)
{
    if (!fixture) {
        return;
    }
    if (fixture->library.symbolmap) {
        kh_destroy(symbolmap, fixture->library.symbolmap);
        fixture->library.symbolmap = NULL;
    }
    if (fixture->library.priv.w.lib) {
        dlclose(fixture->library.priv.w.lib);
        fixture->library.priv.w.lib = NULL;
    }
    free(fixture->scope.libraries);
    fixture->scope.libraries = NULL;
    fixture->scope.libsz = 0;
}

static int runtime_fixture_setup(runtime_fixture_t *fixture)
{
    static char libc_name[] = "libc.so.6";
    library_t **libraries;
    const char *version_error;
    khint_t key;
    int inserted;

    if (fixture_not_applicable) {
        return FIXTURE_SETUP_SKIP;
    }
    memset(fixture, 0, sizeof(*fixture));
    libraries = malloc(sizeof(*libraries));
    if (!libraries) {
        return FIXTURE_SETUP_ERROR;
    }
    libraries[0] = &fixture->library;
    fixture->scope.libraries = libraries;
    fixture->scope.libsz = 1;
    fixture->scope.context = &fixture->context;
    fixture->context.maplib = &fixture->scope;
    fixture->library.name = libc_name;
    fixture->library.path = libc_name;
    fixture->library.type = LIB_WRAPPED;
    fixture->library.active = 1;
    fixture->library.context = &fixture->context;
    fixture->library.priv.w.lib =
        dlopen("libc.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (!fixture->library.priv.w.lib) {
        fprintf(stderr, "dlopen(libc.so.6): %s\n", dlerror());
        runtime_fixture_destroy(fixture);
        return FIXTURE_SETUP_ERROR;
    }
    dlerror();
    fixture->native_symbol = (uintptr_t)dlvsym(
        fixture->library.priv.w.lib, FIXTURE_SYMBOL, FIXTURE_VERSION);
    version_error = dlerror();
    if (!fixture->native_symbol || version_error) {
        printf("SKIP: %s@%s is not provided by this host libc; "
               "runtime helper-chain fixture is not applicable\n",
               FIXTURE_SYMBOL, FIXTURE_VERSION);
        fixture_not_applicable = 1;
        runtime_fixture_destroy(fixture);
        return FIXTURE_SETUP_SKIP;
    }

    fixture->library.priv.w.bridge = (bridge_t *)&fixture->bridge_map;
    fixture->library.symbolmap = kh_init(symbolmap);
    if (!fixture->library.symbolmap) {
        runtime_fixture_destroy(fixture);
        return FIXTURE_SETUP_ERROR;
    }
    key = kh_put(symbolmap, fixture->library.symbolmap, FIXTURE_SYMBOL,
                 &inserted);
    if (inserted == -1 || key == kh_end(fixture->library.symbolmap)) {
        runtime_fixture_destroy(fixture);
        return FIXTURE_SETUP_ERROR;
    }
    kh_value(fixture->library.symbolmap, key) = fixture_iFp;
    fixture->bridge_entry.CC = 0xCC;
    fixture->bridge_entry.S = 'S';
    fixture->bridge_entry.C = 'C';
    fixture->bridge_entry.w = fixture_iFp;
    fixture->bridge_entry.f = fixture->native_symbol;
    fixture->bridge_entry.C3 = 0xC3;
    fixture->bridge_map.native_symbol = (void *)fixture->native_symbol;
    fixture->bridge_map.target = (uintptr_t)&fixture->bridge_entry.CC;
    return FIXTURE_SETUP_OK;
}

static void test_runtime_adapter_helper_chain(void)
{
    const uintptr_t canary = 0xcafebabedeadbeefULL;
    const uintptr_t legacy_target = 0x7bad0000;
    runtime_fixture_t fixture;
    int setup_status;
    uintptr_t bridge_target;
    guarded_slot_t slot = { 0x71000010, canary };
    kzt_guest_registry_t *registry;
    kzt_wrapper_bridge_provider_t runtime_provider;
    kzt_rela_request_enricher_input_t enrich_input = { 0 };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_request_t request;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_patch_spike_guard_t guard;
    kzt_patch_spike_config_t config = { 1, 1, 1 };

    setup_status = runtime_fixture_setup(&fixture);
    if (setup_status == FIXTURE_SETUP_SKIP) {
        return;
    }
    if (setup_status != FIXTURE_SETUP_OK) {
        ++failures;
        return;
    }
    bridge_target = fixture.bridge_map.target;
    check_int("runtime-provider.guest-native-distinct",
              bridge_target != fixture.native_symbol, 1);
    check_int("runtime-provider.prepare",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library, bridge_target,
                  FIXTURE_SYMBOL,
                  FIXTURE_VERSION, &runtime_provider),
              1);
    check_int("runtime-provider.map-checked",
              fixture.bridge_map.check_calls > 0, 1);
    check_int("runtime-provider.no-add",
              runtime_provider.bridge_ops.add_bridge == NULL, 1);

    registry = helper_chain_registry();
    request = request_for(&slot, legacy_target, FIXTURE_VERSION);
    enrich_input.registry = registry;
    enrich_input.slot_current_value_is_unresolved_stub = 0;
    enrich_input.wrapper_manifest = &runtime_provider.manifest;
    enrich_input.bridge_ops = &runtime_provider.bridge_ops;
    check_int("enrich.call",
              kzt_rela_immediate_request_enrich(
                  &request, &enrich_input, &enrich_result),
              0);
    check_ulong("enrich.bridge", request.native_bridge_target,
                bridge_target);

    kzt_patch_spike_guard_init(&guard, &config);
    check_int("writer.call",
              kzt_rela_immediate_jump_slot_try_write(
                  &request, &guard, NULL, &writer_result),
              0);
    check_int("writer.called", writer_result.writer_called, 1);
    check_int("writer.skip-legacy", writer_result.skip_legacy_write, 1);
    check_ulong("writer.slot-is-bridge", slot.value, bridge_target);
    check_int("writer.slot-not-legacy", slot.value != legacy_target, 1);
    check_ulong("writer.canary", slot.canary, canary);
    kzt_guest_registry_destroy(&registry);
    runtime_fixture_destroy(&fixture);
}

static void test_version_mismatch_leaves_helper_fallback_eligible(void)
{
    const uintptr_t canary = 0x1122334455667788ULL;
    const uintptr_t legacy_target = 0x7bad1000;
    const uintptr_t initial_slot = 0x71000010;
    runtime_fixture_t fixture;
    int setup_status;
    uintptr_t bridge_target;
    guarded_slot_t slot = { initial_slot, canary };
    kzt_wrapper_bridge_provider_t runtime_provider;
    kzt_guest_registry_t *registry;
    kzt_rela_request_enricher_input_t enrich_input = { 0 };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_request_t request;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_patch_spike_guard_t guard;
    kzt_patch_spike_config_t config = { 1, 1, 1 };

    setup_status = runtime_fixture_setup(&fixture);
    if (setup_status == FIXTURE_SETUP_SKIP) {
        return;
    }
    if (setup_status != FIXTURE_SETUP_OK) {
        ++failures;
        return;
    }
    bridge_target = fixture.bridge_map.target;
    check_int("mismatch.provider",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library, bridge_target,
                  FIXTURE_SYMBOL,
                  "GLIBC_NOT_REAL", &runtime_provider),
              0);
    registry = helper_chain_registry();
    request = request_for(&slot, legacy_target, "GLIBC_NOT_REAL");
    enrich_input.registry = registry;
    enrich_input.slot_current_value_is_unresolved_stub = 0;
    enrich_input.wrapper_manifest = &runtime_provider.manifest;
    enrich_input.bridge_ops = &runtime_provider.bridge_ops;
    check_int("mismatch.enrich",
              kzt_rela_immediate_request_enrich(
                  &request, &enrich_input, &enrich_result),
              0);
    kzt_patch_spike_guard_init(&guard, &config);
    check_int("mismatch.writer",
              kzt_rela_immediate_jump_slot_try_write(
                  &request, &guard, NULL, &writer_result),
              0);
    check_int("mismatch.writer-not-called", writer_result.writer_called, 0);
    check_int("mismatch.fallback-eligible",
              writer_result.skip_legacy_write, 0);
    check_ulong("mismatch.helper-left-slot-untouched", slot.value,
                initial_slot);
    check_ulong("mismatch.canary", slot.canary, canary);
    kzt_guest_registry_destroy(&registry);
    runtime_fixture_destroy(&fixture);
}

static void test_bridge_owner_mismatch_fails_closed(void)
{
    runtime_fixture_t fixture;
    kzt_wrapper_bridge_provider_t runtime_provider;
    uintptr_t resolved_target;
    int setup_status;

    setup_status = runtime_fixture_setup(&fixture);
    if (setup_status == FIXTURE_SETUP_SKIP) {
        return;
    }
    if (setup_status != FIXTURE_SETUP_OK) {
        ++failures;
        return;
    }
    resolved_target = fixture.bridge_map.target;
    fixture.bridge_map.target = resolved_target + sizeof(onebridge_t);
    check_int("owner-mismatch.prepare",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library, resolved_target,
                  FIXTURE_SYMBOL, FIXTURE_VERSION, &runtime_provider),
              0);
    check_int("owner-mismatch.map-checked",
              fixture.bridge_map.check_calls > 0, 1);
    check_int("owner-mismatch.unavailable",
              runtime_provider.manifest.available, 0);
    runtime_fixture_destroy(&fixture);
}

static void test_null_inputs_fail_without_bridge_inspection(void)
{
    runtime_fixture_t fixture;
    kzt_wrapper_bridge_provider_t runtime_provider;
    uintptr_t resolved_target;
    int setup_status;

    check_int("null-provider.error",
              kzt_rela_runtime_wrapper_provider_prepare(
                  NULL, NULL, 0, NULL, NULL, NULL),
              -1);

    setup_status = runtime_fixture_setup(&fixture);
    if (setup_status == FIXTURE_SETUP_SKIP) {
        return;
    }
    if (setup_status != FIXTURE_SETUP_OK) {
        ++failures;
        return;
    }
    resolved_target = fixture.bridge_map.target;
    check_int("null-target.prepare",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library, 0, FIXTURE_SYMBOL,
                  FIXTURE_VERSION, &runtime_provider),
              0);
    fixture.bridge_map.target = 0;
    check_int("null-map-result.prepare",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library, resolved_target,
                  FIXTURE_SYMBOL, FIXTURE_VERSION, &runtime_provider),
              0);
    check_int("null-map-result.checked",
              fixture.bridge_map.check_calls > 0, 1);
    fixture.bridge_map.target = resolved_target;
    fixture.library.priv.w.bridge = NULL;
    check_int("null-bridge-map.prepare",
              kzt_rela_runtime_wrapper_provider_prepare(
                  &fixture.context, &fixture.library,
                  fixture.bridge_map.target, FIXTURE_SYMBOL,
                  FIXTURE_VERSION, &runtime_provider),
              0);
    check_int("null-exact.target",
              kzt_bridge_is_exact(0, fixture_iFp,
                                  (void *)fixture.native_symbol),
              0);
    runtime_fixture_destroy(&fixture);
}

int main(void)
{
    test_runtime_adapter_helper_chain();
    test_version_mismatch_leaves_helper_fallback_eligible();
    test_bridge_owner_mismatch_fails_closed();
    test_null_inputs_fail_without_bridge_inspection();

    if (failures) {
        fprintf(stderr, "kzt-rela-runtime-helper-chain: %d failure(s)\n",
                failures);
        return 1;
    }
    if (fixture_not_applicable) {
        puts("kzt-rela-runtime-helper-chain: skipped");
        return 77;
    }
    puts("kzt-rela-runtime-helper-chain: ok");
    return 0;
}
