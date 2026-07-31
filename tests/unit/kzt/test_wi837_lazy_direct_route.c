#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_lazy_direct_route.h"

typedef struct fixture {
    uintptr_t slot;
    uintptr_t bridge_target;
    int source_valid;
    int provider_available;
    int provider_generation_delta;
    int bridge_available;
    int wrong_bridge_version;
    int lease_available;
    int final_valid;
    kzt_lazy_direct_route_cas_status_t cas_status;
    int source_calls;
    int provider_acquire_calls;
    int provider_release_calls;
    int bridge_calls;
    int lease_acquire_calls;
    int lease_release_calls;
    int final_validate_calls;
    int cas_calls;
    int write_calls;
    uintptr_t cas_expected;
} fixture_t;

static int failures;

#define CHECK(name, condition) do {                                  \
    if (!(condition)) {                                              \
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__); \
        ++failures;                                                  \
    }                                                               \
} while (0)

static int validate_source(const kzt_lazy_direct_route_input_t *input,
                           void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->source_calls;
    CHECK("source.generation",
          input->source.generation ==
              input->source_dynamic_view_generation);
    return fixture->source_valid;
}

static int acquire_provider(const kzt_lazy_direct_route_input_t *input,
                            kzt_lazy_direct_route_provider_t *provider,
                            void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->provider_acquire_calls;
    if (!fixture->provider_available) {
        return -1;
    }
    *provider = (kzt_lazy_direct_route_provider_t) {
        .handle = fixture,
        .link_map_addr = input->provider.link_map_addr,
        .generation = input->provider.generation +
                      fixture->provider_generation_delta,
        .namespace_id = input->namespace_id,
        .namespace_kind = input->namespace_kind,
    };
    return 0;
}

static void release_provider(kzt_lazy_direct_route_provider_t *provider,
                             void *opaque)
{
    fixture_t *fixture = opaque;

    CHECK("provider.release-handle", provider->handle == fixture);
    ++fixture->provider_release_calls;
    memset(provider, 0, sizeof(*provider));
}

static int find_wrapper_bridge(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    kzt_lazy_direct_route_bridge_t *bridge,
    void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->bridge_calls;
    CHECK("bridge.provider-live", provider->handle == fixture);
    if (!fixture->bridge_available) {
        return -1;
    }
    *bridge = (kzt_lazy_direct_route_bridge_t) {
        .target = fixture->bridge_target,
        .version_evidence = input->version_evidence,
        .version = fixture->wrong_bridge_version ?
                       "GLIBC_2.2.5" : input->version,
    };
    return 0;
}

static int acquire_decision_lease(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    kzt_lazy_direct_route_lease_t *lease,
    void *opaque)
{
    fixture_t *fixture = opaque;

    (void)input;
    ++fixture->lease_acquire_calls;
    CHECK("lease.provider-live", provider->handle == fixture);
    if (!fixture->lease_available) {
        return -1;
    }
    lease->handle = fixture;
    lease->active = 1;
    return 0;
}

static void release_decision_lease(kzt_lazy_direct_route_lease_t *lease,
                                   void *opaque)
{
    fixture_t *fixture = opaque;

    CHECK("lease.release-active",
          lease->active && lease->handle == fixture);
    ++fixture->lease_release_calls;
    memset(lease, 0, sizeof(*lease));
}

static int validate_final(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    const kzt_lazy_direct_route_bridge_t *bridge,
    const kzt_lazy_direct_route_lease_t *lease,
    void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->final_validate_calls;
    CHECK("final.slot", input->slot_addr == (uintptr_t)&fixture->slot);
    CHECK("final.provider-live", provider->handle == fixture);
    CHECK("final.bridge", bridge->target == fixture->bridge_target);
    CHECK("final.lease", lease->active && lease->handle == fixture);
    return fixture->final_valid;
}

static kzt_lazy_direct_route_cas_status_t cas_slot(
    uintptr_t slot_addr,
    uintptr_t expected,
    uintptr_t replacement,
    const kzt_lazy_direct_route_lease_t *lease,
    void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->cas_calls;
    fixture->cas_expected = expected;
    CHECK("cas.address", slot_addr == (uintptr_t)&fixture->slot);
    CHECK("cas.lease", lease->active && lease->handle == fixture);
    if (fixture->cas_status != KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED ||
        fixture->slot != expected) {
        return fixture->cas_status;
    }
    fixture->slot = replacement;
    ++fixture->write_calls;
    return KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED;
}

static fixture_t fixture(void)
{
    return (fixture_t) {
        .slot = 0x71000100,
        .bridge_target = 0x72000200,
        .source_valid = 1,
        .provider_available = 1,
        .bridge_available = 1,
        .lease_available = 1,
        .final_valid = 1,
        .cas_status = KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED,
    };
}

static kzt_guest_dynamic_view_t complete_dynamic_view(void)
{
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = 0x40001000,
        .load_bias = 0x40000000,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 16,
        .has_null = 1,
        .symtab = { 1, 0x40002000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .strtab = { 1, 0x40003000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .syment = { 1, 24, KZT_GUEST_DYNAMIC_SCALAR },
        .versym = { 1, 0x40004000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .verneed = { 1, 0x40005000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .verneednum = { 1, 1, KZT_GUEST_DYNAMIC_SCALAR },
        .jmprel = { 1, 0x40006000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .pltrelsz = { 1, 24, KZT_GUEST_DYNAMIC_SCALAR },
        .pltrel = { 1, 7, KZT_GUEST_DYNAMIC_SCALAR },
        .pltgot = { 1, 0x40007000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
    };

    return view;
}

static kzt_lazy_direct_route_input_t input_for(
    fixture_t *fixture,
    const kzt_guest_dynamic_view_t *view)
{
    return (kzt_lazy_direct_route_input_t) {
        .enabled = 1,
        .preemption_safe = 1,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        .source = { 0x1000, 7 },
        .provider = { 0x2000, 11 },
        .source_dynamic_view = view,
        .source_dynamic_view_generation = 7,
        .symbol = "dlerror",
        .version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .version = "GLIBC_2.34",
        .slot_addr = (uintptr_t)&fixture->slot,
        .guest_unresolved_slot = fixture->slot,
        .expected_current_slot = fixture->slot,
    };
}

static kzt_lazy_direct_route_ops_t ops_for(fixture_t *fixture)
{
    return (kzt_lazy_direct_route_ops_t) {
        .validate_source = validate_source,
        .acquire_provider = acquire_provider,
        .release_provider = release_provider,
        .find_wrapper_bridge = find_wrapper_bridge,
        .acquire_decision_lease = acquire_decision_lease,
        .release_decision_lease = release_decision_lease,
        .validate_final = validate_final,
        .cas_slot = cas_slot,
        .opaque = fixture,
    };
}

static void test_only_strong_global_binding_is_eligible(void)
{
    CHECK("binding.global",
          kzt_lazy_direct_symbol_binding_supported(
              ELF_ST_INFO(STB_GLOBAL, STT_FUNC)));
    CHECK("binding.weak",
          !kzt_lazy_direct_symbol_binding_supported(
              ELF_ST_INFO(STB_WEAK, STT_FUNC)));
    CHECK("binding.local",
          !kzt_lazy_direct_symbol_binding_supported(
              ELF_ST_INFO(STB_LOCAL, STT_FUNC)));
}

static void test_complete_evidence_applies_native_once(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;

    CHECK("success.status",
          kzt_lazy_direct_route_apply(&input, &ops, &result) ==
              KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED);
    CHECK("success.result",
          result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          result.reason == KZT_LAZY_DIRECT_ROUTE_REASON_NATIVE_APPLIED &&
          result.selected_target == f.bridge_target);
    CHECK("success.slot", f.slot == f.bridge_target);
    CHECK("success.one-write", f.write_calls == 1 && f.cas_calls == 1);
    CHECK("success.source", f.source_calls == 1);
    CHECK("success.provider",
          f.provider_acquire_calls == 1 &&
          f.provider_release_calls == 1);
    CHECK("success.bridge", f.bridge_calls == 1);
    CHECK("success.lease",
          f.lease_acquire_calls == 1 &&
          f.lease_release_calls == 1);
    CHECK("success.final", f.final_validate_calls == 1);
}

static void test_managed_bridge_uses_current_value_for_cas(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t guest_unresolved_slot = f.slot;
    uintptr_t managed_bridge = 0x71000900;

    f.slot = managed_bridge;
    input.guest_unresolved_slot = guest_unresolved_slot;
    input.expected_current_slot = managed_bridge;
    CHECK("managed.status",
          kzt_lazy_direct_route_apply(&input, &ops, &result) ==
              KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED);
    CHECK("managed.cas-current",
          f.cas_expected == managed_bridge &&
          f.slot == f.bridge_target && f.write_calls == 1);
}

static void check_guest_required(
    const char *name,
    kzt_lazy_direct_route_status_t status,
    const kzt_lazy_direct_route_result_t *result,
    kzt_lazy_direct_route_reason_t reason,
    const fixture_t *fixture,
    uintptr_t expected_slot)
{
    if (status != KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED ||
        result->status != KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED ||
        result->reason != reason || result->selected_target != 0 ||
        fixture->slot != expected_slot || fixture->write_calls != 0) {
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__);
        ++failures;
    }
}

static void test_disabled_requires_guest_without_callbacks(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    input.enabled = 0;
    check_guest_required(
        "disabled",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_DISABLED, &f, original);
    CHECK("disabled.no-callbacks",
          f.source_calls == 0 && f.provider_acquire_calls == 0 &&
          f.bridge_calls == 0 && f.lease_acquire_calls == 0 &&
          f.final_validate_calls == 0 && f.cas_calls == 0);
}

static void test_unproven_preemption_requires_guest_without_callbacks(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    input.preemption_safe = 0;
    check_guest_required(
        "preemption-unproven",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN,
        &f, original);
    CHECK("preemption-unproven.no-callbacks",
          f.source_calls == 0 && f.provider_acquire_calls == 0 &&
          f.bridge_calls == 0 && f.lease_acquire_calls == 0 &&
          f.final_validate_calls == 0 && f.cas_calls == 0);
}

static void test_non_main_namespace_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    input.namespace_id = 3;
    input.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
    check_guest_required(
        "namespace",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_NON_MAIN_NAMESPACE,
        &f, original);
    CHECK("namespace.no-source", f.source_calls == 0);
}

static void test_unknown_and_error_version_require_guest(void)
{
    const kzt_symbol_version_evidence_t evidence[] = {
        KZT_SYMBOL_VERSION_UNKNOWN,
        KZT_SYMBOL_VERSION_ERROR,
    };
    size_t i;

    for (i = 0; i < sizeof(evidence) / sizeof(evidence[0]); ++i) {
        fixture_t f = fixture();
        kzt_guest_dynamic_view_t view = complete_dynamic_view();
        kzt_lazy_direct_route_input_t input = input_for(&f, &view);
        kzt_lazy_direct_route_ops_t ops = ops_for(&f);
        kzt_lazy_direct_route_result_t result;
        uintptr_t original = f.slot;

        input.version_evidence = evidence[i];
        check_guest_required(
            "version-evidence",
            kzt_lazy_direct_route_apply(&input, &ops, &result),
            &result, KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_VERSION,
            &f, original);
        CHECK("version-evidence.no-source", f.source_calls == 0);
    }
}

static void test_confirmed_unversioned_evidence_can_apply(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;

    input.version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    input.version = NULL;
    memset(&view.versym, 0, sizeof(view.versym));
    memset(&view.verneed, 0, sizeof(view.verneed));
    memset(&view.verneednum, 0, sizeof(view.verneednum));
    CHECK("unversioned.status",
          kzt_lazy_direct_route_apply(&input, &ops, &result) ==
              KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED);
    CHECK("unversioned.write",
          f.write_calls == 1 && f.slot == f.bridge_target);
}

static void test_wrong_wrapper_version_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.wrong_bridge_version = 1;
    check_guest_required(
        "wrong-wrapper-version",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result,
        KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_VERSION_MISMATCH,
        &f, original);
    CHECK("wrong-wrapper-version.release",
          f.provider_release_calls == 1 &&
          f.lease_acquire_calls == 0 && f.cas_calls == 0);
}

static void test_source_failure_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.source_valid = 0;
    check_guest_required(
        "source-failure",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_SOURCE_REJECTED,
        &f, original);
    CHECK("source-failure.stops",
          f.source_calls == 1 && f.provider_acquire_calls == 0);
}

static void test_source_generation_mismatch_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    input.source_dynamic_view_generation =
        input.source.generation + 1;
    check_guest_required(
        "source-generation",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_INPUT,
        &f, original);
    CHECK("source-generation.no-source", f.source_calls == 0);
}

static void test_provider_failure_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.provider_available = 0;
    check_guest_required(
        "provider-failure",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE,
        &f, original);
    CHECK("provider-failure.no-release",
          f.provider_acquire_calls == 1 &&
          f.provider_release_calls == 0 && f.bridge_calls == 0);
}

static void test_provider_generation_mismatch_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.provider_generation_delta = 1;
    check_guest_required(
        "provider-generation",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_MISMATCH,
        &f, original);
    CHECK("provider-generation.release",
          f.provider_release_calls == 1 && f.bridge_calls == 0);
}

static void test_incomplete_dynamic_view_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    view.jmprel.present = 0;
    check_guest_required(
        "dynamic-view",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result,
        KZT_LAZY_DIRECT_ROUTE_REASON_INCOMPLETE_DYNAMIC_VIEW,
        &f, original);
    CHECK("dynamic-view.no-source", f.source_calls == 0);
}

static void test_missing_bridge_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.bridge_available = 0;
    check_guest_required(
        "bridge-missing",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_UNAVAILABLE,
        &f, original);
    CHECK("bridge-missing.release",
          f.provider_release_calls == 1 &&
          f.lease_acquire_calls == 0);
}

static void test_lease_failure_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.lease_available = 0;
    check_guest_required(
        "lease-failure",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_LEASE_UNAVAILABLE,
        &f, original);
    CHECK("lease-failure.release",
          f.lease_acquire_calls == 1 &&
          f.lease_release_calls == 0 &&
          f.provider_release_calls == 1);
}

static void test_final_validation_failure_requires_guest(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.final_valid = 0;
    check_guest_required(
        "final-validation",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result,
        KZT_LAZY_DIRECT_ROUTE_REASON_FINAL_VALIDATION_FAILED,
        &f, original);
    CHECK("final-validation.release",
          f.final_validate_calls == 1 && f.cas_calls == 0 &&
          f.lease_release_calls == 1 &&
              f.provider_release_calls == 1);
}

static void test_guest_owned_dlclose_requires_guest_without_callbacks(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    input.symbol = "dlclose";
    check_guest_required(
        "guest-dlclose",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_GUEST_OWNED_SYMBOL,
        &f, original);
    CHECK("guest-dlclose.no-callbacks",
          f.source_calls == 0 &&
          f.provider_acquire_calls == 0 &&
          f.bridge_calls == 0 &&
          f.lease_acquire_calls == 0 &&
          f.final_validate_calls == 0 &&
          f.cas_calls == 0);
}

static void test_cas_mismatch_requires_guest_without_writing(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t competitor = 0x73000300;

    f.slot = competitor;
    f.cas_status = KZT_LAZY_DIRECT_ROUTE_CAS_MISMATCH;
    check_guest_required(
        "cas-mismatch",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_CAS_MISMATCH,
        &f, competitor);
    CHECK("cas-mismatch.one-attempt",
          f.cas_calls == 1 && f.write_calls == 0 &&
          f.lease_release_calls == 1 &&
          f.provider_release_calls == 1);
}

static void test_cas_error_requires_guest_without_writing(void)
{
    fixture_t f = fixture();
    kzt_guest_dynamic_view_t view = complete_dynamic_view();
    kzt_lazy_direct_route_input_t input = input_for(&f, &view);
    kzt_lazy_direct_route_ops_t ops = ops_for(&f);
    kzt_lazy_direct_route_result_t result;
    uintptr_t original = f.slot;

    f.cas_status = KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    check_guest_required(
        "cas-error",
        kzt_lazy_direct_route_apply(&input, &ops, &result),
        &result, KZT_LAZY_DIRECT_ROUTE_REASON_CAS_ERROR,
        &f, original);
    CHECK("cas-error.one-attempt",
          f.cas_calls == 1 && f.write_calls == 0);
}

int main(void)
{
    test_only_strong_global_binding_is_eligible();
    test_complete_evidence_applies_native_once();
    test_managed_bridge_uses_current_value_for_cas();
    test_guest_owned_dlclose_requires_guest_without_callbacks();
    test_disabled_requires_guest_without_callbacks();
    test_unproven_preemption_requires_guest_without_callbacks();
    test_non_main_namespace_requires_guest();
    test_unknown_and_error_version_require_guest();
    test_confirmed_unversioned_evidence_can_apply();
    test_wrong_wrapper_version_requires_guest();
    test_source_failure_requires_guest();
    test_source_generation_mismatch_requires_guest();
    test_provider_failure_requires_guest();
    test_provider_generation_mismatch_requires_guest();
    test_incomplete_dynamic_view_requires_guest();
    test_missing_bridge_requires_guest();
    test_lease_failure_requires_guest();
    test_final_validation_failure_requires_guest();
    test_cas_mismatch_requires_guest_without_writing();
    test_cas_error_requires_guest_without_writing();

    if (failures) {
        fprintf(stderr, "%d WI-837 lazy direct route checks failed\n",
                failures);
        return 1;
    }
    puts("WI-837 lazy direct route checks passed");
    return 0;
}
