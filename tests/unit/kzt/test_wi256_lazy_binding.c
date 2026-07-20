#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_lazy_binding.h"

typedef struct fixture {
    uintptr_t slot;
    uintptr_t guest_target;
    uintptr_t native_bridge;
    uintptr_t competing_target;
    int post_bind_valid;
    kzt_lazy_binding_route_status_t route_status;
    int load_calls;
    int validate_calls;
    int route_calls;
} fixture_t;

static int failures;

#define CHECK(name, condition) do {                                      \
    if (!(condition)) {                                                  \
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__);     \
        ++failures;                                                      \
    }                                                                   \
} while (0)

static int load_slot(uintptr_t slot_addr, uintptr_t *value, void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->load_calls;
    *value = *(uintptr_t *)slot_addr;
    return 0;
}

static int validate_post_bind(const kzt_lazy_binding_pending_t *pending,
                              uintptr_t guest_target, void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->validate_calls;
    CHECK("validate.slot", pending->slot_addr == (uintptr_t)&fixture->slot);
    CHECK("validate.guest-target", guest_target == fixture->guest_target);
    return fixture->post_bind_valid;
}

static int route_guest_target(const kzt_lazy_binding_pending_t *pending,
                              uintptr_t guest_target,
                              kzt_lazy_binding_route_result_t *result,
                              void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->route_calls;
    CHECK("route.main-namespace", pending->namespace_id == 0);
    CHECK("route.main-namespace-kind",
          pending->namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN);
    CHECK("route.version-evidence",
          kzt_symbol_version_evidence_valid(pending->version_evidence,
                                            pending->version));
    CHECK("route.guest-target", guest_target == fixture->guest_target);
    result->status = fixture->route_status;
    switch (fixture->route_status) {
    case KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED:
        result->selected_target = fixture->native_bridge;
        result->final_value = fixture->native_bridge;
        fixture->slot = fixture->native_bridge;
        break;
    case KZT_LAZY_BINDING_ROUTE_CAS_MISMATCH:
        result->selected_target = fixture->competing_target;
        result->final_value = fixture->competing_target;
        fixture->slot = fixture->competing_target;
        break;
    case KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED:
    case KZT_LAZY_BINDING_ROUTE_ERROR:
        result->selected_target = guest_target;
        result->final_value = guest_target;
        break;
    }
    return 0;
}

static fixture_t fixture(void)
{
    return (fixture_t) {
        .slot = 0x71000100,
        .guest_target = 0x72000200,
        .native_bridge = 0x73000300,
        .competing_target = 0x74000400,
        .post_bind_valid = 1,
        .route_status = KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED,
    };
}

static kzt_lazy_binding_begin_request_t begin_request_for(fixture_t *fixture)
{
    return (kzt_lazy_binding_begin_request_t) {
        .enabled = 1,
        .context_id = 0x1000,
        .source_link_map = 0x2000,
        .source_generation = 7,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        .relocation_index = 3,
        .slot_addr = (uintptr_t)&fixture->slot,
        .unresolved_stub = fixture->slot,
        .symbol = "realloc",
        .version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .version = "GLIBC_2.2.5",
        .guest_resolver = 0x75000500,
    };
}

static kzt_lazy_binding_ops_t ops_for(fixture_t *fixture)
{
    return (kzt_lazy_binding_ops_t) {
        .load_slot = load_slot,
        .validate_post_bind = validate_post_bind,
        .route_guest_target = route_guest_target,
        .opaque = fixture,
    };
}

static void begin_binding(kzt_lazy_binding_begin_request_t *request,
                          kzt_lazy_binding_pending_t *pending,
                          kzt_lazy_binding_result_t *result)
{
    memset(pending, 0, sizeof(*pending));
    CHECK("begin.call",
          kzt_lazy_binding_begin(request, pending, result) == 0);
}

static void test_first_call_hands_off_to_guest(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&request, &pending, &result);

    CHECK("first.status",
          result.status == KZT_LAZY_BINDING_HANDOFF_GUEST);
    CHECK("first.armed", pending.armed == 1);
    CHECK("first.result-armed", result.pending_armed == 1);
    CHECK("first.guest-resolver",
          result.selected_target == request.guest_resolver);
    CHECK("first.slot-still-stub", f.slot == request.unresolved_stub);
    CHECK("first.no-route", f.route_calls == 0);
}

static void test_post_bind_call_can_install_native_bridge(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&request, &pending, &result);

    /* This write represents the guest dynamic linker completing call one. */
    f.slot = f.guest_target;
    CHECK("complete.call",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("complete.status",
          result.status == KZT_LAZY_BINDING_NATIVE_APPLIED);
    CHECK("complete.before", result.slot_before == f.guest_target);
    CHECK("complete.after", result.slot_after == f.native_bridge);
    CHECK("complete.slot", f.slot == f.native_bridge);
    CHECK("complete.one-route", f.route_calls == 1);
    CHECK("complete.consumed", result.pending_armed == 0);
}

static void test_expected_target_mismatch_preserves_competitor_without_retry(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&request, &pending, &result);

    f.slot = f.guest_target;
    f.route_status = KZT_LAZY_BINDING_ROUTE_CAS_MISMATCH;
    CHECK("race.call",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("race.status", result.status == KZT_LAZY_BINDING_CAS_MISMATCH);
    CHECK("race.preserve", f.slot == f.competing_target);
    CHECK("race.report-final", result.slot_after == f.competing_target);
    CHECK("race.one-route", f.route_calls == 1);
    CHECK("race.consumed", result.pending_armed == 0);
}

static void test_missing_symbol_version_fails_open(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    request.version = NULL;
    begin_binding(&request, &pending, &result);
    f.slot = f.guest_target;
    CHECK("version.complete",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("version.status",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK("version.reason",
          result.reason == KZT_LAZY_BINDING_REASON_MISSING_VERSION);
    CHECK("version.slot", f.slot == f.guest_target);
    CHECK("version.no-route", f.route_calls == 0);
    CHECK("version.consumed", result.pending_armed == 0);
}

static void test_confirmed_unversioned_binding_can_apply(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    request.version_evidence = KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    request.version = NULL;
    begin_binding(&request, &pending, &result);
    CHECK("unversioned.begin",
          result.status == KZT_LAZY_BINDING_HANDOFF_GUEST &&
          pending.version_evidence ==
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED &&
          pending.version == NULL);
    f.slot = f.guest_target;
    CHECK("unversioned.complete",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("unversioned.applied",
          result.status == KZT_LAZY_BINDING_NATIVE_APPLIED &&
          f.route_calls == 1 && f.slot == f.native_bridge);
}

static void test_unknown_and_error_version_evidence_fail_open(void)
{
    kzt_symbol_version_evidence_t evidence[] = {
        KZT_SYMBOL_VERSION_UNKNOWN,
        KZT_SYMBOL_VERSION_ERROR,
    };
    size_t i;

    for (i = 0; i < sizeof(evidence) / sizeof(evidence[0]); ++i) {
        fixture_t f = fixture();
        kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
        kzt_lazy_binding_ops_t ops = ops_for(&f);
        kzt_lazy_binding_result_t result;
        kzt_lazy_binding_pending_t pending;

        request.version_evidence = evidence[i];
        begin_binding(&request, &pending, &result);
        CHECK("untrusted.evidence-propagated",
              pending.version_evidence == evidence[i]);
        f.slot = f.guest_target;
        CHECK("untrusted.complete",
              kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
        CHECK("untrusted.preserved",
              result.status == KZT_LAZY_BINDING_GUEST_PRESERVED &&
              result.reason == KZT_LAZY_BINDING_REASON_MISSING_VERSION &&
              f.route_calls == 0 && f.slot == f.guest_target);
    }
}

static void test_post_bind_validation_failure_keeps_guest_target(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&request, &pending, &result);

    f.slot = f.guest_target;
    f.post_bind_valid = 0;
    CHECK("validation.complete",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("validation.status",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK("validation.reason",
          result.reason == KZT_LAZY_BINDING_REASON_POST_BIND_INVALID);
    CHECK("validation.slot", f.slot == f.guest_target);
    CHECK("validation.one-check", f.validate_calls == 1);
    CHECK("validation.no-route", f.route_calls == 0);
    CHECK("validation.consumed", result.pending_armed == 0);
}

static void test_slot_unchanged_consumes_pending(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_ops_t ops = ops_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&request, &pending, &result);

    CHECK("unchanged.complete",
          kzt_lazy_binding_complete(&pending, &ops, &result) == 0);
    CHECK("unchanged.status",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK("unchanged.reason",
          result.reason == KZT_LAZY_BINDING_REASON_SLOT_UNCHANGED);
    CHECK("unchanged.no-route", f.route_calls == 0);
    CHECK("unchanged.consumed", pending.armed == 0 &&
          result.pending_cleared == 1);
}

static void test_overlong_symbol_and_version_fail_open(void)
{
    char overlong[KZT_LAZY_BINDING_SYMBOL_MAX + 1];
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    memset(overlong, 'x', sizeof(overlong) - 1);
    overlong[sizeof(overlong) - 1] = '\0';
    memset(&pending, 0, sizeof(pending));
    request.symbol = overlong;
    CHECK("long-symbol.begin",
          kzt_lazy_binding_begin(&request, &pending, &result) == 0);
    CHECK("long-symbol.preserved",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED &&
          result.reason == KZT_LAZY_BINDING_REASON_INVALID_REQUEST &&
          pending.armed == 0);

    memset(&pending, 0, sizeof(pending));
    request = begin_request_for(&f);
    request.version = overlong;
    CHECK("long-version.begin",
          kzt_lazy_binding_begin(&request, &pending, &result) == 0);
    CHECK("long-version.preserved",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED &&
          result.reason == KZT_LAZY_BINDING_REASON_INVALID_REQUEST &&
          pending.armed == 0);
}

static void test_nested_pending_busy_preserves_outer_state(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t outer = begin_request_for(&f);
    kzt_lazy_binding_begin_request_t nested = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;
    kzt_lazy_binding_pending_t saved;

    begin_binding(&outer, &pending, &result);
    saved = pending;
    saved.symbol = pending.symbol ? saved.symbol_storage : NULL;
    saved.version = pending.version ? saved.version_storage : NULL;

    nested.relocation_index = outer.relocation_index + 1;
    nested.slot_addr += sizeof(uintptr_t);
    CHECK("nested.begin",
          kzt_lazy_binding_begin(&nested, &pending, &result) == 0);
    CHECK("nested.busy",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED &&
          result.reason == KZT_LAZY_BINDING_REASON_PENDING_BUSY);
    CHECK("nested.outer-armed", pending.armed == 1);
    CHECK("nested.outer-identity",
          pending.context_id == saved.context_id &&
          pending.source_link_map == saved.source_link_map &&
          pending.source_generation == saved.source_generation &&
          pending.relocation_index == saved.relocation_index &&
          pending.slot_addr == saved.slot_addr &&
          !strcmp(pending.symbol, saved.symbol) &&
          !strcmp(pending.version, saved.version));
}

static void test_new_context_replaces_abandoned_pending(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t abandoned = begin_request_for(&f);
    kzt_lazy_binding_begin_request_t next = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&abandoned, &pending, &result);

    next.context_id = abandoned.context_id + 1;
    next.source_link_map = abandoned.source_link_map + 0x1000;
    next.source_generation = abandoned.source_generation + 1;
    next.relocation_index = abandoned.relocation_index + 1;
    next.slot_addr += sizeof(uintptr_t);
    next.symbol = "next_context_symbol";

    CHECK("new-context.begin",
          kzt_lazy_binding_begin(&next, &pending, &result) == 0);
    CHECK("new-context.handoff",
          result.status == KZT_LAZY_BINDING_HANDOFF_GUEST &&
          result.reason == KZT_LAZY_BINDING_REASON_NONE &&
          result.pending_armed == 1);
    CHECK("new-context.replaced",
          pending.armed == 1 &&
          pending.context_id == next.context_id &&
          pending.source_link_map == next.source_link_map &&
          pending.source_generation == next.source_generation &&
          pending.relocation_index == next.relocation_index &&
          pending.slot_addr == next.slot_addr &&
          !strcmp(pending.symbol, next.symbol));
}

static void test_cancelled_pending_allows_same_context_retry(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t first = begin_request_for(&f);
    kzt_lazy_binding_begin_request_t retry = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    begin_binding(&first, &pending, &result);

    kzt_lazy_binding_cancel(&pending);
    CHECK("cancel.cleared", pending.armed == 0 &&
          pending.context_id == 0 && pending.source_link_map == 0 &&
          pending.slot_addr == 0 && pending.symbol == NULL &&
          pending.version == NULL);

    retry.relocation_index = first.relocation_index + 1;
    retry.slot_addr += sizeof(uintptr_t);
    retry.symbol = "retry_symbol";
    CHECK("cancel.retry",
          kzt_lazy_binding_begin(&retry, &pending, &result) == 0);
    CHECK("cancel.retry-armed",
          result.status == KZT_LAZY_BINDING_HANDOFF_GUEST &&
          result.pending_armed == 1 && pending.armed == 1 &&
          pending.context_id == retry.context_id &&
          pending.relocation_index == retry.relocation_index &&
          pending.slot_addr == retry.slot_addr &&
          !strcmp(pending.symbol, retry.symbol));
}

static void test_only_main_namespace_is_armed(void)
{
    fixture_t f = fixture();
    kzt_lazy_binding_begin_request_t request = begin_request_for(&f);
    kzt_lazy_binding_result_t result;
    kzt_lazy_binding_pending_t pending;

    request.namespace_id = 1;
    request.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
    begin_binding(&request, &pending, &result);
    CHECK("namespace.status",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK("namespace.reason",
          result.reason == KZT_LAZY_BINDING_REASON_NON_MAIN_NAMESPACE);
    CHECK("namespace.not-armed", pending.armed == 0);
    CHECK("namespace.guest-resolver",
          result.selected_target == request.guest_resolver);
    CHECK("namespace.slot", f.slot == request.unresolved_stub);

    request.namespace_id = 0;
    request.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN;
    begin_binding(&request, &pending, &result);
    CHECK("main.status",
          result.status == KZT_LAZY_BINDING_HANDOFF_GUEST);
    CHECK("main.armed", pending.armed == 1);
}

int main(void)
{
    test_first_call_hands_off_to_guest();
    test_post_bind_call_can_install_native_bridge();
    test_expected_target_mismatch_preserves_competitor_without_retry();
    test_missing_symbol_version_fails_open();
    test_confirmed_unversioned_binding_can_apply();
    test_unknown_and_error_version_evidence_fail_open();
    test_post_bind_validation_failure_keeps_guest_target();
    test_only_main_namespace_is_armed();
    test_slot_unchanged_consumes_pending();
    test_overlong_symbol_and_version_fail_open();
    test_nested_pending_busy_preserves_outer_state();
    test_new_context_replaces_abandoned_pending();
    test_cancelled_pending_allows_same_context_retry();
    if (failures) {
        fprintf(stderr, "%d WI-256 lazy-binding checks failed\n", failures);
        return 1;
    }
    puts("KZT WI-256 lazy binding: PASS");
    return 0;
}
