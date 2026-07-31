#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_plt_resolver_adapter.h"

typedef enum begin_outcome {
    BEGIN_ARMED = 0,
    BEGIN_PENDING_OCCUPIED,
    BEGIN_GENERATION_CHANGED,
    BEGIN_NON_MAIN_NAMESPACE,
    BEGIN_CALLBACK_FAILED,
} begin_outcome_t;

typedef struct fixture {
    CPUX86State cpu;
    uint64_t stack[10];
    uintptr_t object_head;
    uintptr_t relocation_slot;
    uintptr_t return_address;
    uintptr_t self_link_map;
    uintptr_t object_guest_resolver;
    uintptr_t forbidden_global_resolver;
    unsigned long generation;
    uintptr_t namespace_id;
    kzt_guest_library_namespace_kind_t namespace_kind;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    int source_enabled;
    int source_present;
    begin_outcome_t begin_outcome;
    int lookup_calls;
    int begin_calls;
    int pending_creations;
    uintptr_t completion_bridge;
    uintptr_t original_return;
    kzt_lazy_binding_pending_t pending;
    kzt_lazy_binding_begin_request_t captured_request;
} fixture_t;

static int failures;

#define CHECK(name, condition) do {                                      \
    if (!(condition)) {                                                  \
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__);     \
        ++failures;                                                      \
    }                                                                   \
} while (0)

static void reset_frame(fixture_t *fixture)
{
    memset(fixture->stack, 0, sizeof(fixture->stack));
    fixture->stack[3] = fixture->object_head;
    fixture->stack[4] = fixture->relocation_slot;
    fixture->stack[5] = fixture->return_address;
    fixture->cpu.regs[R_ESP] = (uintptr_t)&fixture->stack[3];
}

static void fixture_init(fixture_t *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->object_head = 0x11000100;
    fixture->relocation_slot = 5;
    fixture->return_address = 0x12000200;
    fixture->self_link_map = 0x13000300;
    fixture->object_guest_resolver = 0x14000400;
    fixture->forbidden_global_resolver = 0x15000500;
    fixture->generation = 7;
    fixture->namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN;
    fixture->version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    fixture->version = "GLIBC_2.2.5";
    fixture->source_enabled = 1;
    fixture->source_present = 1;
    fixture->begin_outcome = BEGIN_ARMED;
    reset_frame(fixture);
}

static int lookup_source(uintptr_t object_head,
                         kzt_plt_resolver_source_t *source, void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->lookup_calls;
    CHECK("lookup.object-head", object_head == fixture->object_head);
    if (!fixture->source_present) {
        return -1;
    }
    *source = (kzt_plt_resolver_source_t) {
        .enabled = fixture->source_enabled,
        .context_id = 0x16000600,
        .object_head = fixture->object_head,
        .source_link_map = fixture->self_link_map,
        .source_generation = fixture->generation,
        .namespace_id = fixture->namespace_id,
        .namespace_kind = fixture->namespace_kind,
        .version_evidence = fixture->version_evidence,
        .version = fixture->version,
        .guest_resolver = fixture->object_guest_resolver,
    };
    return 0;
}

/* Contract 1 is mocked as a boundary.  No owner/provider/native decision is
 * reproduced in this adapter test. */
static int begin_lazy_binding(
    const kzt_lazy_binding_begin_request_t *request,
    kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result, void *opaque)
{
    fixture_t *fixture = opaque;

    ++fixture->begin_calls;
    fixture->captured_request = *request;
    memset(result, 0, sizeof(*result));
    result->selected_target = fixture->object_guest_resolver;
    if (!request->enabled) {
        result->status = KZT_LAZY_BINDING_BYPASS;
        result->reason = KZT_LAZY_BINDING_REASON_DISABLED;
        return 0;
    }
    switch (fixture->begin_outcome) {
    case BEGIN_ARMED:
        if (!pending->armed) {
            pending->armed = 1;
            ++fixture->pending_creations;
        }
        result->status = KZT_LAZY_BINDING_HANDOFF_GUEST;
        result->pending_armed = 1;
        break;
    case BEGIN_PENDING_OCCUPIED:
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_PENDING_OCCUPIED;
        result->pending_armed = 0;
        break;
    case BEGIN_GENERATION_CHANGED:
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_GENERATION_CHANGED;
        result->pending_armed = 0;
        break;
    case BEGIN_NON_MAIN_NAMESPACE:
        result->status = KZT_LAZY_BINDING_GUEST_PRESERVED;
        result->reason = KZT_LAZY_BINDING_REASON_NON_MAIN_NAMESPACE;
        result->pending_armed = 0;
        break;
    case BEGIN_CALLBACK_FAILED:
        return -1;
    }
    return 0;
}

static kzt_plt_resolver_runtime_ops_t ops_for(fixture_t *fixture)
{
    return (kzt_plt_resolver_runtime_ops_t) {
        .lookup_source = lookup_source,
        .begin_lazy_binding = begin_lazy_binding,
        .pending = &fixture->pending,
        .completion_bridge = fixture->completion_bridge,
        .original_return = &fixture->original_return,
        .opaque = fixture,
    };
}

static void check_guest_frame(const char *prefix, fixture_t *fixture)
{
    uint64_t *sp = (uint64_t *)fixture->cpu.regs[R_ESP];

    CHECK(prefix, sp == &fixture->stack[2]);
    CHECK("frame.object-resolver", sp[0] == fixture->object_guest_resolver);
    CHECK("frame.self-link-map", sp[1] == fixture->self_link_map);
    CHECK("frame.relocation-slot", sp[2] == fixture->relocation_slot);
    CHECK("frame.return-address", sp[3] == fixture->return_address);
    CHECK("frame.no-global-resolver",
          sp[0] != fixture->forbidden_global_resolver);
}

static void check_original_frame(const char *prefix, fixture_t *fixture)
{
    uint64_t *sp = (uint64_t *)fixture->cpu.regs[R_ESP];

    CHECK(prefix, sp == &fixture->stack[3]);
    CHECK("original.object-head", sp[0] == fixture->object_head);
    CHECK("original.relocation-slot", sp[1] == fixture->relocation_slot);
    CHECK("original.return-address", sp[2] == fixture->return_address);
}

static void test_reads_real_frame_and_preserves_return_address(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&f);
    ops = ops_for(&f);
    CHECK("frame.enter", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("frame.status",
          result.status == KZT_PLT_RESOLVER_HANDOFF_GUEST);
    CHECK("frame.object", result.object_head == f.object_head);
    CHECK("frame.slot", result.relocation_slot == f.relocation_slot);
    CHECK("frame.return", result.return_address == f.return_address);
    CHECK("frame.lookup-once", f.lookup_calls == 1);
    CHECK("frame.begin-once", f.begin_calls == 1);
    check_guest_frame("frame.stack-pointer", &f);
}

static void test_handoff_without_completion_bridge_keeps_return_slot(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;
    uint64_t *sp;

    fixture_init(&f);
    f.original_return = 0xfeedface;
    ops = ops_for(&f);
    CHECK("no-bridge.enter",
          kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("no-bridge.handoff",
          result.status == KZT_PLT_RESOLVER_HANDOFF_GUEST);
    sp = (uint64_t *)f.cpu.regs[R_ESP];
    CHECK("no-bridge.final-rsp", sp == &f.stack[2]);
    CHECK("no-bridge.resolver", sp[0] == f.object_guest_resolver);
    CHECK("no-bridge.link-map", sp[1] == f.self_link_map);
    CHECK("no-bridge.slot", sp[2] == f.relocation_slot);
    CHECK("no-bridge.return", sp[3] == f.return_address);
    CHECK("no-bridge.original-return-unchanged",
          f.original_return == 0xfeedface);
}

static void test_handoff_with_completion_bridge_preserves_original_return(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;
    uint64_t *sp;

    fixture_init(&f);
    f.completion_bridge = 0x17000700;
    ops = ops_for(&f);
    CHECK("bridge.enter",
          kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("bridge.handoff", result.status == KZT_PLT_RESOLVER_HANDOFF_GUEST);
    sp = (uint64_t *)f.cpu.regs[R_ESP];
    CHECK("bridge.final-rsp", sp == &f.stack[2]);
    CHECK("bridge.resolver", sp[0] == f.object_guest_resolver);
    CHECK("bridge.link-map", sp[1] == f.self_link_map);
    CHECK("bridge.slot", sp[2] == f.relocation_slot);
    CHECK("bridge.return", sp[3] == f.completion_bridge);
    CHECK("bridge.original-return", f.original_return == f.return_address);
}

static void test_uses_per_object_resolver_and_calls_only_contract_one(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&f);
    ops = ops_for(&f);
    CHECK("object.enter", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("object.selected",
          result.selected_resolver == f.object_guest_resolver);
    CHECK("object.not-global",
          result.selected_resolver != f.forbidden_global_resolver);
    CHECK("object.contract-one-once", f.begin_calls == 1);
    CHECK("object.request-link-map",
          f.captured_request.source_link_map == f.self_link_map);
    CHECK("object.request-generation",
          f.captured_request.source_generation == f.generation);
    CHECK("object.request-namespace",
          f.captured_request.namespace_id == f.namespace_id &&
          f.captured_request.namespace_kind == f.namespace_kind);
    CHECK("object.request-relocation",
          f.captured_request.relocation_index == f.relocation_slot);
}

static void test_forwards_explicit_version_evidence(void)
{
    static const struct {
        kzt_symbol_version_evidence_t evidence;
        const char *version;
    } cases[] = {
        { KZT_SYMBOL_VERSION_VERSIONED, "GLIBC_2.2.5" },
        { KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL },
        { KZT_SYMBOL_VERSION_ERROR, NULL },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fixture_t f;
        kzt_plt_resolver_runtime_ops_t ops;
        kzt_plt_resolver_enter_result_t result;

        fixture_init(&f);
        f.version_evidence = cases[i].evidence;
        f.version = cases[i].version;
        ops = ops_for(&f);
        CHECK("version.enter",
              kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
        CHECK("version.evidence",
              f.captured_request.version_evidence == cases[i].evidence);
        CHECK("version.value",
              f.captured_request.version == cases[i].version);
    }
}

static void test_main_generation_match_creates_one_pending(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&f);
    ops = ops_for(&f);
    CHECK("pending.first", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("pending.first-armed", result.pending_armed == 1);
    CHECK("pending.created-once", f.pending_creations == 1);

    reset_frame(&f);
    f.begin_outcome = BEGIN_PENDING_OCCUPIED;
    CHECK("pending.second", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("pending.second-fail-open",
          result.status == KZT_PLT_RESOLVER_GUEST_PRESERVED);
    CHECK("pending.still-created-once", f.pending_creations == 1);
    CHECK("pending.contract-called-per-entry", f.begin_calls == 2);
    check_guest_frame("pending.second-stack", &f);
}

static void test_nested_pending_busy_preserves_outer_cpu_pending(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;
    kzt_lazy_binding_pending_t saved;

    fixture_init(&f);
    f.pending = (kzt_lazy_binding_pending_t) {
        .armed = 1,
        .context_id = 0x9000,
        .source_link_map = 0x9100,
        .source_generation = 11,
        .relocation_index = 4,
        .slot_addr = 0x9200,
        .guest_resolver = 0x9300,
    };
    saved = f.pending;
    f.begin_outcome = BEGIN_PENDING_OCCUPIED;
    ops = ops_for(&f);
    CHECK("nested.enter", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("nested.preserved", !memcmp(&f.pending, &saved, sizeof(saved)));
    CHECK("nested.status",
          result.status == KZT_PLT_RESOLVER_GUEST_PRESERVED);
    check_guest_frame("nested.stack-pointer", &f);
}

static void test_missing_object_restores_original_frame(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&f);
    ops = ops_for(&f);
    f.source_present = 0;
    CHECK("missing.enter", kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("missing.status",
          result.status == KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED);
    CHECK("missing.no-contract-one", f.begin_calls == 0);
    CHECK("missing.no-pending", f.pending_creations == 0);
    check_original_frame("missing.stack-pointer", &f);
}

static void test_second_object_lookup_failure_never_uses_first_resolver(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&f);
    f.object_head = 0x21000100;
    f.self_link_map = 0x23000300;
    f.object_guest_resolver = 0x24000400;
    f.forbidden_global_resolver = 0x14000400;
    f.source_present = 0;
    reset_frame(&f);
    ops = ops_for(&f);
    CHECK("second-missing.enter",
          kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("second-missing.legacy-frame",
          result.status == KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED);
    CHECK("second-missing.no-selected-resolver",
          result.selected_resolver == 0);
    CHECK("second-missing.not-first-resolver",
          result.selected_resolver != f.forbidden_global_resolver);
    CHECK("second-missing.no-begin", f.begin_calls == 0);
    check_original_frame("second-missing.stack-pointer", &f);
}

static void test_disabled_object_hands_off_once_to_its_guest_resolver(void)
{
    fixture_t f;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;
    uintptr_t original_sp;

    fixture_init(&f);
    f.source_enabled = 0;
    f.generation = 0;
    f.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_UNSUPPORTED;
    original_sp = f.cpu.regs[R_ESP];
    ops = ops_for(&f);
    CHECK("disabled-fallback.enter",
          kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
    CHECK("disabled-fallback.status",
          result.status == KZT_PLT_RESOLVER_GUEST_PRESERVED);
    CHECK("disabled-fallback.resolver",
          result.selected_resolver == f.object_guest_resolver);
    CHECK("disabled-fallback.lookup-once", f.lookup_calls == 1);
    CHECK("disabled-fallback.begin-once", f.begin_calls == 1);
    CHECK("disabled-fallback.no-pending", f.pending_creations == 0);
    CHECK("disabled-fallback.one-resolver-push",
          f.cpu.regs[R_ESP] + sizeof(uint64_t) == original_sp);
    check_guest_frame("disabled-fallback.stack-pointer", &f);
}

static void test_contract_one_rejections_restore_guest_frame(void)
{
    const begin_outcome_t outcomes[] = {
        BEGIN_PENDING_OCCUPIED,
        BEGIN_GENERATION_CHANGED,
        BEGIN_NON_MAIN_NAMESPACE,
        BEGIN_CALLBACK_FAILED,
    };

    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        fixture_t f;
        kzt_plt_resolver_runtime_ops_t ops;
        kzt_plt_resolver_enter_result_t result;

        fixture_init(&f);
        ops = ops_for(&f);
        f.begin_outcome = outcomes[i];
        if (outcomes[i] == BEGIN_NON_MAIN_NAMESPACE) {
            f.namespace_id = 1;
            f.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
        }
        CHECK("reject.enter",
              kzt_plt_resolver_enter(&f.cpu, &ops, &result) == 0);
        CHECK("reject.status",
              result.status == KZT_PLT_RESOLVER_GUEST_PRESERVED);
        CHECK("reject.contract-one-once", f.begin_calls == 1);
        CHECK("reject.no-pending", f.pending_creations == 0);
        check_guest_frame("reject.stack-pointer", &f);
    }
}

static void test_resolver_injection_requires_distinct_guest_target(void)
{
    CHECK("inject.valid",
          kzt_plt_resolver_injection_allowed(0x1000, 0x2000));
    CHECK("inject.no-guest",
          !kzt_plt_resolver_injection_allowed(0, 0x2000));
    CHECK("inject.no-bridge",
          !kzt_plt_resolver_injection_allowed(0x1000, 0));
    CHECK("inject.no-recursion",
          !kzt_plt_resolver_injection_allowed(0x2000, 0x2000));
}

static void test_resolver_entry_bounds_are_checked_before_access(void)
{
    const uintptr_t rela_table = 0x1000;
    const uintptr_t symbol_table = 0x2000;
    const size_t rela_size = 4 * 24;

    CHECK("bounds.rela-first",
          kzt_plt_resolver_relocation_index_valid(
              0, rela_table, rela_size, 24));
    CHECK("bounds.rela-last",
          kzt_plt_resolver_relocation_index_valid(
              3, rela_table, rela_size, 24));
    CHECK("bounds.rela-past-end",
          !kzt_plt_resolver_relocation_index_valid(
              4, rela_table, rela_size, 24));
    CHECK("bounds.rela-int-overflow",
          !kzt_plt_resolver_relocation_index_valid(
              UINT64_MAX, rela_table, rela_size, 24));
    CHECK("bounds.rela-missing-table",
          !kzt_plt_resolver_relocation_index_valid(
              0, 0, rela_size, 24));
    CHECK("bounds.rela-zero-entry",
          !kzt_plt_resolver_relocation_index_valid(
              0, rela_table, rela_size, 0));
    CHECK("bounds.rela-truncated-table",
          !kzt_plt_resolver_relocation_index_valid(
              0, rela_table, rela_size - 1, 24));
    CHECK("bounds.symbol-first",
          kzt_plt_resolver_symbol_index_valid(0, symbol_table, 3));
    CHECK("bounds.symbol-last",
          kzt_plt_resolver_symbol_index_valid(2, symbol_table, 3));
    CHECK("bounds.symbol-past-end",
          !kzt_plt_resolver_symbol_index_valid(3, symbol_table, 3));
    CHECK("bounds.symbol-missing-table",
          !kzt_plt_resolver_symbol_index_valid(0, 0, 3));
    CHECK("bounds.symbol-empty",
          !kzt_plt_resolver_symbol_index_valid(0, symbol_table, 0));
}

int main(void)
{
    test_reads_real_frame_and_preserves_return_address();
    test_handoff_without_completion_bridge_keeps_return_slot();
    test_handoff_with_completion_bridge_preserves_original_return();
    test_uses_per_object_resolver_and_calls_only_contract_one();
    test_forwards_explicit_version_evidence();
    test_main_generation_match_creates_one_pending();
    test_nested_pending_busy_preserves_outer_cpu_pending();
    test_missing_object_restores_original_frame();
    test_second_object_lookup_failure_never_uses_first_resolver();
    test_disabled_object_hands_off_once_to_its_guest_resolver();
    test_contract_one_rejections_restore_guest_frame();
    test_resolver_injection_requires_distinct_guest_target();
    test_resolver_entry_bounds_are_checked_before_access();
    if (failures) {
        fprintf(stderr, "%d WI-256 resolver-adapter checks failed\n",
                failures);
        return 1;
    }
    puts("KZT WI-256 PLT resolver adapter: PASS");
    return 0;
}
