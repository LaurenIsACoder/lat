#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_plt_resolver_adapter.h"

typedef struct fixture {
    CPUX86State cpu;
    uint64_t stack[10];
    uintptr_t object_head;
    uintptr_t relocation_slot;
    uintptr_t return_address;
    uintptr_t self_link_map;
    uintptr_t object_guest_resolver;
    int source_present;
    int lookup_calls;
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
    fixture->source_present = 1;
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
        .source_link_map = fixture->self_link_map,
        .guest_resolver = fixture->object_guest_resolver,
    };
    return 0;
}

static kzt_plt_resolver_runtime_ops_t ops_for(fixture_t *fixture)
{
    return (kzt_plt_resolver_runtime_ops_t) {
        .lookup_source = lookup_source,
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
}

static void check_original_frame(const char *prefix, fixture_t *fixture)
{
    uint64_t *sp = (uint64_t *)fixture->cpu.regs[R_ESP];

    CHECK(prefix, sp == &fixture->stack[3]);
    CHECK("original.object-head", sp[0] == fixture->object_head);
    CHECK("original.relocation-slot", sp[1] == fixture->relocation_slot);
    CHECK("original.return-address", sp[2] == fixture->return_address);
}

static void test_handoff_preserves_exact_return_address(void)
{
    fixture_t fixture;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&fixture);
    ops = ops_for(&fixture);
    CHECK("handoff.enter",
          kzt_plt_resolver_enter(&fixture.cpu, &ops, &result) == 0);
    CHECK("handoff.status", result.status == KZT_PLT_RESOLVER_HANDOFF_GUEST);
    CHECK("handoff.object", result.object_head == fixture.object_head);
    CHECK("handoff.slot", result.relocation_slot == fixture.relocation_slot);
    CHECK("handoff.return", result.return_address == fixture.return_address);
    CHECK("handoff.selected",
          result.selected_resolver == fixture.object_guest_resolver);
    CHECK("handoff.lookup-once", fixture.lookup_calls == 1);
    check_guest_frame("handoff.stack-pointer", &fixture);
}

static void test_each_object_uses_its_own_guest_resolver(void)
{
    fixture_t fixture;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&fixture);
    fixture.object_head = 0x21000100;
    fixture.self_link_map = 0x23000300;
    fixture.object_guest_resolver = 0x24000400;
    reset_frame(&fixture);
    ops = ops_for(&fixture);
    CHECK("object.enter",
          kzt_plt_resolver_enter(&fixture.cpu, &ops, &result) == 0);
    CHECK("object.selected",
          result.selected_resolver == fixture.object_guest_resolver);
    check_guest_frame("object.stack-pointer", &fixture);
}

static void test_missing_source_leaves_intercepted_frame_unchanged(void)
{
    fixture_t fixture;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;

    fixture_init(&fixture);
    fixture.source_present = 0;
    ops = ops_for(&fixture);
    CHECK("missing.enter",
          kzt_plt_resolver_enter(&fixture.cpu, &ops, &result) == 0);
    CHECK("missing.status",
          result.status == KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED);
    CHECK("missing.no-selected-resolver", result.selected_resolver == 0);
    check_original_frame("missing.stack-pointer", &fixture);
}

static void test_invalid_arguments_fail_without_touching_the_frame(void)
{
    fixture_t fixture;
    kzt_plt_resolver_runtime_ops_t ops;
    kzt_plt_resolver_enter_result_t result;
    uintptr_t original_sp;

    fixture_init(&fixture);
    ops = ops_for(&fixture);
    original_sp = fixture.cpu.regs[R_ESP];
    CHECK("invalid.no-cpu", kzt_plt_resolver_enter(NULL, &ops, &result) == -1);
    CHECK("invalid.no-ops",
          kzt_plt_resolver_enter(&fixture.cpu, NULL, &result) == -1);
    CHECK("invalid.no-result",
          kzt_plt_resolver_enter(&fixture.cpu, &ops, NULL) == -1);
    CHECK("invalid.stack-unchanged", fixture.cpu.regs[R_ESP] == original_sp);
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
    test_handoff_preserves_exact_return_address();
    test_each_object_uses_its_own_guest_resolver();
    test_missing_source_leaves_intercepted_frame_unchanged();
    test_invalid_arguments_fail_without_touching_the_frame();
    test_resolver_injection_requires_distinct_guest_target();
    test_resolver_entry_bounds_are_checked_before_access();
    if (failures) {
        fprintf(stderr, "%d WI-256 resolver-adapter checks failed\n",
                failures);
        return 1;
    }
    puts("WI-256 PLT resolver adapter tests: PASS");
    return 0;
}
