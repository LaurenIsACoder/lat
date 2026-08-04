#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_rela_request_enricher.h"
#include "target/i386/latx/include/kzt_rela_stub_detector.h"

static int failures;

typedef struct fake_bridge_state {
    uintptr_t next_bridge_target;
    int check_calls;
    int add_calls;
} fake_bridge_state_t;

typedef struct fake_slot_entry {
    uintptr_t *slot;
    int read_calls;
    int writer_write_calls;
    int legacy_write_calls;
} fake_slot_entry_t;

typedef struct fake_slot_bank {
    uintptr_t canary_before;
    uintptr_t values[2];
    uintptr_t canary_after;
    fake_slot_entry_t entries[2];
    int invalid_accesses;
} fake_slot_bank_t;

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

static uintptr_t fake_check_bridge(uintptr_t native_symbol, void *opaque)
{
    fake_bridge_state_t *state = opaque;

    (void)native_symbol;
    ++state->check_calls;
    return 0;
}

static uintptr_t fake_add_bridge(
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque)
{
    fake_bridge_state_t *state = opaque;

    if (!request || !request->native_symbol) {
        return 0;
    }

    ++state->add_calls;
    return state->next_bridge_target;
}

static kzt_wrapper_probe_bridge_ops_t bridge_ops(fake_bridge_state_t *state)
{
    return (kzt_wrapper_probe_bridge_ops_t) {
        .check_bridge = fake_check_bridge,
        .add_bridge = fake_add_bridge,
        .opaque = state,
    };
}

static fake_slot_entry_t *fake_slot_find(fake_slot_bank_t *bank,
                                         uintptr_t slot_addr)
{
    size_t i;

    if (!bank) {
        return NULL;
    }
    for (i = 0; i < sizeof(bank->entries) / sizeof(bank->entries[0]); ++i) {
        if ((uintptr_t)bank->entries[i].slot == slot_addr) {
            return &bank->entries[i];
        }
    }

    ++bank->invalid_accesses;
    return NULL;
}

static int fake_slot_read(uintptr_t slot_addr, uintptr_t *value, void *opaque)
{
    fake_slot_entry_t *slot = fake_slot_find(opaque, slot_addr);

    if (!slot || !value) {
        return -1;
    }

    ++slot->read_calls;
    *value = *slot->slot;
    return 0;
}

static int fake_slot_write(uintptr_t slot_addr, uintptr_t value, void *opaque)
{
    fake_slot_entry_t *slot = fake_slot_find(opaque, slot_addr);

    if (!slot) {
        return -1;
    }

    ++slot->writer_write_calls;
    *slot->slot = value;
    return 0;
}

static kzt_patch_spike_slot_ops_t fake_slot_ops(fake_slot_bank_t *bank)
{
    return (kzt_patch_spike_slot_ops_t) {
        .read_slot = fake_slot_read,
        .write_slot = fake_slot_write,
        .opaque = bank,
    };
}

static kzt_patch_spike_guard_t enabled_guard(void)
{
    kzt_patch_spike_config_t config = {
        .enabled = 1,
        .write_enabled = 1,
        .budget = 4,
    };
    kzt_patch_spike_guard_t guard;

    kzt_patch_spike_guard_init(&guard, &config);
    return guard;
}

static void fake_legacy_write(fake_slot_bank_t *bank, uintptr_t slot_addr,
                              uintptr_t legacy_target)
{
    fake_slot_entry_t *slot = fake_slot_find(bank, slot_addr);

    if (!slot) {
        return;
    }

    ++slot->legacy_write_calls;
    *(uintptr_t *)slot_addr = legacy_target;
}

static void fake_slot_bank_init(fake_slot_bank_t *bank,
                                uintptr_t canary_before,
                                uintptr_t selected_value,
                                uintptr_t other_value,
                                uintptr_t canary_after)
{
    memset(bank, 0, sizeof(*bank));
    bank->canary_before = canary_before;
    bank->values[0] = selected_value;
    bank->values[1] = other_value;
    bank->canary_after = canary_after;
    bank->entries[0].slot = &bank->values[0];
    bank->entries[1].slot = &bank->values[1];
}

static kzt_guest_object_observation_t observation(
    uintptr_t link_map_addr, uintptr_t map_start, uintptr_t map_end,
    const char *soname)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x2000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { soname, KZT_GUEST_FIELD_OK },
        .soname = { soname, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_dynamic_view_t dynamic_view(uintptr_t dynamic_addr,
                                             uintptr_t load_bias)
{
    return (kzt_guest_dynamic_view_t) {
        .dynamic_addr = dynamic_addr,
        .load_bias = load_bias,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 1,
        .has_null = 1,
    };
}

static kzt_guest_registry_t *registry_with_source_and_owner(
    int commit_dynamic, int include_owner)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t source = observation(
        0x1000, 0x70000000, 0x70010000, "librequester.so");
    kzt_guest_object_observation_t owner = observation(
        0x2000, 0x71000000, 0x71010000, "libgtk-3.so");
    kzt_guest_dynamic_view_t view = dynamic_view(0x70002000, 0x70000000);

    check_int("registry.observe.source",
              kzt_guest_registry_observe(registry, &source),
              KZT_GUEST_REGISTRY_ADDED);
    if (include_owner) {
        check_int("registry.observe.owner",
                  kzt_guest_registry_observe(registry, &owner),
                  KZT_GUEST_REGISTRY_ADDED);
    }
    if (commit_dynamic) {
        check_int("registry.dynamic",
                  kzt_guest_registry_commit_dynamic_view(
                      registry, source.link_map_addr, 1, &view),
                  KZT_GUEST_REGISTRY_UPDATED);
    }

    return registry;
}

static const kzt_wrapper_probe_entry_t wrapper_entries[] = {
    {
        .symbol_name = "gtk_widget_show",
        .symbol_version = "GTK_3.0",
        .wrapper_name = "wrappedgtk3",
        .wrapper_symbol_version = "GTK_3.0",
        .native_symbol = 0x60000000,
    },
};

static kzt_wrapper_probe_manifest_t wrapper_manifest(void)
{
    return (kzt_wrapper_probe_manifest_t) {
        .available = 1,
        .manifest_name = "wrappedgtk3",
        .entries = wrapper_entries,
        .entry_count = sizeof(wrapper_entries) / sizeof(wrapper_entries[0]),
    };
}

static kzt_rela_immediate_candidate_request_t base_request(void)
{
    return (kzt_rela_immediate_candidate_request_t) {
        .relocation_type = R_X86_64_JUMP_SLOT,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 7,
        .entry_addr = 0x70003000,
        .source = {
            .known = 1,
            .map_start = 0x70000000,
            .map_end = 0x70010000,
            .soname = "fallback-requester",
            .path = "/fallback/requester",
        },
        .dynamic_addr = 0x70002000,
        .load_bias = 0x70000000,
        .slot_addr = 0x70004000,
        .slot_current_value_present = 1,
        .slot_current_value = 0x71000010,
        .expected_guest_target = 0x71000020,
        .native_bridge_target = 0x7fffffff,
        .legacy_target = 0x71000020,
        .symbol_index = 9,
        .symbol_name = "gtk_widget_show",
        .version = "GTK_3.0",
    };
}

static void enrich_and_plan(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *enrich_result,
    kzt_rela_immediate_candidate_result_t *plan_result)
{
    check_int("enrich.call",
              kzt_rela_immediate_request_enrich(
                  request, input, enrich_result), 0);
    check_int("plan.call",
              kzt_rela_immediate_jump_slot_plan(request, plan_result), 0);
}

static void test_all_evidence_allows_approved_plan(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("approved.dynamic", request.dynamic_view_available, 1);
    check_ulong("approved.source.link_map", request.source.link_map_addr,
                0x1000);
    check_ulong("approved.source.generation", request.source.generation, 1);
    check_int("approved.owner", request.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_int("approved.wrapper", request.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("approved.bridge", request.native_bridge_target,
                0x72000000);
    check_int("approved.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_int("approved.reason", plan_result.decision.reason,
              KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);
    check_int("approved.add_bridge", bridge.add_calls, 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_source_and_owner_enrichment_do_not_need_snapshot_allocation(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_rela_request_enricher_input_t input = { .registry = registry };
    kzt_rela_request_enricher_result_t result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    kzt_guest_registry_test_set_alloc_failure_after(0);
    check_int("compact-enrich.call",
              kzt_rela_immediate_request_enrich(&request, &input, &result),
              0);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_ulong("compact-enrich.source", request.source.link_map_addr,
                0x1000);
    check_ulong("compact-enrich.source-generation", request.source.generation,
                1);
    check_int("compact-enrich.owner", request.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_ulong("compact-enrich.owner-link-map",
                request.current_owner.link_map_addr, 0x2000);
    kzt_guest_registry_destroy(&registry);
}

static void test_wrapper_only_preserves_validated_base_evidence(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t full_input = { .registry = registry };
    kzt_rela_request_wrapper_only_input_t wrapper_input = {
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t result;
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_request_t before;

    kzt_rela_request_enricher_result_init(&result);
    check_int("wrapper_only.base", kzt_rela_immediate_request_enrich(
                  &request, &full_input, &result), 0);
    before = request;
    check_int("wrapper_only.call",
              kzt_rela_immediate_request_enrich_wrapper_only(
                  &request, &wrapper_input, &result), 0);
    check_ulong("wrapper_only.source.link_map", request.source.link_map_addr,
                before.source.link_map_addr);
    check_ulong("wrapper_only.source.generation", request.source.generation,
                before.source.generation);
    check_ulong("wrapper_only.dynamic.addr", request.dynamic_addr,
                before.dynamic_addr);
    check_ulong("wrapper_only.dynamic.bias", request.load_bias,
                before.load_bias);
    check_int("wrapper_only.dynamic.available", request.dynamic_view_available,
              before.dynamic_view_available);
    check_ulong("wrapper_only.dynamic.generation",
                request.dynamic_view_generation,
                before.dynamic_view_generation);
    check_ulong("wrapper_only.owner.link_map",
                request.current_owner.link_map_addr,
                before.current_owner.link_map_addr);
    check_ulong("wrapper_only.owner.generation",
                request.current_owner.generation,
                before.current_owner.generation);
    check_int("wrapper_only.owner.match", request.owner_match,
              before.owner_match);
    check_ulong("wrapper_only.slot.addr", request.slot_addr,
                before.slot_addr);
    check_ulong("wrapper_only.slot.value", request.slot_current_value,
                before.slot_current_value);
    check_ulong("wrapper_only.symbol.index", request.symbol_index,
                before.symbol_index);
    check_int("wrapper_only.symbol.name",
              strcmp(request.symbol_name, before.symbol_name), 0);
    check_int("wrapper_only.version.evidence", request.version_evidence,
              before.version_evidence);
    check_int("wrapper_only.version", strcmp(request.version, before.version),
              0);
    check_ulong("wrapper_only.bridge", request.native_bridge_target,
                bridge.next_bridge_target);
    check_int("wrapper_only.add", bridge.add_calls, 1);
    kzt_guest_registry_destroy(&registry);
}

static void test_wrapper_only_needs_validated_base_evidence(void)
{
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_wrapper_only_input_t input = {
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    kzt_rela_request_enricher_result_init(&result);
    request.dynamic_view_available = 0;
    request.owner_match = KZT_PATCH_OWNER_MATCH;
    request.current_owner.known = 1;
    request.current_owner.link_map_addr = 0x2000;
    request.current_owner.generation = 1;
    check_int("wrapper_only.missing-base",
              kzt_rela_immediate_request_enrich_wrapper_only(
                  &request, &input, &result), 0);
    check_ulong("wrapper_only.missing-base.no-bridge",
                request.native_bridge_target, 0);
    check_int("wrapper_only.missing-base.no-add", bridge.add_calls, 0);
}

static void test_unresolved_stub_detector_coordinates_and_bounds(void)
{
    const uintptr_t plt_start = 0x2000;
    const uintptr_t plt_end = 0x2040;
    const uintptr_t gotplt_start = 0x3000;
    const uintptr_t gotplt_end = 0x3040;
    const intptr_t load_bias = 0x71000000;
    const intptr_t negative_bias = -0x1000;

    check_int("detector.delta0.plt.start",
              kzt_rela_slot_current_is_unresolved_stub(
                  plt_start, KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW,
                  0, plt_start, plt_end,
                  gotplt_start, gotplt_end), 1);
    check_int("detector.delta0.gotplt.last",
              kzt_rela_slot_current_is_unresolved_stub(
                  gotplt_end - 1,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  0, plt_start, plt_end,
                  gotplt_start, gotplt_end), 1);
    check_int("detector.delta0.plt.end",
              kzt_rela_slot_current_is_unresolved_stub(
                  plt_end, KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW,
                  0, plt_start, plt_end,
                  gotplt_start, gotplt_end), 0);
    check_int("detector.delta0.gotplt.before",
              kzt_rela_slot_current_is_unresolved_stub(
                  gotplt_start - 1,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  0, plt_start, plt_end,
                  gotplt_start, gotplt_end), 0);
    check_int("detector.positive_delta.plt",
              kzt_rela_slot_current_is_unresolved_stub(
                  plt_start + load_bias + 0x10,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED, load_bias,
                  plt_start, plt_end, gotplt_start, gotplt_end), 1);
    check_int("detector.positive_delta.gotplt",
              kzt_rela_slot_current_is_unresolved_stub(
                  gotplt_start + load_bias + 0x18,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED, load_bias,
                  plt_start, plt_end, gotplt_start, gotplt_end), 1);
    check_int("detector.delta.link_time_before_lazy_adjust",
              kzt_rela_slot_current_is_unresolved_stub(
                  plt_start + 0x10,
                  KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW, load_bias,
                  plt_start, plt_end, gotplt_start, gotplt_end), 1);
    check_int("detector.delta.resolved_same_dso",
              kzt_rela_slot_current_is_unresolved_stub(
                  load_bias + 0x5000,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED, load_bias,
                  plt_start, plt_end, gotplt_start, gotplt_end), 0);
    check_int("detector.delta.runtime_end",
              kzt_rela_slot_current_is_unresolved_stub(
                  load_bias + gotplt_end,
                  KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED, load_bias,
                  plt_start, plt_end, gotplt_start, gotplt_end), 0);
    check_int("detector.negative_delta.plt",
              kzt_rela_slot_current_is_unresolved_stub(
                  0x3010, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  negative_bias, 0x4000, 0x4040, 0x5000, 0x5040), 1);
    check_int("detector.negative_delta.gotplt",
              kzt_rela_slot_current_is_unresolved_stub(
                  0x4018, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  negative_bias, 0x4000, 0x4040, 0x5000, 0x5040), 1);
    check_int("detector.negative_delta.raw_collision_is_text",
              kzt_rela_slot_current_is_unresolved_stub(
                  0x2010, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  negative_bias, 0x2000, 0x2040, 0x5000, 0x5040), 0);
    check_int("detector.unknown.raw_looking_value",
              kzt_rela_slot_current_is_unresolved_stub(
                  plt_start + 0x10, KZT_RELA_STUB_COORDINATE_UNKNOWN,
                  load_bias, plt_start, plt_end,
                  gotplt_start, gotplt_end), 0);
    check_int("detector.overflow.no_wrap",
              kzt_rela_slot_current_is_unresolved_stub(
                  0x10, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  0x20, UINTPTR_MAX - 0x10, UINTPTR_MAX - 0x8,
                  0, 0), 0);
    check_int("detector.underflow.no_wrap",
              kzt_rela_slot_current_is_unresolved_stub(
                  0x10, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                  -0x20, 0x10, 0x18, 0, 0), 0);
}

static void test_jump_slot_defer_plan(void)
{
    const uintptr_t plt_start = 0x2000;
    const uintptr_t plt_end = 0x2040;
    const uintptr_t gotplt_start = 0x3000;
    const uintptr_t gotplt_end = 0x3040;
    const intptr_t load_bias = 0x71000000;
    static const struct {
        const char *name;
        uintptr_t slot_current_value;
        int bind_is_local;
        int bindnow;
        int need_resolver_present;
        int expected_unresolved_stub;
        int expected_defer;
        int expected_add_delta;
    } cases[] = {
        { "raw", 0x2010, 0, 0, 1, 1, 1, 1 },
        { "runtime-rebased", 0x71002010, 0, 0, 1, 1, 1, 0 },
        { "resolved", 0x71005000, 0, 0, 1, 0, 0, 0 },
        { "local.raw", 0x2010, 1, 0, 1, 1, 0, 0 },
        { "local.runtime", 0x71002010, 1, 0, 1, 1, 0, 0 },
        { "bindnow.raw", 0x2010, 0, 1, 1, 1, 0, 0 },
        { "bindnow.runtime", 0x71002010, 0, 1, 1, 1, 0, 0 },
        { "no-need-resolver.raw", 0x2010, 0, 0, 0, 1, 0, 0 },
        { "no-need-resolver.runtime", 0x71002010, 0, 0, 0, 1, 0, 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        kzt_rela_jump_slot_defer_input_t input = {
            .slot_current_value = cases[i].slot_current_value,
            .bind_is_local = cases[i].bind_is_local,
            .bindnow = cases[i].bindnow,
            .need_resolver_present = cases[i].need_resolver_present,
            .load_bias = load_bias,
            .plt_start = plt_start,
            .plt_end = plt_end,
            .gotplt_start = gotplt_start,
            .gotplt_end = gotplt_end,
        };
        kzt_rela_jump_slot_defer_plan_t plan =
            kzt_rela_jump_slot_defer_plan(&input);

        check_int(cases[i].name, plan.slot_is_unresolved_stub,
                  cases[i].expected_unresolved_stub);
        check_int(cases[i].name, plan.should_defer,
                  cases[i].expected_defer);
        check_int(cases[i].name, plan.should_add_delta,
                  cases[i].expected_add_delta);
    }

    {
        kzt_rela_jump_slot_defer_input_t overlapping_input = {
            .slot_current_value = 0x2020,
            .need_resolver_present = 1,
            .load_bias = 0x10,
            .plt_start = 0x2000,
            .plt_end = 0x2040,
        };
        kzt_rela_jump_slot_defer_plan_t plan =
            kzt_rela_jump_slot_defer_plan(&overlapping_input);

        check_int("overlap.unresolved", plan.slot_is_unresolved_stub, 1);
        check_int("overlap.defer", plan.should_defer, 1);
        check_int("overlap.add-delta", plan.should_add_delta, 0);
    }
}

static void test_distinct_targets_write_only_selected_slot(void)
{
    const uintptr_t current_target = 0x71000010;
    const uintptr_t expected_guest_target = 0x71000020;
    const uintptr_t native_bridge_target = 0x72000030;
    const uintptr_t legacy_target = 0x73000040;
    const uintptr_t other_value = 0x75000060;
    const uintptr_t canary_before = 0x1111222233334444;
    const uintptr_t canary_after = 0xaaaabbbbccccdddd;
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = {
        .next_bridge_target = native_bridge_target,
    };
    kzt_wrapper_probe_bridge_ops_t bridge_provider = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &bridge_provider,
    };
    fake_slot_bank_t bank;
    kzt_patch_spike_slot_ops_t slot_ops = fake_slot_ops(&bank);
    kzt_patch_spike_guard_t guard = enabled_guard();
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_rela_immediate_candidate_request_t request = base_request();
    uintptr_t selected_slot;

    fake_slot_bank_init(&bank, canary_before, current_target, other_value,
                        canary_after);
    selected_slot = (uintptr_t)&bank.values[0];

    request.slot_addr = selected_slot;
    request.slot_current_value = current_target;
    request.expected_guest_target = expected_guest_target;
    request.native_bridge_target = 0;
    request.legacy_target = legacy_target;

    check_int("targets.enrich",
              kzt_rela_immediate_request_enrich(
                  &request, &input, &enrich_result), 0);
    check_ulong("targets.expected", request.expected_guest_target,
                expected_guest_target);
    check_ulong("targets.bridge", request.native_bridge_target,
                native_bridge_target);
    check_ulong("targets.legacy", request.legacy_target, legacy_target);
    check_ulong("targets.slot", request.slot_addr, selected_slot);
    check_int("targets.owner", request.owner_match, KZT_PATCH_OWNER_MATCH);

    check_int("targets.write",
              kzt_rela_immediate_jump_slot_try_write(
                  &request, &guard, &slot_ops, &writer_result), 0);
    check_int("targets.decision", writer_result.plan.decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_int("targets.writer", writer_result.writer_called, 1);
    check_int("targets.skip_legacy", writer_result.skip_legacy_write, 1);
    check_ulong("targets.record.slot", writer_result.record.slot_addr,
                selected_slot);
    check_ulong("targets.record.expected", writer_result.record.expected_value,
                current_target);
    check_ulong("targets.record.replacement",
                writer_result.record.replacement_value,
                native_bridge_target);
    check_ulong("targets.selected.value", bank.values[0],
                native_bridge_target);
    check_int("targets.selected.writes",
              bank.entries[0].writer_write_calls, 1);
    check_ulong("targets.other.value", bank.values[1], other_value);
    check_int("targets.other.writes", bank.entries[1].writer_write_calls, 0);
    check_ulong("targets.canary.before", bank.canary_before, canary_before);
    check_ulong("targets.canary.after", bank.canary_after, canary_after);
    check_int("targets.invalid_accesses", bank.invalid_accesses, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_unresolved_stub_skips_owner_and_falls_back_to_legacy(void)
{
    const uintptr_t plt_start = 0x1000;
    const uintptr_t plt_end = 0x1040;
    const uintptr_t gotplt_start = 0x2000;
    const uintptr_t gotplt_end = 0x2040;
    const intptr_t load_bias = 0x70fff000;
    const uintptr_t stub_target = 0x71000010;
    const uintptr_t expected_guest_target = 0x71000020;
    const uintptr_t native_bridge_target = 0x72000030;
    const uintptr_t legacy_target = 0x73000040;
    const uintptr_t other_value = 0x75000060;
    const uintptr_t canary_before = 0x1111222233334444;
    const uintptr_t canary_after = 0xaaaabbbbccccdddd;
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = {
        .next_bridge_target = native_bridge_target,
    };
    kzt_wrapper_probe_bridge_ops_t bridge_provider = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &bridge_provider,
    };
    fake_slot_bank_t bank;
    kzt_patch_spike_slot_ops_t slot_ops = fake_slot_ops(&bank);
    kzt_patch_spike_guard_t guard = enabled_guard();
    kzt_owner_resolution_t unsafe_resolution;
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_rela_immediate_candidate_request_t request = base_request();
    uintptr_t selected_slot;

    fake_slot_bank_init(&bank, canary_before, stub_target, other_value,
                        canary_after);
    selected_slot = (uintptr_t)&bank.values[0];
    input.slot_current_value_is_unresolved_stub =
        kzt_rela_slot_current_is_unresolved_stub(
            stub_target, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
            load_bias, plt_start, plt_end,
            gotplt_start, gotplt_end);
    check_int("stub.detector", input.slot_current_value_is_unresolved_stub,
              1);

    request.slot_addr = selected_slot;
    request.slot_current_value = stub_target;
    request.expected_guest_target = expected_guest_target;
    request.native_bridge_target = 0;
    request.legacy_target = legacy_target;

    kzt_owner_resolver_init(&unsafe_resolution);
    check_int("stub.control.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, stub_target, expected_guest_target,
                  &unsafe_resolution), 0);
    check_int("stub.control.would_match", unsafe_resolution.owner_match,
              KZT_PATCH_OWNER_MATCH);

    check_int("stub.enrich",
              kzt_rela_immediate_request_enrich(
                  &request, &input, &enrich_result), 0);
    check_int("stub.owner", request.owner_match, KZT_PATCH_OWNER_UNKNOWN);
    check_int("stub.owner.known", request.current_owner.known, 0);
    check_int("stub.lazy_deferred", request.lazy_binding_deferred, 1);
    check_int("stub.owner_present", enrich_result.owner_present, 0);

    check_int("stub.write",
              kzt_rela_immediate_jump_slot_try_write(
                  &request, &guard, &slot_ops, &writer_result), 0);
    check_int("stub.plan.status", writer_result.plan.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("stub.plan.reason", writer_result.plan.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING);
    check_int("stub.plan.candidate", writer_result.plan.candidate_present, 0);
    check_int("stub.writer", writer_result.writer_called, 0);
    check_int("stub.skip_legacy", writer_result.skip_legacy_write, 0);

    if (!writer_result.skip_legacy_write) {
        fake_legacy_write(&bank, request.slot_addr, request.legacy_target);
    }
    check_ulong("stub.selected.value", bank.values[0], legacy_target);
    check_int("stub.selected.writer_writes",
              bank.entries[0].writer_write_calls, 0);
    check_int("stub.selected.legacy_writes",
              bank.entries[0].legacy_write_calls, 1);
    check_ulong("stub.other.value", bank.values[1], other_value);
    check_int("stub.other.writer_writes",
              bank.entries[1].writer_write_calls, 0);
    check_int("stub.other.legacy_writes",
              bank.entries[1].legacy_write_calls, 0);
    check_ulong("stub.canary.before", bank.canary_before, canary_before);
    check_ulong("stub.canary.after", bank.canary_after, canary_after);
    check_int("stub.invalid_accesses", bank.invalid_accesses, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_no_manifest_keeps_default_fail_open(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = NULL,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("no_manifest.wrapper", request.wrapper_match,
              KZT_PATCH_WRAPPER_NO_MANIFEST);
    check_ulong("no_manifest.bridge", request.native_bridge_target, 0);
    check_int("no_manifest.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("no_manifest.reason", plan_result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST);
    check_int("no_manifest.add_bridge", bridge.add_calls, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_missing_owner_blocks_approved_plan(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 0);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("missing_owner.owner", request.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("missing_owner.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("missing_owner.reason", plan_result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);
    check_int("missing_owner.no_add_bridge", bridge.add_calls, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_missing_dynamic_view_blocks_approved_plan(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(0, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000000 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("missing_dynamic.available", request.dynamic_view_available, 0);
    check_int("missing_dynamic.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("missing_dynamic.reason", plan_result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW);
    check_int("missing_dynamic.no_add_bridge", bridge.add_calls, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_bridge_zero_blocks_approved_plan(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("bridge_zero.wrapper", request.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("bridge_zero.bridge", request.native_bridge_target, 0);
    check_int("bridge_zero.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("bridge_zero.reason", plan_result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET);

    kzt_guest_registry_destroy(&registry);
}

static void test_native_bridge_is_not_used_as_expected_owner(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_guest_object_observation_t bridge_like = observation(
        0x3000, 0x72000000, 0x72010000, "libbridge-like.so");
    kzt_wrapper_probe_manifest_t manifest = wrapper_manifest();
    fake_bridge_state_t bridge = { .next_bridge_target = 0x72000080 };
    kzt_wrapper_probe_bridge_ops_t ops = bridge_ops(&bridge);
    kzt_rela_request_enricher_input_t input = {
        .registry = registry,
        .wrapper_manifest = &manifest,
        .bridge_ops = &ops,
    };
    kzt_rela_request_enricher_result_t enrich_result;
    kzt_rela_immediate_candidate_result_t plan_result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    check_int("bridge_like.observe",
              kzt_guest_registry_observe(registry, &bridge_like),
              KZT_GUEST_REGISTRY_ADDED);
    enrich_and_plan(&request, &input, &enrich_result, &plan_result);
    check_int("bridge_like.owner", request.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_ulong("bridge_like.bridge", request.native_bridge_target,
                0x72000080);
    check_int("bridge_like.decision", plan_result.decision.kind,
              KZT_PATCH_DECISION_APPROVED);

    kzt_guest_registry_destroy(&registry);
}

static void test_dead_object_is_not_relocation_source(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(0, 0);
    kzt_rela_request_enricher_input_t input = { .registry = registry };
    kzt_rela_request_enricher_result_t result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    check_int("dead_source.retire", kzt_guest_registry_retire(
                  registry, 0x1000, 1), 0);
    check_int("dead_source.enrich", kzt_rela_immediate_request_enrich(
                  &request, &input, &result), 0);
    check_int("dead_source.absent", result.source_present, 0);
    check_ulong("dead_source.no-link-map", request.source.link_map_addr, 0);
    check_int("dead_source.no-dynamic", request.dynamic_view_available, 0);
    kzt_guest_registry_destroy(&registry);
}

static void test_malformed_wrapper_evidence_does_not_fail_base_enrichment(void)
{
    kzt_guest_registry_t *registry = registry_with_source_and_owner(1, 1);
    kzt_rela_request_enricher_input_t input = { .registry = registry };
    kzt_rela_request_enricher_result_t result;
    kzt_rela_immediate_candidate_request_t request = base_request();

    request.symbol_name = NULL;
    check_int("malformed-wrapper.base-enrich",
              kzt_rela_immediate_request_enrich(
                  &request, &input, &result), 0);
    check_int("malformed-wrapper.default", request.wrapper_match,
              KZT_PATCH_WRAPPER_NO_MANIFEST);
    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_all_evidence_allows_approved_plan();
    test_source_and_owner_enrichment_do_not_need_snapshot_allocation();
    test_wrapper_only_preserves_validated_base_evidence();
    test_wrapper_only_needs_validated_base_evidence();
    test_unresolved_stub_detector_coordinates_and_bounds();
    test_jump_slot_defer_plan();
    test_distinct_targets_write_only_selected_slot();
    test_unresolved_stub_skips_owner_and_falls_back_to_legacy();
    test_no_manifest_keeps_default_fail_open();
    test_missing_owner_blocks_approved_plan();
    test_missing_dynamic_view_blocks_approved_plan();
    test_bridge_zero_blocks_approved_plan();
    test_native_bridge_is_not_used_as_expected_owner();
    test_dead_object_is_not_relocation_source();
    test_malformed_wrapper_evidence_does_not_fail_base_enrichment();

    if (failures) {
        fprintf(stderr, "kzt-rela-request-enricher: %d failure(s)\n",
                failures);
        return 1;
    }

    printf("kzt-rela-request-enricher: ok\n");
    return 0;
}
