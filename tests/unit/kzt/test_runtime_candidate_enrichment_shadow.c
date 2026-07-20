#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_runtime_candidate_shadow.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define TEST_ELF64_R_INFO(symbol, type) \
    (((uint64_t)(symbol) << 32) | (uint32_t)(type))

#define TEST_SOURCE_LINK_MAP 0x1000ULL
#define TEST_OWNER_A_LINK_MAP 0x2000ULL
#define TEST_OWNER_B_LINK_MAP 0x3000ULL
#define TEST_SOURCE_BASE 0x60000000ULL
#define TEST_OWNER_A_BASE 0x71000000ULL
#define TEST_OWNER_B_BASE 0x72000000ULL
#define TEST_LOAD_BIAS TEST_SOURCE_BASE
#define TEST_PLT_RELA_ADDR 0x68001000ULL
#define TEST_RELA_ADDR 0x68002000ULL
#define TEST_SYMTAB_ADDR 0x68003000ULL
#define TEST_STRTAB_ADDR 0x68004000ULL
#define TEST_VERSYM_ADDR 0x68005000ULL
#define TEST_VERNEED_ADDR 0x68006000ULL
#define TEST_PLT_SLOT_ADDR (TEST_LOAD_BIAS + 0x3010)
#define TEST_GOT_SLOT_ADDR (TEST_LOAD_BIAS + 0x4020)
#define TEST_NATIVE_PUTS 0x90001000ULL
#define TEST_NATIVE_ERRNO 0x90002000ULL
#define TEST_LEGACY_TARGET 0xa0003000ULL

enum {
    TEST_SYMBOL_PUTS = 1,
    TEST_SYMBOL_ERRNO = 2,
    TEST_STR_PUTS = 1,
    TEST_STR_ERRNO = 6,
    TEST_STR_VERSION = 12,
};

static const char test_dynstr[] =
    "\0puts\0errno\0GLIBC_2.2.5\0";

static int failures;
static size_t tests_run;
static size_t slot_write_checks;

typedef struct fake_region {
    uintptr_t guest_base;
    const void *host_base;
    size_t size;
} fake_region_t;

typedef struct fake_memory {
    fake_region_t regions[16];
    size_t region_count;
    uintptr_t fail_addr;
    size_t read_calls;
} fake_memory_t;

typedef struct guarded_slot {
    uint64_t before;
    uint64_t value;
    uint64_t after;
} guarded_slot_t;

typedef struct version_fixture {
    Elf64_Verneed need;
    Elf64_Vernaux aux;
} version_fixture_t;

typedef struct expected_target_state {
    uintptr_t target;
    size_t calls;
    const char *last_symbol;
} expected_target_state_t;

typedef struct bridge_state {
    uintptr_t cache_target;
    uintptr_t add_target;
    uintptr_t last_native_symbol;
    size_t check_calls;
    size_t mutation_calls;
} bridge_state_t;

typedef struct stub_classifier_state {
    uintptr_t plt_start;
    uintptr_t plt_end;
    uintptr_t gotplt_start;
    uintptr_t gotplt_end;
    size_t calls;
} stub_classifier_state_t;

typedef struct generation_query_state {
    unsigned long generations[4];
    int results[4];
    size_t response_count;
    size_t calls;
} generation_query_state_t;

typedef struct shadow_fixture {
    fake_memory_t memory;
    kzt_guest_link_map_reader_ops_t reader_ops;
    kzt_guest_registry_t *registry;
    kzt_guest_dynamic_view_t view;
    kzt_patch_object_ref_t source;

    Elf64_Rela plt_rela;
    Elf64_Rela rela;
    Elf64_Sym symbols[3];
    Elf64_Half versions[3];
    version_fixture_t version;
    guarded_slot_t plt_slot;
    guarded_slot_t got_slot;

    kzt_patch_candidate_t candidates[2];
    char string_storage[256];
    kzt_runtime_candidate_shadow_record_t records[2];

    kzt_wrapper_probe_entry_t manifest_entries[2];
    kzt_wrapper_probe_manifest_t manifest;
    expected_target_state_t expected;
    bridge_state_t bridge;
    kzt_wrapper_probe_bridge_ops_t bridge_ops;
    stub_classifier_state_t stub_classifier;
    generation_query_state_t generation_query;

    kzt_runtime_got_plt_candidate_request_t collector_request;
    kzt_runtime_candidate_shadow_input_t input;
    kzt_runtime_candidate_shadow_result_t result;
} shadow_fixture_t;

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_size(const char *name, size_t got, size_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %lu expected %lu\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_ulong(const char *name,
                        unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n",
            name, got, expected);
    ++failures;
}

static void check_memory(const char *name,
                         const void *got,
                         const void *expected,
                         size_t size)
{
    if (memcmp(got, expected, size) == 0) {
        return;
    }

    fprintf(stderr, "%s: memory changed\n", name);
    ++failures;
}

static void add_region(fake_memory_t *memory,
                       uintptr_t guest_base,
                       const void *host_base,
                       size_t size)
{
    fake_region_t *region;

    if (memory->region_count >= ARRAY_SIZE(memory->regions)) {
        ++failures;
        return;
    }

    region = &memory->regions[memory->region_count++];
    region->guest_base = guest_base;
    region->host_base = host_base;
    region->size = size;
}

static int fake_read_memory(uintptr_t guest_addr,
                            void *dst,
                            size_t size,
                            void *opaque)
{
    fake_memory_t *memory = opaque;
    size_t i;

    ++memory->read_calls;
    if (memory->fail_addr && guest_addr == memory->fail_addr) {
        return -1;
    }

    for (i = 0; i < memory->region_count; ++i) {
        const fake_region_t *region = &memory->regions[i];
        uintptr_t offset;

        if (guest_addr < region->guest_base) {
            continue;
        }

        offset = guest_addr - region->guest_base;
        if (offset > region->size || size > region->size - offset) {
            continue;
        }

        memcpy(dst, (const char *)region->host_base + offset, size);
        return 0;
    }

    return -1;
}

static kzt_guest_dynamic_field_t runtime_field(uint64_t value)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS,
    };
}

static kzt_guest_dynamic_field_t scalar_field(uint64_t value)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = KZT_GUEST_DYNAMIC_SCALAR,
    };
}

static kzt_guest_object_observation_t object_observation(
    uintptr_t link_map_addr,
    uintptr_t map_start,
    uintptr_t map_end,
    const char *soname,
    const char *path)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { path, KZT_GUEST_FIELD_OK },
        .soname = { soname, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_patch_object_ref_t source_ref_from_registry(
    kzt_guest_registry_t *registry)
{
    kzt_guest_registry_dump_t dump = { 0 };
    kzt_patch_object_ref_t source = {
        .known = 1,
        .link_map_addr = TEST_SOURCE_LINK_MAP,
        .map_start = TEST_SOURCE_BASE,
        .map_end = TEST_SOURCE_BASE + 0x10000,
        .soname = "libsource.so",
        .path = "/guest/libsource.so",
    };
    size_t i;

    if (kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        ++failures;
        return source;
    }

    for (i = 0; i < dump.count; ++i) {
        if (dump.objects[i].link_map_addr == TEST_SOURCE_LINK_MAP) {
            source.generation = dump.objects[i].generation;
            break;
        }
    }

    kzt_guest_registry_dump_free(&dump);
    return source;
}

static int resolve_expected_guest_target(
    const kzt_patch_candidate_t *candidate,
    uintptr_t *expected_guest_target,
    void *opaque)
{
    expected_target_state_t *state = opaque;

    ++state->calls;
    state->last_symbol = candidate->symbol_name;
    if (!state->target) {
        return -1;
    }

    *expected_guest_target = state->target;
    return 0;
}

static uintptr_t check_bridge(uintptr_t native_symbol, void *opaque)
{
    bridge_state_t *state = opaque;

    ++state->check_calls;
    state->last_native_symbol = native_symbol;
    return state->cache_target;
}

static uintptr_t unexpected_mutating_bridge(
    const kzt_wrapper_probe_bridge_request_t *request,
    void *opaque)
{
    bridge_state_t *state = opaque;

    (void)request;
    ++state->mutation_calls;
    return state->add_target;
}

static kzt_runtime_candidate_shadow_stub_classification_t
classify_precise_stub(const kzt_patch_candidate_t *candidate, void *opaque)
{
    stub_classifier_state_t *state = opaque;
    uintptr_t start = 0;
    uintptr_t end = 0;

    ++state->calls;
    if (candidate->reloc_type == KZT_PATCH_RELOCATION_JUMP_SLOT) {
        start = state->plt_start;
        end = state->plt_end;
    } else if (candidate->reloc_type == KZT_PATCH_RELOCATION_GLOB_DAT) {
        start = state->gotplt_start;
        end = state->gotplt_end;
    } else {
        return KZT_RUNTIME_CANDIDATE_SHADOW_STUB_UNKNOWN;
    }

    if (start == 0 || start >= end) {
        return KZT_RUNTIME_CANDIDATE_SHADOW_STUB_UNKNOWN;
    }

    return candidate->slot_current_value >= start &&
           candidate->slot_current_value < end ?
           KZT_RUNTIME_CANDIDATE_SHADOW_STUB_MATCH :
           KZT_RUNTIME_CANDIDATE_SHADOW_STUB_NO_MATCH;
}

static int query_test_generation(uintptr_t link_map_addr,
                                 unsigned long *generation,
                                 void *opaque)
{
    generation_query_state_t *state = opaque;
    size_t index;

    (void)link_map_addr;
    if (state->response_count == 0) {
        return -1;
    }

    index = state->calls < state->response_count ?
            state->calls : state->response_count - 1;
    ++state->calls;
    if (state->results[index] != 0) {
        return state->results[index];
    }

    *generation = state->generations[index];
    return 0;
}

static void fixture_init(shadow_fixture_t *fixture, int include_glob_dat)
{
    kzt_guest_object_observation_t source;
    kzt_guest_object_observation_t owner_a;
    kzt_guest_object_observation_t owner_b;

    memset(fixture, 0, sizeof(*fixture));
    fixture->registry = kzt_guest_registry_init();
    source = object_observation(
        TEST_SOURCE_LINK_MAP, TEST_SOURCE_BASE,
        TEST_SOURCE_BASE + 0x10000, "libsource.so",
        "/guest/libsource.so");
    owner_a = object_observation(
        TEST_OWNER_A_LINK_MAP, TEST_OWNER_A_BASE,
        TEST_OWNER_A_BASE + 0x10000, "libowner-a.so",
        "/guest/libowner-a.so");
    owner_b = object_observation(
        TEST_OWNER_B_LINK_MAP, TEST_OWNER_B_BASE,
        TEST_OWNER_B_BASE + 0x10000, "libowner-b.so",
        "/guest/libowner-b.so");

    check_int("fixture.observe.source",
              kzt_guest_registry_observe(fixture->registry, &source),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("fixture.observe.owner-a",
              kzt_guest_registry_observe(fixture->registry, &owner_a),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("fixture.observe.owner-b",
              kzt_guest_registry_observe(fixture->registry, &owner_b),
              KZT_GUEST_REGISTRY_ADDED);
    fixture->source = source_ref_from_registry(fixture->registry);

    fixture->reader_ops.read_memory = fake_read_memory;
    fixture->reader_ops.opaque = &fixture->memory;
    fixture->view.dynamic_addr = TEST_SOURCE_BASE + 0x1000;
    fixture->view.load_bias = TEST_LOAD_BIAS;
    fixture->view.status = KZT_GUEST_DYNAMIC_COMPLETE;
    fixture->view.has_null = 1;
    fixture->view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    fixture->view.pltrelsz = scalar_field(sizeof(fixture->plt_rela));
    fixture->view.pltrel = scalar_field(DT_RELA);
    if (include_glob_dat) {
        fixture->view.rela = runtime_field(TEST_RELA_ADDR);
        fixture->view.relasz = scalar_field(sizeof(fixture->rela));
        fixture->view.relaent = scalar_field(sizeof(Elf64_Rela));
    }

    fixture->view.symtab = runtime_field(TEST_SYMTAB_ADDR);
    fixture->view.syment = scalar_field(sizeof(Elf64_Sym));
    fixture->view.strtab = runtime_field(TEST_STRTAB_ADDR);
    fixture->view.strsz = scalar_field(sizeof(test_dynstr));
    fixture->view.versym = runtime_field(TEST_VERSYM_ADDR);
    fixture->view.verneed = runtime_field(TEST_VERNEED_ADDR);
    fixture->view.verneednum = scalar_field(1);

    fixture->plt_rela.r_offset = TEST_PLT_SLOT_ADDR - TEST_LOAD_BIAS;
    fixture->plt_rela.r_info =
        TEST_ELF64_R_INFO(TEST_SYMBOL_PUTS, R_X86_64_JUMP_SLOT);
    fixture->rela.r_offset = TEST_GOT_SLOT_ADDR - TEST_LOAD_BIAS;
    fixture->rela.r_info =
        TEST_ELF64_R_INFO(TEST_SYMBOL_ERRNO, R_X86_64_GLOB_DAT);
    fixture->symbols[TEST_SYMBOL_PUTS].st_name = TEST_STR_PUTS;
    fixture->symbols[TEST_SYMBOL_ERRNO].st_name = TEST_STR_ERRNO;
    fixture->versions[TEST_SYMBOL_PUTS] = 2;
    fixture->versions[TEST_SYMBOL_ERRNO] = 2;
    fixture->version.need.vn_version = 1;
    fixture->version.need.vn_cnt = 1;
    fixture->version.need.vn_aux = sizeof(Elf64_Verneed);
    fixture->version.aux.vna_other = 2;
    fixture->version.aux.vna_name = TEST_STR_VERSION;

    fixture->plt_slot.before = 0x1111111111111111ULL;
    fixture->plt_slot.value = TEST_OWNER_A_BASE + 0x40;
    fixture->plt_slot.after = 0x2222222222222222ULL;
    fixture->got_slot.before = 0x3333333333333333ULL;
    fixture->got_slot.value = TEST_OWNER_A_BASE + 0x50;
    fixture->got_slot.after = 0x4444444444444444ULL;

    add_region(&fixture->memory, TEST_PLT_RELA_ADDR,
               &fixture->plt_rela, sizeof(fixture->plt_rela));
    if (include_glob_dat) {
        add_region(&fixture->memory, TEST_RELA_ADDR,
                   &fixture->rela, sizeof(fixture->rela));
    }
    add_region(&fixture->memory, TEST_SYMTAB_ADDR,
               fixture->symbols, sizeof(fixture->symbols));
    add_region(&fixture->memory, TEST_STRTAB_ADDR,
               test_dynstr, sizeof(test_dynstr));
    add_region(&fixture->memory, TEST_VERSYM_ADDR,
               fixture->versions, sizeof(fixture->versions));
    add_region(&fixture->memory, TEST_VERNEED_ADDR,
               &fixture->version, sizeof(fixture->version));
    add_region(&fixture->memory, TEST_PLT_SLOT_ADDR,
               &fixture->plt_slot.value, sizeof(fixture->plt_slot.value));
    if (include_glob_dat) {
        add_region(&fixture->memory, TEST_GOT_SLOT_ADDR,
                   &fixture->got_slot.value,
                   sizeof(fixture->got_slot.value));
    }

    fixture->manifest_entries[0] = (kzt_wrapper_probe_entry_t) {
        .symbol_name = "puts",
        .symbol_version = "GLIBC_2.2.5",
        .wrapper_name = "wrapped_puts",
        .wrapper_symbol_version = "GLIBC_2.2.5",
        .native_symbol = TEST_NATIVE_PUTS,
    };
    fixture->manifest_entries[1] = (kzt_wrapper_probe_entry_t) {
        .symbol_name = "errno",
        .symbol_version = "GLIBC_2.2.5",
        .wrapper_name = "wrapped_errno",
        .wrapper_symbol_version = "GLIBC_2.2.5",
        .native_symbol = TEST_NATIVE_ERRNO,
    };
    fixture->manifest = (kzt_wrapper_probe_manifest_t) {
        .available = 1,
        .manifest_name = "shadow-test",
        .entries = fixture->manifest_entries,
        .entry_count = ARRAY_SIZE(fixture->manifest_entries),
    };
    fixture->expected.target = TEST_OWNER_A_BASE + 0x80;
    fixture->bridge.cache_target = TEST_OWNER_B_BASE + 0x88;
    fixture->bridge.add_target = 0xdeadbeefULL;
    fixture->bridge_ops = (kzt_wrapper_probe_bridge_ops_t) {
        .check_bridge = check_bridge,
        .add_bridge = unexpected_mutating_bridge,
        .opaque = &fixture->bridge,
    };
    fixture->stub_classifier = (stub_classifier_state_t) {
        .plt_start = TEST_SOURCE_BASE + 0x400,
        .plt_end = TEST_SOURCE_BASE + 0x580,
        .gotplt_start = TEST_SOURCE_BASE + 0x580,
        .gotplt_end = TEST_SOURCE_BASE + 0x700,
    };

    fixture->collector_request =
        (kzt_runtime_got_plt_candidate_request_t) {
            .view = &fixture->view,
            .reader_ops = &fixture->reader_ops,
            .source = &fixture->source,
            .dynamic_view_generation = fixture->source.generation,
            .candidates = fixture->candidates,
            .candidate_capacity = ARRAY_SIZE(fixture->candidates),
            .string_storage = fixture->string_storage,
            .string_storage_size = sizeof(fixture->string_storage),
        };
    fixture->input = (kzt_runtime_candidate_shadow_input_t) {
        .collector_request = &fixture->collector_request,
        .registry = fixture->registry,
        .wrapper_manifest = &fixture->manifest,
        .bridge_ops = &fixture->bridge_ops,
        .resolve_expected_guest_target =
            resolve_expected_guest_target,
        .expected_target_opaque = &fixture->expected,
        .classify_stub = classify_precise_stub,
        .stub_classifier_opaque = &fixture->stub_classifier,
        .records = fixture->records,
        .record_capacity = ARRAY_SIZE(fixture->records),
    };
}

static int fixture_run(shadow_fixture_t *fixture)
{
    guarded_slot_t plt_before = fixture->plt_slot;
    guarded_slot_t got_before = fixture->got_slot;
    size_t decision_total = 0;
    size_t reason_total = 0;
    size_t i;
    int status;

    status = kzt_runtime_candidate_shadow_run(
        &fixture->input, &fixture->result);
    if (fixture->result.status ==
        KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN) {
        check_size("fail-open.collector-consumable-count",
                   fixture->result.collector_result.candidate_count, 0);
    }
    for (i = 0;
         i < KZT_RUNTIME_CANDIDATE_SHADOW_DECISION_BUCKETS; ++i) {
        decision_total += fixture->result.decision_histogram[i];
    }
    for (i = 0;
         i < KZT_RUNTIME_CANDIDATE_SHADOW_REASON_BUCKETS; ++i) {
        reason_total += fixture->result.reason_histogram[i];
    }
    check_size("histogram.decision-conservation", decision_total,
               fixture->result.record_count);
    check_size("histogram.reason-conservation", reason_total,
               fixture->result.record_count);
    check_memory("slot.plt", &fixture->plt_slot, &plt_before,
                 sizeof(plt_before));
    check_memory("slot.got", &fixture->got_slot, &got_before,
                 sizeof(got_before));
    slot_write_checks += 2;
    return status;
}

static void fixture_destroy(shadow_fixture_t *fixture)
{
    kzt_guest_registry_destroy(&fixture->registry);
}

static kzt_runtime_candidate_shadow_record_t *record_for_reloc(
    shadow_fixture_t *fixture,
    kzt_patch_relocation_type_t reloc_type)
{
    size_t i;

    for (i = 0; i < fixture->result.record_count; ++i) {
        if (fixture->records[i].decision.reloc_type == reloc_type) {
            return &fixture->records[i];
        }
    }

    return NULL;
}

static void test_w01_owner_match(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    check_int("W01.run", fixture_run(&fixture), 0);
    check_int("W01.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_OK);
    check_size("W01.records", fixture.result.record_count, 1);
    check_int("W01.owner", fixture.records[0].decision.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_int("W01.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_int("W01.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);
    check_size("W01.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w02_owner_mismatch(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.plt_slot.value = TEST_OWNER_B_BASE + 0x40;
    check_int("W02.run", fixture_run(&fixture), 0);
    check_int("W02.owner", fixture.records[0].decision.owner_match,
              KZT_PATCH_OWNER_MISMATCH);
    check_int("W02.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_REJECTED);
    check_int("W02.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_POLICY_OWNER_MISMATCH);
    fixture_destroy(&fixture);
}

static void test_w03_owner_unknown(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.plt_slot.value = 0x7f000040ULL;
    check_int("W03.run", fixture_run(&fixture), 0);
    check_int("W03.owner", fixture.records[0].decision.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("W03.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("W03.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);
    fixture_destroy(&fixture);
}

static void test_w04_no_manifest(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.input.wrapper_manifest = NULL;
    check_int("W04.run", fixture_run(&fixture), 0);
    check_int("W04.wrapper", fixture.records[0].decision.wrapper_match,
              KZT_PATCH_WRAPPER_NO_MANIFEST);
    check_int("W04.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("W04.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST);
    check_size("W04.cache-calls", fixture.bridge.check_calls, 0);
    check_size("W04.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w05_bridge_zero_never_adds(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.bridge.cache_target = 0;
    check_int("W05.run", fixture_run(&fixture), 0);
    check_size("W05.cache-calls", fixture.bridge.check_calls, 1);
    check_size("W05.mutation-calls", fixture.bridge.mutation_calls, 0);
    check_ulong("W05.bridge", fixture.records[0].decision.bridge_target, 0);
    check_int("W05.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("W05.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET);
    fixture_destroy(&fixture);
}

static void test_w06_plt_and_got_stubs_are_deferred(void)
{
    shadow_fixture_t fixture;
    kzt_runtime_candidate_shadow_record_t *plt;
    kzt_runtime_candidate_shadow_record_t *got;

    ++tests_run;
    fixture_init(&fixture, 1);
    fixture.plt_slot.value = TEST_SOURCE_BASE + 0x500;
    fixture.got_slot.value = TEST_SOURCE_BASE + 0x600;
    check_int("W06.run", fixture_run(&fixture), 0);
    check_size("W06.records", fixture.result.record_count, 2);
    plt = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_JUMP_SLOT);
    got = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_GLOB_DAT);
    check_int("W06.plt-present", plt != NULL, 1);
    check_int("W06.got-present", got != NULL, 1);
    if (plt) {
        check_int("W06.plt.decision", plt->decision.kind,
                  KZT_PATCH_DECISION_DEFERRED);
        check_int("W06.plt.reason", plt->decision.reason,
                  KZT_PATCH_REASON_DEFERRED_LAZY_BINDING);
    }
    if (got) {
        check_int("W06.got.decision", got->decision.kind,
                  KZT_PATCH_DECISION_DEFERRED);
        check_int("W06.got.reason", got->decision.reason,
                  KZT_PATCH_REASON_DEFERRED_LAZY_BINDING);
        check_int("W06.got.observe-only", got->observe_only, 1);
    }
    check_size("W06.owner-lookups", fixture.expected.calls, 0);
    check_size("W06.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 1);
    fixture.plt_slot.value = TEST_SOURCE_BASE + 0x8000;
    fixture.got_slot.value = TEST_SOURCE_BASE + 0x8100;
    check_int("W06.same-dso-nonstub.run", fixture_run(&fixture), 0);
    check_size("W06.same-dso-nonstub.records",
               fixture.result.record_count, 2);
    plt = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_JUMP_SLOT);
    got = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_GLOB_DAT);
    if (plt) {
        check_int("W06.same-dso-nonstub.plt-not-deferred",
                  plt->decision.kind == KZT_PATCH_DECISION_DEFERRED, 0);
    }
    if (got) {
        check_int("W06.same-dso-nonstub.got-not-deferred",
                  got->decision.kind == KZT_PATCH_DECISION_DEFERRED, 0);
    }
    check_size("W06.same-dso-nonstub.classifier-calls",
               fixture.stub_classifier.calls, 2);
    check_size("W06.same-dso-nonstub.owner-lookups",
               fixture.expected.calls, 2);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    fixture.plt_slot.value = TEST_SOURCE_BASE + 0x500;
    fixture.input.classify_stub = NULL;
    check_int("W06.no-evidence.run", fixture_run(&fixture), 0);
    check_int("W06.no-evidence.not-deferred",
              fixture.records[0].decision.kind ==
                  KZT_PATCH_DECISION_DEFERRED,
              0);
    check_size("W06.no-evidence.owner-lookups", fixture.expected.calls, 1);
    fixture_destroy(&fixture);
}

static void test_w07_expected_bridge_slot_exclude_legacy(void)
{
    shadow_fixture_t fixture;
    uintptr_t legacy_target = TEST_LEGACY_TARGET;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.plt_slot.value = TEST_OWNER_A_BASE + 0x40;
    fixture.expected.target = TEST_OWNER_A_BASE + 0x80;
    fixture.bridge.cache_target = TEST_OWNER_B_BASE + 0x88;
    check_int("W07.run", fixture_run(&fixture), 0);
    check_ulong("W07.slot-current",
                fixture.records[0].decision.slot_current_value,
                TEST_OWNER_A_BASE + 0x40);
    check_ulong("W07.expected-owner",
                fixture.records[0].owner_resolution.expected_owner
                    .link_map_addr,
                TEST_OWNER_A_LINK_MAP);
    check_ulong("W07.current-owner",
                fixture.records[0].owner_resolution.current_owner
                    .link_map_addr,
                TEST_OWNER_A_LINK_MAP);
    check_ulong("W07.bridge",
                fixture.records[0].decision.bridge_target,
                TEST_OWNER_B_BASE + 0x88);
    check_ulong("W07.cache-key", fixture.bridge.last_native_symbol,
                TEST_NATIVE_PUTS);
    check_int("W07.audit-only", fixture.records[0].audit_only, 1);
    check_int("W07.legacy-not-consumed",
              fixture.records[0].legacy_target_consumed, 0);
    check_int("W07.legacy-not-slot",
              legacy_target ==
                  fixture.records[0].decision.slot_current_value,
              0);
    check_int("W07.legacy-not-bridge",
              legacy_target ==
                  fixture.records[0].decision.bridge_target,
              0);
    check_int("W07.legacy-not-expected",
              legacy_target == fixture.expected.target, 0);
    check_int("W07.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_APPROVED);
    check_size("W07.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w08_bridge_ops_missing(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.input.bridge_ops = NULL;
    check_int("W08.run", fixture_run(&fixture), 0);
    check_int("W08.wrapper", fixture.records[0].decision.wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("W08.bridge", fixture.records[0].decision.bridge_target, 0);
    check_int("W08.decision", fixture.records[0].decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("W08.reason", fixture.records[0].decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET);
    check_size("W08.cache-calls", fixture.bridge.check_calls, 0);
    check_size("W08.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w09_generation_change_fails_open(void)
{
    shadow_fixture_t fixture;
    unsigned long generation;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.collector_request.dynamic_view_generation =
        fixture.source.generation + 1;
    check_int("W09.run", fixture_run(&fixture), 0);
    check_int("W09.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W09.reason", fixture.result.reason,
              KZT_RUNTIME_CANDIDATE_SHADOW_REASON_OBJECT_GENERATION_CHANGED);
    check_size("W09.candidates", fixture.result.candidate_count, 0);
    check_size("W09.records", fixture.result.record_count, 0);
    check_size("W09.owner-lookups", fixture.expected.calls, 0);
    check_size("W09.cache-calls", fixture.bridge.check_calls, 0);
    check_size("W09.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    fixture.source.generation = 0;
    check_int("W09.zero.run", fixture_run(&fixture), 0);
    check_int("W09.zero.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_size("W09.zero.owner-lookups", fixture.expected.calls, 0);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    fixture.source.link_map_addr = TEST_SOURCE_LINK_MAP + 1;
    check_int("W09.disappeared.run", fixture_run(&fixture), 0);
    check_int("W09.disappeared.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_size("W09.disappeared.owner-lookups", fixture.expected.calls, 0);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    fixture.generation_query.response_count = 1;
    fixture.generation_query.results[0] = -1;
    fixture.input.query_generation = query_test_generation;
    fixture.input.generation_query_opaque = &fixture.generation_query;
    check_int("W09.lookup-failed.run", fixture_run(&fixture), 0);
    check_int("W09.lookup-failed.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    fixture.generation_query.response_count = 1;
    fixture.generation_query.results[0] = -2;
    fixture.input.query_generation = query_test_generation;
    fixture.input.generation_query_opaque = &fixture.generation_query;
    check_int("W09.nonunique.run", fixture_run(&fixture), 0);
    check_int("W09.nonunique.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    fixture_destroy(&fixture);

    fixture_init(&fixture, 0);
    generation = fixture.source.generation;
    fixture.generation_query.response_count = 2;
    fixture.generation_query.generations[0] = generation;
    fixture.generation_query.generations[1] = generation + 1;
    fixture.input.query_generation = query_test_generation;
    fixture.input.generation_query_opaque = &fixture.generation_query;
    check_int("W09.cross-generation.run", fixture_run(&fixture), 0);
    check_int("W09.cross-generation.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W09.cross-generation.reason", fixture.result.reason,
              KZT_RUNTIME_CANDIDATE_SHADOW_REASON_OBJECT_GENERATION_CHANGED);
    check_size("W09.cross-generation.queries",
               fixture.generation_query.calls, 2);
    check_size("W09.cross-generation.owner-lookups",
               fixture.expected.calls, 1);
    fixture_destroy(&fixture);
}

static void test_w10_rel_fails_open(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.view.pltrel = scalar_field(DT_REL);
    check_int("W10.run", fixture_run(&fixture), 0);
    check_int("W10.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W10.reason", fixture.result.reason,
              KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_FAIL_OPEN);
    check_int("W10.collector-reason", fixture.result.collector_result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED);
    check_int("W10.table", fixture.result.collector_result.table_kind,
              KZT_PATCH_TABLE_PLT_REL);
    check_size("W10.records", fixture.result.record_count, 0);
    check_size("W10.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w10b_dynamic_rel_fails_open(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.view.rel = runtime_field(TEST_RELA_ADDR + 0x1000);
    fixture.view.relsz = scalar_field(sizeof(Elf64_Rel));
    fixture.view.relent = scalar_field(sizeof(Elf64_Rel));
    check_int("W10b.run", fixture_run(&fixture), 0);
    check_int("W10b.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W10b.reason", fixture.result.reason,
              KZT_RUNTIME_CANDIDATE_SHADOW_REASON_COLLECTOR_FAIL_OPEN);
    check_int("W10b.collector-reason", fixture.result.collector_result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED);
    check_int("W10b.table", fixture.result.collector_result.table_kind,
              KZT_PATCH_TABLE_REL);
    check_size("W10b.records", fixture.result.record_count, 0);
    check_size("W10b.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w11_glob_dat_is_observe_only(void)
{
    shadow_fixture_t fixture;
    kzt_runtime_candidate_shadow_record_t *plt;
    kzt_runtime_candidate_shadow_record_t *got;

    ++tests_run;
    fixture_init(&fixture, 1);
    check_int("W11.run", fixture_run(&fixture), 0);
    check_int("W11.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_OK);
    check_size("W11.records", fixture.result.record_count, 2);
    check_size("W11.eligible", fixture.result.eligible_count, 1);
    check_size("W11.observe-only", fixture.result.observe_only_count, 1);
    check_size("W11.approved-histogram",
               fixture.result.decision_histogram[
                   KZT_PATCH_DECISION_APPROVED], 2);
    plt = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_JUMP_SLOT);
    got = record_for_reloc(&fixture, KZT_PATCH_RELOCATION_GLOB_DAT);
    check_int("W11.plt-present", plt != NULL, 1);
    check_int("W11.got-present", got != NULL, 1);
    if (plt) {
        check_int("W11.plt.eligible", plt->eligible, 1);
        check_int("W11.plt.observe-only", plt->observe_only, 0);
    }
    if (got) {
        check_int("W11.got.decision", got->decision.kind,
                  KZT_PATCH_DECISION_APPROVED);
        check_int("W11.got.eligible", got->eligible, 0);
        check_int("W11.got.observe-only", got->observe_only, 1);
    }
    check_size("W11.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w12_candidate_capacity_fails_open(void)
{
    shadow_fixture_t fixture;
    kzt_patch_candidate_t zero_candidates[2] = { 0 };

    ++tests_run;
    fixture_init(&fixture, 1);
    fixture.collector_request.candidate_capacity = 1;
    check_int("W12.run", fixture_run(&fixture), 0);
    check_int("W12.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W12.collector-reason", fixture.result.collector_result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_CAPACITY_EXCEEDED);
    check_memory("W12.candidates-cleared", fixture.candidates,
                 zero_candidates, sizeof(zero_candidates));
    check_size("W12.records", fixture.result.record_count, 0);
    check_size("W12.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w13_record_capacity_fails_open(void)
{
    shadow_fixture_t fixture;
    kzt_patch_candidate_t zero_candidates[2] = { 0 };
    kzt_runtime_candidate_shadow_record_t zero_records[2] = { 0 };

    ++tests_run;
    fixture_init(&fixture, 1);
    fixture.input.record_capacity = 1;
    check_int("W13.run", fixture_run(&fixture), 0);
    check_int("W13.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W13.reason", fixture.result.reason,
              KZT_RUNTIME_CANDIDATE_SHADOW_REASON_RECORD_CAPACITY_EXCEEDED);
    check_memory("W13.candidates-cleared", fixture.candidates,
                 zero_candidates, sizeof(zero_candidates));
    check_memory("W13.records-cleared", fixture.records,
                 zero_records, sizeof(zero_records));
    check_size("W13.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w14_relocation_read_failure(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.memory.fail_addr = TEST_PLT_RELA_ADDR;
    check_int("W14.run", fixture_run(&fixture), 0);
    check_int("W14.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W14.collector-reason", fixture.result.collector_result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_RELOCATION_READ_FAILED);
    check_ulong("W14.read-error",
                fixture.result.collector_result.read_error_addr,
                TEST_PLT_RELA_ADDR);
    check_size("W14.records", fixture.result.record_count, 0);
    check_size("W14.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

static void test_w15_slot_read_failure(void)
{
    shadow_fixture_t fixture;

    ++tests_run;
    fixture_init(&fixture, 0);
    fixture.memory.fail_addr = TEST_PLT_SLOT_ADDR;
    check_int("W15.run", fixture_run(&fixture), 0);
    check_int("W15.status", fixture.result.status,
              KZT_RUNTIME_CANDIDATE_SHADOW_FAIL_OPEN);
    check_int("W15.collector-reason", fixture.result.collector_result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_READ_FAILED);
    check_ulong("W15.read-error",
                fixture.result.collector_result.read_error_addr,
                TEST_PLT_SLOT_ADDR);
    check_size("W15.records", fixture.result.record_count, 0);
    check_size("W15.mutation-calls", fixture.bridge.mutation_calls, 0);
    fixture_destroy(&fixture);
}

int main(void)
{
    test_w01_owner_match();
    test_w02_owner_mismatch();
    test_w03_owner_unknown();
    test_w04_no_manifest();
    test_w05_bridge_zero_never_adds();
    test_w06_plt_and_got_stubs_are_deferred();
    test_w07_expected_bridge_slot_exclude_legacy();
    test_w08_bridge_ops_missing();
    test_w09_generation_change_fails_open();
    test_w10_rel_fails_open();
    test_w10b_dynamic_rel_fails_open();
    test_w11_glob_dat_is_observe_only();
    test_w12_candidate_capacity_fails_open();
    test_w13_record_capacity_fails_open();
    test_w14_relocation_read_failure();
    test_w15_slot_read_failure();

    if (failures) {
        fprintf(stderr,
                "kzt-runtime-candidate-enrichment-shadow: "
                "%d failure(s), %lu scenario(s)\n",
                failures, (unsigned long)tests_run);
        return 1;
    }

    printf("kzt-runtime-candidate-enrichment-shadow: "
           "%lu scenario(s) passed, %lu guarded slot checks\n",
           (unsigned long)tests_run, (unsigned long)slot_write_checks);
    return 0;
}
