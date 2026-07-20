#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_runtime_got_plt_candidate.h"

#define TEST_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define TEST_R_INFO(sym, type) ((((uint64_t)(sym)) << 32) | (type))

enum {
    TEST_PLT_RELA_ADDR = 0x7000100000ULL,
    TEST_RELA_ADDR = 0x7000200000ULL,
    TEST_STRTAB_ADDR = 0x7000300000ULL,
    TEST_SYMTAB_ADDR = 0x7000400000ULL,
    TEST_VERSYM_ADDR = 0x7000500000ULL,
    TEST_VERNEED_ADDR = 0x7000600000ULL,
    TEST_LOAD_BIAS = 0x7000000000ULL,
    TEST_STR_PUTS = 1,
    TEST_STR_ERRNO = 6,
    TEST_STR_GLIBC = 12,
    TEST_STR_LIBFOO = 24,
    TEST_JUMP_SLOT_SYMBOL = 11,
    TEST_GLOB_DAT_SYMBOL = 22,
};

static const char test_dynstr[] =
    "\0puts\0errno\0GLIBC_2.2.5\0LIBFOO_1.0\0";

typedef struct version_need_image {
    Elf64_Verneed need;
    Elf64_Vernaux aux[2];
} version_need_image_t;

typedef struct symbol_version_fixture {
    Elf64_Sym dynsym[23];
    Elf64_Half versym[23];
    version_need_image_t verneed;
} symbol_version_fixture_t;

typedef struct fake_region {
    uintptr_t guest_base;
    const void *host_base;
    size_t size;
} fake_region_t;

typedef struct fake_memory {
    fake_region_t regions[16];
    size_t region_count;
    uintptr_t fail_addr;
    int read_calls;
} fake_memory_t;

static int failures;

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

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void check_str(const char *name, const char *got, const char *expected)
{
    if ((!got && !expected) ||
        (got && expected && !strcmp(got, expected))) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static void add_region(fake_memory_t *memory,
                       uintptr_t guest_base,
                       const void *host_base,
                       size_t size)
{
    fake_region_t *region = &memory->regions[memory->region_count++];

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

static kzt_guest_link_map_reader_ops_t fake_ops(fake_memory_t *memory)
{
    kzt_guest_link_map_reader_ops_t ops = {
        .read_memory = fake_read_memory,
        .opaque = memory,
    };

    return ops;
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

static kzt_guest_dynamic_view_t base_view(void)
{
    return (kzt_guest_dynamic_view_t) {
        .dynamic_addr = 0x7000002000ULL,
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
    };
}

static kzt_patch_object_ref_t source_ref(void)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = 0x7000001000ULL,
        .map_start = TEST_LOAD_BIAS,
        .map_end = TEST_LOAD_BIAS + 0x100000,
        .generation = 42,
        .soname = "libcandidate.so",
        .path = "/guest/libcandidate.so",
    };
}

static kzt_runtime_got_plt_candidate_request_t make_request(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *ops,
    const kzt_patch_object_ref_t *source,
    kzt_patch_candidate_t *candidates,
    size_t capacity)
{
    static char string_storage[512];

    memset(string_storage, 0, sizeof(string_storage));
    return (kzt_runtime_got_plt_candidate_request_t) {
        .view = view,
        .reader_ops = ops,
        .source = source,
        .dynamic_view_generation = 88,
        .candidates = candidates,
        .candidate_capacity = capacity,
        .string_storage = string_storage,
        .string_storage_size = sizeof(string_storage),
    };
}

static void add_symbol_version_fixture(fake_memory_t *memory,
                                       kzt_guest_dynamic_view_t *view,
                                       symbol_version_fixture_t *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->dynsym[TEST_JUMP_SLOT_SYMBOL].st_name = TEST_STR_PUTS;
    fixture->dynsym[TEST_GLOB_DAT_SYMBOL].st_name = TEST_STR_ERRNO;
    fixture->versym[TEST_JUMP_SLOT_SYMBOL] = 2;
    fixture->versym[TEST_GLOB_DAT_SYMBOL] = 3;
    fixture->verneed.need.vn_version = 1;
    fixture->verneed.need.vn_cnt = 2;
    fixture->verneed.need.vn_aux = sizeof(Elf64_Verneed);
    fixture->verneed.need.vn_next = 0;
    fixture->verneed.aux[0].vna_other = 2;
    fixture->verneed.aux[0].vna_name = TEST_STR_GLIBC;
    fixture->verneed.aux[0].vna_next = sizeof(Elf64_Vernaux);
    fixture->verneed.aux[1].vna_other = 3;
    fixture->verneed.aux[1].vna_name = TEST_STR_LIBFOO;
    fixture->verneed.aux[1].vna_next = 0;

    view->symtab = runtime_field(TEST_SYMTAB_ADDR);
    view->syment = scalar_field(sizeof(Elf64_Sym));
    view->strtab = runtime_field(TEST_STRTAB_ADDR);
    view->strsz = scalar_field(sizeof(test_dynstr));
    view->versym = runtime_field(TEST_VERSYM_ADDR);
    view->verneed = runtime_field(TEST_VERNEED_ADDR);
    view->verneednum = scalar_field(1);

    add_region(memory, TEST_SYMTAB_ADDR, fixture->dynsym,
               sizeof(fixture->dynsym));
    add_region(memory, TEST_STRTAB_ADDR, test_dynstr, sizeof(test_dynstr));
    add_region(memory, TEST_VERSYM_ADDR, fixture->versym,
               sizeof(fixture->versym));
    add_region(memory, TEST_VERNEED_ADDR, &fixture->verneed,
               sizeof(fixture->verneed));
}

static void check_fail_open(
    const char *name,
    const kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_candidate_reason_t reason,
    kzt_patch_reason_t patch_reason)
{
    char field[128];

    snprintf(field, sizeof(field), "%s.status", name);
    check_int(field, result->status,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_FAIL_OPEN);
    snprintf(field, sizeof(field), "%s.reason", name);
    check_int(field, result->reason, reason);
    snprintf(field, sizeof(field), "%s.patch-present", name);
    check_int(field, result->patch_reason_present, 1);
    snprintf(field, sizeof(field), "%s.patch-reason", name);
    check_int(field, result->patch_reason, patch_reason);
    snprintf(field, sizeof(field), "%s.count", name);
    check_size(field, result->candidate_count, 0);
}

static void test_happy_path_enumerates_jump_slot_and_glob_dat(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    Elf64_Rela relas[] = {
        {
            .r_offset = 0x4020,
            .r_info = TEST_R_INFO(TEST_GLOB_DAT_SYMBOL,
                                  R_X86_64_GLOB_DAT),
            .r_addend = 0,
        },
    };
    uint64_t plt_slot = 0x7100001000ULL;
    uint64_t rela_slot = 0x7200002000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_patch_object_ref_t source = source_ref();
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[4];
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    view.rela = runtime_field(TEST_RELA_ADDR);
    view.relasz = scalar_field(sizeof(relas));
    view.relaent = scalar_field(sizeof(Elf64_Rela));
    add_symbol_version_fixture(&memory, &view, &symbols);

    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));
    add_region(&memory, TEST_RELA_ADDR, relas, sizeof(relas));
    add_region(&memory, TEST_LOAD_BIAS + plt_relas[0].r_offset,
               &plt_slot, sizeof(plt_slot));
    add_region(&memory, TEST_LOAD_BIAS + relas[0].r_offset,
               &rela_slot, sizeof(rela_slot));

    request = make_request(&view, &ops, &source, candidates,
                           TEST_ARRAY_SIZE(candidates));
    check_int("happy.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("happy.status", result.status,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_OK);
    check_int("happy.reason", result.reason,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_NONE);
    check_int("happy.patch-present", result.patch_reason_present, 0);
    check_size("happy.count", result.candidate_count, 2);

    check_int("happy.plt.table", candidates[0].table_kind,
              KZT_PATCH_TABLE_PLT_RELA);
    check_size("happy.plt.index", candidates[0].entry_index, 0);
    check_ulong("happy.plt.entry", candidates[0].entry_addr,
                TEST_PLT_RELA_ADDR);
    check_int("happy.plt.reloc", candidates[0].reloc_type,
              KZT_PATCH_RELOCATION_JUMP_SLOT);
    check_ulong("happy.plt.slot", candidates[0].slot_addr,
                TEST_LOAD_BIAS + plt_relas[0].r_offset);
    check_int("happy.plt.current-present",
              candidates[0].slot_current_value_present, 1);
    check_ulong("happy.plt.current", candidates[0].slot_current_value,
                plt_slot);
    check_ulong("happy.plt.symbol", candidates[0].symbol_index,
                TEST_JUMP_SLOT_SYMBOL);
    check_str("happy.plt.symbol-name", candidates[0].symbol_name,
              "puts");
    check_int("happy.plt.version-evidence",
              candidates[0].version_evidence,
              KZT_SYMBOL_VERSION_VERSIONED);
    check_str("happy.plt.version", candidates[0].version,
              "GLIBC_2.2.5");
    check_ulong("happy.plt.source", candidates[0].source.link_map_addr,
                source.link_map_addr);
    check_ulong("happy.plt.source-generation",
                candidates[0].source.generation, source.generation);
    check_ulong("happy.plt.dynamic", candidates[0].dynamic_addr,
                view.dynamic_addr);
    check_ulong("happy.plt.load-bias", candidates[0].load_bias,
                view.load_bias);
    check_ulong("happy.plt.generation",
                candidates[0].dynamic_view_generation, 88);
    check_int("happy.plt.available",
              candidates[0].dynamic_view_available, 1);

    check_int("happy.rela.table", candidates[1].table_kind,
              KZT_PATCH_TABLE_RELA);
    check_size("happy.rela.index", candidates[1].entry_index, 0);
    check_ulong("happy.rela.entry", candidates[1].entry_addr,
                TEST_RELA_ADDR);
    check_int("happy.rela.reloc", candidates[1].reloc_type,
              KZT_PATCH_RELOCATION_GLOB_DAT);
    check_ulong("happy.rela.slot", candidates[1].slot_addr,
                TEST_LOAD_BIAS + relas[0].r_offset);
    check_ulong("happy.rela.current", candidates[1].slot_current_value,
                rela_slot);
    check_ulong("happy.rela.symbol", candidates[1].symbol_index,
                TEST_GLOB_DAT_SYMBOL);
    check_str("happy.rela.symbol-name", candidates[1].symbol_name,
              "errno");
    check_str("happy.rela.version", candidates[1].version,
              "LIBFOO_1.0");
    check_str("happy.status-name",
              kzt_runtime_got_plt_candidate_status_name(result.status),
              "OK");
    check_str("happy.reason-name",
              kzt_runtime_got_plt_candidate_reason_name(result.reason),
              "NONE");

    /* The production shadow route audits one selected relocation with bounded
     * stack storage, even when the object has further candidate tables. */
    {
        kzt_patch_candidate_t one_candidate[1];

        request = make_request(&view, &ops, &source, one_candidate, 1);
        request.only_entry = 1;
        request.only_table_kind = KZT_PATCH_TABLE_PLT_RELA;
        request.only_entry_index = 0;
        check_int("single.collect",
                  kzt_runtime_got_plt_candidates_collect(&request, &result),
                  0);
        check_int("single.status", result.status,
                  KZT_RUNTIME_GOT_PLT_CANDIDATE_OK);
        check_size("single.count", result.candidate_count, 1);
        check_int("single.table", one_candidate[0].table_kind,
                  KZT_PATCH_TABLE_PLT_RELA);
        check_size("single.index", one_candidate[0].entry_index, 0);
    }
}

static void test_single_entry_reads_only_selected_relocation(void)
{
    Elf64_Rela plt_relas[3] = {
        { .r_offset = 0x3010,
          .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                R_X86_64_JUMP_SLOT) },
        { .r_offset = 0x3020,
          .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                R_X86_64_JUMP_SLOT) },
        { .r_offset = 0x3030,
          .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                R_X86_64_JUMP_SLOT) },
    };
    uint64_t selected_slot = 0x7100003000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_patch_object_ref_t source = source_ref();
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidate;
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    add_symbol_version_fixture(&memory, &view, &symbols);
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));
    add_region(&memory, TEST_LOAD_BIAS + plt_relas[2].r_offset,
               &selected_slot, sizeof(selected_slot));
    memory.fail_addr = TEST_PLT_RELA_ADDR;

    request = make_request(&view, &ops, &source, &candidate, 1);
    request.only_entry = 1;
    request.only_table_kind = KZT_PATCH_TABLE_PLT_RELA;
    request.only_entry_index = 2;
    check_int("single-direct.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("single-direct.status", result.status,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_OK);
    check_size("single-direct.count", result.candidate_count, 1);
    check_size("single-direct.index", candidate.entry_index, 2);
    check_ulong("single-direct.entry", candidate.entry_addr,
                TEST_PLT_RELA_ADDR + 2 * sizeof(Elf64_Rela));
}

static void test_missing_dynamic_field_fails_open(void)
{
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrel = scalar_field(DT_RELA);

    check_int("missing.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "missing", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
        KZT_PATCH_REASON_INPUT_MALFORMED_TABLE);
    check_int("missing.table", result.table_kind,
              KZT_PATCH_TABLE_PLT_RELA);
}

static void test_confirmed_unversioned_evidence_is_collected(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    uint64_t plt_slot = 0x7100001000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    add_symbol_version_fixture(&memory, &view, &symbols);
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));
    add_region(&memory, TEST_LOAD_BIAS + plt_relas[0].r_offset,
               &plt_slot, sizeof(plt_slot));

    view.versym.present = 0;
    check_int("no-versym.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("no-versym.status", result.status,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_OK);
    check_size("no-versym.count", result.candidate_count, 1);
    check_int("no-versym.evidence", candidates[0].version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
    check_int("no-versym.result-evidence", result.version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
    check_str("no-versym.version", candidates[0].version, NULL);

    view.versym.present = 1;
    symbols.versym[TEST_JUMP_SLOT_SYMBOL] = 0;
    check_int("versym-zero.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("versym-zero.evidence", candidates[0].version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
    check_str("versym-zero.version", candidates[0].version, NULL);

    symbols.versym[TEST_JUMP_SLOT_SYMBOL] = 1;
    check_int("versym-one.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("versym-one.evidence", candidates[0].version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
    check_str("versym-one.version", candidates[0].version, NULL);
}

static void test_version_read_failure_is_error_and_fails_open(void)
{
    Elf64_Rela plt_rela = {
        .r_offset = 0x3010,
        .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL, R_X86_64_JUMP_SLOT),
    };
    uint64_t plt_slot = 0x7100001000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidate;
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_rela));
    view.pltrel = scalar_field(DT_RELA);
    add_symbol_version_fixture(&memory, &view, &symbols);
    add_region(&memory, TEST_PLT_RELA_ADDR, &plt_rela, sizeof(plt_rela));
    add_region(&memory, TEST_LOAD_BIAS + plt_rela.r_offset,
               &plt_slot, sizeof(plt_slot));
    memory.fail_addr = TEST_VERSYM_ADDR +
                       TEST_JUMP_SLOT_SYMBOL * sizeof(Elf64_Half);
    request = make_request(&view, &ops, NULL, &candidate, 1);

    check_int("version-read.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "version-read", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_VERSION_READ_FAILED,
        KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION);
    check_int("version-read.evidence", result.version_evidence,
              KZT_SYMBOL_VERSION_ERROR);
}

static void test_missing_version_definition_is_error_and_fails_open(void)
{
    Elf64_Rela plt_rela = {
        .r_offset = 0x3010,
        .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL, R_X86_64_JUMP_SLOT),
    };
    uint64_t plt_slot = 0x7100001000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidate;
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_rela));
    view.pltrel = scalar_field(DT_RELA);
    add_symbol_version_fixture(&memory, &view, &symbols);
    view.verneed.present = 0;
    view.verneednum.present = 0;
    add_region(&memory, TEST_PLT_RELA_ADDR, &plt_rela, sizeof(plt_rela));
    add_region(&memory, TEST_LOAD_BIAS + plt_rela.r_offset,
               &plt_slot, sizeof(plt_slot));
    request = make_request(&view, &ops, NULL, &candidate, 1);

    check_int("missing-version-definition.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "missing-version-definition", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION,
        KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION);
    check_int("missing-version-definition.evidence",
              result.version_evidence, KZT_SYMBOL_VERSION_ERROR);
}

static void test_dt_rel_is_unsupported_and_fails_open(void)
{
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.rel = runtime_field(0x7000300000ULL);
    view.relsz = scalar_field(sizeof(Elf64_Rel));
    view.relent = scalar_field(sizeof(Elf64_Rel));

    check_int("dt-rel.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "dt-rel", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED,
        KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION);
    check_int("dt-rel.table", result.table_kind, KZT_PATCH_TABLE_REL);
    check_str("dt-rel.reason-name",
              kzt_runtime_got_plt_candidate_reason_name(result.reason),
              "DT_REL_UNSUPPORTED");
}

static void test_non_divisible_size_fails_open(void)
{
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.rela = runtime_field(TEST_RELA_ADDR);
    view.relasz = scalar_field(sizeof(Elf64_Rela) + 1);
    view.relaent = scalar_field(sizeof(Elf64_Rela));

    check_int("non-divisible.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "non-divisible", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE,
        KZT_PATCH_REASON_INPUT_MALFORMED_TABLE);
    check_int("non-divisible.table", result.table_kind,
              KZT_PATCH_TABLE_RELA);
}

static void test_relocation_reader_failure_fails_open(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    memory.fail_addr = TEST_PLT_RELA_ADDR;
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));

    check_int("reader-fail.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "reader-fail", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_RELOCATION_READ_FAILED,
        KZT_PATCH_REASON_INPUT_MALFORMED_TABLE);
    check_ulong("reader-fail.error-addr", result.read_error_addr,
                TEST_PLT_RELA_ADDR);
    check_str("reader-fail.reason-name",
              kzt_runtime_got_plt_candidate_reason_name(result.reason),
              "RELOCATION_READ_FAILED");
}

static void test_slot_reader_failure_fails_open(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));

    check_int("slot-read-fail.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "slot-read-fail", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_READ_FAILED,
        KZT_PATCH_REASON_INPUT_UNAVAILABLE_CURRENT_GOT);
    check_ulong("slot-read-fail.slot", result.slot_addr,
                TEST_LOAD_BIAS + plt_relas[0].r_offset);
}

static void test_slot_overflow_fails_open(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 8,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request =
        make_request(&view, &ops, NULL, candidates, TEST_ARRAY_SIZE(candidates));
    kzt_runtime_got_plt_candidate_result_t result;

    view.load_bias = UINTPTR_MAX - 7;
    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));

    check_int("slot-overflow.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "slot-overflow", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_OVERFLOW,
        KZT_PATCH_REASON_INPUT_MALFORMED_SLOT);
    check_int("slot-overflow.table", result.table_kind,
              KZT_PATCH_TABLE_PLT_RELA);
}

static void test_non_target_relocations_are_skipped(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_GLOB_DAT),
            .r_addend = 0,
        },
    };
    Elf64_Rela relas[] = {
        {
            .r_offset = 0x4020,
            .r_info = TEST_R_INFO(TEST_GLOB_DAT_SYMBOL,
                                  R_X86_64_RELATIVE),
            .r_addend = 0,
        },
    };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[2];
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    view.rela = runtime_field(TEST_RELA_ADDR);
    view.relasz = scalar_field(sizeof(relas));
    view.relaent = scalar_field(sizeof(Elf64_Rela));
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));
    add_region(&memory, TEST_RELA_ADDR, relas, sizeof(relas));

    request = make_request(&view, &ops, NULL, candidates,
                           TEST_ARRAY_SIZE(candidates));
    check_int("skip.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_int("skip.status", result.status,
              KZT_RUNTIME_GOT_PLT_CANDIDATE_OK);
    check_size("skip.count", result.candidate_count, 0);
}

static void test_capacity_exceeded_fails_open(void)
{
    Elf64_Rela plt_relas[] = {
        {
            .r_offset = 0x3010,
            .r_info = TEST_R_INFO(TEST_JUMP_SLOT_SYMBOL,
                                  R_X86_64_JUMP_SLOT),
            .r_addend = 0,
        },
    };
    Elf64_Rela relas[] = {
        {
            .r_offset = 0x4020,
            .r_info = TEST_R_INFO(TEST_GLOB_DAT_SYMBOL,
                                  R_X86_64_GLOB_DAT),
            .r_addend = 0,
        },
    };
    uint64_t plt_slot = 0x7100001000ULL;
    uint64_t rela_slot = 0x7200002000ULL;
    fake_memory_t memory = { 0 };
    symbol_version_fixture_t symbols;
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_view_t view = base_view();
    kzt_patch_candidate_t candidates[1];
    kzt_runtime_got_plt_candidate_request_t request;
    kzt_runtime_got_plt_candidate_result_t result;

    view.jmprel = runtime_field(TEST_PLT_RELA_ADDR);
    view.pltrelsz = scalar_field(sizeof(plt_relas));
    view.pltrel = scalar_field(DT_RELA);
    view.rela = runtime_field(TEST_RELA_ADDR);
    view.relasz = scalar_field(sizeof(relas));
    view.relaent = scalar_field(sizeof(Elf64_Rela));
    add_symbol_version_fixture(&memory, &view, &symbols);
    add_region(&memory, TEST_PLT_RELA_ADDR, plt_relas, sizeof(plt_relas));
    add_region(&memory, TEST_RELA_ADDR, relas, sizeof(relas));
    add_region(&memory, TEST_LOAD_BIAS + plt_relas[0].r_offset,
               &plt_slot, sizeof(plt_slot));
    add_region(&memory, TEST_LOAD_BIAS + relas[0].r_offset,
               &rela_slot, sizeof(rela_slot));

    request = make_request(&view, &ops, NULL, candidates,
                           TEST_ARRAY_SIZE(candidates));
    check_int("capacity.collect",
              kzt_runtime_got_plt_candidates_collect(&request, &result), 0);
    check_fail_open(
        "capacity", &result,
        KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_CAPACITY_EXCEEDED,
        KZT_PATCH_REASON_INPUT_MALFORMED_TABLE);
    check_int("capacity.table", result.table_kind, KZT_PATCH_TABLE_RELA);
    check_size("capacity.index", result.entry_index, 0);
}

static int test_matches_filter(const char *name, int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--filter") && i + 1 < argc) {
            return strcmp(name, argv[i + 1]) == 0;
        }
    }

    return 1;
}

int main(int argc, char **argv)
{
    if (test_matches_filter("happy_path_enumerates_jump_slot_and_glob_dat",
                            argc, argv)) {
        test_happy_path_enumerates_jump_slot_and_glob_dat();
    }
    if (test_matches_filter("single_entry_reads_only_selected_relocation",
                            argc, argv)) {
        test_single_entry_reads_only_selected_relocation();
    }
    if (test_matches_filter("missing_dynamic_field_fails_open",
                            argc, argv)) {
        test_missing_dynamic_field_fails_open();
    }
    if (test_matches_filter("confirmed_unversioned_evidence_is_collected",
                            argc, argv)) {
        test_confirmed_unversioned_evidence_is_collected();
    }
    if (test_matches_filter("version_read_failure_is_error_and_fails_open",
                            argc, argv)) {
        test_version_read_failure_is_error_and_fails_open();
    }
    if (test_matches_filter(
            "missing_version_definition_is_error_and_fails_open",
            argc, argv)) {
        test_missing_version_definition_is_error_and_fails_open();
    }
    if (test_matches_filter("dt_rel_is_unsupported_and_fails_open",
                            argc, argv)) {
        test_dt_rel_is_unsupported_and_fails_open();
    }
    if (test_matches_filter("non_divisible_size_fails_open", argc, argv)) {
        test_non_divisible_size_fails_open();
    }
    if (test_matches_filter("relocation_reader_failure_fails_open",
                            argc, argv)) {
        test_relocation_reader_failure_fails_open();
    }
    if (test_matches_filter("slot_reader_failure_fails_open", argc, argv)) {
        test_slot_reader_failure_fails_open();
    }
    if (test_matches_filter("slot_overflow_fails_open", argc, argv)) {
        test_slot_overflow_fails_open();
    }
    if (test_matches_filter("non_target_relocations_are_skipped",
                            argc, argv)) {
        test_non_target_relocations_are_skipped();
    }
    if (test_matches_filter("capacity_exceeded_fails_open", argc, argv)) {
        test_capacity_exceeded_fails_open();
    }

    if (failures) {
        fprintf(stderr,
                "kzt-runtime-got-plt-candidate: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-runtime-got-plt-candidate: selected tests passed");
    return 0;
}
