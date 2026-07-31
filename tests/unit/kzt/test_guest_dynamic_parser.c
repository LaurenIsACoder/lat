#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_dynamic.h"

#define TEST_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KZT_TEST_UNKNOWN_DYNAMIC_TAG 0x6000000d

typedef struct fake_dynamic_memory {
    uintptr_t base;
    size_t size;
    int read_calls;
} fake_dynamic_memory_t;

static int failures;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

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

static void check_u64(const char *name, uint64_t got, uint64_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%llx expected 0x%llx\n", name,
            (unsigned long long)got, (unsigned long long)expected);
    ++failures;
}

static void check_i64(const char *name, int64_t got, int64_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %lld expected %lld\n", name,
            (long long)got, (long long)expected);
    ++failures;
}

static int fake_read_memory(uintptr_t guest_addr, void *dst, size_t size,
                            void *opaque)
{
    fake_dynamic_memory_t *memory = opaque;

    ++memory->read_calls;
    if (guest_addr < memory->base ||
        size > memory->size ||
        guest_addr - memory->base > memory->size - size) {
        return -1;
    }

    memcpy(dst, (const void *)guest_addr, size);
    return 0;
}

static kzt_guest_link_map_reader_ops_t fake_ops(fake_dynamic_memory_t *memory)
{
    kzt_guest_link_map_reader_ops_t ops = {
        .read_memory = fake_read_memory,
        .opaque = memory,
    };

    return ops;
}

static void check_field(const char *name,
                        const kzt_guest_dynamic_field_t *field,
                        uint64_t value,
                        kzt_guest_dynamic_address_semantics_t semantics)
{
    check_true(name, field->present);
    check_u64(name, field->value, value);
    check_int(name, field->address_semantics, semantics);
}

static void test_complete_runtime_dynamic_view(void)
{
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_NEEDED, .d_un.d_val = 0x10 },
        { .d_tag = DT_NEEDED, .d_un.d_val = 0x38 },
        { .d_tag = DT_SYMTAB, .d_un.d_ptr = 0x7000010000 },
        { .d_tag = DT_STRTAB, .d_un.d_ptr = 0x7000020000 },
        { .d_tag = DT_SYMENT, .d_un.d_val = sizeof(Elf64_Sym) },
        { .d_tag = DT_STRSZ, .d_un.d_val = 0x220 },
        { .d_tag = DT_HASH, .d_un.d_ptr = 0x7000030000 },
        { .d_tag = DT_GNU_HASH, .d_un.d_ptr = 0x7000040000 },
        { .d_tag = DT_VERSYM, .d_un.d_ptr = 0x7000050000 },
        { .d_tag = DT_VERNEED, .d_un.d_ptr = 0x6fffc60000 },
        { .d_tag = DT_VERNEEDNUM, .d_un.d_val = 2 },
        { .d_tag = DT_VERDEF, .d_un.d_ptr = 0x6fffc70000 },
        { .d_tag = DT_VERDEFNUM, .d_un.d_val = 1 },
        { .d_tag = DT_RELA, .d_un.d_ptr = 0x7000080000 },
        { .d_tag = DT_RELASZ, .d_un.d_val = 0x60 },
        { .d_tag = DT_RELAENT, .d_un.d_val = sizeof(Elf64_Rela) },
        { .d_tag = DT_REL, .d_un.d_ptr = 0x7000090000 },
        { .d_tag = DT_RELSZ, .d_un.d_val = 0x40 },
        { .d_tag = DT_RELENT, .d_un.d_val = sizeof(Elf64_Rel) },
        { .d_tag = DT_JMPREL, .d_un.d_ptr = 0x70000a0000 },
        { .d_tag = DT_PLTRELSZ, .d_un.d_val = 0x30 },
        { .d_tag = DT_PLTREL, .d_un.d_val = DT_RELA },
        { .d_tag = DT_PLTGOT, .d_un.d_ptr = 0x70000b0000 },
        { .d_tag = DT_NULL, .d_un.d_val = 0 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };

    check_int("dynamic.complete.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x400000,
                                      &ops, &result),
              0);
    check_int("dynamic.complete.status", result.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_int("dynamic.complete.view-status", result.view.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_true("dynamic.complete.has-null", result.view.has_null);
    check_size("dynamic.complete.entry-count", result.entry_count,
               TEST_ARRAY_SIZE(dynamic) - 1);
    check_size("dynamic.complete.view-entry-count", result.view.entry_count,
               TEST_ARRAY_SIZE(dynamic) - 1);
    check_int("dynamic.complete.reader-calls", memory.read_calls,
              TEST_ARRAY_SIZE(dynamic));

    check_field("dynamic.symtab", &result.view.symtab, 0x7000010000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.strtab", &result.view.strtab, 0x7000020000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.syment", &result.view.syment, sizeof(Elf64_Sym),
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.strsz", &result.view.strsz, 0x220,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.hash", &result.view.hash, 0x7000030000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.gnu-hash", &result.view.gnu_hash, 0x7000040000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.versym", &result.view.versym, 0x7000050000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.verneed", &result.view.verneed, 0x7000060000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.verneednum", &result.view.verneednum, 2,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.verdef", &result.view.verdef, 0x7000070000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.verdefnum", &result.view.verdefnum, 1,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.rela", &result.view.rela, 0x7000080000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.relasz", &result.view.relasz, 0x60,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.relaent", &result.view.relaent, sizeof(Elf64_Rela),
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.rel", &result.view.rel, 0x7000090000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.relsz", &result.view.relsz, 0x40,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.relent", &result.view.relent, sizeof(Elf64_Rel),
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.jmprel", &result.view.jmprel, 0x70000a0000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("dynamic.pltrelsz", &result.view.pltrelsz, 0x30,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.pltrel", &result.view.pltrel, DT_RELA,
                KZT_GUEST_DYNAMIC_SCALAR);
    check_field("dynamic.pltgot", &result.view.pltgot, 0x70000b0000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);

    check_size("dynamic.needed.count", result.view.needed_count, 2);
    check_int("dynamic.needed.semantics",
              result.view.needed_address_semantics,
              KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET);
    check_u64("dynamic.needed.0", result.view.needed_offsets[0], 0x10);
    check_u64("dynamic.needed.1", result.view.needed_offsets[1], 0x38);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_dynamic_address_semantics(void)
{
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_SYMTAB, .d_un.d_ptr = 0x5000010000 },
        { .d_tag = DT_STRTAB, .d_un.d_ptr = 0x5000020000 },
        { .d_tag = DT_JMPREL, .d_un.d_ptr = 0x5000030000 },
        { .d_tag = DT_PLTGOT, .d_un.d_ptr = 0x5000040000 },
        { .d_tag = DT_NEEDED, .d_un.d_val = 0x84 },
        { .d_tag = DT_NULL, .d_un.d_val = 0 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };

    check_int("semantics.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x100000,
                                      &ops, &result),
              0);
    check_int("semantics.status", result.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_field("semantics.symtab", &result.view.symtab, 0x5000010000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("semantics.strtab", &result.view.strtab, 0x5000020000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("semantics.jmprel", &result.view.jmprel, 0x5000030000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("semantics.pltgot", &result.view.pltgot, 0x5000040000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_size("semantics.needed.count", result.view.needed_count, 1);
    check_int("semantics.needed.semantics",
              result.view.needed_address_semantics,
              KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET);
    check_u64("semantics.needed.offset", result.view.needed_offsets[0],
              0x84);
    check_u64("semantics.load-bias-preserved", result.view.load_bias,
              0x100000);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_version_tables_are_load_bias_relative_only(void)
{
    const uintptr_t load_bias = 0x71000000;
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_SYMTAB, .d_un.d_ptr = 0x71001000 },
        { .d_tag = DT_STRTAB, .d_un.d_ptr = 0x71002000 },
        { .d_tag = DT_JMPREL, .d_un.d_ptr = 0x71003000 },
        { .d_tag = DT_VERSYM, .d_un.d_ptr = 0x71004000 },
        { .d_tag = DT_VERNEED, .d_un.d_ptr = 0x2b0 },
        { .d_tag = DT_VERDEF, .d_un.d_ptr = 0x390 },
        { .d_tag = DT_NULL, .d_un.d_val = 0 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };

    check_int("version-relative.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, load_bias,
                                      &ops, &result),
              0);
    check_int("version-relative.status", result.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_field("version-relative.symtab", &result.view.symtab, 0x71001000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("version-relative.strtab", &result.view.strtab, 0x71002000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("version-relative.jmprel", &result.view.jmprel, 0x71003000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("version-relative.versym", &result.view.versym, 0x71004000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("version-relative.verneed", &result.view.verneed,
                load_bias + 0x2b0, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_field("version-relative.verdef", &result.view.verdef,
                load_bias + 0x390, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_version_table_load_bias_overflow_is_fail_open(void)
{
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_VERNEED, .d_un.d_ptr = 1 },
        { .d_tag = DT_NULL, .d_un.d_val = 0 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };

    check_int("version-overflow.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, UINTPTR_MAX,
                                      &ops, &result),
              0);
    check_int("version-overflow.status", result.status,
              KZT_GUEST_DYNAMIC_ERROR);
    check_int("version-overflow.view-status", result.view.status,
              KZT_GUEST_DYNAMIC_ERROR);
    check_int("version-overflow.error", result.error,
              KZT_GUEST_DYNAMIC_ERROR_ADDRESS_OVERFLOW);
    check_true("version-overflow.no-verneed", !result.view.verneed.present);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_read_failure_reports_parser_state(void)
{
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_SYMTAB, .d_un.d_ptr = 0x5000010000 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };
    uintptr_t expected_error_addr = (uintptr_t)&dynamic[1];

    check_int("read-failure.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x100000,
                                      &ops, &result),
              0);
    check_int("read-failure.status", result.status,
              KZT_GUEST_DYNAMIC_READ_ERROR);
    check_int("read-failure.view-status", result.view.status,
              KZT_GUEST_DYNAMIC_READ_ERROR);
    check_int("read-failure.error", result.error,
              KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE);
    check_size("read-failure.entry-count", result.entry_count, 1);
    check_size("read-failure.view-entry-count", result.view.entry_count, 1);
    check_u64("read-failure.addr", result.read_error_addr,
              expected_error_addr);
    check_size("read-failure.scan-limit", result.scan_limit,
               KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_size("read-failure.view-scan-limit", result.view.scan_limit,
               KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_int("read-failure.reader-calls", memory.read_calls, 2);
    check_true("read-failure.no-null", !result.view.has_null);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_missing_null_stops_at_scan_limit(void)
{
    Elf64_Dyn dynamic[KZT_GUEST_DYNAMIC_SCAN_LIMIT];
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };
    size_t i;

    for (i = 0; i < TEST_ARRAY_SIZE(dynamic); ++i) {
        dynamic[i].d_tag = DT_SYMENT;
        dynamic[i].d_un.d_val = sizeof(Elf64_Sym);
    }

    check_int("scan-limit.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x100000,
                                      &ops, &result),
              0);
    check_int("scan-limit.status", result.status,
              KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL);
    check_int("scan-limit.view-status", result.view.status,
              KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL);
    check_int("scan-limit.error", result.error,
              KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED);
    check_size("scan-limit.entry-count", result.entry_count,
               KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_size("scan-limit.view-entry-count", result.view.entry_count,
               KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_size("scan-limit.scan-limit", result.scan_limit,
               KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_int("scan-limit.reader-calls", memory.read_calls,
              KZT_GUEST_DYNAMIC_SCAN_LIMIT);
    check_true("scan-limit.no-null", !result.view.has_null);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_unknown_tag_is_diagnostic_only(void)
{
    Elf64_Dyn dynamic[] = {
        { .d_tag = KZT_TEST_UNKNOWN_DYNAMIC_TAG, .d_un.d_val = 0x44 },
        { .d_tag = DT_STRTAB, .d_un.d_ptr = 0x5000020000 },
        { .d_tag = DT_NULL, .d_un.d_val = 0 },
    };
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };

    check_int("unknown-tag.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x100000,
                                      &ops, &result),
              0);
    check_int("unknown-tag.status", result.status,
              KZT_GUEST_DYNAMIC_COMPLETE);
    check_int("unknown-tag.error", result.error,
              KZT_GUEST_DYNAMIC_ERROR_NONE);
    check_size("unknown-tag.count", result.unknown_tag_count, 1);
    check_size("unknown-tag.view-count", result.view.unknown_tag_count, 1);
    check_i64("unknown-tag.first", result.first_unknown_tag,
              KZT_TEST_UNKNOWN_DYNAMIC_TAG);
    check_i64("unknown-tag.view-first", result.view.first_unknown_tag,
              KZT_TEST_UNKNOWN_DYNAMIC_TAG);
    check_size("unknown-tag.index", result.first_unknown_tag_index, 0);
    check_size("unknown-tag.view-index", result.view.first_unknown_tag_index,
               0);
    check_field("unknown-tag.strtab", &result.view.strtab, 0x5000020000,
                KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
    check_true("unknown-tag.has-null", result.view.has_null);

    kzt_guest_dynamic_parse_result_clear(&result);
}

static void test_too_many_needed_reports_resource_limit(void)
{
    Elf64_Dyn dynamic[KZT_GUEST_DYNAMIC_NEEDED_LIMIT + 2];
    fake_dynamic_memory_t memory = {
        .base = (uintptr_t)dynamic,
        .size = sizeof(dynamic),
    };
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_dynamic_parse_result_t result = { 0 };
    size_t i;

    for (i = 0; i < KZT_GUEST_DYNAMIC_NEEDED_LIMIT + 1; ++i) {
        dynamic[i].d_tag = DT_NEEDED;
        dynamic[i].d_un.d_val = i * 0x10;
    }
    dynamic[KZT_GUEST_DYNAMIC_NEEDED_LIMIT + 1].d_tag = DT_NULL;
    dynamic[KZT_GUEST_DYNAMIC_NEEDED_LIMIT + 1].d_un.d_val = 0;

    check_int("needed-limit.parse",
              kzt_guest_dynamic_parse((uintptr_t)dynamic, 0x100000,
                                      &ops, &result),
              0);
    check_int("needed-limit.status", result.status,
              KZT_GUEST_DYNAMIC_ERROR);
    check_int("needed-limit.view-status", result.view.status,
              KZT_GUEST_DYNAMIC_ERROR);
    check_int("needed-limit.error", result.error,
              KZT_GUEST_DYNAMIC_ERROR_TOO_MANY_NEEDED);
    check_size("needed-limit.entry-count", result.entry_count,
               KZT_GUEST_DYNAMIC_NEEDED_LIMIT);
    check_size("needed-limit.view-entry-count", result.view.entry_count,
               KZT_GUEST_DYNAMIC_NEEDED_LIMIT);
    check_size("needed-limit.needed-count", result.view.needed_count,
               KZT_GUEST_DYNAMIC_NEEDED_LIMIT);
    check_true("needed-limit.no-null", !result.view.has_null);

    kzt_guest_dynamic_parse_result_clear(&result);
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
    if (test_matches_filter("complete_runtime_dynamic_view", argc, argv)) {
        test_complete_runtime_dynamic_view();
    }
    if (test_matches_filter("dynamic_address_semantics", argc, argv)) {
        test_dynamic_address_semantics();
    }
    if (test_matches_filter("version_tables_are_load_bias_relative_only",
                            argc, argv)) {
        test_version_tables_are_load_bias_relative_only();
    }
    if (test_matches_filter("version_table_load_bias_overflow_is_fail_open",
                            argc, argv)) {
        test_version_table_load_bias_overflow_is_fail_open();
    }
    if (test_matches_filter("read_failure_reports_parser_state",
                            argc, argv)) {
        test_read_failure_reports_parser_state();
    }
    if (test_matches_filter("missing_null_stops_at_scan_limit", argc, argv)) {
        test_missing_null_stops_at_scan_limit();
    }
    if (test_matches_filter("unknown_tag_is_diagnostic_only", argc, argv)) {
        test_unknown_tag_is_diagnostic_only();
    }
    if (test_matches_filter("too_many_needed_reports_resource_limit",
                            argc, argv)) {
        test_too_many_needed_reports_resource_limit();
    }

    if (failures) {
        fprintf(stderr, "kzt-guest-dynamic-parser: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-guest-dynamic-parser: selected contract tests passed");
    return 0;
}
