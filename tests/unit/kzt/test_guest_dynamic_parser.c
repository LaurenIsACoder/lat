#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_dynamic.h"

#define TEST_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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
        { .d_tag = DT_VERNEED, .d_un.d_ptr = 0x7000060000 },
        { .d_tag = DT_VERNEEDNUM, .d_un.d_val = 2 },
        { .d_tag = DT_VERDEF, .d_un.d_ptr = 0x7000070000 },
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

    if (failures) {
        fprintf(stderr, "kzt-guest-dynamic-parser: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-guest-dynamic-parser: selected contract tests passed");
    return 0;
}
