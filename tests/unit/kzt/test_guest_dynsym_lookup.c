#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_guest_dynsym_lookup.h"

enum {
    TEST_LOAD_BIAS = 0x7000000000ULL,
    TEST_SYMTAB_ADDR = 0x7000010000ULL,
    TEST_STRTAB_ADDR = 0x7000020000ULL,
    TEST_GNU_HASH_ADDR = 0x7000030000ULL,
    TEST_HASH_ADDR = 0x7000040000ULL,
    TEST_VERSYM_ADDR = 0x7000050000ULL,
    TEST_VERDEF_ADDR = 0x7000060000ULL,
    TEST_VERNEED_ADDR = 0x7000070000ULL,
};

typedef struct fake_region {
    uintptr_t guest_base;
    const void *host_base;
    size_t size;
} fake_region_t;

typedef struct fake_memory {
    fake_region_t regions[16];
    size_t region_count;
    uintptr_t fail_addr;
} fake_memory_t;

typedef struct gnu_hash_one_symbol {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t bloom[1];
    uint32_t buckets[1];
    uint32_t chains[1];
} gnu_hash_one_symbol_t;

typedef struct gnu_hash_long_chain {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t bloom[1];
    uint32_t buckets[1];
    uint32_t chains[4096];
} gnu_hash_long_chain_t;

typedef struct gnu_hash_four_symbols {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t bloom[1];
    uint32_t buckets[1];
    uint32_t chains[4];
} gnu_hash_four_symbols_t;

typedef struct sysv_hash_three_symbols {
    uint32_t nbuckets;
    uint32_t nchains;
    uint32_t buckets[2];
    uint32_t chains[3];
} sysv_hash_three_symbols_t;

typedef struct version_definition {
    Elf64_Verdef definition;
    Elf64_Verdaux auxiliary;
} version_definition_t;

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_u32(const char *name, uint32_t got, uint32_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %u expected %u\n", name, got, expected);
    ++failures;
}

static void check_uintptr(const char *name,
                           uintptr_t got,
                           uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_unknown(const char *name,
                          const kzt_guest_dynsym_lookup_result_t *result)
{
    char field[128];

    snprintf(field, sizeof(field), "%s.status", name);
    check_int(field, result->status, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    snprintf(field, sizeof(field), "%s.binding", name);
    check_int(field, result->binding, 0);
    snprintf(field, sizeof(field), "%s.symbol-index", name);
    check_u32(field, result->symbol_index, 0);
    snprintf(field, sizeof(field), "%s.runtime-address", name);
    check_uintptr(field, result->runtime_address, 0);
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

static uint32_t gnu_hash(const char *name)
{
    uint32_t hash = 5381;

    while (*name) {
        hash = hash * 33 + (unsigned char)*name++;
    }

    return hash;
}

static uint32_t sysv_hash(const char *name)
{
    uint32_t hash = 0;

    while (*name) {
        uint32_t high;

        hash = (hash << 4) + (unsigned char)*name++;
        high = hash & UINT32_C(0xf0000000);
        if (high) {
            hash ^= high >> 24;
        }
        hash &= ~high;
    }

    return hash;
}

static void test_gnu_hash_finds_global_symbol(void)
{
    static const char strings[] = "\0target\0";
    Elf64_Sym symbols[2] = { 0 };
    gnu_hash_one_symbol_t hash = { 0 };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x1234;

    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 5;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    hash.chains[0] = symbol_hash | 1;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));

    memset(&result, 0xa5, sizeof(result));
    check_int("gnu.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("gnu.result-status", result.status,
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("gnu.binding", result.binding, STB_GLOBAL);
    check_u32("gnu.symbol-index", result.symbol_index, 1);
    check_uintptr("gnu.runtime-address", result.runtime_address,
                  TEST_LOAD_BIAS + 0x1234);

    view.symtab.address_semantics = KZT_GUEST_DYNAMIC_ADDRESS_UNKNOWN;
    check_int("gnu.unknown-address-semantics",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("gnu.unknown-address-semantics-result", &result);
}

static void test_sysv_hash_finds_global_symbol(void)
{
    static const char strings[] = "\0target\0other\0";
    Elf64_Sym symbols[3] = { 0 };
    sysv_hash_three_symbols_t hash = {
        .nbuckets = 2,
        .nchains = 3,
        .chains = { 0, 2, 0 },
    };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .hash = runtime_field(TEST_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;

    hash.buckets[sysv_hash("target") % hash.nbuckets] = 1;
    symbols[1].st_name = 8;
    symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x1111;
    symbols[2].st_name = 1;
    symbols[2].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[2].st_other = STV_DEFAULT;
    symbols[2].st_shndx = 1;
    symbols[2].st_value = 0x5678;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_HASH_ADDR, &hash, sizeof(hash));

    memset(&result, 0xa5, sizeof(result));
    check_int("sysv.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("sysv.result-status", result.status,
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("sysv.binding", result.binding, STB_GLOBAL);
    check_u32("sysv.symbol-index", result.symbol_index, 2);
    check_uintptr("sysv.runtime-address", result.runtime_address,
                  TEST_LOAD_BIAS + 0x5678);
}

static void test_gnu_hash_skips_ineligible_definitions(void)
{
    static const char strings[] = "\0target\0";
    Elf64_Sym symbols[5] = { 0 };
    gnu_hash_four_symbols_t hash = { 0 };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");
    size_t i;

    for (i = 1; i < 5; ++i) {
        symbols[i].st_name = 1;
        symbols[i].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
        symbols[i].st_other = STV_DEFAULT;
        symbols[i].st_shndx = 1;
        symbols[i].st_value = 0x1000 + i;
    }
    symbols[1].st_shndx = SHN_UNDEF;
    symbols[2].st_other = 2;
    symbols[3].st_info = ELF_ST_INFO(STB_LOCAL, STT_FUNC);
    symbols[4].st_other = STV_PROTECTED;

    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 5;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    for (i = 0; i < 3; ++i) {
        hash.chains[i] = symbol_hash & ~UINT32_C(1);
    }
    hash.chains[3] = symbol_hash | 1;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));

    check_int("eligibility.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("eligibility.binding", result.binding, STB_GLOBAL);
    check_u32("eligibility.symbol-index", result.symbol_index, 4);
    check_uintptr("eligibility.runtime-address", result.runtime_address,
                  TEST_LOAD_BIAS + 0x1004);
}

static void test_gnu_hash_reports_weak_binding(void)
{
    static const char strings[] = "\0target\0";
    Elf64_Sym symbols[2] = { 0 };
    gnu_hash_one_symbol_t hash = { 0 };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF_ST_INFO(STB_WEAK, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x3456;

    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 5;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    hash.chains[0] = symbol_hash | 1;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));

    check_int("weak.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("weak.binding", result.binding, STB_WEAK);
    check_u32("weak.symbol-index", result.symbol_index, 1);
    check_uintptr("weak.runtime-address", result.runtime_address,
                  TEST_LOAD_BIAS + 0x3456);
}

static void test_gnu_hash_counts_all_loader_candidate_kinds(void)
{
    static const char strings[] = "\0target\0";
    static const unsigned char types[] = {
        STT_NOTYPE,
        STT_OBJECT,
        STT_FUNC,
        STT_COMMON,
        STT_TLS,
#ifdef STT_GNU_IFUNC
        STT_GNU_IFUNC,
#endif
    };
    Elf64_Sym symbols[2] = { 0 };
    gnu_hash_one_symbol_t hash = { 0 };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");
    size_t i;

    symbols[1].st_name = 1;
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x4567;
    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 63;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    hash.chains[0] = symbol_hash | 1;
    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));

    for (i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, types[i]);
        check_int("loader-candidate.type",
                  kzt_guest_dynsym_lookup(
                      &view, &reader_ops, "target",
                      KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                      NULL, &result),
                  KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    }
#ifdef STB_GNU_UNIQUE
    symbols[1].st_info = ELF_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    check_int("loader-candidate.gnu-unique",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("loader-candidate.gnu-unique-binding",
              result.binding, STB_GNU_UNIQUE);
#endif
}

static void test_versioned_symbol_matches_verdef(void)
{
    static const char strings[] =
        "\0target\0GLIBC_2.2.5\0OTHER_1.0\0";
    Elf64_Sym symbols[2] = { 0 };
    Elf64_Half versions[2] = { 0, 2 };
    gnu_hash_one_symbol_t hash = { 0 };
    version_definition_t verdef = {
        .definition = {
            .vd_version = 1,
            .vd_ndx = 2,
            .vd_cnt = 1,
            .vd_aux = sizeof(Elf64_Verdef),
        },
        .auxiliary = {
            .vda_name = 8,
        },
    };
    fake_memory_t memory = {
        .fail_addr = TEST_VERNEED_ADDR,
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
        .versym = runtime_field(TEST_VERSYM_ADDR),
        .verneed = runtime_field(TEST_VERNEED_ADDR),
        .verneednum = scalar_field(1),
        .verdef = runtime_field(TEST_VERDEF_ADDR),
        .verdefnum = scalar_field(1),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x789a;

    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 5;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    hash.chains[0] = symbol_hash | 1;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));
    add_region(&memory, TEST_VERSYM_ADDR, versions, sizeof(versions));
    add_region(&memory, TEST_VERDEF_ADDR, &verdef, sizeof(verdef));

    check_int("version-match.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_VERSIONED, "GLIBC_2.2.5", &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
    check_int("version-match.binding", result.binding, STB_GLOBAL);
    check_u32("version-match.symbol-index", result.symbol_index, 1);
    check_uintptr("version-match.runtime-address", result.runtime_address,
                  TEST_LOAD_BIAS + 0x789a);

    check_int("version-mismatch.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_VERSIONED, "OTHER_1.0", &result),
              KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
    check_int("version-mismatch.result-status", result.status,
              KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
    check_int("version-mismatch.binding", result.binding, 0);
    check_u32("version-mismatch.symbol-index", result.symbol_index, 0);
    check_uintptr("version-mismatch.runtime-address",
                  result.runtime_address, 0);
}

static void test_unversioned_symbol_rejects_hidden_version(void)
{
    static const char strings[] = "\0target\0";
    Elf64_Sym symbols[2] = { 0 };
    Elf64_Half versions[2] = { 0, 0x8002 };
    gnu_hash_one_symbol_t hash = { 0 };
    fake_memory_t memory = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
        .versym = runtime_field(TEST_VERSYM_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uint32_t symbol_hash = gnu_hash("target");

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x4321;
    hash.nbuckets = 1;
    hash.symoffset = 1;
    hash.bloom_size = 1;
    hash.bloom_shift = 63;
    hash.bloom[0] = UINT64_MAX;
    hash.buckets[0] = 1;
    hash.chains[0] = symbol_hash | 1;

    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    add_region(&memory, TEST_GNU_HASH_ADDR, &hash, sizeof(hash));
    add_region(&memory, TEST_VERSYM_ADDR, versions, sizeof(versions));

    check_int("hidden-version.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
    versions[1] = 2;
    check_int("default-version.status",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_FOUND);
}

static void test_untrusted_gnu_hash_returns_unknown(void)
{
    static const char strings[] = "\0target\0";
    Elf64_Sym symbols[2] = { 0 };
    gnu_hash_one_symbol_t bad_header = {
        .nbuckets = 1,
        .symoffset = 1,
        .bloom_size = 0,
        .bloom_shift = 5,
    };
    gnu_hash_one_symbol_t overflow_header = {
        .nbuckets = 1,
        .symoffset = 1,
        .bloom_size = 1,
        .bloom_shift = 5,
    };
    gnu_hash_one_symbol_t bad_shift = {
        .nbuckets = 1,
        .symoffset = 1,
        .bloom_size = 1,
        .bloom_shift = 64,
        .bloom = { UINT64_MAX },
    };
    sysv_hash_three_symbols_t valid_sysv_fallback = {
        .nbuckets = 2,
        .nchains = 2,
    };
    gnu_hash_long_chain_t long_chain = {
        .nbuckets = 1,
        .symoffset = 1,
        .bloom_size = 1,
        .bloom_shift = 5,
        .bloom = { UINT64_MAX },
        .buckets = { 1 },
    };
    fake_memory_t memory = {
        .fail_addr = TEST_GNU_HASH_ADDR,
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_dynamic_view_t view = {
        .load_bias = TEST_LOAD_BIAS,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .has_null = 1,
        .symtab = runtime_field(TEST_SYMTAB_ADDR),
        .strtab = runtime_field(TEST_STRTAB_ADDR),
        .syment = scalar_field(sizeof(Elf64_Sym)),
        .strsz = scalar_field(sizeof(strings)),
        .gnu_hash = runtime_field(TEST_GNU_HASH_ADDR),
    };
    kzt_guest_dynsym_lookup_result_t result;
    uintptr_t overflow_addr = UINTPTR_MAX - 15;

    memset(&result, 0xa5, sizeof(result));
    check_int("read-failure.return",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("read-failure", &result);

    memory.fail_addr = 0;
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 0x1234;
    valid_sysv_fallback
        .buckets[sysv_hash("target") % valid_sysv_fallback.nbuckets] = 1;
    add_region(&memory, TEST_GNU_HASH_ADDR, &bad_header,
               sizeof(bad_header));
    add_region(&memory, TEST_HASH_ADDR, &valid_sysv_fallback,
               sizeof(valid_sysv_fallback));
    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    view.hash = runtime_field(TEST_HASH_ADDR);
    memset(&result, 0xa5, sizeof(result));
    check_int("bad-header.return",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("bad-header", &result);

    memset(&memory, 0, sizeof(memory));
    add_region(&memory, TEST_GNU_HASH_ADDR, &bad_shift, sizeof(bad_shift));
    memset(&result, 0xa5, sizeof(result));
    check_int("bad-shift.return",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("bad-shift", &result);

    memset(&memory, 0, sizeof(memory));
    add_region(&memory, overflow_addr, &overflow_header,
               sizeof(uint32_t) * 4);
    view.gnu_hash = runtime_field(overflow_addr);
    memset(&result, 0xa5, sizeof(result));
    check_int("overflow.return",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("overflow", &result);

    memset(&memory, 0, sizeof(memory));
    view.gnu_hash = runtime_field(TEST_GNU_HASH_ADDR);
    add_region(&memory, TEST_GNU_HASH_ADDR, &long_chain,
               sizeof(long_chain));
    add_region(&memory, TEST_SYMTAB_ADDR, symbols, sizeof(symbols));
    add_region(&memory, TEST_STRTAB_ADDR, strings, sizeof(strings));
    memset(&result, 0xa5, sizeof(result));
    check_int("chain-limit.return",
              kzt_guest_dynsym_lookup(
                  &view, &reader_ops, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &result),
              KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    check_unknown("chain-limit", &result);
}

int main(void)
{
    test_gnu_hash_finds_global_symbol();
    test_sysv_hash_finds_global_symbol();
    test_gnu_hash_skips_ineligible_definitions();
    test_gnu_hash_reports_weak_binding();
    test_gnu_hash_counts_all_loader_candidate_kinds();
    test_versioned_symbol_matches_verdef();
    test_unversioned_symbol_rejects_hidden_version();
    test_untrusted_gnu_hash_returns_unknown();

    if (failures) {
        fprintf(stderr, "FAIL: %d assertion(s)\n", failures);
        return 1;
    }

    puts("PASS");
    return 0;
}
