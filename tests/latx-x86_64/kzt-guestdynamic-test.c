#include "guestdynamic.h"

#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int failures;

static void check_int(const char *name, unsigned long got,
                      unsigned long expected)
{
    if (got == expected)
        return;

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void test_ready_dynamic_info(void)
{
    Elf64_Dyn dynamic[] = {
        {.d_tag = DT_NEEDED, .d_un.d_val = 7},
        {.d_tag = DT_RPATH, .d_un.d_val = 11},
        {.d_tag = DT_RUNPATH, .d_un.d_val = 13},
        {.d_tag = DT_STRTAB, .d_un.d_ptr = 0x1000},
        {.d_tag = DT_STRSZ, .d_un.d_val = 0x80},
        {.d_tag = DT_SYMTAB, .d_un.d_ptr = 0x2000},
        {.d_tag = DT_SYMENT, .d_un.d_val = sizeof(Elf64_Sym)},
        {.d_tag = DT_RELA, .d_un.d_ptr = 0x3000},
        {.d_tag = DT_RELASZ, .d_un.d_val = 2 * sizeof(Elf64_Rela)},
        {.d_tag = DT_RELAENT, .d_un.d_val = sizeof(Elf64_Rela)},
        {.d_tag = DT_JMPREL, .d_un.d_ptr = 0x4000},
        {.d_tag = DT_PLTRELSZ, .d_un.d_val = 3 * sizeof(Elf64_Rela)},
        {.d_tag = DT_PLTREL, .d_un.d_val = DT_RELA},
        {.d_tag = DT_PLTGOT, .d_un.d_ptr = 0x5000},
        {.d_tag = DT_INIT_ARRAY, .d_un.d_ptr = 0x6000},
        {.d_tag = DT_INIT_ARRAYSZ, .d_un.d_val = 4 * sizeof(Elf64_Addr)},
        {.d_tag = DT_FINI_ARRAY, .d_un.d_ptr = 0x7000},
        {.d_tag = DT_FINI_ARRAYSZ, .d_un.d_val = sizeof(Elf64_Addr)},
        {.d_tag = DT_VERNEED, .d_un.d_ptr = 0x8000},
        {.d_tag = DT_VERNEEDNUM, .d_un.d_val = 2},
        {.d_tag = DT_NULL},
    };
    KztDynamicView view;
    KztDynamicInfo info;

    KztParseDynamicView(&view, dynamic, ARRAY_SIZE(dynamic));
    KztBuildDynamicInfo(&info, &view);

    check_int("ready.status", view.status, KZT_DYNAMIC_VIEW_READY);
    check_int("ready.entries", view.entry_count, ARRAY_SIZE(dynamic) - 1);
    check_int("ready.needed", view.summary.needed_count, 1);
    check_int("ready.rpath", view.summary.rpath_count, 1);
    check_int("ready.runpath", view.summary.runpath_count, 1);
    check_int("ready.strtab", info.strtab, 0x1000);
    check_int("ready.strsz", info.strsz, 0x80);
    check_int("ready.symtab", info.symtab, 0x2000);
    check_int("ready.rela", info.rela, 0x3000);
    check_int("ready.relasz", info.relasz, 2 * sizeof(Elf64_Rela));
    check_int("ready.rela_count_available", info.has_rela_count, 1);
    check_int("ready.rela_count", info.rela_count, 2);
    check_int("ready.pltent", info.pltent, sizeof(Elf64_Rela));
    check_int("ready.plt_count_available", info.has_plt_count, 1);
    check_int("ready.plt_count", info.plt_count, 3);
    check_int("ready.initarray_count", info.initarray_count, 4);
    check_int("ready.finiarray_count", info.finiarray_count, 1);
    check_int("ready.verneed_count", info.verneed_count, 2);
    check_int("ready.errors", info.errors, 0);
}

static void test_empty_and_truncated_dynamic(void)
{
    Elf64_Dyn dynamic[] = {
        {.d_tag = DT_NEEDED, .d_un.d_val = 1},
    };
    KztDynamicView view;

    KztParseDynamicView(&view, NULL, 16);
    check_int("empty.status", view.status, KZT_DYNAMIC_VIEW_EMPTY);
    check_int("empty.entries", view.entry_count, 0);

    KztParseDynamicView(&view, dynamic, ARRAY_SIZE(dynamic));
    check_int("truncated.status", view.status, KZT_DYNAMIC_VIEW_TRUNCATED);
    check_int("truncated.entries", view.entry_count, ARRAY_SIZE(dynamic));
    check_int("truncated.flag", view.summary.truncated, 1);
}

static void test_dynamic_info_errors(void)
{
    Elf64_Dyn dynamic[] = {
        {.d_tag = DT_REL, .d_un.d_ptr = 0x1000},
        {.d_tag = DT_RELENT, .d_un.d_val = 1},
        {.d_tag = DT_JMPREL, .d_un.d_ptr = 0x2000},
        {.d_tag = DT_PLTREL, .d_un.d_val = DT_REL},
        {.d_tag = DT_PLTRELSZ, .d_un.d_val = sizeof(Elf64_Rel) + 1},
        {.d_tag = DT_NULL},
    };
    KztDynamicView view;
    KztDynamicInfo info;

    KztParseDynamicView(&view, dynamic, ARRAY_SIZE(dynamic));
    KztBuildDynamicInfo(&info, &view);

    check_int("errors.status", view.status, KZT_DYNAMIC_VIEW_READY);
    check_int("errors.flags", info.errors,
              KZT_DYNAMIC_ERROR_RELENT | KZT_DYNAMIC_ERROR_PLTSZ);
}

static void test_dynamic_string_iteration(void)
{
    static const char strtab[] =
        "\0libfirst.so\0ignored-rpath\0libsecond.so\0";
    Elf64_Dyn dynamic[] = {
        {.d_tag = DT_NEEDED, .d_un.d_val = 1},
        {.d_tag = DT_RPATH, .d_un.d_val = 13},
        {.d_tag = DT_NEEDED, .d_un.d_val = 27},
        {.d_tag = DT_NEEDED, .d_un.d_val = sizeof(strtab)},
        {.d_tag = DT_NULL},
    };
    KztDynamicStringTable strings = {
        .data = strtab,
        .size = sizeof(strtab),
    };
    KztDynamicStringEntry entry;
    KztDynamicView view;
    size_t index = 0;

    KztParseDynamicView(&view, dynamic, ARRAY_SIZE(dynamic));

    check_int("strings.first", KztNextDynamicString(&view, DT_NEEDED,
                                                    &index, &strings,
                                                    &entry), 1);
    check_int("strings.first.offset", entry.offset, 1);
    check_int("strings.first.value", entry.value[3], 'f');

    check_int("strings.second", KztNextDynamicString(&view, DT_NEEDED,
                                                     &index, &strings,
                                                     &entry), 1);
    check_int("strings.second.offset", entry.offset, 27);
    check_int("strings.second.value", entry.value[3], 's');

    check_int("strings.invalid", KztNextDynamicString(&view, DT_NEEDED,
                                                      &index, &strings,
                                                      &entry), 1);
    check_int("strings.invalid.value", (uintptr_t)entry.value, 0);

    check_int("strings.done", KztNextDynamicString(&view, DT_NEEDED,
                                                   &index, &strings,
                                                   &entry), 0);
}

static void test_dynamic_symbol_counts(void)
{
    uint32_t sysv_hash[] = {
        1, 9, 0, 0,
    };
    struct {
        uint32_t header[4];
        Elf64_Addr bloom[1];
        uint32_t buckets[1];
        uint32_t chains[2];
    } gnu_hash = {
        .header = {1, 3, 1, 0},
        .bloom = {0},
        .buckets = {3},
        .chains = {0, 1},
    };
    KztDynamicInfo info;

    memset(&info, 0, sizeof(info));
    info.hash = (uintptr_t)sysv_hash;
    check_int("symbols.sysv.available",
              KztResolveDynamicSymbolCount(&info, 0), 1);
    check_int("symbols.sysv.has_count", info.has_dynsym_count, 1);
    check_int("symbols.sysv.count", info.dynsym_count, 9);

    memset(&info, 0, sizeof(info));
    info.gnu_hash = (uintptr_t)&gnu_hash;
    check_int("symbols.gnu.available",
              KztResolveDynamicSymbolCount(&info, 0), 1);
    check_int("symbols.gnu.has_count", info.has_dynsym_count, 1);
    check_int("symbols.gnu.count", info.dynsym_count, 5);
    check_int("symbols.gnu.errors", info.errors, 0);
}

static void test_dynamic_info_for_object(void)
{
    uint32_t sysv_hash[] = {
        1, 4, 0, 0,
    };
    Elf64_Dyn dynamic[] = {
        {.d_tag = DT_STRTAB, .d_un.d_ptr = 0x1000},
        {.d_tag = DT_STRSZ, .d_un.d_val = 0x20},
        {.d_tag = DT_HASH, .d_un.d_ptr = (uintptr_t)sysv_hash},
        {.d_tag = DT_NULL},
    };
    KztDynamicView view;
    KztDynamicInfo info;

    KztParseDynamicView(&view, dynamic, ARRAY_SIZE(dynamic));
    KztBuildDynamicInfoForObject(&info, &view, 0);

    check_int("info-object.strtab", info.strtab, 0x1000);
    check_int("info-object.has-dynsym-count", info.has_dynsym_count, 1);
    check_int("info-object.dynsym-count", info.dynsym_count, 4);
}

static void test_dynamic_symbol_entries(void)
{
    static const char strtab[] = "\0alpha\0beta\0";
    Elf64_Sym symbols[] = {
        {.st_name = 1, .st_info = 0x12, .st_other = 0,
         .st_shndx = 3, .st_value = 0x1000, .st_size = 0x20},
        {.st_name = 7, .st_info = 0x22, .st_other = 1,
         .st_shndx = 4, .st_value = 0x2000, .st_size = 0x30},
    };
    KztDynamicSymbolTable table = {
        .symbols = symbols,
        .count = ARRAY_SIZE(symbols),
        .strings = {
            .data = strtab,
            .size = sizeof(strtab),
        },
    };
    KztDynamicInfo info;
    KztDynamicSymbolEntry entry;

    memset(&info, 0, sizeof(info));
    info.strtab = (uintptr_t)strtab;
    info.strsz = sizeof(strtab);
    info.symtab = (uintptr_t)symbols;
    info.dynsym_count = ARRAY_SIZE(symbols);
    info.has_dynsym_count = 1;
    memset(&table, 0, sizeof(table));
    check_int("symtab.from-info",
              KztDynamicSymbolTableFromInfo(&info, 0, &table), 1);
    check_int("symtab.from-info.count", table.count, ARRAY_SIZE(symbols));
    check_int("symtab.from-info.strtab", (uintptr_t)table.strings.data,
              (uintptr_t)strtab);

    check_int("symtab.first", KztDynamicSymbolAt(&table, 0, &entry), 1);
    check_int("symtab.first.name", entry.name[0], 'a');
    check_int("symtab.first.value", entry.symbol->st_value, 0x1000);

    check_int("symtab.second", KztDynamicSymbolAt(&table, 1, &entry), 1);
    check_int("symtab.second.name", entry.name[0], 'b');
    check_int("symtab.second.size", entry.symbol->st_size, 0x30);

    check_int("symtab.done", KztDynamicSymbolAt(&table, 2, &entry), 0);
}

static void test_dynamic_versym_pointer(void)
{
    Elf64_Half versym[] = {0, 2, 3};

    check_int("versym.ptr",
              (uintptr_t)KztDynamicVersymFromPtr((uintptr_t)versym, 0),
              (uintptr_t)versym);
    check_int("versym.null",
              (uintptr_t)KztDynamicVersymFromPtr(0, 0), 0);
}

static void test_dynamic_verneed_entries(void)
{
    static const char strtab[] = "\0libc.so.6\0GLIBC_2.2.5\0GLIBC_2.17\0";
    struct {
        Elf64_Verneed need;
        Elf64_Vernaux aux[2];
    } verneed = {
        .need = {
            .vn_version = 1,
            .vn_cnt = 2,
            .vn_file = 1,
            .vn_aux = sizeof(Elf64_Verneed),
        },
        .aux = {
            {
                .vna_hash = 0x1234,
                .vna_other = 2,
                .vna_name = 11,
                .vna_next = sizeof(Elf64_Vernaux),
            },
            {
                .vna_hash = 0x5678,
                .vna_other = 3,
                .vna_name = 23,
            },
        },
    };
    KztDynamicStringTable strings = {
        .data = strtab,
        .size = sizeof(strtab),
    };
    KztDynamicVerneedEntry need;
    KztDynamicVernauxEntry aux;

    check_int("verneed.ptr",
              (uintptr_t)KztDynamicVerneedFromPtr((uintptr_t)&verneed, 0),
              (uintptr_t)&verneed);
    check_int("verneed.entry",
              KztDynamicVerneedAt(&verneed.need, 0, &strings, &need), 1);
    check_int("verneed.file", need.file[0], 'l');
    check_int("verneed.aux0",
              KztDynamicVernauxAt(&need, 0, &strings, &aux), 1);
    check_int("verneed.aux0.name", aux.name[6], '2');
    check_int("verneed.aux0.other", aux.record->vna_other, 2);
    check_int("verneed.aux1",
              KztDynamicVernauxAt(&need, 1, &strings, &aux), 1);
    check_int("verneed.aux1.name", aux.name[8], '1');
    check_int("verneed.done",
              KztDynamicVernauxAt(&need, 2, &strings, &aux), 0);
    check_int("verneed.walk-limit",
              KztDynamicVerneedAt(&verneed.need,
                                  KZT_DYNAMIC_VERSION_WALK_MAX,
                                  &strings, &need), 0);
    verneed.need.vn_aux = 0;
    check_int("verneed.no-aux",
              KztDynamicVernauxAt(&need, 0, &strings, &aux), 0);
}

static void test_dynamic_verdef_entries(void)
{
    static const char strtab[] = "\0libfoo.so\0FOO_1.0\0FOO_PRIVATE\0";
    struct {
        Elf64_Verdef def;
        Elf64_Verdaux aux[2];
    } verdef = {
        .def = {
            .vd_version = 1,
            .vd_ndx = 2,
            .vd_cnt = 2,
            .vd_hash = 0x12345678,
            .vd_aux = sizeof(Elf64_Verdef),
        },
        .aux = {
            {
                .vda_name = 11,
                .vda_next = sizeof(Elf64_Verdaux),
            },
            {
                .vda_name = 19,
            },
        },
    };
    KztDynamicStringTable strings = {
        .data = strtab,
        .size = sizeof(strtab),
    };
    KztDynamicVerdefEntry def;
    KztDynamicVerdauxEntry aux;

    check_int("verdef.ptr",
              (uintptr_t)KztDynamicVerdefFromPtr((uintptr_t)&verdef, 0),
              (uintptr_t)&verdef);
    check_int("verdef.entry",
              KztDynamicVerdefAt(&verdef.def, 0, &def), 1);
    check_int("verdef.index", def.record->vd_ndx, 2);
    check_int("verdef.aux0",
              KztDynamicVerdauxAt(&def, 0, &strings, &aux), 1);
    check_int("verdef.aux0.name", aux.name[4], '1');
    check_int("verdef.aux1",
              KztDynamicVerdauxAt(&def, 1, &strings, &aux), 1);
    check_int("verdef.aux1.name", aux.name[4], 'P');
    check_int("verdef.done",
              KztDynamicVerdauxAt(&def, 2, &strings, &aux), 0);
    check_int("verdef.walk-limit",
              KztDynamicVerdefAt(&verdef.def,
                                 KZT_DYNAMIC_VERSION_WALK_MAX, &def), 0);
    verdef.def.vd_aux = 0;
    check_int("verdef.no-aux",
              KztDynamicVerdauxAt(&def, 0, &strings, &aux), 0);
}

static void test_dynamic_relocation_entries(void)
{
    Elf64_Rel rel[] = {
        {.r_offset = 0x1000, .r_info = 0x1234},
    };
    Elf64_Rela rela[] = {
        {.r_offset = 0x2000, .r_info = 0x5678, .r_addend = -8},
    };
    KztDynamicRelocationTable table;
    KztDynamicRelocationEntry entry;

    check_int("relocs.ptr",
              (uintptr_t)KztDynamicRelocationsFromPtr((uintptr_t)rel, 0),
              (uintptr_t)rel);
    check_int("relocs.null",
              (uintptr_t)KztDynamicRelocationsFromPtr(0, 0), 0);

    table.entries = rel;
    table.count = ARRAY_SIZE(rel);
    table.entry_size = sizeof(Elf64_Rel);
    check_int("relocs.rel.entry",
              KztDynamicRelocationAt(&table, 0, &entry), 1);
    check_int("relocs.rel.offset", entry.offset, 0x1000);
    check_int("relocs.rel.info", entry.info, 0x1234);
    check_int("relocs.rel.has-addend", entry.has_addend, 0);
    check_int("relocs.rel.done",
              KztDynamicRelocationAt(&table, 1, &entry), 0);

    table.entries = rela;
    table.count = ARRAY_SIZE(rela);
    table.entry_size = sizeof(Elf64_Rela);
    check_int("relocs.rela.entry",
              KztDynamicRelocationAt(&table, 0, &entry), 1);
    check_int("relocs.rela.offset", entry.offset, 0x2000);
    check_int("relocs.rela.info", entry.info, 0x5678);
    check_int("relocs.rela.addend", (unsigned long)entry.addend,
              (unsigned long)-8);
    check_int("relocs.rela.has-addend", entry.has_addend, 1);

    table.entry_size = 1;
    check_int("relocs.invalid",
              KztDynamicRelocationAt(&table, 0, &entry), 0);
}

int main(void)
{
    test_ready_dynamic_info();
    test_empty_and_truncated_dynamic();
    test_dynamic_info_errors();
    test_dynamic_string_iteration();
    test_dynamic_symbol_counts();
    test_dynamic_info_for_object();
    test_dynamic_symbol_entries();
    test_dynamic_versym_pointer();
    test_dynamic_verneed_entries();
    test_dynamic_verdef_entries();
    test_dynamic_relocation_entries();

    if (failures)
        return 1;

    puts("KZT guestdynamic tests passed");
    return 0;
}
