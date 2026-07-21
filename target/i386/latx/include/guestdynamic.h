#ifndef __GUESTDYNAMIC_H_
#define __GUESTDYNAMIC_H_

#include <stddef.h>
#include <stdint.h>

#include "elf.h"

#define KZT_DYNAMIC_SCAN_MAX 4096
#define KZT_DYNAMIC_VERSION_WALK_MAX 4096

typedef int (*KztDynamicRangeValidator)(const void *addr, size_t size,
                                        void *opaque);

typedef struct KztDynamicSummary {
    size_t entries;
    size_t needed_count;
    size_t rpath_count;
    size_t runpath_count;
    int has_null;
    int truncated;
    uintptr_t strtab;
    size_t strsz;
    uintptr_t symtab;
    size_t syment;
    uintptr_t hash;
    uintptr_t gnu_hash;
    uintptr_t rel;
    size_t relsz;
    size_t relent;
    uintptr_t rela;
    size_t relasz;
    size_t relaent;
    uintptr_t jmprel;
    size_t pltrelsz;
    uint64_t pltrel;
    uintptr_t pltgot;
    uintptr_t init;
    uintptr_t init_array;
    size_t init_arraysz;
    uintptr_t fini;
    uintptr_t fini_array;
    size_t fini_arraysz;
    uintptr_t versym;
    uintptr_t verneed;
    size_t verneednum;
    uintptr_t verdef;
    size_t verdefnum;
} KztDynamicSummary;

typedef enum KztDynamicViewStatus {
    KZT_DYNAMIC_VIEW_EMPTY,
    KZT_DYNAMIC_VIEW_READY,
    KZT_DYNAMIC_VIEW_TRUNCATED,
} KztDynamicViewStatus;

typedef struct KztDynamicView {
    const Elf64_Dyn *entries;
    size_t entry_count;
    KztDynamicViewStatus status;
    KztDynamicSummary summary;
} KztDynamicView;

typedef enum KztDynamicError {
    KZT_DYNAMIC_ERROR_RELENT = 1u << 0,
    KZT_DYNAMIC_ERROR_RELAENT = 1u << 1,
    KZT_DYNAMIC_ERROR_PLTREL = 1u << 2,
    KZT_DYNAMIC_ERROR_PLTSZ = 1u << 3,
    KZT_DYNAMIC_ERROR_GNU_HASH = 1u << 4,
} KztDynamicError;

typedef struct KztDynamicInfo {
    KztDynamicRangeValidator range_is_readable;
    void *range_opaque;
    uintptr_t strtab;
    size_t strsz;
    uintptr_t symtab;
    size_t syment;
    uintptr_t hash;
    uintptr_t gnu_hash;
    size_t dynsym_count;
    int has_dynsym_count;
    uintptr_t rel;
    size_t relsz;
    int relent;
    size_t rel_count;
    int has_rel_count;
    uintptr_t rela;
    size_t relasz;
    int relaent;
    size_t rela_count;
    int has_rela_count;
    uintptr_t jmprel;
    size_t pltsz;
    int pltent;
    size_t plt_count;
    int has_plt_count;
    uint64_t pltrel;
    uintptr_t pltgot;
    uintptr_t initentry;
    uintptr_t initarray;
    size_t initarray_count;
    uintptr_t finientry;
    uintptr_t finiarray;
    size_t finiarray_count;
    uintptr_t versym;
    uintptr_t verneed;
    int verneed_count;
    uintptr_t verdef;
    int verdef_count;
    unsigned errors;
} KztDynamicInfo;

typedef struct KztDynamicStringTable {
    const char *data;
    size_t size;
} KztDynamicStringTable;

typedef struct KztDynamicStringEntry {
    const Elf64_Dyn *dynamic;
    size_t offset;
    const char *value;
} KztDynamicStringEntry;

typedef struct KztDynamicSymbolTable {
    const Elf64_Sym *symbols;
    size_t count;
    KztDynamicStringTable strings;
} KztDynamicSymbolTable;

typedef struct KztDynamicSymbolEntry {
    const Elf64_Sym *symbol;
    const char *name;
} KztDynamicSymbolEntry;

typedef struct KztDynamicVerneedEntry {
    const KztDynamicInfo *info;
    const Elf64_Verneed *record;
    const char *file;
} KztDynamicVerneedEntry;

typedef struct KztDynamicVernauxEntry {
    const Elf64_Vernaux *record;
    const char *name;
} KztDynamicVernauxEntry;

typedef struct KztDynamicVerdefEntry {
    const KztDynamicInfo *info;
    const Elf64_Verdef *record;
} KztDynamicVerdefEntry;

typedef struct KztDynamicVerdauxEntry {
    const Elf64_Verdaux *record;
    const char *name;
} KztDynamicVerdauxEntry;

typedef struct KztDynamicRelocationTable {
    const void *entries;
    size_t count;
    int entry_size;
} KztDynamicRelocationTable;

typedef struct KztDynamicRelocationEntry {
    uintptr_t offset;
    uint64_t info;
    int64_t addend;
    int has_addend;
} KztDynamicRelocationEntry;

void KztParseDynamicView(KztDynamicView *view, const Elf64_Dyn *dynamic,
                         size_t max_entries);
void KztBuildDynamicInfo(KztDynamicInfo *info, const KztDynamicView *view);
void KztDynamicInfoSetRangeValidator(KztDynamicInfo *info,
                                     KztDynamicRangeValidator validator,
                                     void *opaque);
void KztBuildDynamicInfoForObject(KztDynamicInfo *info,
                                  const KztDynamicView *view,
                                  uintptr_t load_bias);
uintptr_t KztDynamicApplyLoadBias(uintptr_t value, uintptr_t load_bias);
const char *KztDynamicStrtabFromPtr(uintptr_t strtab, uintptr_t load_bias);
int KztDynamicStringTableFromInfo(const KztDynamicInfo *info,
                                  uintptr_t load_bias,
                                  KztDynamicStringTable *table);
const char *KztDynamicStringAt(const KztDynamicStringTable *strtab,
                               size_t offset);
int KztNextDynamicString(const KztDynamicView *view, int tag,
                         size_t *index,
                         const KztDynamicStringTable *strtab,
                         KztDynamicStringEntry *entry);
int KztResolveDynamicSymbolCount(KztDynamicInfo *info, uintptr_t load_bias);
const Elf64_Sym *KztDynamicSymtabFromPtr(uintptr_t symtab,
                                         uintptr_t load_bias);
int KztDynamicSymbolTableFromInfo(const KztDynamicInfo *info,
                                  uintptr_t load_bias,
                                  KztDynamicSymbolTable *table);
int KztDynamicSymbolAt(const KztDynamicSymbolTable *symtab, size_t index,
                       KztDynamicSymbolEntry *entry);
const Elf64_Half *KztDynamicVersymFromPtr(uintptr_t versym,
                                          uintptr_t load_bias);
const Elf64_Half *KztDynamicVersymFromInfo(const KztDynamicInfo *info,
                                           uintptr_t load_bias);
const Elf64_Verneed *KztDynamicVerneedFromPtr(uintptr_t verneed,
                                              uintptr_t load_bias);
const Elf64_Verneed *KztDynamicVerneedFromInfo(const KztDynamicInfo *info,
                                               uintptr_t load_bias);
int KztDynamicVerneedAt(const Elf64_Verneed *base, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVerneedEntry *entry);
int KztDynamicVerneedAtFromInfo(const KztDynamicInfo *info,
                                const Elf64_Verneed *base, size_t index,
                                const KztDynamicStringTable *strtab,
                                KztDynamicVerneedEntry *entry);
int KztDynamicVernauxAt(const KztDynamicVerneedEntry *verneed, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVernauxEntry *entry);
const Elf64_Verdef *KztDynamicVerdefFromPtr(uintptr_t verdef,
                                            uintptr_t load_bias);
const Elf64_Verdef *KztDynamicVerdefFromInfo(const KztDynamicInfo *info,
                                             uintptr_t load_bias);
int KztDynamicVerdefAt(const Elf64_Verdef *base, size_t index,
                       KztDynamicVerdefEntry *entry);
int KztDynamicVerdefAtFromInfo(const KztDynamicInfo *info,
                               const Elf64_Verdef *base, size_t index,
                               KztDynamicVerdefEntry *entry);
int KztDynamicVerdauxAt(const KztDynamicVerdefEntry *verdef, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVerdauxEntry *entry);
const void *KztDynamicRelocationsFromPtr(uintptr_t relocations,
                                         uintptr_t load_bias);
const void *KztDynamicRelocationsFromInfo(const KztDynamicInfo *info,
                                          uintptr_t relocations,
                                          uintptr_t load_bias,
                                          size_t count, int entry_size);
int KztDynamicRelocationAt(const KztDynamicRelocationTable *table,
                           size_t index,
                           KztDynamicRelocationEntry *entry);

#endif //__GUESTDYNAMIC_H_
