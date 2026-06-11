#include "guestdynamic.h"

#include <string.h>

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

#define KZT_GNU_HASH_CHAIN_WALK_MAX (1024 * 1024)

static int KztDynamicRangeIsReadable(const KztDynamicInfo *info,
                                     const void *addr, size_t size)
{
    uintptr_t start = (uintptr_t)addr;

    if (!addr)
        return 0;
    if (!size)
        return 1;
    if (size > UINTPTR_MAX - start)
        return 0;
    if (!info || !info->range_is_readable)
        return 1;
    return info->range_is_readable(addr, size, info->range_opaque);
}

static int KztDynamicTableRangeIsReadable(const KztDynamicInfo *info,
                                          const void *addr, size_t count,
                                          size_t entry_size)
{
    if (!addr || !count || !entry_size)
        return 0;
    if (count > SIZE_MAX / entry_size)
        return 0;
    return KztDynamicRangeIsReadable(info, addr, count * entry_size);
}

static int KztDynamicOffsetPtr(uintptr_t base, size_t count,
                               size_t entry_size, uintptr_t *result)
{
    size_t offset;

    if (count > SIZE_MAX / entry_size)
        return 0;

    offset = count * entry_size;
    if (offset > UINTPTR_MAX - base)
        return 0;

    *result = base + offset;
    return 1;
}

/*
 * The in-memory parser builds a compact view from l_ld.  It deliberately
 * records only dynamic-loader facts that can be compared with the legacy
 * file parser or consumed by later loader code.
 */
static void KztDynamicSummaryAdd(KztDynamicSummary *summary,
                                 const Elf64_Dyn *entry)
{
    Elf64_Word val = entry->d_un.d_val;
    Elf64_Addr ptr = entry->d_un.d_ptr;

    switch (entry->d_tag) {
        case DT_NEEDED:
            ++summary->needed_count;
            break;
        case DT_RPATH:
            ++summary->rpath_count;
            break;
        case DT_RUNPATH:
            ++summary->runpath_count;
            break;
        case DT_STRTAB:
            summary->strtab = ptr;
            break;
        case DT_STRSZ:
            summary->strsz = val;
            break;
        case DT_SYMTAB:
            summary->symtab = ptr;
            break;
        case DT_SYMENT:
            summary->syment = val;
            break;
        case DT_HASH:
            summary->hash = ptr;
            break;
        case DT_GNU_HASH:
            summary->gnu_hash = ptr;
            break;
        case DT_REL:
            summary->rel = ptr;
            break;
        case DT_RELSZ:
            summary->relsz = val;
            break;
        case DT_RELENT:
            summary->relent = val;
            break;
        case DT_RELA:
            summary->rela = ptr;
            break;
        case DT_RELASZ:
            summary->relasz = val;
            break;
        case DT_RELAENT:
            summary->relaent = val;
            break;
        case DT_JMPREL:
            summary->jmprel = ptr;
            break;
        case DT_PLTRELSZ:
            summary->pltrelsz = val;
            break;
        case DT_PLTREL:
            summary->pltrel = val;
            break;
        case DT_PLTGOT:
            summary->pltgot = ptr;
            break;
        case DT_INIT:
            summary->init = ptr;
            break;
        case DT_INIT_ARRAY:
            summary->init_array = ptr;
            break;
        case DT_INIT_ARRAYSZ:
            summary->init_arraysz = val;
            break;
        case DT_FINI:
            summary->fini = ptr;
            break;
        case DT_FINI_ARRAY:
            summary->fini_array = ptr;
            break;
        case DT_FINI_ARRAYSZ:
            summary->fini_arraysz = val;
            break;
        case DT_VERSYM:
            summary->versym = ptr;
            break;
        case DT_VERNEED:
            summary->verneed = ptr;
            break;
        case DT_VERNEEDNUM:
            summary->verneednum = val;
            break;
        case DT_VERDEF:
            summary->verdef = ptr;
            break;
        case DT_VERDEFNUM:
            summary->verdefnum = val;
            break;
    }
}

void KztParseDynamicView(KztDynamicView *view, const Elf64_Dyn *dynamic,
                         size_t max_entries)
{
    memset(view, 0, sizeof(*view));

    if (!dynamic || !max_entries) {
        view->status = KZT_DYNAMIC_VIEW_EMPTY;
        return;
    }

    view->entries = dynamic;

    for (size_t i = 0; i < max_entries; ++i) {
        if (dynamic[i].d_tag == DT_NULL) {
            view->summary.has_null = 1;
            view->entry_count = view->summary.entries;
            view->status = KZT_DYNAMIC_VIEW_READY;
            return;
        }
        ++view->summary.entries;
        KztDynamicSummaryAdd(&view->summary, dynamic + i);
    }

    view->summary.truncated = 1;
    view->entry_count = view->summary.entries;
    view->status = KZT_DYNAMIC_VIEW_TRUNCATED;
}

/*
 * KztDynamicInfo is the compatibility shape used by old loader code.  Keeping
 * the conversion explicit lets the memory parser run in parallel with the
 * file parser until their views are proven equivalent.
 */
void KztBuildDynamicInfo(KztDynamicInfo *info, const KztDynamicView *view)
{
    const KztDynamicSummary *summary = &view->summary;

    memset(info, 0, sizeof(*info));

    info->strtab = summary->strtab;
    info->strsz = summary->strsz;
    info->symtab = summary->symtab;
    info->syment = summary->syment;
    info->hash = summary->hash;
    info->gnu_hash = summary->gnu_hash;
    info->rel = summary->rel;
    info->relsz = summary->relsz;
    info->relent = summary->relent;
    info->rela = summary->rela;
    info->relasz = summary->relasz;
    info->relaent = summary->relaent;
    info->jmprel = summary->jmprel;
    info->pltsz = summary->pltrelsz;
    info->pltrel = summary->pltrel;
    info->pltgot = summary->pltgot;
    info->initentry = summary->init;
    info->initarray = summary->init_array;
    info->initarray_count = summary->init_arraysz / sizeof(Elf64_Addr);
    info->finientry = summary->fini;
    info->finiarray = summary->fini_array;
    info->finiarray_count = summary->fini_arraysz / sizeof(Elf64_Addr);
    info->versym = summary->versym;
    info->verneed = summary->verneed;
    info->verneed_count = summary->verneednum;
    info->verdef = summary->verdef;
    info->verdef_count = summary->verdefnum;

    if (info->rel && info->relent != sizeof(Elf64_Rel))
        info->errors |= KZT_DYNAMIC_ERROR_RELENT;
    if (info->rel && info->relent) {
        info->rel_count = info->relsz / info->relent;
        info->has_rel_count = 1;
    }
    if (info->rela && info->relaent != sizeof(Elf64_Rela))
        info->errors |= KZT_DYNAMIC_ERROR_RELAENT;
    if (info->rela && info->relaent) {
        info->rela_count = info->relasz / info->relaent;
        info->has_rela_count = 1;
    }
    if (info->jmprel) {
        if (info->pltrel == DT_REL) {
            info->pltent = sizeof(Elf64_Rel);
        } else if (info->pltrel == DT_RELA) {
            info->pltent = sizeof(Elf64_Rela);
        } else {
            info->errors |= KZT_DYNAMIC_ERROR_PLTREL;
        }
        if (info->pltent && (info->pltsz / info->pltent) * info->pltent
            != info->pltsz) {
            info->errors |= KZT_DYNAMIC_ERROR_PLTSZ;
        }
        if (info->pltent) {
            info->plt_count = info->pltsz / info->pltent;
            info->has_plt_count = 1;
        }
    }
}

void KztDynamicInfoSetRangeValidator(KztDynamicInfo *info,
                                     KztDynamicRangeValidator validator,
                                     void *opaque)
{
    info->range_is_readable = validator;
    info->range_opaque = opaque;
}

uintptr_t KztDynamicApplyLoadBias(uintptr_t value, uintptr_t load_bias)
{
    if (!value)
        return 0;

    if (load_bias && value < load_bias) {
        if (value > UINTPTR_MAX - load_bias)
            return 0;
        value += load_bias;
    }

    return value;
}

const char *KztDynamicStrtabFromPtr(uintptr_t strtab, uintptr_t load_bias)
{
    strtab = KztDynamicApplyLoadBias(strtab, load_bias);
    if (!strtab)
        return NULL;

    return (const char *)strtab;
}

int KztDynamicStringTableFromInfo(const KztDynamicInfo *info,
                                  uintptr_t load_bias,
                                  KztDynamicStringTable *table)
{
    table->data = KztDynamicStrtabFromPtr(info->strtab, load_bias);
    table->size = info->strsz;
    if (!KztDynamicTableRangeIsReadable(info, table->data, table->size, 1)) {
        table->data = NULL;
        table->size = 0;
        return 0;
    }
    return table->data && table->size;
}

const char *KztDynamicStringAt(const KztDynamicStringTable *strtab,
                               size_t offset)
{
    uintptr_t value_addr;
    const char *value;

    if (!strtab->data || offset >= strtab->size)
        return NULL;

    if (!KztDynamicOffsetPtr((uintptr_t)strtab->data, offset, 1,
                             &value_addr))
        return NULL;

    value = (const char *)value_addr;
    if (!memchr(value, '\0', strtab->size - offset))
        return NULL;

    return value;
}

int KztNextDynamicString(const KztDynamicView *view, int tag,
                         size_t *index,
                         const KztDynamicStringTable *strtab,
                         KztDynamicStringEntry *entry)
{
    while (*index < view->entry_count) {
        const Elf64_Dyn *dynamic = view->entries + (*index)++;

        if (dynamic->d_tag != tag)
            continue;

        entry->dynamic = dynamic;
        entry->offset = dynamic->d_un.d_val;
        entry->value = KztDynamicStringAt(strtab, entry->offset);
        return 1;
    }

    memset(entry, 0, sizeof(*entry));
    return 0;
}

static int KztResolveSysvHashSymbolCount(KztDynamicInfo *info,
                                          uintptr_t load_bias)
{
    const uint32_t *hash =
        (const uint32_t *)KztDynamicApplyLoadBias(info->hash, load_bias);

    if (!KztDynamicRangeIsReadable(info, hash, 2 * sizeof(*hash)))
        return 0;

    info->dynsym_count = hash[1];
    info->has_dynsym_count = 1;
    return 1;
}

static int KztResolveGnuHashSymbolCount(KztDynamicInfo *info,
                                        uintptr_t load_bias)
{
    uintptr_t header_addr = KztDynamicApplyLoadBias(info->gnu_hash,
                                                    load_bias);
    const uint32_t *header = (const uint32_t *)header_addr;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uintptr_t bloom_addr;
    uintptr_t buckets_addr;
    uintptr_t chains_addr;
    const uint32_t *buckets;
    size_t count = 0;

    if (!header)
        return 0;
    if (!KztDynamicRangeIsReadable(info, header, 4 * sizeof(*header)))
        return 0;

    nbuckets = header[0];
    symoffset = header[1];
    bloom_size = header[2];
    count = symoffset;

    if (!KztDynamicOffsetPtr(header_addr, 4, sizeof(*header), &bloom_addr)
        || !KztDynamicOffsetPtr(bloom_addr, bloom_size, sizeof(Elf64_Addr),
                                &buckets_addr)
        || !KztDynamicOffsetPtr(buckets_addr, nbuckets, sizeof(*buckets),
                                &chains_addr)) {
        info->errors |= KZT_DYNAMIC_ERROR_GNU_HASH;
        return 0;
    }

    buckets = (const uint32_t *)buckets_addr;
    if (!KztDynamicTableRangeIsReadable(info, (const void *)bloom_addr,
                                        bloom_size, sizeof(Elf64_Addr))
        || !KztDynamicTableRangeIsReadable(info, buckets, nbuckets,
                                           sizeof(*buckets))) {
        info->errors |= KZT_DYNAMIC_ERROR_GNU_HASH;
        return 0;
    }

    for (uint32_t i = 0; i < nbuckets; ++i) {
        uint32_t sym = buckets[i];
        size_t guard = 0;

        if (!sym)
            continue;
        if (sym < symoffset) {
            info->errors |= KZT_DYNAMIC_ERROR_GNU_HASH;
            return 0;
        }

        for (;;) {
            uintptr_t chain_addr;
            uint32_t chain;
            size_t next_count;

            if (!KztDynamicOffsetPtr(chains_addr, sym - symoffset,
                                     sizeof(chain), &chain_addr)
                || !KztDynamicRangeIsReadable(info, (const void *)chain_addr,
                                              sizeof(chain))) {
                info->errors |= KZT_DYNAMIC_ERROR_GNU_HASH;
                return 0;
            }
            chain = *(const uint32_t *)chain_addr;
            next_count = (size_t)sym + 1;
            if (next_count > count)
                count = next_count;
            if (chain & 1)
                break;
            if (++guard > KZT_GNU_HASH_CHAIN_WALK_MAX
                || sym == UINT32_MAX) {
                info->errors |= KZT_DYNAMIC_ERROR_GNU_HASH;
                return 0;
            }
            ++sym;
        }
    }

    info->dynsym_count = count;
    info->has_dynsym_count = 1;
    return 1;
}

int KztResolveDynamicSymbolCount(KztDynamicInfo *info, uintptr_t load_bias)
{
    if (KztResolveSysvHashSymbolCount(info, load_bias))
        return 1;

    return KztResolveGnuHashSymbolCount(info, load_bias);
}

void KztBuildDynamicInfoForObject(KztDynamicInfo *info,
                                  const KztDynamicView *view,
                                  uintptr_t load_bias)
{
    KztBuildDynamicInfo(info, view);
    KztResolveDynamicSymbolCount(info, load_bias);
}

const Elf64_Sym *KztDynamicSymtabFromPtr(uintptr_t symtab,
                                         uintptr_t load_bias)
{
    symtab = KztDynamicApplyLoadBias(symtab, load_bias);
    if (!symtab)
        return NULL;

    return (const Elf64_Sym *)symtab;
}

int KztDynamicSymbolTableFromInfo(const KztDynamicInfo *info,
                                  uintptr_t load_bias,
                                  KztDynamicSymbolTable *table)
{
    int has_strings;

    table->symbols = KztDynamicSymtabFromPtr(info->symtab, load_bias);
    table->count = info->dynsym_count;
    has_strings = KztDynamicStringTableFromInfo(info, load_bias,
                                                &table->strings);
    if (!table->symbols || !info->has_dynsym_count || !has_strings)
        return 0;
    if (!KztDynamicTableRangeIsReadable(info, table->symbols, table->count,
                                        sizeof(*table->symbols))) {
        table->symbols = NULL;
        table->count = 0;
        return 0;
    }
    return 1;
}

int KztDynamicSymbolAt(const KztDynamicSymbolTable *symtab, size_t index,
                       KztDynamicSymbolEntry *entry)
{
    const Elf64_Sym *symbol;

    if (!symtab->symbols || index >= symtab->count) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    symbol = symtab->symbols + index;
    entry->symbol = symbol;
    entry->name = KztDynamicStringAt(&symtab->strings, symbol->st_name);
    return 1;
}

const Elf64_Half *KztDynamicVersymFromPtr(uintptr_t versym,
                                          uintptr_t load_bias)
{
    versym = KztDynamicApplyLoadBias(versym, load_bias);
    if (!versym)
        return NULL;

    return (const Elf64_Half *)versym;
}

const Elf64_Half *KztDynamicVersymFromInfo(const KztDynamicInfo *info,
                                           uintptr_t load_bias)
{
    const Elf64_Half *versym = KztDynamicVersymFromPtr(info->versym,
                                                       load_bias);

    if (!KztDynamicTableRangeIsReadable(info, versym, info->dynsym_count,
                                        sizeof(*versym)))
        return NULL;
    return versym;
}

const Elf64_Verneed *KztDynamicVerneedFromPtr(uintptr_t verneed,
                                              uintptr_t load_bias)
{
    verneed = KztDynamicApplyLoadBias(verneed, load_bias);
    if (!verneed)
        return NULL;

    return (const Elf64_Verneed *)verneed;
}

const Elf64_Verneed *KztDynamicVerneedFromInfo(const KztDynamicInfo *info,
                                               uintptr_t load_bias)
{
    const Elf64_Verneed *verneed =
        KztDynamicVerneedFromPtr(info->verneed, load_bias);

    if (!KztDynamicRangeIsReadable(info, verneed, sizeof(*verneed)))
        return NULL;
    return verneed;
}

int KztDynamicVerneedAt(const Elf64_Verneed *base, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVerneedEntry *entry)
{
    return KztDynamicVerneedAtFromInfo(NULL, base, index, strtab, entry);
}

int KztDynamicVerneedAtFromInfo(const KztDynamicInfo *info,
                                const Elf64_Verneed *base, size_t index,
                                const KztDynamicStringTable *strtab,
                                KztDynamicVerneedEntry *entry)
{
    const Elf64_Verneed *need = base;

    if (!KztDynamicRangeIsReadable(info, need, sizeof(*need))
        || index >= KZT_DYNAMIC_VERSION_WALK_MAX) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    for (size_t i = 0; need && i < index; ++i) {
        uintptr_t next_addr;

        if (!need->vn_next) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        if (!KztDynamicOffsetPtr((uintptr_t)need, need->vn_next, 1,
                                 &next_addr)) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        need = (const Elf64_Verneed *)next_addr;
        if (!KztDynamicRangeIsReadable(info, need, sizeof(*need))) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
    }

    if (!KztDynamicRangeIsReadable(info, need, sizeof(*need))) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    entry->info = info;
    entry->record = need;
    entry->file = KztDynamicStringAt(strtab, need->vn_file);
    return 1;
}

int KztDynamicVernauxAt(const KztDynamicVerneedEntry *verneed, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVernauxEntry *entry)
{
    const Elf64_Vernaux *aux;
    uintptr_t aux_addr;

    const KztDynamicInfo *info = verneed->info;

    if (!verneed->record || !verneed->record->vn_aux
        || index >= verneed->record->vn_cnt
        || index >= KZT_DYNAMIC_VERSION_WALK_MAX) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    if (!KztDynamicOffsetPtr((uintptr_t)verneed->record,
                             verneed->record->vn_aux, 1, &aux_addr)) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    aux = (const Elf64_Vernaux *)aux_addr;
    if (!KztDynamicRangeIsReadable(info, aux, sizeof(*aux))) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    for (size_t i = 0; i < index; ++i) {
        uintptr_t next_addr;

        if (!aux->vna_next) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        if (!KztDynamicOffsetPtr((uintptr_t)aux, aux->vna_next, 1,
                                 &next_addr)) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        aux = (const Elf64_Vernaux *)next_addr;
        if (!KztDynamicRangeIsReadable(info, aux, sizeof(*aux))) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
    }

    entry->record = aux;
    entry->name = KztDynamicStringAt(strtab, aux->vna_name);
    return 1;
}

const Elf64_Verdef *KztDynamicVerdefFromPtr(uintptr_t verdef,
                                            uintptr_t load_bias)
{
    verdef = KztDynamicApplyLoadBias(verdef, load_bias);
    if (!verdef)
        return NULL;

    return (const Elf64_Verdef *)verdef;
}

const Elf64_Verdef *KztDynamicVerdefFromInfo(const KztDynamicInfo *info,
                                             uintptr_t load_bias)
{
    const Elf64_Verdef *verdef = KztDynamicVerdefFromPtr(info->verdef,
                                                         load_bias);

    if (!KztDynamicRangeIsReadable(info, verdef, sizeof(*verdef)))
        return NULL;
    return verdef;
}

int KztDynamicVerdefAt(const Elf64_Verdef *base, size_t index,
                       KztDynamicVerdefEntry *entry)
{
    return KztDynamicVerdefAtFromInfo(NULL, base, index, entry);
}

int KztDynamicVerdefAtFromInfo(const KztDynamicInfo *info,
                               const Elf64_Verdef *base, size_t index,
                               KztDynamicVerdefEntry *entry)
{
    const Elf64_Verdef *def = base;

    if (!KztDynamicRangeIsReadable(info, def, sizeof(*def))
        || index >= KZT_DYNAMIC_VERSION_WALK_MAX) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    for (size_t i = 0; def && i < index; ++i) {
        uintptr_t next_addr;

        if (!def->vd_next) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        if (!KztDynamicOffsetPtr((uintptr_t)def, def->vd_next, 1,
                                 &next_addr)) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        def = (const Elf64_Verdef *)next_addr;
        if (!KztDynamicRangeIsReadable(info, def, sizeof(*def))) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
    }

    if (!KztDynamicRangeIsReadable(info, def, sizeof(*def))) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    entry->info = info;
    entry->record = def;
    return 1;
}

int KztDynamicVerdauxAt(const KztDynamicVerdefEntry *verdef, size_t index,
                        const KztDynamicStringTable *strtab,
                        KztDynamicVerdauxEntry *entry)
{
    const Elf64_Verdaux *aux;
    uintptr_t aux_addr;

    const KztDynamicInfo *info = verdef->info;

    if (!verdef->record || !verdef->record->vd_aux
        || index >= verdef->record->vd_cnt
        || index >= KZT_DYNAMIC_VERSION_WALK_MAX) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }

    if (!KztDynamicOffsetPtr((uintptr_t)verdef->record,
                             verdef->record->vd_aux, 1, &aux_addr)) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    aux = (const Elf64_Verdaux *)aux_addr;
    if (!KztDynamicRangeIsReadable(info, aux, sizeof(*aux))) {
        memset(entry, 0, sizeof(*entry));
        return 0;
    }
    for (size_t i = 0; i < index; ++i) {
        uintptr_t next_addr;

        if (!aux->vda_next) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        if (!KztDynamicOffsetPtr((uintptr_t)aux, aux->vda_next, 1,
                                 &next_addr)) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
        aux = (const Elf64_Verdaux *)next_addr;
        if (!KztDynamicRangeIsReadable(info, aux, sizeof(*aux))) {
            memset(entry, 0, sizeof(*entry));
            return 0;
        }
    }

    entry->record = aux;
    entry->name = KztDynamicStringAt(strtab, aux->vda_name);
    return 1;
}

const void *KztDynamicRelocationsFromPtr(uintptr_t relocations,
                                         uintptr_t load_bias)
{
    relocations = KztDynamicApplyLoadBias(relocations, load_bias);
    if (!relocations)
        return NULL;

    return (const void *)relocations;
}

const void *KztDynamicRelocationsFromInfo(const KztDynamicInfo *info,
                                          uintptr_t relocations,
                                          uintptr_t load_bias,
                                          size_t count, int entry_size)
{
    const void *entries = KztDynamicRelocationsFromPtr(relocations,
                                                       load_bias);

    if (!KztDynamicTableRangeIsReadable(info, entries, count, entry_size))
        return NULL;
    return entries;
}

int KztDynamicRelocationAt(const KztDynamicRelocationTable *table,
                           size_t index,
                           KztDynamicRelocationEntry *entry)
{
    memset(entry, 0, sizeof(*entry));

    if (!table->entries || index >= table->count)
        return 0;

    if (table->entry_size == sizeof(Elf64_Rel)) {
        uintptr_t entry_addr;
        const Elf64_Rel *rel;

        if (!KztDynamicOffsetPtr((uintptr_t)table->entries, index,
                                 sizeof(*rel), &entry_addr))
            return 0;
        rel = (const Elf64_Rel *)entry_addr;
        entry->offset = rel->r_offset;
        entry->info = rel->r_info;
        return 1;
    }

    if (table->entry_size == sizeof(Elf64_Rela)) {
        uintptr_t entry_addr;
        const Elf64_Rela *rela;

        if (!KztDynamicOffsetPtr((uintptr_t)table->entries, index,
                                 sizeof(*rela), &entry_addr))
            return 0;
        rela = (const Elf64_Rela *)entry_addr;
        entry->offset = rela->r_offset;
        entry->info = rela->r_info;
        entry->addend = rela->r_addend;
        entry->has_addend = 1;
        return 1;
    }

    return 0;
}
