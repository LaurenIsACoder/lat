#include "kzt_guest_dynsym_lookup.h"

#include <stddef.h>
#include <string.h>

#include "elf.h"

#define KZT_GUEST_DYNSYM_GNU_CHAIN_LIMIT 4096
#define KZT_GUEST_DYNSYM_GNU_HEADER_WORDS 4
#define KZT_GUEST_DYNSYM_SYSV_CHAIN_LIMIT 4096
#define KZT_GUEST_DYNSYM_VERSION_SCAN_LIMIT 128

typedef enum kzt_guest_dynsym_symbol_match {
    KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN = -1,
    KZT_GUEST_DYNSYM_SYMBOL_NO_MATCH = 0,
    KZT_GUEST_DYNSYM_SYMBOL_MATCH = 1,
} kzt_guest_dynsym_symbol_match_t;

static void kzt_guest_dynsym_result_clear(
    kzt_guest_dynsym_lookup_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->status = KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
}

static kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_finish(
    kzt_guest_dynsym_lookup_result_t *result,
    kzt_guest_dynsym_lookup_status_t status)
{
    result->status = status;
    return status;
}

static int kzt_guest_dynsym_add(uintptr_t base,
                                uintptr_t offset,
                                uintptr_t *result)
{
    if (base > UINTPTR_MAX - offset) {
        return -1;
    }

    *result = base + offset;
    return 0;
}

static int kzt_guest_dynsym_index_addr(uintptr_t base,
                                       size_t entry_size,
                                       uint32_t index,
                                       uintptr_t *result)
{
    uintptr_t offset;

    if (entry_size == 0 || index > UINTPTR_MAX / entry_size) {
        return -1;
    }

    offset = (uintptr_t)index * entry_size;
    return kzt_guest_dynsym_add(base, offset, result);
}

static int kzt_guest_dynsym_scaled_offset(uint64_t count,
                                          size_t entry_size,
                                          uintptr_t *result)
{
    if (entry_size == 0 || count > UINTPTR_MAX / entry_size) {
        return -1;
    }

    *result = (uintptr_t)count * entry_size;
    return 0;
}

static int kzt_guest_dynsym_read(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t address,
    void *value,
    size_t size)
{
    return reader_ops->read_memory(address, value, size, reader_ops->opaque);
}

static int kzt_guest_dynsym_runtime_field_valid(
    const kzt_guest_dynamic_field_t *field)
{
    return field->present &&
           field->address_semantics == KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS;
}

static int kzt_guest_dynsym_scalar_field_valid(
    const kzt_guest_dynamic_field_t *field)
{
    return field->present &&
           field->address_semantics == KZT_GUEST_DYNAMIC_SCALAR;
}

static uint32_t kzt_guest_dynsym_gnu_hash(const char *name)
{
    uint32_t hash = 5381;

    while (*name) {
        hash = hash * 33 + (unsigned char)*name++;
    }

    return hash;
}

static uint32_t kzt_guest_dynsym_sysv_hash(const char *name)
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

static kzt_guest_dynsym_symbol_match_t
kzt_guest_dynsym_name_matches(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uint32_t string_offset,
    const char *symbol)
{
    uintptr_t strtab;
    uintptr_t string_addr;
    size_t strsz;
    size_t symbol_size;
    size_t compared = 0;

    strtab = (uintptr_t)view->strtab.value;
    if (view->strsz.value > SIZE_MAX) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }
    strsz = (size_t)view->strsz.value;
    if (string_offset >= strsz ||
        kzt_guest_dynsym_add(strtab, string_offset, &string_addr) != 0) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    symbol_size = strlen(symbol) + 1;
    if (symbol_size > strsz - string_offset) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    while (compared < symbol_size) {
        char buffer[64];
        size_t remaining = symbol_size - compared;
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        uintptr_t read_addr;

        if (kzt_guest_dynsym_add(string_addr, compared, &read_addr) != 0 ||
            kzt_guest_dynsym_read(reader_ops, read_addr, buffer, chunk) != 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }
        if (memcmp(buffer, symbol + compared, chunk) != 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_NO_MATCH;
        }
        compared += chunk;
    }

    return KZT_GUEST_DYNSYM_SYMBOL_MATCH;
}

static kzt_guest_dynsym_symbol_match_t
kzt_guest_dynsym_version_matches(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uint32_t symbol_index,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version)
{
    uintptr_t versym_addr;
    uintptr_t verdef_addr;
    Elf64_Half raw_version;
    unsigned int version_index;
    size_t definition_limit;
    size_t i;

    if (version_evidence == KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED) {
        if (!view->versym.present) {
            return KZT_GUEST_DYNSYM_SYMBOL_MATCH;
        }
        if (!kzt_guest_dynsym_runtime_field_valid(&view->versym) ||
            kzt_guest_dynsym_index_addr(
                (uintptr_t)view->versym.value, sizeof(raw_version),
                symbol_index, &versym_addr) != 0 ||
            kzt_guest_dynsym_read(reader_ops, versym_addr, &raw_version,
                                  sizeof(raw_version)) != 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }
        if (raw_version & UINT16_C(0x8000)) {
            return KZT_GUEST_DYNSYM_SYMBOL_NO_MATCH;
        }
        return KZT_GUEST_DYNSYM_SYMBOL_MATCH;
    }
    if (version_evidence != KZT_SYMBOL_VERSION_VERSIONED ||
        !version || !version[0] ||
        !kzt_guest_dynsym_runtime_field_valid(&view->versym) ||
        !kzt_guest_dynsym_runtime_field_valid(&view->verdef) ||
        (view->verdefnum.present &&
         !kzt_guest_dynsym_scalar_field_valid(&view->verdefnum))) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    if (kzt_guest_dynsym_index_addr(
            (uintptr_t)view->versym.value, sizeof(raw_version),
            symbol_index, &versym_addr) != 0 ||
        kzt_guest_dynsym_read(reader_ops, versym_addr, &raw_version,
                              sizeof(raw_version)) != 0) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    version_index = raw_version & 0x7fff;
    if (version_index < 2) {
        return KZT_GUEST_DYNSYM_SYMBOL_NO_MATCH;
    }

    if (view->verdefnum.present) {
        if (view->verdefnum.value == 0 ||
            view->verdefnum.value > KZT_GUEST_DYNSYM_VERSION_SCAN_LIMIT) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }
        definition_limit = (size_t)view->verdefnum.value;
    } else {
        definition_limit = KZT_GUEST_DYNSYM_VERSION_SCAN_LIMIT;
    }

    verdef_addr = (uintptr_t)view->verdef.value;
    for (i = 0; i < definition_limit; ++i) {
        Elf64_Verdef definition;

        if (kzt_guest_dynsym_read(reader_ops, verdef_addr, &definition,
                                  sizeof(definition)) != 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }

        if ((definition.vd_ndx & 0x7fff) == version_index) {
            uintptr_t auxiliary_addr;
            Elf64_Verdaux auxiliary;

            if (definition.vd_cnt == 0 || definition.vd_aux == 0 ||
                kzt_guest_dynsym_add(verdef_addr, definition.vd_aux,
                                     &auxiliary_addr) != 0 ||
                kzt_guest_dynsym_read(reader_ops, auxiliary_addr, &auxiliary,
                                      sizeof(auxiliary)) != 0) {
                return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
            }

            return kzt_guest_dynsym_name_matches(
                view, reader_ops, auxiliary.vda_name, version);
        }

        if (definition.vd_next == 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }
        if (kzt_guest_dynsym_add(verdef_addr, definition.vd_next,
                                 &verdef_addr) != 0) {
            return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
        }
    }

    return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
}

static kzt_guest_dynsym_symbol_match_t
kzt_guest_dynsym_inspect_symbol(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    uint32_t symbol_index,
    kzt_guest_dynsym_lookup_result_t *result)
{
    uintptr_t symtab = (uintptr_t)view->symtab.value;
    uintptr_t symbol_addr;
    uintptr_t runtime_address;
    Elf64_Sym candidate;
    unsigned char binding;
    unsigned char type;
    unsigned char visibility;
    kzt_guest_dynsym_symbol_match_t name_match;

    if (kzt_guest_dynsym_index_addr(symtab, sizeof(candidate), symbol_index,
                                    &symbol_addr) != 0 ||
        kzt_guest_dynsym_read(reader_ops, symbol_addr, &candidate,
                              sizeof(candidate)) != 0) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    name_match = kzt_guest_dynsym_name_matches(
        view, reader_ops, candidate.st_name, symbol);
    if (name_match != KZT_GUEST_DYNSYM_SYMBOL_MATCH) {
        return name_match;
    }

    name_match = kzt_guest_dynsym_version_matches(
        view, reader_ops, symbol_index, version_evidence, version);
    if (name_match != KZT_GUEST_DYNSYM_SYMBOL_MATCH) {
        return name_match;
    }

    binding = ELF64_ST_BIND(candidate.st_info);
    type = ELF64_ST_TYPE(candidate.st_info);
    visibility = candidate.st_other & 0x3;
    if (candidate.st_shndx == SHN_UNDEF ||
        (visibility != STV_DEFAULT && visibility != STV_PROTECTED) ||
        (binding != STB_GLOBAL && binding != STB_WEAK &&
         binding != KZT_ELF_STB_GNU_UNIQUE) ||
        (type != STT_NOTYPE && type != STT_OBJECT &&
         type != STT_FUNC && type != STT_COMMON && type != STT_TLS &&
         type != KZT_ELF_STT_GNU_IFUNC)) {
        return KZT_GUEST_DYNSYM_SYMBOL_NO_MATCH;
    }
    if (candidate.st_value > UINTPTR_MAX) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }
    if (candidate.st_shndx == SHN_ABS) {
        runtime_address = (uintptr_t)candidate.st_value;
    } else if (kzt_guest_dynsym_add(
                   view->load_bias, (uintptr_t)candidate.st_value,
                   &runtime_address) != 0) {
        return KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN;
    }

    result->binding = binding;
    result->type = type;
    result->visibility = visibility;
    result->symbol_index = symbol_index;
    result->runtime_address = runtime_address;
    return KZT_GUEST_DYNSYM_SYMBOL_MATCH;
}

static kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_lookup_gnu(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    kzt_guest_dynsym_lookup_result_t *result)
{
    uintptr_t header_addr = (uintptr_t)view->gnu_hash.value;
    uintptr_t bloom_addr;
    uintptr_t buckets_addr;
    uintptr_t chains_addr;
    uintptr_t bloom_word_addr;
    uintptr_t bucket_addr;
    uintptr_t chain_addr;
    uintptr_t table_size;
    uint32_t header[KZT_GUEST_DYNSYM_GNU_HEADER_WORDS];
    uint32_t hash = kzt_guest_dynsym_gnu_hash(symbol);
    uint32_t bucket;
    uint32_t symbol_index;
    uint64_t bloom_word;
    uint64_t bloom_mask;
    size_t i;

    if (kzt_guest_dynsym_read(reader_ops, header_addr, header,
                              sizeof(header)) != 0 ||
        header[0] == 0 || header[2] == 0 || header[3] >= 64) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }

    if (kzt_guest_dynsym_add(header_addr, sizeof(header), &bloom_addr) != 0 ||
        kzt_guest_dynsym_scaled_offset(
            header[2], sizeof(uint64_t), &table_size) != 0 ||
        kzt_guest_dynsym_add(bloom_addr, table_size, &buckets_addr) != 0 ||
        kzt_guest_dynsym_scaled_offset(
            header[0], sizeof(uint32_t), &table_size) != 0 ||
        kzt_guest_dynsym_add(buckets_addr, table_size, &chains_addr) != 0) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }

    if (kzt_guest_dynsym_index_addr(
            bloom_addr, sizeof(uint64_t),
            (hash / 64) % header[2], &bloom_word_addr) != 0 ||
        kzt_guest_dynsym_read(reader_ops, bloom_word_addr, &bloom_word,
                              sizeof(bloom_word)) != 0) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }

    bloom_mask = (UINT64_C(1) << (hash % 64)) |
                 (UINT64_C(1) <<
                  (((uint64_t)hash >> header[3]) % 64));
    if ((bloom_word & bloom_mask) != bloom_mask) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
    }

    if (kzt_guest_dynsym_index_addr(
            buckets_addr, sizeof(uint32_t), hash % header[0],
            &bucket_addr) != 0 ||
        kzt_guest_dynsym_read(reader_ops, bucket_addr, &bucket,
                              sizeof(bucket)) != 0) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }
    if (bucket == 0 || bucket < header[1]) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
    }

    symbol_index = bucket;
    if (kzt_guest_dynsym_index_addr(
            chains_addr, sizeof(uint32_t), bucket - header[1],
            &chain_addr) != 0) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }

    for (i = 0; i < KZT_GUEST_DYNSYM_GNU_CHAIN_LIMIT; ++i) {
        uint32_t chain_hash;

        if (kzt_guest_dynsym_read(reader_ops, chain_addr, &chain_hash,
                                  sizeof(chain_hash)) != 0) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
        }
        if ((chain_hash | 1) == (hash | 1)) {
            kzt_guest_dynsym_symbol_match_t match =
                kzt_guest_dynsym_inspect_symbol(
                    view, reader_ops, symbol, version_evidence, version,
                    symbol_index, result);

            if (match == KZT_GUEST_DYNSYM_SYMBOL_MATCH) {
                return kzt_guest_dynsym_finish(
                    result, KZT_GUEST_DYNSYM_LOOKUP_FOUND);
            }
            if (match == KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN) {
                return kzt_guest_dynsym_finish(
                    result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
            }
        }
        if (chain_hash & 1) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
        }
        if (symbol_index == UINT32_MAX ||
            kzt_guest_dynsym_add(chain_addr, sizeof(uint32_t),
                                 &chain_addr) != 0) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
        }
        ++symbol_index;
    }

    return kzt_guest_dynsym_finish(
        result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
}

static kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_lookup_sysv(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    kzt_guest_dynsym_lookup_result_t *result)
{
    uintptr_t header_addr = (uintptr_t)view->hash.value;
    uintptr_t buckets_addr;
    uintptr_t chains_addr;
    uintptr_t bucket_addr;
    uintptr_t chain_addr;
    uintptr_t table_size;
    uint32_t header[2];
    uint32_t symbol_index;
    size_t i;

    if (kzt_guest_dynsym_read(reader_ops, header_addr, header,
                              sizeof(header)) != 0 ||
        header[0] == 0 || header[1] == 0 ||
        kzt_guest_dynsym_add(header_addr, sizeof(header),
                             &buckets_addr) != 0 ||
        kzt_guest_dynsym_scaled_offset(
            header[0], sizeof(uint32_t), &table_size) != 0 ||
        kzt_guest_dynsym_add(buckets_addr, table_size, &chains_addr) != 0 ||
        kzt_guest_dynsym_index_addr(
            buckets_addr, sizeof(uint32_t),
            kzt_guest_dynsym_sysv_hash(symbol) % header[0],
            &bucket_addr) != 0 ||
        kzt_guest_dynsym_read(reader_ops, bucket_addr, &symbol_index,
                              sizeof(symbol_index)) != 0) {
        return kzt_guest_dynsym_finish(
            result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
    }

    for (i = 0; i < KZT_GUEST_DYNSYM_SYSV_CHAIN_LIMIT; ++i) {
        uint32_t next_index;
        kzt_guest_dynsym_symbol_match_t match;

        if (symbol_index == 0) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_NOT_FOUND);
        }
        if (symbol_index >= header[1]) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
        }

        match = kzt_guest_dynsym_inspect_symbol(
            view, reader_ops, symbol, version_evidence, version,
            symbol_index, result);
        if (match == KZT_GUEST_DYNSYM_SYMBOL_MATCH) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_FOUND);
        }
        if (match == KZT_GUEST_DYNSYM_SYMBOL_UNKNOWN) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
        }

        if (kzt_guest_dynsym_index_addr(
                chains_addr, sizeof(uint32_t), symbol_index,
                &chain_addr) != 0 ||
            kzt_guest_dynsym_read(reader_ops, chain_addr, &next_index,
                                  sizeof(next_index)) != 0) {
            return kzt_guest_dynsym_finish(
                result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
        }
        symbol_index = next_index;
    }

    return kzt_guest_dynsym_finish(
        result, KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN);
}

kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_lookup(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    kzt_guest_dynsym_lookup_result_t *result)
{
    if (!result) {
        return KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
    }
    kzt_guest_dynsym_result_clear(result);

    if (!view || !reader_ops || !reader_ops->read_memory ||
        !symbol || !symbol[0] ||
        view->status != KZT_GUEST_DYNAMIC_COMPLETE ||
        !kzt_guest_dynsym_runtime_field_valid(&view->symtab) ||
        !kzt_guest_dynsym_runtime_field_valid(&view->strtab) ||
        !kzt_guest_dynsym_scalar_field_valid(&view->syment) ||
        !kzt_guest_dynsym_scalar_field_valid(&view->strsz) ||
        view->syment.value != sizeof(Elf64_Sym)) {
        return KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
    }
    if (view->gnu_hash.present) {
        if (!kzt_guest_dynsym_runtime_field_valid(&view->gnu_hash)) {
            return KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
        }
        return kzt_guest_dynsym_lookup_gnu(
            view, reader_ops, symbol, version_evidence, version, result);
    }
    if (view->hash.present) {
        if (!kzt_guest_dynsym_runtime_field_valid(&view->hash)) {
            return KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
        }
        return kzt_guest_dynsym_lookup_sysv(
            view, reader_ops, symbol, version_evidence, version, result);
    }

    return KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
}
