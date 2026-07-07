#include "kzt_runtime_got_plt_candidate.h"

#include <string.h>

#include "elf.h"

#define KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT 128

typedef struct kzt_runtime_got_plt_string_pool {
    char *storage;
    size_t size;
    size_t used;
} kzt_runtime_got_plt_string_pool_t;

static void kzt_runtime_got_plt_result_clear(
    kzt_runtime_got_plt_candidate_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->status = KZT_RUNTIME_GOT_PLT_CANDIDATE_OK;
    result->reason = KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_NONE;
    result->table_kind = KZT_PATCH_TABLE_UNKNOWN;
}

static int kzt_runtime_got_plt_result_set(
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_candidate_status_t status,
    kzt_runtime_got_plt_candidate_reason_t reason,
    kzt_patch_reason_t patch_reason,
    kzt_patch_table_kind_t table_kind,
    size_t entry_index,
    uintptr_t entry_addr,
    uintptr_t slot_addr,
    uintptr_t read_error_addr)
{
    result->status = status;
    result->reason = reason;
    result->patch_reason_present = 1;
    result->patch_reason = patch_reason;
    result->candidate_count = 0;
    result->table_kind = table_kind;
    result->entry_index = entry_index;
    result->entry_addr = entry_addr;
    result->slot_addr = slot_addr;
    result->read_error_addr = read_error_addr;
    return 0;
}

static int kzt_runtime_got_plt_fail_open(
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_candidate_reason_t reason,
    kzt_patch_reason_t patch_reason,
    kzt_patch_table_kind_t table_kind,
    size_t entry_index,
    uintptr_t entry_addr,
    uintptr_t slot_addr,
    uintptr_t read_error_addr)
{
    return kzt_runtime_got_plt_result_set(
        result, KZT_RUNTIME_GOT_PLT_CANDIDATE_FAIL_OPEN, reason,
        patch_reason, table_kind, entry_index, entry_addr, slot_addr,
        read_error_addr);
}

static int kzt_runtime_got_plt_u64_to_size(uint64_t value, size_t *out)
{
    if (value > (uint64_t)SIZE_MAX) {
        return -1;
    }

    *out = (size_t)value;
    return 0;
}

static int kzt_runtime_got_plt_add_u64(uintptr_t base,
                                       uint64_t offset,
                                       uintptr_t *out)
{
    if (offset > (uint64_t)UINTPTR_MAX) {
        return -1;
    }

    if (base > UINTPTR_MAX - (uintptr_t)offset) {
        return -1;
    }

    *out = base + (uintptr_t)offset;
    return 0;
}

static int kzt_runtime_got_plt_entry_addr(uintptr_t table_addr,
                                          size_t entry_size,
                                          size_t index,
                                          uintptr_t *entry_addr)
{
    uintptr_t offset;

    if (entry_size == 0 || index > UINTPTR_MAX / entry_size) {
        return -1;
    }

    offset = index * entry_size;
    if (table_addr > UINTPTR_MAX - offset) {
        return -1;
    }

    *entry_addr = table_addr + offset;
    return 0;
}

static int kzt_runtime_got_plt_table_bounds_valid(uintptr_t table_addr,
                                                  size_t table_size)
{
    if (table_size == 0) {
        return 0;
    }

    if (table_addr > UINTPTR_MAX - (table_size - 1)) {
        return -1;
    }

    return 0;
}

static int kzt_runtime_got_plt_has_rel_table(
    const kzt_guest_dynamic_view_t *view)
{
    return view->rel.present || view->relsz.present || view->relent.present;
}

static int kzt_runtime_got_plt_has_plt_table(
    const kzt_guest_dynamic_view_t *view)
{
    return view->jmprel.present || view->pltrelsz.present ||
           view->pltrel.present;
}

static int kzt_runtime_got_plt_has_rela_table(
    const kzt_guest_dynamic_view_t *view)
{
    return view->rela.present || view->relasz.present ||
           view->relaent.present;
}

static int kzt_runtime_got_plt_read_rela(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Rela *rela)
{
    return reader_ops->read_memory(entry_addr, rela, sizeof(*rela),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_slot(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t slot_addr,
    uintptr_t *slot_value)
{
    uint64_t raw_value = 0;

    if (reader_ops->read_memory(slot_addr, &raw_value, sizeof(raw_value),
                                reader_ops->opaque) != 0) {
        return -1;
    }

    if (raw_value > (uint64_t)UINTPTR_MAX) {
        return -1;
    }

    *slot_value = (uintptr_t)raw_value;
    return 0;
}

static int kzt_runtime_got_plt_read_sym(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Sym *sym)
{
    return reader_ops->read_memory(entry_addr, sym, sizeof(*sym),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_half(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Half *value)
{
    return reader_ops->read_memory(entry_addr, value, sizeof(*value),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_verneed(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Verneed *verneed)
{
    return reader_ops->read_memory(entry_addr, verneed, sizeof(*verneed),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_vernaux(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Vernaux *vernaux)
{
    return reader_ops->read_memory(entry_addr, vernaux, sizeof(*vernaux),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_verdef(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Verdef *verdef)
{
    return reader_ops->read_memory(entry_addr, verdef, sizeof(*verdef),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_read_verdaux(
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    uintptr_t entry_addr,
    Elf64_Verdaux *verdaux)
{
    return reader_ops->read_memory(entry_addr, verdaux, sizeof(*verdaux),
                                   reader_ops->opaque);
}

static int kzt_runtime_got_plt_pool_copy_byte(
    kzt_runtime_got_plt_string_pool_t *pool,
    size_t offset,
    char value)
{
    if (!pool->storage || offset >= pool->size) {
        return -1;
    }

    pool->storage[offset] = value;
    return 0;
}

static int kzt_runtime_got_plt_read_string(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_string_pool_t *pool,
    uint64_t string_offset,
    const char **out)
{
    uintptr_t string_addr = 0;
    uint64_t remaining;
    size_t start;
    size_t i;

    if (!request->view->strtab.present || !request->view->strsz.present ||
        string_offset >= request->view->strsz.value) {
        return -1;
    }

    if (kzt_runtime_got_plt_add_u64((uintptr_t)request->view->strtab.value,
                                    string_offset, &string_addr) != 0) {
        return -1;
    }

    remaining = request->view->strsz.value - string_offset;
    if (remaining > (uint64_t)SIZE_MAX) {
        return -1;
    }

    start = pool->used;
    for (i = 0; i < (size_t)remaining; ++i) {
        char value;

        if (request->reader_ops->read_memory(string_addr + i, &value,
                                             sizeof(value),
                                             request->reader_ops->opaque) !=
            0) {
            return -1;
        }

        if (kzt_runtime_got_plt_pool_copy_byte(pool, pool->used, value) !=
            0) {
            return -1;
        }
        ++pool->used;

        if (value == '\0') {
            if (pool->used == start + 1) {
                return -1;
            }
            *out = &pool->storage[start];
            return 0;
        }
    }

    return -1;
}

static int kzt_runtime_got_plt_read_symbol_name(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    unsigned long symbol_index,
    kzt_patch_table_kind_t table_kind,
    size_t entry_index,
    uintptr_t entry_addr,
    const char **symbol_name)
{
    uintptr_t sym_addr = 0;
    size_t syment = 0;
    Elf64_Sym sym;

    if (!request->view->symtab.present || !request->view->syment.present ||
        !request->view->strtab.present || !request->view->strsz.present) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_u64_to_size(request->view->syment.value,
                                        &syment) != 0 ||
        syment != sizeof(Elf64_Sym) ||
        kzt_runtime_got_plt_entry_addr((uintptr_t)request->view->symtab.value,
                                       syment, symbol_index,
                                       &sym_addr) != 0) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_NAME,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_read_sym(request->reader_ops, sym_addr,
                                     &sym) != 0) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SYMBOL_READ_FAILED,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME, table_kind,
            entry_index, entry_addr, 0, sym_addr);
        return -1;
    }

    if (kzt_runtime_got_plt_read_string(request, pool, sym.st_name,
                                        symbol_name) != 0) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_NAME,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    return 0;
}

static int kzt_runtime_got_plt_read_version_string_from_verneed(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_string_pool_t *pool,
    unsigned int version,
    const char **version_name,
    uintptr_t *read_error_addr)
{
    uintptr_t verneed_addr;
    size_t verneed_count;
    size_t i;

    if (!request->view->verneed.present) {
        return 1;
    }

    verneed_addr = (uintptr_t)request->view->verneed.value;
    if (request->view->verneednum.present &&
        request->view->verneednum.value < KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT) {
        verneed_count = (size_t)request->view->verneednum.value;
    } else {
        verneed_count = KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT;
    }

    for (i = 0; i < verneed_count; ++i) {
        Elf64_Verneed verneed;
        uintptr_t aux_addr;
        size_t j;

        if (kzt_runtime_got_plt_read_verneed(request->reader_ops,
                                             verneed_addr, &verneed) != 0) {
            *read_error_addr = verneed_addr;
            return -1;
        }

        if (kzt_runtime_got_plt_add_u64(verneed_addr, verneed.vn_aux,
                                        &aux_addr) != 0) {
            return -1;
        }

        for (j = 0; j < verneed.vn_cnt &&
                    j < KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT; ++j) {
            Elf64_Vernaux aux;

            if (kzt_runtime_got_plt_read_vernaux(request->reader_ops,
                                                 aux_addr, &aux) != 0) {
                *read_error_addr = aux_addr;
                return -1;
            }

            if ((aux.vna_other & 0x7fff) == version) {
                return kzt_runtime_got_plt_read_string(
                           request, pool, aux.vna_name, version_name) == 0
                           ? 0
                           : -1;
            }

            if (aux.vna_next == 0) {
                break;
            }
            if (kzt_runtime_got_plt_add_u64(aux_addr, aux.vna_next,
                                            &aux_addr) != 0) {
                return -1;
            }
        }

        if (verneed.vn_next == 0) {
            break;
        }
        if (kzt_runtime_got_plt_add_u64(verneed_addr, verneed.vn_next,
                                        &verneed_addr) != 0) {
            return -1;
        }
    }

    return 1;
}

static int kzt_runtime_got_plt_read_version_string_from_verdef(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_string_pool_t *pool,
    unsigned int version,
    const char **version_name,
    uintptr_t *read_error_addr)
{
    uintptr_t verdef_addr;
    size_t verdef_count;
    size_t i;

    if (!request->view->verdef.present) {
        return 1;
    }

    verdef_addr = (uintptr_t)request->view->verdef.value;
    if (request->view->verdefnum.present &&
        request->view->verdefnum.value < KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT) {
        verdef_count = (size_t)request->view->verdefnum.value;
    } else {
        verdef_count = KZT_RUNTIME_GOT_PLT_VERSION_SCAN_LIMIT;
    }

    for (i = 0; i < verdef_count; ++i) {
        Elf64_Verdef verdef;

        if (kzt_runtime_got_plt_read_verdef(request->reader_ops,
                                            verdef_addr, &verdef) != 0) {
            *read_error_addr = verdef_addr;
            return -1;
        }

        if (verdef.vd_ndx == version) {
            Elf64_Verdaux aux;
            uintptr_t aux_addr;

            if (verdef.vd_cnt < 1 ||
                kzt_runtime_got_plt_add_u64(verdef_addr, verdef.vd_aux,
                                            &aux_addr) != 0) {
                return -1;
            }

            if (kzt_runtime_got_plt_read_verdaux(request->reader_ops,
                                                 aux_addr, &aux) != 0) {
                *read_error_addr = aux_addr;
                return -1;
            }

            return kzt_runtime_got_plt_read_string(
                       request, pool, aux.vda_name, version_name) == 0
                       ? 0
                       : -1;
        }

        if (verdef.vd_next == 0) {
            break;
        }
        if (kzt_runtime_got_plt_add_u64(verdef_addr, verdef.vd_next,
                                        &verdef_addr) != 0) {
            return -1;
        }
    }

    return 1;
}

static int kzt_runtime_got_plt_read_symbol_version(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    unsigned long symbol_index,
    kzt_patch_table_kind_t table_kind,
    size_t entry_index,
    uintptr_t entry_addr,
    const char **version_name)
{
    uintptr_t versym_addr = 0;
    uintptr_t read_error_addr = 0;
    Elf64_Half raw_version = 0;
    unsigned int version;
    int lookup_status;

    if (!request->view->versym.present) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_entry_addr((uintptr_t)request->view->versym.value,
                                       sizeof(raw_version), symbol_index,
                                       &versym_addr) != 0) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_read_half(request->reader_ops, versym_addr,
                                      &raw_version) != 0) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_VERSION_READ_FAILED,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, table_kind,
            entry_index, entry_addr, 0, versym_addr);
        return -1;
    }

    version = raw_version & 0x7fff;
    if (version < 2) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, table_kind,
            entry_index, entry_addr, 0, 0);
        return -1;
    }

    lookup_status = kzt_runtime_got_plt_read_version_string_from_verneed(
        request, pool, version, version_name, &read_error_addr);
    if (lookup_status == 1) {
        lookup_status = kzt_runtime_got_plt_read_version_string_from_verdef(
            request, pool, version, version_name, &read_error_addr);
    }

    if (lookup_status == 0) {
        return 0;
    }

    kzt_runtime_got_plt_fail_open(
        result,
        lookup_status < 0
            ? KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_VERSION_READ_FAILED
            : KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION,
        KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, table_kind,
        entry_index, entry_addr, 0, read_error_addr);
    return -1;
}

static kzt_patch_relocation_type_t kzt_runtime_got_plt_reloc_type(
    unsigned int elf_reloc_type)
{
    switch (elf_reloc_type) {
    case R_X86_64_JUMP_SLOT:
        return KZT_PATCH_RELOCATION_JUMP_SLOT;
    case R_X86_64_GLOB_DAT:
        return KZT_PATCH_RELOCATION_GLOB_DAT;
    case R_X86_64_RELATIVE:
        return KZT_PATCH_RELOCATION_RELATIVE;
    case R_X86_64_COPY:
        return KZT_PATCH_RELOCATION_COPY;
    case R_X86_64_IRELATIVE:
        return KZT_PATCH_RELOCATION_IRELATIVE;
    }

    return KZT_PATCH_RELOCATION_OTHER;
}

static int kzt_runtime_got_plt_target_relocation(
    kzt_patch_table_kind_t table_kind,
    unsigned int elf_reloc_type)
{
    if (table_kind == KZT_PATCH_TABLE_PLT_RELA) {
        return elf_reloc_type == R_X86_64_JUMP_SLOT;
    }

    if (table_kind == KZT_PATCH_TABLE_RELA) {
        return elf_reloc_type == R_X86_64_GLOB_DAT;
    }

    return 0;
}

static int kzt_runtime_got_plt_append_candidate(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    size_t *candidate_count,
    kzt_patch_table_kind_t table_kind,
    size_t entry_index,
    uintptr_t entry_addr,
    const Elf64_Rela *rela)
{
    kzt_patch_candidate_t candidate;
    uintptr_t slot_addr = 0;
    uintptr_t slot_value = 0;
    unsigned int elf_reloc_type = ELF64_R_TYPE(rela->r_info);
    unsigned long symbol_index = ELF64_R_SYM(rela->r_info);
    const char *symbol_name = NULL;
    const char *version_name = NULL;

    if (kzt_runtime_got_plt_add_u64(request->view->load_bias,
                                    rela->r_offset, &slot_addr) != 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_OVERFLOW,
            KZT_PATCH_REASON_INPUT_MALFORMED_SLOT, table_kind, entry_index,
            entry_addr, 0, 0);
        return -1;
    }

    if (*candidate_count >= request->candidate_capacity) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_CAPACITY_EXCEEDED,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, table_kind, entry_index,
            entry_addr, slot_addr, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_read_slot(request->reader_ops, slot_addr,
                                      &slot_value) != 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_READ_FAILED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_CURRENT_GOT, table_kind,
            entry_index, entry_addr, slot_addr, slot_addr);
        return -1;
    }

    if (kzt_runtime_got_plt_read_symbol_name(
            request, result, pool, symbol_index, table_kind, entry_index,
            entry_addr, &symbol_name) != 0) {
        return -1;
    }

    if (kzt_runtime_got_plt_read_symbol_version(
            request, result, pool, symbol_index, table_kind, entry_index,
            entry_addr, &version_name) != 0) {
        return -1;
    }

    memset(&candidate, 0, sizeof(candidate));
    if (request->source) {
        candidate.source = *request->source;
    }
    candidate.dynamic_addr = request->view->dynamic_addr;
    candidate.load_bias = request->view->load_bias;
    candidate.dynamic_view_generation = request->dynamic_view_generation;
    candidate.dynamic_view_available = 1;
    candidate.table_kind = table_kind;
    candidate.entry_index = entry_index;
    candidate.entry_addr = entry_addr;
    candidate.reloc_type = kzt_runtime_got_plt_reloc_type(elf_reloc_type);
    candidate.slot_addr = slot_addr;
    candidate.slot_current_value_present = 1;
    candidate.slot_current_value = slot_value;
    candidate.lazy_binding_deferred = 0;
    candidate.symbol_index = symbol_index;
    candidate.symbol_name = symbol_name;
    candidate.version = version_name;
    candidate.owner_match = KZT_PATCH_OWNER_UNKNOWN;

    request->candidates[*candidate_count] = candidate;
    ++*candidate_count;
    return 0;
}

static int kzt_runtime_got_plt_enumerate_rela_table(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    kzt_patch_table_kind_t table_kind,
    uintptr_t table_addr,
    size_t table_size,
    size_t entry_size,
    size_t *candidate_count)
{
    size_t entry_count;
    size_t i;

    if (entry_size != sizeof(Elf64_Rela) ||
        table_size % entry_size != 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, table_kind, 0,
            table_addr, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_table_bounds_valid(table_addr, table_size) != 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_TABLE_OVERFLOW,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, table_kind, 0,
            table_addr, 0, 0);
        return -1;
    }

    entry_count = table_size / entry_size;
    for (i = 0; i < entry_count; ++i) {
        Elf64_Rela rela;
        uintptr_t entry_addr = 0;
        unsigned int elf_reloc_type;

        if (kzt_runtime_got_plt_entry_addr(table_addr, entry_size, i,
                                           &entry_addr) != 0) {
            kzt_runtime_got_plt_fail_open(
                result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_TABLE_OVERFLOW,
                KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, table_kind, i,
                table_addr, 0, 0);
            return -1;
        }

        if (kzt_runtime_got_plt_read_rela(request->reader_ops, entry_addr,
                                          &rela) != 0) {
            kzt_runtime_got_plt_fail_open(
                result,
                KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_RELOCATION_READ_FAILED,
                KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, table_kind, i,
                entry_addr, 0, entry_addr);
            return -1;
        }

        elf_reloc_type = ELF64_R_TYPE(rela.r_info);
        if (!kzt_runtime_got_plt_target_relocation(table_kind,
                                                   elf_reloc_type)) {
            continue;
        }

        if (kzt_runtime_got_plt_append_candidate(
                request, result, pool, candidate_count, table_kind, i,
                entry_addr, &rela) != 0) {
            return -1;
        }
    }

    return 0;
}

static int kzt_runtime_got_plt_enumerate_plt_rela(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    size_t *candidate_count)
{
    const kzt_guest_dynamic_view_t *view = request->view;
    size_t table_size = 0;

    if (!kzt_runtime_got_plt_has_plt_table(view)) {
        return 0;
    }

    if (!view->jmprel.present || !view->pltrelsz.present ||
        !view->pltrel.present) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE,
            KZT_PATCH_TABLE_PLT_RELA, 0, 0, 0, 0);
        return -1;
    }

    if (view->pltrel.value == DT_REL) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION,
            KZT_PATCH_TABLE_PLT_REL, 0, view->jmprel.value, 0, 0);
        return -1;
    }

    if (view->pltrel.value != DT_RELA ||
        kzt_runtime_got_plt_u64_to_size(view->pltrelsz.value,
                                        &table_size) != 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE,
            KZT_PATCH_TABLE_PLT_RELA, 0, view->jmprel.value, 0, 0);
        return -1;
    }

    return kzt_runtime_got_plt_enumerate_rela_table(
        request, result, pool, KZT_PATCH_TABLE_PLT_RELA,
        (uintptr_t)view->jmprel.value, table_size, sizeof(Elf64_Rela),
        candidate_count);
}

static int kzt_runtime_got_plt_enumerate_rela(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result,
    kzt_runtime_got_plt_string_pool_t *pool,
    size_t *candidate_count)
{
    const kzt_guest_dynamic_view_t *view = request->view;
    size_t table_size = 0;
    size_t entry_size = 0;

    if (!kzt_runtime_got_plt_has_rela_table(view)) {
        return 0;
    }

    if (!view->rela.present || !view->relasz.present ||
        !view->relaent.present) {
        kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE,
            KZT_PATCH_TABLE_RELA, 0, 0, 0, 0);
        return -1;
    }

    if (kzt_runtime_got_plt_u64_to_size(view->relasz.value,
                                        &table_size) != 0 ||
        kzt_runtime_got_plt_u64_to_size(view->relaent.value,
                                        &entry_size) != 0 ||
        entry_size == 0) {
        kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE, KZT_PATCH_TABLE_RELA,
            0, view->rela.value, 0, 0);
        return -1;
    }

    return kzt_runtime_got_plt_enumerate_rela_table(
        request, result, pool, KZT_PATCH_TABLE_RELA, (uintptr_t)view->rela.value,
        table_size, entry_size, candidate_count);
}

int kzt_runtime_got_plt_candidates_collect(
    const kzt_runtime_got_plt_candidate_request_t *request,
    kzt_runtime_got_plt_candidate_result_t *result)
{
    size_t candidate_count = 0;
    kzt_runtime_got_plt_string_pool_t pool = { 0 };

    if (!result) {
        return -1;
    }

    kzt_runtime_got_plt_result_clear(result);

    if (!request || !request->view || !request->reader_ops ||
        !request->reader_ops->read_memory ||
        (!request->candidates && request->candidate_capacity > 0) ||
        ((!request->string_storage || request->string_storage_size == 0) &&
         request->candidate_capacity > 0)) {
        kzt_runtime_got_plt_result_set(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_ERROR,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_INVALID_ARGUMENT,
            KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT,
            KZT_PATCH_TABLE_UNKNOWN, 0, 0, 0, 0);
        return -1;
    }

    pool.storage = request->string_storage;
    pool.size = request->string_storage_size;

    if (request->view->status != KZT_GUEST_DYNAMIC_COMPLETE) {
        return kzt_runtime_got_plt_fail_open(
            result,
            KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DYNAMIC_VIEW_UNAVAILABLE,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW,
            KZT_PATCH_TABLE_UNKNOWN, 0, 0, 0, 0);
    }

    if (request->view->pltrel.present &&
        request->view->pltrel.value == DT_REL) {
        return kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION,
            KZT_PATCH_TABLE_PLT_REL, 0, request->view->jmprel.value, 0, 0);
    }

    if (kzt_runtime_got_plt_has_rel_table(request->view)) {
        return kzt_runtime_got_plt_fail_open(
            result, KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION,
            KZT_PATCH_TABLE_REL, 0, request->view->rel.value, 0, 0);
    }

    if (kzt_runtime_got_plt_enumerate_plt_rela(
            request, result, &pool, &candidate_count) != 0) {
        return 0;
    }

    if (kzt_runtime_got_plt_enumerate_rela(
            request, result, &pool, &candidate_count) != 0) {
        return 0;
    }

    result->candidate_count = candidate_count;
    return 0;
}

const char *kzt_runtime_got_plt_candidate_status_name(
    kzt_runtime_got_plt_candidate_status_t status)
{
    switch (status) {
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_OK:
        return "OK";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_FAIL_OPEN:
        return "FAIL_OPEN";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_ERROR:
        return "ERROR";
    }

    return "UNKNOWN";
}

const char *kzt_runtime_got_plt_candidate_reason_name(
    kzt_runtime_got_plt_candidate_reason_t reason)
{
    switch (reason) {
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_NONE:
        return "NONE";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DYNAMIC_VIEW_UNAVAILABLE:
        return "DYNAMIC_VIEW_UNAVAILABLE";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_DT_REL_UNSUPPORTED:
        return "DT_REL_UNSUPPORTED";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MISSING_DYNAMIC_FIELD:
        return "MISSING_DYNAMIC_FIELD";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_TABLE:
        return "MALFORMED_TABLE";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_TABLE_OVERFLOW:
        return "TABLE_OVERFLOW";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_RELOCATION_READ_FAILED:
        return "RELOCATION_READ_FAILED";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_OVERFLOW:
        return "SLOT_OVERFLOW";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SLOT_READ_FAILED:
        return "SLOT_READ_FAILED";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_SYMBOL_READ_FAILED:
        return "SYMBOL_READ_FAILED";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_NAME:
        return "MALFORMED_SYMBOL_NAME";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_VERSION_READ_FAILED:
        return "VERSION_READ_FAILED";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_MALFORMED_SYMBOL_VERSION:
        return "MALFORMED_SYMBOL_VERSION";
    case KZT_RUNTIME_GOT_PLT_CANDIDATE_REASON_CAPACITY_EXCEEDED:
        return "CAPACITY_EXCEEDED";
    }

    return "UNKNOWN";
}
