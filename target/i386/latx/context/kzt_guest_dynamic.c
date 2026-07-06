#include "kzt_guest_dynamic.h"

#include <string.h>

static void kzt_guest_dynamic_field_set(
    kzt_guest_dynamic_field_t *field,
    uint64_t value,
    kzt_guest_dynamic_address_semantics_t semantics)
{
    field->present = 1;
    field->value = value;
    field->address_semantics = semantics;
}

static int kzt_guest_dynamic_read_entry(
    uintptr_t dynamic_addr,
    size_t index,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    Elf64_Dyn *entry,
    uintptr_t *entry_addr)
{
    uintptr_t offset;

    if (index > UINTPTR_MAX / sizeof(*entry)) {
        return -1;
    }

    offset = index * sizeof(*entry);
    if (dynamic_addr > UINTPTR_MAX - offset) {
        return -1;
    }

    *entry_addr = dynamic_addr + offset;
    return reader_ops->read_memory(*entry_addr, entry, sizeof(*entry),
                                   reader_ops->opaque) == 0 ? 0 : -1;
}

static int kzt_guest_dynamic_add_needed(kzt_guest_dynamic_view_t *view,
                                        uint64_t offset)
{
    size_t new_count = view->needed_count + 1;

    if (new_count < view->needed_count ||
        new_count > KZT_GUEST_DYNAMIC_NEEDED_LIMIT) {
        return -1;
    }

    view->needed_offsets[view->needed_count] = offset;
    view->needed_count = new_count;
    view->needed_address_semantics = KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET;
    return 0;
}

static void kzt_guest_dynamic_record_unknown_tag(
    kzt_guest_dynamic_view_t *view,
    int64_t tag,
    size_t index)
{
    if (view->unknown_tag_count == 0) {
        view->first_unknown_tag = tag;
        view->first_unknown_tag_index = index;
    }
    ++view->unknown_tag_count;
}

static int kzt_guest_dynamic_record_entry(kzt_guest_dynamic_view_t *view,
                                          const Elf64_Dyn *entry,
                                          size_t index)
{
    uint64_t value = entry->d_un.d_val;
    uint64_t ptr = entry->d_un.d_ptr;

    switch (entry->d_tag) {
    case DT_NEEDED:
        return kzt_guest_dynamic_add_needed(view, value);
    case DT_SYMTAB:
        kzt_guest_dynamic_field_set(&view->symtab, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_STRTAB:
        kzt_guest_dynamic_field_set(&view->strtab, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_SYMENT:
        kzt_guest_dynamic_field_set(&view->syment, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_STRSZ:
        kzt_guest_dynamic_field_set(&view->strsz, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_HASH:
        kzt_guest_dynamic_field_set(&view->hash, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_GNU_HASH:
        kzt_guest_dynamic_field_set(&view->gnu_hash, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_VERSYM:
        kzt_guest_dynamic_field_set(&view->versym, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_VERNEED:
        kzt_guest_dynamic_field_set(&view->verneed, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_VERNEEDNUM:
        kzt_guest_dynamic_field_set(&view->verneednum, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_VERDEF:
        kzt_guest_dynamic_field_set(&view->verdef, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_VERDEFNUM:
        kzt_guest_dynamic_field_set(&view->verdefnum, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_RELA:
        kzt_guest_dynamic_field_set(&view->rela, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_RELASZ:
        kzt_guest_dynamic_field_set(&view->relasz, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_RELAENT:
        kzt_guest_dynamic_field_set(&view->relaent, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_REL:
        kzt_guest_dynamic_field_set(&view->rel, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_RELSZ:
        kzt_guest_dynamic_field_set(&view->relsz, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_RELENT:
        kzt_guest_dynamic_field_set(&view->relent, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_JMPREL:
        kzt_guest_dynamic_field_set(&view->jmprel, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    case DT_PLTRELSZ:
        kzt_guest_dynamic_field_set(&view->pltrelsz, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_PLTREL:
        kzt_guest_dynamic_field_set(&view->pltrel, value,
                                    KZT_GUEST_DYNAMIC_SCALAR);
        break;
    case DT_PLTGOT:
        kzt_guest_dynamic_field_set(&view->pltgot, ptr,
                                    KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS);
        break;
    default:
        kzt_guest_dynamic_record_unknown_tag(view, entry->d_tag, index);
        break;
    }

    return 0;
}

static void kzt_guest_dynamic_publish_view(
    kzt_guest_dynamic_parse_result_t *result,
    const kzt_guest_dynamic_view_t *view)
{
    result->status = view->status;
    result->entry_count = view->entry_count;
    result->scan_limit = view->scan_limit;
    result->unknown_tag_count = view->unknown_tag_count;
    result->first_unknown_tag = view->first_unknown_tag;
    result->first_unknown_tag_index = view->first_unknown_tag_index;
    result->view = *view;
}

int kzt_guest_dynamic_parse(
    uintptr_t dynamic_addr,
    uintptr_t load_bias,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_dynamic_parse_result_t *result)
{
    kzt_guest_dynamic_view_t view;
    size_t i;

    if (!result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->status = KZT_GUEST_DYNAMIC_ERROR;
    result->error = KZT_GUEST_DYNAMIC_ERROR_INVALID_ARGUMENT;

    if (!dynamic_addr || !reader_ops || !reader_ops->read_memory) {
        return -1;
    }

    memset(&view, 0, sizeof(view));
    view.dynamic_addr = dynamic_addr;
    view.load_bias = load_bias;
    view.scan_limit = KZT_GUEST_DYNAMIC_SCAN_LIMIT;

    for (i = 0; i < KZT_GUEST_DYNAMIC_SCAN_LIMIT; ++i) {
        Elf64_Dyn entry;
        uintptr_t entry_addr = 0;

        if (kzt_guest_dynamic_read_entry(dynamic_addr, i, reader_ops,
                                         &entry, &entry_addr) != 0) {
            view.status = KZT_GUEST_DYNAMIC_READ_ERROR;
            view.entry_count = i;
            result->read_error_addr = entry_addr;
            result->error = KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE;
            kzt_guest_dynamic_publish_view(result, &view);
            return 0;
        }

        if (entry.d_tag == DT_NULL) {
            view.status = KZT_GUEST_DYNAMIC_COMPLETE;
            view.entry_count = i;
            view.has_null = 1;
            result->error = KZT_GUEST_DYNAMIC_ERROR_NONE;
            kzt_guest_dynamic_publish_view(result, &view);
            return 0;
        }

        if (kzt_guest_dynamic_record_entry(&view, &entry, i) != 0) {
            view.status = KZT_GUEST_DYNAMIC_ERROR;
            view.entry_count = i;
            result->status = KZT_GUEST_DYNAMIC_ERROR;
            result->error = KZT_GUEST_DYNAMIC_ERROR_TOO_MANY_NEEDED;
            kzt_guest_dynamic_publish_view(result, &view);
            return 0;
        }
    }

    view.status = KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    view.entry_count = KZT_GUEST_DYNAMIC_SCAN_LIMIT;
    result->error = KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED;
    kzt_guest_dynamic_publish_view(result, &view);
    return 0;
}

void kzt_guest_dynamic_view_destroy(kzt_guest_dynamic_view_t *view)
{
    if (!view) {
        return;
    }

    memset(view, 0, sizeof(*view));
}

void kzt_guest_dynamic_parse_result_clear(
    kzt_guest_dynamic_parse_result_t *result)
{
    if (!result) {
        return;
    }

    kzt_guest_dynamic_view_destroy(&result->view);
    memset(result, 0, sizeof(*result));
}
