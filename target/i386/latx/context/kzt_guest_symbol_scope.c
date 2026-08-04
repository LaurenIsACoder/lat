#include "kzt_guest_symbol_scope.h"

#include <string.h>

#include "elf.h"
#include "kzt_guest_dynamic.h"
#include "kzt_guest_dynsym_lookup.h"

/* These private offsets are authorized only by the exact loader layout enum;
 * the generic box64 link_map_x64 declaration is not layout evidence. */
#define KZT_GLIBC_2_39_LINK_MAP_REAL_OFFSET 0x28
#define KZT_GLIBC_2_39_LINK_MAP_AUDIT_FLAGS_OFFSET 0x350
#define KZT_GLIBC_2_39_LINK_MAP_AUDIT_ANY_PLT_MASK UINT64_C(0x2000000000000)
#define KZT_GLIBC_2_39_LINK_MAP_RELOC_RESULT_OFFSET 0x378
#define KZT_GLIBC_2_39_LINK_MAP_SCOPE_MAX_OFFSET 0x3c0
#define KZT_GLIBC_2_39_LINK_MAP_SCOPE_OFFSET 0x3c8

typedef struct kzt_guest_scope_elem_x64 {
    uint64_t r_list;
    uint32_t r_nlist;
    uint32_t padding;
} kzt_guest_scope_elem_x64_t;

typedef struct kzt_guest_symbol_scope_snapshot {
    kzt_guest_symbol_scope_identity_t identity;
    uintptr_t maps[KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT];
} kzt_guest_symbol_scope_snapshot_t;

static uint64_t kzt_guest_symbol_scope_mix(uint64_t value, uint64_t item)
{
    value ^= item + UINT64_C(0x9e3779b97f4a7c15) + (value << 6) +
             (value >> 2);
    return value;
}

static uint64_t kzt_guest_symbol_scope_text_fingerprint(uint64_t value,
                                                        const char *text)
{
    if (!text) {
        return kzt_guest_symbol_scope_mix(value, 0);
    }
    do {
        value = kzt_guest_symbol_scope_mix(value, (unsigned char)*text);
    } while (*text++);
    return value;
}

static uint64_t kzt_guest_symbol_scope_query_fingerprint(
    const kzt_guest_symbol_scope_request_t *request)
{
    uint64_t value = UINT64_C(0x6b7a745f73636f70);

    value = kzt_guest_symbol_scope_text_fingerprint(value, request->symbol);
    value = kzt_guest_symbol_scope_mix(value, request->version_evidence);
    value = kzt_guest_symbol_scope_text_fingerprint(value, request->version);
    value = kzt_guest_symbol_scope_mix(value, request->reference_binding);
    value = kzt_guest_symbol_scope_mix(value, request->reference_type);
    value = kzt_guest_symbol_scope_mix(value, request->reference_visibility);
    return value;
}

static int kzt_guest_symbol_scope_add(uintptr_t base, size_t offset,
                                      uintptr_t *address)
{
    if (!address || base > UINTPTR_MAX - offset) {
        return -1;
    }
    *address = base + offset;
    return 0;
}

static int kzt_guest_symbol_scope_read(
    const kzt_guest_link_map_reader_ops_t *reader_ops, uintptr_t address,
    void *value, size_t size)
{
    if (!reader_ops || !reader_ops->read_memory || !address || !value ||
        !size) {
        return -1;
    }
    return reader_ops->read_memory(address, value, size,
                                   reader_ops->opaque) == 0 ? 0 : -1;
}

static int kzt_guest_symbol_scope_contains(
    const uintptr_t *items, size_t count, uintptr_t item)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        if (items[i] == item) {
            return 1;
        }
    }
    return 0;
}

static int kzt_guest_symbol_scope_source_equal(
    const kzt_guest_symbol_scope_source_t *left,
    const kzt_guest_symbol_scope_source_t *right)
{
    return left && right &&
           left->link_map_addr == right->link_map_addr &&
           left->generation == right->generation &&
           left->namespace_id == right->namespace_id &&
           left->namespace_head == right->namespace_head &&
           left->layout == right->layout;
}

static int kzt_guest_symbol_scope_identity_equal(
    const kzt_guest_symbol_scope_identity_t *left,
    const kzt_guest_symbol_scope_identity_t *right)
{
    return left && right &&
           kzt_guest_symbol_scope_source_equal(&left->source,
                                               &right->source) &&
           left->scope_array_addr == right->scope_array_addr &&
           left->scope_list_count == right->scope_list_count &&
           left->scope_map_count == right->scope_map_count &&
           left->value == right->value;
}

static kzt_guest_symbol_scope_reason_t kzt_guest_symbol_scope_read_snapshot(
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_snapshot_t *snapshot)
{
    uintptr_t scope_max_addr;
    uintptr_t scope_addr;
    uintptr_t scope_array;
    uintptr_t scope_elems[KZT_GUEST_SYMBOL_SCOPE_LIST_LIMIT];
    size_t scope_max;
    size_t scope_count = 0;
    size_t map_count = 0;
    uint64_t value = UINT64_C(0x6b7a745f6c73636f);
    int source_seen = 0;
    int terminated = 0;
    size_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    if (!request || !request->source.link_map_addr ||
        !request->source.generation || request->source.namespace_id != 0 ||
        !request->source.namespace_head ||
        request->source.layout !=
            KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF) {
        return KZT_GUEST_SYMBOL_SCOPE_REASON_LAYOUT_UNSUPPORTED;
    }
    {
        int classification = kzt_guest_link_map_classify_namespace(
            request->source.link_map_addr, NULL,
            request->source.namespace_head, reader_ops, NULL);

        if (classification < 0) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
        }
        if (classification == 0) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_CROSS_NAMESPACE;
        }
    }
    if (kzt_guest_symbol_scope_add(
            request->source.link_map_addr,
            KZT_GLIBC_2_39_LINK_MAP_SCOPE_MAX_OFFSET, &scope_max_addr) != 0 ||
        kzt_guest_symbol_scope_add(
            request->source.link_map_addr,
            KZT_GLIBC_2_39_LINK_MAP_SCOPE_OFFSET, &scope_addr) != 0 ||
        kzt_guest_symbol_scope_read(reader_ops, scope_max_addr, &scope_max,
                                    sizeof(scope_max)) != 0 ||
        kzt_guest_symbol_scope_read(reader_ops, scope_addr, &scope_array,
                                    sizeof(scope_array)) != 0 ||
        !scope_array || !scope_max ||
        scope_max > KZT_GUEST_SYMBOL_SCOPE_LIST_LIMIT) {
        return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
    }

    value = kzt_guest_symbol_scope_mix(value, request->source.link_map_addr);
    value = kzt_guest_symbol_scope_mix(value, request->source.generation);
    value = kzt_guest_symbol_scope_mix(value, request->source.namespace_head);
    value = kzt_guest_symbol_scope_mix(value, request->source.layout);
    value = kzt_guest_symbol_scope_mix(value, scope_array);
    value = kzt_guest_symbol_scope_mix(value, scope_max);

    for (i = 0; i < scope_max; ++i) {
        uintptr_t entry_addr;
        uintptr_t scope_elem;
        kzt_guest_scope_elem_x64_t before;
        kzt_guest_scope_elem_x64_t after;
        size_t j;

        if (i > UINTPTR_MAX / sizeof(uintptr_t) ||
            kzt_guest_symbol_scope_add(
                scope_array, i * sizeof(uintptr_t), &entry_addr) != 0 ||
            kzt_guest_symbol_scope_read(
                reader_ops, entry_addr, &scope_elem, sizeof(scope_elem)) != 0) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
        }
        value = kzt_guest_symbol_scope_mix(value, scope_elem);
        if (!scope_elem) {
            terminated = 1;
            break;
        }
        if (kzt_guest_symbol_scope_contains(scope_elems, scope_count,
                                            scope_elem)) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_DUPLICATE;
        }
        scope_elems[scope_count++] = scope_elem;
        if (kzt_guest_symbol_scope_read(reader_ops, scope_elem, &before,
                                        sizeof(before)) != 0 ||
            !before.r_list || !before.r_nlist ||
            before.r_nlist > KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT - map_count) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
        }
        value = kzt_guest_symbol_scope_mix(value, before.r_list);
        value = kzt_guest_symbol_scope_mix(value, before.r_nlist);
        for (j = 0; j < before.r_nlist; ++j) {
            uintptr_t map_entry_addr;
            uintptr_t map;
            uintptr_t real_addr;
            uintptr_t real_map;
            uintptr_t audit_flags_addr;
            uintptr_t reloc_result_addr;
            uintptr_t reloc_result;
            uint64_t audit_flags;
            kzt_guest_link_map_identity_t identity;
            int classification;

            if (j > UINTPTR_MAX / sizeof(uintptr_t) ||
                kzt_guest_symbol_scope_add(
                    (uintptr_t)before.r_list, j * sizeof(uintptr_t),
                    &map_entry_addr) != 0 ||
                kzt_guest_symbol_scope_read(
                    reader_ops, map_entry_addr, &map, sizeof(map)) != 0 ||
                !map) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
            }
            if (kzt_guest_symbol_scope_contains(snapshot->maps, map_count,
                                                map)) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_DUPLICATE;
            }
            classification = kzt_guest_link_map_classify_namespace(
                map, NULL, request->source.namespace_head, reader_ops, NULL);
            if (classification < 0) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
            }
            if (classification == 0) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_CROSS_NAMESPACE;
            }
            if (kzt_guest_symbol_scope_add(
                    map, KZT_GLIBC_2_39_LINK_MAP_REAL_OFFSET,
                    &real_addr) != 0 ||
                kzt_guest_symbol_scope_read(
                    reader_ops, real_addr, &real_map, sizeof(real_map)) != 0) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
            }
            if (real_map != map) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED;
            }
            if (kzt_guest_symbol_scope_add(
                    map, KZT_GLIBC_2_39_LINK_MAP_AUDIT_FLAGS_OFFSET,
                    &audit_flags_addr) != 0 ||
                kzt_guest_symbol_scope_add(
                    map, KZT_GLIBC_2_39_LINK_MAP_RELOC_RESULT_OFFSET,
                    &reloc_result_addr) != 0 ||
                kzt_guest_symbol_scope_read(
                    reader_ops, audit_flags_addr, &audit_flags,
                    sizeof(audit_flags)) != 0 ||
                kzt_guest_symbol_scope_read(
                    reader_ops, reloc_result_addr, &reloc_result,
                    sizeof(reloc_result)) != 0) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
            }
            if ((audit_flags &
                 KZT_GLIBC_2_39_LINK_MAP_AUDIT_ANY_PLT_MASK) != 0 ||
                reloc_result) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED;
            }
            if (kzt_guest_link_map_read_identity(
                    map, reader_ops, &identity) != 0) {
                return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
            }
            snapshot->maps[map_count++] = map;
            source_seen |= map == request->source.link_map_addr;
            value = kzt_guest_symbol_scope_mix(value, map);
            value = kzt_guest_symbol_scope_mix(value, identity.load_bias);
            value = kzt_guest_symbol_scope_mix(value, identity.dynamic_addr);
            value = kzt_guest_symbol_scope_mix(value, audit_flags);
            value = kzt_guest_symbol_scope_mix(value, reloc_result);
        }
        if (kzt_guest_symbol_scope_read(reader_ops, scope_elem, &after,
                                        sizeof(after)) != 0 ||
            after.r_list != before.r_list ||
            after.r_nlist != before.r_nlist) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE;
        }
    }
    if (!terminated || !scope_count || !map_count || !source_seen) {
        return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
    }
    {
        size_t confirmed_scope_max;
        uintptr_t confirmed_scope_array;

        if (kzt_guest_symbol_scope_read(
                reader_ops, scope_max_addr, &confirmed_scope_max,
                sizeof(confirmed_scope_max)) != 0 ||
            kzt_guest_symbol_scope_read(
                reader_ops, scope_addr, &confirmed_scope_array,
                sizeof(confirmed_scope_array)) != 0 ||
            confirmed_scope_max != scope_max ||
            confirmed_scope_array != scope_array) {
            return KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE;
        }
    }

    snapshot->identity.source = request->source;
    snapshot->identity.scope_array_addr = scope_array;
    snapshot->identity.scope_list_count = scope_count;
    snapshot->identity.scope_map_count = map_count;
    snapshot->identity.value = value;
    return KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER;
}

static kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_finish(
    kzt_guest_symbol_scope_result_t *result,
    kzt_guest_symbol_scope_reason_t reason)
{
    result->reason = reason;
    result->status =
        reason == KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER ?
        KZT_GUEST_SYMBOL_SCOPE_SAFE :
        KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    return result->status;
}

static void kzt_guest_symbol_scope_clear(
    kzt_guest_symbol_scope_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->status = KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    result->reason = KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE;
}

static kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_incomplete(
    kzt_guest_symbol_scope_result_t *result,
    kzt_guest_symbol_scope_reason_t reason)
{
    result->scope_complete = 0;
    result->lookup_order_known = 0;
    result->selected_provider_link_map = 0;
    result->selected_provider_address = 0;
    result->selected_provider_binding = 0;
    result->selected_provider_type = 0;
    result->selected_provider_visibility = 0;
    return kzt_guest_symbol_scope_finish(result, reason);
}

static int kzt_guest_symbol_scope_request_valid(
    const kzt_guest_symbol_scope_request_t *request)
{
    return request && request->symbol && request->symbol[0] &&
           request->reference_binding == STB_GLOBAL &&
           request->reference_type == STT_FUNC &&
           request->reference_visibility == STV_DEFAULT &&
           kzt_symbol_version_evidence_valid(request->version_evidence,
                                             request->version);
}

static kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_evaluate(
    const kzt_guest_symbol_scope_request_t *request,
    uintptr_t selected_provider_link_map, uintptr_t selected_provider_address,
    int require_selected_provider,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    kzt_guest_symbol_scope_snapshot_t before;
    kzt_guest_symbol_scope_snapshot_t after;
    kzt_guest_symbol_scope_reason_t read_reason;
    size_t i;

    if (!result) {
        return KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    }
    kzt_guest_symbol_scope_clear(result);
    if (!request || !request->symbol || !request->symbol[0] ||
        !reader_ops || !reader_ops->read_memory ||
        !kzt_symbol_version_evidence_valid(request->version_evidence,
                                           request->version) ||
        (require_selected_provider &&
         (!selected_provider_link_map || !selected_provider_address))) {
        return result->status;
    }
    if (!kzt_guest_symbol_scope_request_valid(request)) {
        return kzt_guest_symbol_scope_finish(
            result, KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_REFERENCE);
    }
    result->query_fingerprint =
        kzt_guest_symbol_scope_query_fingerprint(request);
    read_reason = kzt_guest_symbol_scope_read_snapshot(
        request, reader_ops, &before);
    if (read_reason != KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER) {
        return kzt_guest_symbol_scope_incomplete(result, read_reason);
    }
    result->scope_identity = before.identity;

    for (i = 0; i < before.identity.scope_map_count; ++i) {
        kzt_guest_link_map_identity_t identity;
        kzt_guest_dynamic_parse_result_t dynamic_result;
        kzt_guest_dynsym_lookup_result_t lookup_result;
        kzt_guest_dynsym_lookup_status_t lookup_status;

        if (kzt_guest_link_map_read_identity(
                before.maps[i], reader_ops, &identity) != 0 ||
            kzt_guest_dynamic_parse(
                identity.dynamic_addr, identity.load_bias,
                reader_ops, &dynamic_result) != 0 ||
            dynamic_result.status != KZT_GUEST_DYNAMIC_COMPLETE) {
            return kzt_guest_symbol_scope_incomplete(
                result, KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE);
        }
        lookup_status = kzt_guest_dynsym_lookup(
            &dynamic_result.view, reader_ops, request->symbol,
            request->version_evidence, request->version, &lookup_result);
        kzt_guest_dynamic_parse_result_clear(&dynamic_result);
        if (lookup_status == KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN) {
            return kzt_guest_symbol_scope_incomplete(
                result, KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE);
        }
        if (lookup_status == KZT_GUEST_DYNSYM_LOOKUP_FOUND) {
            ++result->candidate_count;
            if (!result->selected_provider_link_map) {
                result->selected_provider_link_map = before.maps[i];
                result->selected_provider_address =
                    lookup_result.runtime_address;
                result->selected_provider_binding = lookup_result.binding;
                result->selected_provider_type = lookup_result.type;
                result->selected_provider_visibility =
                    lookup_result.visibility;
            }
        }
    }

    read_reason = kzt_guest_symbol_scope_read_snapshot(
        request, reader_ops, &after);
    if (read_reason != KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER ||
        !kzt_guest_symbol_scope_identity_equal(&before.identity,
                                               &after.identity)) {
        return kzt_guest_symbol_scope_incomplete(
            result, KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE);
    }

    result->scope_complete = 1;
    result->lookup_order_known = 1;
    if (!result->selected_provider_link_map ||
        !result->selected_provider_address ||
        (require_selected_provider &&
         (result->selected_provider_link_map != selected_provider_link_map ||
          result->selected_provider_address != selected_provider_address))) {
        return kzt_guest_symbol_scope_finish(
            result, KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH);
    }
    if (result->selected_provider_binding != STB_GLOBAL) {
        return kzt_guest_symbol_scope_finish(
            result,
            KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING);
    }
    if (result->selected_provider_type != STT_FUNC ||
        result->selected_provider_visibility != STV_DEFAULT) {
        return kzt_guest_symbol_scope_finish(
            result,
            KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED);
    }
    return kzt_guest_symbol_scope_finish(
        result, KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);
}

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_discover(
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    return kzt_guest_symbol_scope_evaluate(
        request, 0, 0, 0, reader_ops, result);
}

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_check(
    const kzt_guest_symbol_scope_request_t *request,
    uintptr_t selected_provider_link_map,
    uintptr_t selected_provider_address,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    return kzt_guest_symbol_scope_evaluate(
        request, selected_provider_link_map, selected_provider_address, 1,
        reader_ops, result);
}

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_revalidate(
    const kzt_guest_symbol_scope_result_t *proof,
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    kzt_guest_symbol_scope_result_t current;
    kzt_guest_symbol_scope_result_t checked;

    if (!result) {
        return KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    }
    kzt_guest_symbol_scope_clear(&checked);
    if (proof) {
        checked = *proof;
    }
    if (!proof || !request ||
        proof->status != KZT_GUEST_SYMBOL_SCOPE_SAFE ||
        proof->reason != KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER ||
        !proof->scope_complete || !proof->lookup_order_known ||
        !proof->selected_provider_link_map ||
        !proof->selected_provider_address ||
        proof->selected_provider_binding != STB_GLOBAL ||
        proof->selected_provider_type != STT_FUNC ||
        proof->selected_provider_visibility != STV_DEFAULT ||
        proof->query_fingerprint !=
            kzt_guest_symbol_scope_query_fingerprint(request) ||
        !kzt_guest_symbol_scope_source_equal(
            &proof->scope_identity.source, &request->source) ||
        kzt_guest_symbol_scope_evaluate(
            request, proof->selected_provider_link_map,
            proof->selected_provider_address, 1, reader_ops, &current) !=
            KZT_GUEST_SYMBOL_SCOPE_SAFE ||
        !kzt_guest_symbol_scope_identity_equal(
            &proof->scope_identity, &current.scope_identity) ||
        proof->candidate_count != current.candidate_count ||
        proof->selected_provider_binding !=
            current.selected_provider_binding ||
        proof->selected_provider_type != current.selected_provider_type ||
        proof->selected_provider_visibility !=
            current.selected_provider_visibility) {
        checked.status = KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
        checked.reason = KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE;
        checked.scope_complete = 0;
        checked.lookup_order_known = 0;
        checked.selected_provider_link_map = 0;
        checked.selected_provider_address = 0;
        checked.selected_provider_binding = 0;
        checked.selected_provider_type = 0;
        checked.selected_provider_visibility = 0;
        *result = checked;
        return result->status;
    }
    *result = current;
    return result->status;
}

const char *kzt_guest_symbol_scope_reason_name(
    kzt_guest_symbol_scope_reason_t reason)
{
    switch (reason) {
    case KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER:
        return "SELECTED_PROVIDER";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE:
        return "SCOPE_INCOMPLETE";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING:
        return "UNSUPPORTED_PROVIDER_BINDING";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_REFERENCE:
        return "UNSUPPORTED_REFERENCE";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH:
        return "PROVIDER_MISMATCH";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE:
        return "SCOPE_STALE";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_LAYOUT_UNSUPPORTED:
        return "LAYOUT_UNSUPPORTED";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_DUPLICATE:
        return "SCOPE_DUPLICATE";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_CROSS_NAMESPACE:
        return "CROSS_NAMESPACE";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED:
        return "SCOPE_SEMANTICS_UNSUPPORTED";
    case KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED:
        return "AUDIT_UNSUPPORTED";
    }
    return "UNKNOWN";
}
