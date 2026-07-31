#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_guest_symbol_scope.h"

#ifndef STV_HIDDEN
#define STV_HIDDEN 2
#endif

#define TEST_AUDIT_ANY_PLT_MASK UINT64_C(0x2000000000000)

typedef struct test_link_map {
    uint64_t l_addr;
    uint64_t l_name;
    uint64_t l_ld;
    uint64_t l_next;
    uint64_t l_prev;
    uint64_t l_real;
    uint64_t l_ns;
    unsigned char private_before_audit_flags[
        0x350 - 7 * sizeof(uint64_t)];
    uint64_t audit_flags;
    unsigned char private_before_reloc_result[0x378 - 0x358];
    uint64_t reloc_result;
    unsigned char private_before_scope_max[0x3c0 - 0x380];
    uint64_t l_scope_max;
    uint64_t l_scope;
    uint64_t l_local_scope[2];
} test_link_map_t;

typedef struct test_scope_elem {
    uint64_t r_list;
    uint32_t r_nlist;
    uint32_t padding;
} test_scope_elem_t;

typedef struct test_sysv_hash {
    uint32_t nbucket;
    uint32_t nchain;
    uint32_t buckets[1];
    uint32_t chains[2];
} test_sysv_hash_t;

typedef struct test_object {
    test_link_map_t map;
    Elf64_Dyn dynamic[6];
    Elf64_Sym symbols[2];
    char strings[16];
    test_sysv_hash_t hash;
} test_object_t;

typedef struct fake_memory {
    uintptr_t base;
    const void *data;
    size_t size;
    uintptr_t fail_addr;
    uintptr_t unstable_addr;
    size_t unstable_after_reads;
    size_t unstable_reads;
    uintptr_t unstable_value;
} fake_memory_t;

typedef struct test_scope_storage {
    test_scope_elem_t scope_elems[KZT_GUEST_SYMBOL_SCOPE_LIST_LIMIT];
    uintptr_t scope_array[KZT_GUEST_SYMBOL_SCOPE_LIST_LIMIT + 1];
    uintptr_t scope_maps[KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT];
} test_scope_storage_t;

static int failures;
static test_scope_storage_t scope_storage;

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
    fprintf(stderr, "%s: got %zu expected %zu\n", name, got, expected);
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

static int fake_read_memory(uintptr_t guest_addr,
                            void *dst,
                            size_t size,
                            void *opaque)
{
    fake_memory_t *memory = opaque;
    uintptr_t offset;

    if (memory->fail_addr && guest_addr == memory->fail_addr) {
        return -1;
    }
    if (memory->unstable_addr && guest_addr == memory->unstable_addr &&
        size == sizeof(memory->unstable_value) &&
        ++memory->unstable_reads > memory->unstable_after_reads) {
        memcpy(dst, &memory->unstable_value, size);
        return 0;
    }
    if (guest_addr >= memory->base) {
        offset = guest_addr - memory->base;
        if (offset <= memory->size && size <= memory->size - offset) {
            memcpy(dst, (const char *)memory->data + offset, size);
            return 0;
        }
    }
    if (guest_addr >= (uintptr_t)&scope_storage) {
        offset = guest_addr - (uintptr_t)&scope_storage;
        if (offset <= sizeof(scope_storage) &&
            size <= sizeof(scope_storage) - offset) {
            memcpy(dst, (const char *)&scope_storage + offset, size);
            return 0;
        }
    }
    return -1;
}

static void init_object(test_object_t *object,
                        unsigned char binding,
                        uintptr_t runtime_address)
{
    memset(object, 0, sizeof(*object));

    object->map.l_ld = (uintptr_t)object->dynamic;
    object->map.l_real = (uintptr_t)&object->map;
    object->dynamic[0].d_tag = DT_SYMTAB;
    object->dynamic[0].d_un.d_ptr = (uintptr_t)object->symbols;
    object->dynamic[1].d_tag = DT_STRTAB;
    object->dynamic[1].d_un.d_ptr = (uintptr_t)object->strings;
    object->dynamic[2].d_tag = DT_SYMENT;
    object->dynamic[2].d_un.d_val = sizeof(Elf64_Sym);
    object->dynamic[3].d_tag = DT_STRSZ;
    object->dynamic[3].d_un.d_val = sizeof(object->strings);
    object->dynamic[4].d_tag = DT_HASH;
    object->dynamic[4].d_un.d_ptr = (uintptr_t)&object->hash;
    object->dynamic[5].d_tag = DT_NULL;

    memcpy(object->strings, "\0target\0", sizeof("\0target\0"));
    object->symbols[1].st_name = 1;
    object->symbols[1].st_info = ELF_ST_INFO(binding, STT_FUNC);
    object->symbols[1].st_other = STV_DEFAULT;
    object->symbols[1].st_shndx = SHN_ABS;
    object->symbols[1].st_value = runtime_address;

    object->hash.nbucket = 1;
    object->hash.nchain = 2;
    object->hash.buckets[0] = 1;
}

static void hide_object_symbol(test_object_t *object)
{
    object->hash.buckets[0] = 0;
}

static void link_objects(test_object_t *objects, size_t count)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        objects[i].map.l_prev =
            i == 0 ? 0 : (uintptr_t)&objects[i - 1].map;
        objects[i].map.l_next =
            i + 1 < count ? (uintptr_t)&objects[i + 1].map : 0;
    }
}

static void set_source_scope(test_link_map_t *source,
                             test_link_map_t *const *maps,
                             size_t map_count)
{
    size_t i;

    memset(&scope_storage, 0, sizeof(scope_storage));
    scope_storage.scope_elems[0].r_list =
        (uintptr_t)scope_storage.scope_maps;
    scope_storage.scope_elems[0].r_nlist = (uint32_t)map_count;
    scope_storage.scope_array[0] =
        (uintptr_t)&scope_storage.scope_elems[0];
    for (i = 0; i < map_count; ++i) {
        scope_storage.scope_maps[i] = (uintptr_t)maps[i];
    }
    source->l_scope_max = 2;
    source->l_scope = (uintptr_t)scope_storage.scope_array;
    source->l_local_scope[0] = (uintptr_t)&scope_storage.scope_elems[0];
}

static void set_source_scope_from_chain(test_link_map_t *source)
{
    test_link_map_t *maps[KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT];
    test_link_map_t *current = source;
    size_t count = 0;

    while (current && count < KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT) {
        maps[count++] = current;
        current = (test_link_map_t *)(uintptr_t)current->l_next;
    }
    set_source_scope(source, maps, count);
}

static kzt_guest_symbol_scope_request_t scope_request(
    uintptr_t source_link_map, uintptr_t namespace_head, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version)
{
    return (kzt_guest_symbol_scope_request_t) {
        .source = {
            .link_map_addr = source_link_map,
            .generation = 1,
            .namespace_id = 0,
            .namespace_head = namespace_head,
            .layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF,
        },
        .symbol = symbol,
        .version_evidence = version_evidence,
        .version = version,
        .reference_binding = STB_GLOBAL,
        .reference_type = STT_FUNC,
        .reference_visibility = STV_DEFAULT,
    };
}

static kzt_guest_symbol_scope_status_t scope_check(
    uintptr_t namespace_head, uintptr_t selected_provider_link_map,
    uintptr_t selected_provider_address,
    const char *symbol, kzt_symbol_version_evidence_t version_evidence,
    const char *version, const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    test_link_map_t *source = (test_link_map_t *)namespace_head;
    kzt_guest_symbol_scope_request_t request;

    if (source && !source->l_scope) {
        set_source_scope_from_chain(source);
    }
    request = scope_request(namespace_head, namespace_head, symbol,
                            version_evidence, version);
    return kzt_guest_symbol_scope_check(
        &request, selected_provider_link_map, selected_provider_address,
        reader_ops, result);
}

static kzt_guest_symbol_scope_status_t scope_discover(
    uintptr_t namespace_head, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    test_link_map_t *source = (test_link_map_t *)namespace_head;
    kzt_guest_symbol_scope_request_t request;

    if (source && !source->l_scope) {
        set_source_scope_from_chain(source);
    }
    request = scope_request(namespace_head, namespace_head, symbol,
                            version_evidence, version);
    return kzt_guest_symbol_scope_discover(&request, reader_ops, result);
}

static kzt_guest_symbol_scope_status_t scope_revalidate(
    const kzt_guest_symbol_scope_result_t *proof,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    kzt_guest_symbol_scope_request_t request = scope_request(
        proof->scope_identity.source.link_map_addr,
        proof->scope_identity.source.namespace_head, "target",
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL);

    request.source = proof->scope_identity.source;
    return kzt_guest_symbol_scope_revalidate(
        proof, &request, reader_ops, result);
}

static void test_namespace_local_provider_outside_source_scope_is_rejected(void)
{
    test_object_t objects[2];
    test_link_map_t *source_maps[1];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x7171);
    link_objects(objects, 2);
    source_maps[0] = &objects[0].map;
    set_source_scope(&objects[0].map, source_maps, 1);

    check_int("local-outside-scope.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[1].map,
                  0x7171,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("local-outside-scope.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH);
    check_size("local-outside-scope.candidate-count",
               result.candidate_count, 0);
}

static void test_unique_global_provider_is_safe(void)
{
    test_object_t objects[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x1234);
    link_objects(objects, 2);

    memset(&result, 0xa5, sizeof(result));
    check_int("unique.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[1].map,
                  0x1234,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("unique.result-status", result.status,
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("unique.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);
    check_size("unique.candidate-count", result.candidate_count, 1);
    check_int("unique.scope-complete", result.scope_complete, 1);
    check_int("unique.lookup-order-known", result.lookup_order_known, 1);
    check_uintptr("unique.link-map", result.selected_provider_link_map,
                  (uintptr_t)&objects[1].map);
    check_uintptr("unique.address", result.selected_provider_address, 0x1234);
    check_int("unique.binding", result.selected_provider_binding, STB_GLOBAL);
    check_int("unique.type", result.selected_provider_type, STT_FUNC);
    check_int("unique.visibility", result.selected_provider_visibility,
              STV_DEFAULT);
    check_uintptr("unique.scope-source",
                  result.scope_identity.source.link_map_addr,
                  (uintptr_t)&objects[0].map);
    check_size("unique.scope-map-count",
               result.scope_identity.scope_map_count, 2);

    memset(&result, 0xa5, sizeof(result));
    check_int("discover.status",
              scope_discover(
                  (uintptr_t)&objects[0].map,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("discover.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);
    check_size("discover.candidate-count", result.candidate_count, 1);
    check_uintptr("discover.link-map",
                  result.selected_provider_link_map,
                  (uintptr_t)&objects[1].map);
    check_uintptr("discover.address",
                  result.selected_provider_address, 0x1234);
    check_int("discover.binding",
              result.selected_provider_binding, STB_GLOBAL);
}

static void test_multiple_definitions_count_weak_candidate(void)
{
    test_object_t objects[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_GLOBAL, 0x1111);
    init_object(&objects[1], STB_WEAK, 0x2222);
    link_objects(objects, 2);

    check_int("multiple.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[0].map,
                  0x1111,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("multiple.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);
    check_size("multiple.candidate-count", result.candidate_count, 2);
    check_int("multiple.scope-complete", result.scope_complete, 1);
    check_int("multiple.lookup-order-known", result.lookup_order_known, 1);
    check_uintptr("multiple.selected-link-map",
                  result.selected_provider_link_map,
                  (uintptr_t)&objects[0].map);
    check_int("multiple.selected-binding",
              result.selected_provider_binding, STB_GLOBAL);
}

static void test_multiple_strong_definitions_select_first_provider(void)
{
    test_object_t objects[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_GLOBAL, 0x2111);
    init_object(&objects[1], STB_GLOBAL, 0x2222);
    link_objects(objects, 2);

    check_int("multiple-strong.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[0].map,
                  0x2111,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("multiple-strong.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);
    check_size("multiple-strong.candidate-count",
               result.candidate_count, 2);
    check_int("multiple-strong.scope-complete",
              result.scope_complete, 1);
    check_int("multiple-strong.lookup-order-known",
              result.lookup_order_known, 1);
    check_uintptr("multiple-strong.selected",
                  result.selected_provider_link_map,
                  (uintptr_t)&objects[0].map);
}

static void test_unique_weak_provider_requires_guest(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_WEAK, 0x3333);

    check_int("weak.status",
              scope_check(
                  (uintptr_t)&object.map,
                  (uintptr_t)&object.map,
                  0x3333,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("weak.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING);
    check_size("weak.candidate-count", result.candidate_count, 1);
    check_uintptr("weak.unique-link-map",
                  result.selected_provider_link_map,
                  (uintptr_t)&object.map);
    check_int("weak.unique-binding",
              result.selected_provider_binding, STB_WEAK);
}

static void test_non_function_or_protected_provider_requires_guest(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x3535);
    object.symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
    check_int("provider-type.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("provider-type.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED);

    object.symbols[1].st_info = ELF_ST_INFO(STB_GLOBAL, STT_FUNC);
    object.symbols[1].st_other = STV_PROTECTED;
    check_int("provider-visibility.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("provider-visibility.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED);
}

#ifdef STB_GNU_UNIQUE
static void test_unique_gnu_binding_requires_guest(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GNU_UNIQUE, 0x3434);

    check_int("gnu-unique.status",
              scope_check(
                  (uintptr_t)&object.map,
                  (uintptr_t)&object.map,
                  0x3434,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("gnu-unique.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING);
    check_size("gnu-unique.candidate-count", result.candidate_count, 1);
    check_int("gnu-unique.binding",
              result.selected_provider_binding, STB_GNU_UNIQUE);
}
#endif

static void test_selected_provider_must_match_unique_candidate(void)
{
    test_object_t objects[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x4444);
    link_objects(objects, 2);

    check_int("mismatch.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[0].map,
                  0x4444,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("mismatch.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH);
    check_size("mismatch.candidate-count", result.candidate_count, 1);
    check_uintptr("mismatch.actual-link-map",
                  result.selected_provider_link_map,
                  (uintptr_t)&objects[1].map);
    check_int("mismatch.scope-complete", result.scope_complete, 1);

    check_int("mismatch-address.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[1].map, 0x4445, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("mismatch-address.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH);
}

static void test_incomplete_scope_fails_open(void)
{
    test_object_t objects[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x5555);
    link_objects(objects, 2);
    memory.fail_addr = (uintptr_t)&objects[1].hash;

    check_int("incomplete.status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[1].map,
                  0x5555,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("incomplete.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE);
    check_int("incomplete.scope-complete", result.scope_complete, 0);
    check_int("incomplete.lookup-order-known",
              result.lookup_order_known, 0);
    check_uintptr("incomplete.no-unique-link-map",
                  result.selected_provider_link_map, 0);
}

static void test_scope_pointer_read_failure_fails_open(void)
{
    test_object_t object;
    test_link_map_t *maps[1];
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5757);
    maps[0] = &object.map;
    set_source_scope(&object.map, maps, 1);
    memory.fail_addr =
        (uintptr_t)&object.map + offsetof(test_link_map_t, l_scope);

    check_int("scope-read-failure.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("scope-read-failure.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE);
}

static void test_scope_pointer_instability_fails_open(void)
{
    test_object_t object;
    test_link_map_t *maps[1];
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5858);
    maps[0] = &object.map;
    set_source_scope(&object.map, maps, 1);
    memory.unstable_addr =
        (uintptr_t)&object.map + offsetof(test_link_map_t, l_scope);
    memory.unstable_after_reads = 1;

    check_int("scope-pointer-unstable.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("scope-pointer-unstable.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE);
}

static void test_duplicate_scope_map_fails_open(void)
{
    test_object_t object;
    test_link_map_t *maps[2];
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5959);
    maps[0] = &object.map;
    maps[1] = &object.map;
    set_source_scope(&object.map, maps, 2);

    check_int("duplicate.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("duplicate.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_DUPLICATE);
}

static void test_cross_namespace_scope_map_fails_open(void)
{
    test_object_t objects[2];
    test_link_map_t *maps[2];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x5a5a);
    objects[0].map.l_next = (uintptr_t)&objects[1].map;
    objects[1].map.l_prev = 0;
    maps[0] = &objects[0].map;
    maps[1] = &objects[1].map;
    set_source_scope(&objects[0].map, maps, 2);

    check_int("cross-namespace.status",
              scope_discover(
                  (uintptr_t)&objects[0].map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("cross-namespace.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_CROSS_NAMESPACE);
}

static void test_layout_and_private_semantics_fail_open(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_request_t request;
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5b5b);
    set_source_scope_from_chain(&object.map);
    request = scope_request(
        (uintptr_t)&object.map, (uintptr_t)&object.map, "target",
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL);
    request.source.layout = KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    check_int("layout.status",
              kzt_guest_symbol_scope_discover(
                  &request, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("layout.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_LAYOUT_UNSUPPORTED);

    request.source.layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF;
    object.map.l_real = 0;
    check_int("private-semantics.status",
              kzt_guest_symbol_scope_discover(
                  &request, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("private-semantics.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED);
}

static void test_loader_audit_state_fails_open(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5d5d);
    object.map.audit_flags = TEST_AUDIT_ANY_PLT_MASK;
    check_int("audit-flags.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("audit-flags.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED);

    object.map.audit_flags = 0;
    object.map.reloc_result = 0x1234;
    check_int("audit-reloc-result.status",
              scope_discover(
                  (uintptr_t)&object.map, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("audit-reloc-result.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED);
}

static void test_version_and_reference_evidence_fail_open(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_request_t request;
    kzt_guest_symbol_scope_result_t result;

    init_object(&object, STB_GLOBAL, 0x5c5c);
    set_source_scope_from_chain(&object.map);
    request = scope_request(
        (uintptr_t)&object.map, (uintptr_t)&object.map, "target",
        KZT_SYMBOL_VERSION_UNKNOWN, NULL);
    check_int("version-evidence.status",
              kzt_guest_symbol_scope_discover(
                  &request, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);

    request.version_evidence = KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    request.reference_visibility = STV_HIDDEN;
    check_int("visibility-evidence.status",
              kzt_guest_symbol_scope_discover(
                  &request, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("visibility-evidence.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_REFERENCE);

    request.reference_visibility = STV_DEFAULT;
    request.reference_type = STT_OBJECT;
    check_int("reference-type.status",
              kzt_guest_symbol_scope_discover(
                  &request, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("reference-type.reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_REFERENCE);
}

static void test_scope_revalidation_detects_change(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t proof;
    kzt_guest_symbol_scope_result_t revalidated;

    init_object(&object, STB_GLOBAL, 0x6666);
    check_int("revalidate.proof",
              scope_check(
                  (uintptr_t)&object.map,
                  (uintptr_t)&object.map,
                  0x6666,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &proof),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("revalidate.stable",
              scope_revalidate(
                  &proof, &reader_ops, &revalidated),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    check_int("revalidate.stable-reason", revalidated.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER);

    object.map.l_addr = 0x1000;
    check_int("revalidate.changed",
              scope_revalidate(
                  &proof, &reader_ops, &revalidated),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("revalidate.changed-reason", revalidated.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE);
    check_int("revalidate.changed-complete",
              revalidated.scope_complete, 0);
    check_int("revalidate.changed-order-known",
              revalidated.lookup_order_known, 0);
}

static void test_scope_revalidation_detects_member_change(void)
{
    test_object_t objects[2];
    test_link_map_t *initial_maps[2];
    test_link_map_t *changed_maps[1];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t proof;
    kzt_guest_symbol_scope_result_t revalidated;

    init_object(&objects[0], STB_LOCAL, 0);
    hide_object_symbol(&objects[0]);
    init_object(&objects[1], STB_GLOBAL, 0x6767);
    link_objects(objects, 2);
    initial_maps[0] = &objects[0].map;
    initial_maps[1] = &objects[1].map;
    set_source_scope(&objects[0].map, initial_maps, 2);
    check_int("scope-member-change.proof",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[1].map, 0x6767, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &proof),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);

    changed_maps[0] = &objects[0].map;
    set_source_scope(&objects[0].map, changed_maps, 1);
    check_int("scope-member-change.status",
              scope_revalidate(&proof, &reader_ops, &revalidated),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("scope-member-change.reason", revalidated.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE);
}

static void test_scope_revalidation_detects_symbol_change(void)
{
    test_object_t object;
    fake_memory_t memory = {
        .base = (uintptr_t)&object,
        .data = &object,
        .size = sizeof(object),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t proof;
    kzt_guest_symbol_scope_result_t revalidated;

    init_object(&object, STB_GLOBAL, 0x6868);
    check_int("symbol-change.proof",
              scope_check(
                  (uintptr_t)&object.map, (uintptr_t)&object.map,
                  0x6868, "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                  &reader_ops, &proof),
              KZT_GUEST_SYMBOL_SCOPE_SAFE);
    object.symbols[1].st_info = ELF_ST_INFO(STB_WEAK, STT_FUNC);
    check_int("symbol-change.status",
              scope_revalidate(&proof, &reader_ops, &revalidated),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("symbol-change.reason", revalidated.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE);
}

static void test_scope_walk_limit_is_256(void)
{
    test_object_t objects[257];
    fake_memory_t memory = {
        .base = (uintptr_t)objects,
        .data = objects,
        .size = sizeof(objects),
    };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fake_read_memory,
        .opaque = &memory,
    };
    kzt_guest_symbol_scope_result_t result;
    size_t i;

    for (i = 0; i < 257; ++i) {
        init_object(&objects[i], STB_LOCAL, 0);
        hide_object_symbol(&objects[i]);
    }
    link_objects(objects, 256);

    check_int("limit.exact-status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[0].map,
                  1,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("limit.exact-reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH);
    check_int("limit.exact-complete", result.scope_complete, 1);
    check_size("limit.exact-count",
               result.scope_identity.scope_map_count, 256);

    link_objects(objects, 257);
    scope_storage.scope_elems[0].r_nlist = 257;
    check_int("limit.exceeded-status",
              scope_check(
                  (uintptr_t)&objects[0].map,
                  (uintptr_t)&objects[0].map,
                  1,
                  "target",
                  KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
                  NULL, &reader_ops, &result),
              KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED);
    check_int("limit.exceeded-reason", result.reason,
              KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE);
    check_int("limit.exceeded-complete", result.scope_complete, 0);
}

static void test_reason_names_are_stable_log_values(void)
{
    check_int("reason.selected",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER),
                     "SELECTED_PROVIDER"), 0);
    check_int("reason.incomplete",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE),
                     "SCOPE_INCOMPLETE"), 0);
    check_int("reason.layout",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_LAYOUT_UNSUPPORTED),
                     "LAYOUT_UNSUPPORTED"), 0);
    check_int("reason.binding",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING),
                     "UNSUPPORTED_PROVIDER_BINDING"), 0);
    check_int("reason.mismatch",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH),
                     "PROVIDER_MISMATCH"), 0);
    check_int("reason.stale",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE),
                     "SCOPE_STALE"), 0);
    check_int("reason.audit",
              strcmp(kzt_guest_symbol_scope_reason_name(
                         KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED),
                     "AUDIT_UNSUPPORTED"), 0);
}

int main(void)
{
    test_namespace_local_provider_outside_source_scope_is_rejected();
    test_unique_global_provider_is_safe();
    test_multiple_definitions_count_weak_candidate();
    test_multiple_strong_definitions_select_first_provider();
    test_unique_weak_provider_requires_guest();
    test_non_function_or_protected_provider_requires_guest();
#ifdef STB_GNU_UNIQUE
    test_unique_gnu_binding_requires_guest();
#endif
    test_selected_provider_must_match_unique_candidate();
    test_incomplete_scope_fails_open();
    test_scope_pointer_read_failure_fails_open();
    test_scope_pointer_instability_fails_open();
    test_duplicate_scope_map_fails_open();
    test_cross_namespace_scope_map_fails_open();
    test_layout_and_private_semantics_fail_open();
    test_loader_audit_state_fails_open();
    test_version_and_reference_evidence_fail_open();
    test_scope_revalidation_detects_change();
    test_scope_revalidation_detects_member_change();
    test_scope_revalidation_detects_symbol_change();
    test_scope_walk_limit_is_256();
    test_reason_names_are_stable_log_values();

    if (failures) {
        fprintf(stderr, "FAIL: %d checks failed\n", failures);
        return 1;
    }
    puts("PASS");
    return 0;
}
