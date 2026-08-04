#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kzt_guest_link_map_reader.h"

#define KZT_GUEST_LINK_MAP_WALK_LIMIT 256

/* The public x86_64 link_map prefix is stable.  Fields after l_prev are glibc
 * implementation details and must not be used as registry evidence. */
typedef struct kzt_guest_link_map_public_prefix {
    uint64_t l_addr;
    uint64_t l_name;
    uint64_t l_ld;
    uint64_t l_next;
    uint64_t l_prev;
} kzt_guest_link_map_public_prefix_t;

#ifdef KZT_GUEST_LINK_MAP_READER_TEST
static long test_alloc_failure_after = -1;

void kzt_guest_link_map_reader_test_set_alloc_failure_after(long allocations)
{
    test_alloc_failure_after = allocations;
}
#endif

static void *kzt_link_map_reader_malloc(size_t size)
{
#ifdef KZT_GUEST_LINK_MAP_READER_TEST
    if (test_alloc_failure_after == 0) {
        return NULL;
    }
    if (test_alloc_failure_after > 0) {
        --test_alloc_failure_after;
    }
#endif
    return malloc(size);
}

static void kzt_link_map_reader_free(void *ptr)
{
    free(ptr);
}

static void kzt_guest_scalar_set_unknown(kzt_guest_scalar_field_t *field)
{
    field->value = 0;
    field->status = KZT_GUEST_FIELD_UNKNOWN;
}

static void kzt_guest_string_set_unknown(kzt_guest_string_field_t *field)
{
    field->value = NULL;
    field->status = KZT_GUEST_FIELD_UNKNOWN;
}

static void kzt_guest_observation_init(kzt_guest_object_observation_t *observation)
{
    memset(observation, 0, sizeof(*observation));
    kzt_guest_scalar_set_unknown(&observation->load_bias);
    kzt_guest_scalar_set_unknown(&observation->dynamic_addr);
    kzt_guest_scalar_set_unknown(&observation->map_start);
    kzt_guest_scalar_set_unknown(&observation->map_end);
    kzt_guest_scalar_set_unknown(&observation->namespace_id);
    kzt_guest_string_set_unknown(&observation->path);
    observation->soname.value = NULL;
    observation->soname.status = KZT_GUEST_FIELD_NOT_PARSED;
    observation->dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED;
}

static int kzt_guest_read_memory(uintptr_t guest_addr,
                                 void *dst,
                                 size_t size,
                                 const kzt_guest_link_map_reader_ops_t *ops)
{
    if (!ops || !ops->read_memory) {
        return -1;
    }
    return ops->read_memory(guest_addr, dst, size, ops->opaque) == 0 ? 0 : -1;
}

static int kzt_guest_field_addr(uintptr_t base, size_t offset, uintptr_t *addr)
{
    if (base > UINTPTR_MAX - offset) {
        return -1;
    }

    *addr = base + offset;
    return 0;
}

static int kzt_guest_read_uintptr_field(
    uintptr_t base,
    size_t offset,
    size_t field_size,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *value)
{
    uintptr_t addr;
    uint64_t raw = 0;

    if (field_size > sizeof(raw) ||
        kzt_guest_field_addr(base, offset, &addr) != 0) {
        return -1;
    }

    if (kzt_guest_read_memory(addr, &raw, field_size, ops) != 0) {
        return -1;
    }

    *value = (uintptr_t)raw;
    return 0;
}

static void kzt_guest_read_scalar_field(
    uintptr_t base,
    size_t offset,
    size_t field_size,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_scalar_field_t *field)
{
    uintptr_t value = 0;

    field->value = 0;
    if (kzt_guest_read_uintptr_field(base, offset, field_size, ops, &value) != 0) {
        field->status = KZT_GUEST_FIELD_READ_ERROR;
        return;
    }

    field->value = value;
    field->status = KZT_GUEST_FIELD_OK;
}

static int kzt_guest_read_link_map_pointer(
    uintptr_t link_map_addr,
    size_t offset,
    size_t field_size,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *value)
{
    *value = 0;
    return kzt_guest_read_uintptr_field(link_map_addr, offset, field_size,
                                        ops, value);
}

int kzt_guest_link_map_read_identity(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_link_map_identity_t *identity)
{
    if (!identity) {
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    if (!link_map_addr || !ops || !ops->read_memory ||
        kzt_guest_read_uintptr_field(
            link_map_addr,
            offsetof(kzt_guest_link_map_public_prefix_t, l_addr),
            sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_addr),
            ops, &identity->load_bias) != 0 ||
        kzt_guest_read_uintptr_field(
            link_map_addr,
            offsetof(kzt_guest_link_map_public_prefix_t, l_ld),
            sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_ld),
            ops, &identity->dynamic_addr) != 0) {
        memset(identity, 0, sizeof(*identity));
        return -1;
    }
    return 0;
}

int kzt_guest_link_map_identity_matches(
    const kzt_guest_link_map_identity_t *identity,
    uintptr_t expected_load_bias,
    uintptr_t expected_dynamic_addr)
{
    return identity && expected_dynamic_addr &&
           identity->load_bias == expected_load_bias &&
           identity->dynamic_addr == expected_dynamic_addr;
}

int kzt_guest_link_map_read_predecessor(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *predecessor)
{
    if (!predecessor) {
        return -1;
    }
    *predecessor = 0;
    if (!link_map_addr || !ops || !ops->read_memory) {
        return -1;
    }
    return kzt_guest_read_uintptr_field(
        link_map_addr,
        offsetof(kzt_guest_link_map_public_prefix_t, l_prev),
        sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_prev),
        ops, predecessor);
}

int kzt_guest_link_map_read_successor(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *successor)
{
    if (!successor) {
        return -1;
    }
    *successor = 0;
    if (!link_map_addr || !ops || !ops->read_memory) {
        return -1;
    }
    return kzt_guest_read_uintptr_field(
        link_map_addr,
        offsetof(kzt_guest_link_map_public_prefix_t, l_next),
        sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_next),
        ops, successor);
}

static uint64_t kzt_guest_link_map_fingerprint_mix(uint64_t value,
                                                   uint64_t component)
{
    size_t i;

    for (i = 0; i < sizeof(component); ++i) {
        value ^= component & UINT64_C(0xff);
        value *= UINT64_C(1099511628211);
        component >>= 8;
    }
    return value;
}

int kzt_guest_link_map_read_fingerprint(
    uintptr_t namespace_head,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_link_map_fingerprint_t *fingerprint)
{
    uintptr_t visited[KZT_GUEST_LINK_MAP_WALK_LIMIT];
    uintptr_t current = namespace_head;
    uint64_t value = UINT64_C(14695981039346656037);
    size_t count = 0;

    if (!fingerprint) {
        return -1;
    }
    memset(fingerprint, 0, sizeof(*fingerprint));
    if (!current || !ops || !ops->read_memory) {
        return -1;
    }

    while (count < KZT_GUEST_LINK_MAP_WALK_LIMIT) {
        kzt_guest_link_map_identity_t identity;
        uintptr_t successor = 0;
        size_t i;

        for (i = 0; i < count; ++i) {
            if (visited[i] == current) {
                return -1;
            }
        }
        visited[count] = current;

        if (kzt_guest_link_map_read_identity(current, ops, &identity) != 0 ||
            kzt_guest_link_map_read_successor(current, ops, &successor) != 0) {
            return -1;
        }

        value = kzt_guest_link_map_fingerprint_mix(value, count);
        value = kzt_guest_link_map_fingerprint_mix(value, current);
        value = kzt_guest_link_map_fingerprint_mix(value,
                                                   identity.load_bias);
        value = kzt_guest_link_map_fingerprint_mix(value,
                                                   identity.dynamic_addr);
        ++count;

        if (!successor) {
            value = kzt_guest_link_map_fingerprint_mix(value, count);
            fingerprint->namespace_head = namespace_head;
            fingerprint->link_map_count = count;
            fingerprint->value = value;
            return 0;
        }
        current = successor;
    }

    return -1;
}

int kzt_guest_link_map_revalidate_fingerprint(
    const kzt_guest_link_map_fingerprint_t *expected,
    const kzt_guest_link_map_reader_ops_t *ops)
{
    kzt_guest_link_map_fingerprint_t current;

    if (!expected || !expected->namespace_head ||
        expected->link_map_count == 0 ||
        expected->link_map_count > KZT_GUEST_LINK_MAP_WALK_LIMIT) {
        return -1;
    }
    if (kzt_guest_link_map_read_fingerprint(
            expected->namespace_head, ops, &current) != 0) {
        return -1;
    }
    return current.namespace_head == expected->namespace_head &&
           current.link_map_count == expected->link_map_count &&
           current.value == expected->value;
}

int kzt_guest_link_map_classify_namespace(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_identity_t *main_identity,
    uintptr_t confirmed_main_head,
    const kzt_guest_link_map_reader_ops_t *ops,
    uintptr_t *namespace_head)
{
    uintptr_t visited[KZT_GUEST_LINK_MAP_WALK_LIMIT];
    uintptr_t current = link_map_addr;
    size_t count = 0;

    if (namespace_head) {
        *namespace_head = 0;
    }

    if (!current || !ops || !ops->read_memory ||
        (!confirmed_main_head &&
         (!main_identity || !main_identity->dynamic_addr))) {
        return -1;
    }

    while (count < KZT_GUEST_LINK_MAP_WALK_LIMIT) {
        uintptr_t previous = 0;
        size_t i;

        for (i = 0; i < count; ++i) {
            if (visited[i] == current) {
                return -1;
            }
        }
        visited[count++] = current;
        if (kzt_guest_read_uintptr_field(
                current,
                offsetof(kzt_guest_link_map_public_prefix_t, l_prev),
                sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_prev),
                ops, &previous) != 0) {
            return -1;
        }

        if (!previous) {
            kzt_guest_link_map_identity_t head_identity;

            if (namespace_head) {
                *namespace_head = current;
            }
            if (confirmed_main_head) {
                return current == confirmed_main_head ? 1 : 0;
            }
            if (kzt_guest_link_map_read_identity(current, ops,
                                                 &head_identity) != 0) {
                if (namespace_head) {
                    *namespace_head = 0;
                }
                return -1;
            }
            return kzt_guest_link_map_identity_matches(
                &head_identity, main_identity->load_bias,
                main_identity->dynamic_addr) ? 1 : 0;
        }
        current = previous;
    }

    return -1;
}

int kzt_guest_link_map_read_name_snapshot(
    uintptr_t guest_name_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    size_t max_len,
    kzt_guest_string_field_t *name)
{
    char *snapshot;
    size_t i;

    if (!name) {
        return -1;
    }

    kzt_guest_string_set_unknown(name);
    if (!guest_name_addr) {
        return 0;
    }

    if (max_len == 0) {
        return 0;
    }

    snapshot = kzt_link_map_reader_malloc(max_len + 1);
    if (!snapshot) {
        name->status = KZT_GUEST_FIELD_READ_ERROR;
        return 0;
    }

    for (i = 0; i < max_len; ++i) {
        if (kzt_guest_read_memory(guest_name_addr + i, &snapshot[i], 1,
                                  ops) != 0) {
            kzt_link_map_reader_free(snapshot);
            name->status = KZT_GUEST_FIELD_READ_ERROR;
            return 0;
        }

        if (snapshot[i] == '\0') {
            name->value = snapshot;
            name->status = KZT_GUEST_FIELD_OK;
            return 0;
        }
    }

    kzt_link_map_reader_free(snapshot);
    return 0;
}

int kzt_guest_link_map_read_observation(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_object_observation_t *observation)
{
    uintptr_t guest_name_addr = 0;
    int name_ptr_read;

    if (!observation) {
        return -1;
    }

    kzt_guest_observation_init(observation);

    if (!link_map_addr || !ops || !ops->read_memory) {
        return -1;
    }

    observation->link_map_addr = link_map_addr;
    kzt_guest_read_scalar_field(
        link_map_addr,
        offsetof(kzt_guest_link_map_public_prefix_t, l_addr),
        sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_addr), ops,
        &observation->load_bias);
    kzt_guest_read_scalar_field(
        link_map_addr,
        offsetof(kzt_guest_link_map_public_prefix_t, l_ld),
        sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_ld), ops,
        &observation->dynamic_addr);

    name_ptr_read = kzt_guest_read_link_map_pointer(
        link_map_addr,
        offsetof(kzt_guest_link_map_public_prefix_t, l_name),
        sizeof(((kzt_guest_link_map_public_prefix_t *)0)->l_name), ops,
        &guest_name_addr);
    if (name_ptr_read != 0) {
        observation->path.value = NULL;
        observation->path.status = KZT_GUEST_FIELD_READ_ERROR;
        return 0;
    }

    if (kzt_guest_link_map_read_name_snapshot(
            guest_name_addr, ops, KZT_GUEST_LINK_MAP_NAME_LIMIT,
            &observation->path) != 0) {
        return -1;
    }

    return 0;
}

void kzt_guest_link_map_observation_clear(
    kzt_guest_object_observation_t *observation)
{
    if (!observation) {
        return;
    }

    kzt_guest_link_map_string_clear(&observation->path);
    kzt_guest_link_map_string_clear(&observation->soname);
    kzt_guest_observation_init(observation);
}

void kzt_guest_link_map_string_clear(kzt_guest_string_field_t *field)
{
    if (!field) {
        return;
    }

    kzt_link_map_reader_free((void *)field->value);
    kzt_guest_string_set_unknown(field);
}
