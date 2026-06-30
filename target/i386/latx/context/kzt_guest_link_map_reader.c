#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kzt_guest_link_map_reader.h"
#include "box64context.h"

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
        name->status = KZT_GUEST_FIELD_TRUNCATED;
        return 0;
    }

    snapshot = kzt_link_map_reader_malloc(max_len + 1);
    if (!snapshot) {
        name->status = KZT_GUEST_FIELD_READ_ERROR;
        return 0;
    }

    for (i = 0; i < max_len; ++i) {
        if (kzt_guest_read_memory(guest_name_addr + i, &snapshot[i], 1, ops) != 0) {
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

    snapshot[max_len] = '\0';
    name->value = snapshot;
    name->status = KZT_GUEST_FIELD_TRUNCATED;
    return 0;
}

int kzt_guest_link_map_read_observation(
    uintptr_t link_map_addr,
    const kzt_guest_link_map_reader_ops_t *ops,
    kzt_guest_object_observation_t *observation)
{
    uintptr_t guest_name_addr = 0;
    uintptr_t load_bias = 0;
    int name_ptr_read;

    if (!observation) {
        return -1;
    }

    kzt_guest_observation_init(observation);

    if (!link_map_addr || !ops || !ops->read_memory) {
        return -1;
    }

    if (kzt_guest_read_uintptr_field(
            link_map_addr, offsetof(struct link_map_x64, l_addr),
            sizeof(((struct link_map_x64 *)0)->l_addr), ops,
            &load_bias) != 0) {
        return -1;
    }

    observation->link_map_addr = link_map_addr;
    observation->load_bias.value = load_bias;
    observation->load_bias.status = KZT_GUEST_FIELD_OK;
    kzt_guest_read_scalar_field(
        link_map_addr, offsetof(struct link_map_x64, l_ld),
        sizeof(((struct link_map_x64 *)0)->l_ld), ops,
        &observation->dynamic_addr);
    kzt_guest_read_scalar_field(
        link_map_addr, offsetof(struct link_map_x64, l_map_start),
        sizeof(((struct link_map_x64 *)0)->l_map_start), ops,
        &observation->map_start);
    kzt_guest_read_scalar_field(
        link_map_addr, offsetof(struct link_map_x64, l_map_end),
        sizeof(((struct link_map_x64 *)0)->l_map_end), ops,
        &observation->map_end);
    kzt_guest_read_scalar_field(
        link_map_addr, offsetof(struct link_map_x64, l_ns),
        sizeof(((struct link_map_x64 *)0)->l_ns), ops,
        &observation->namespace_id);

    name_ptr_read = kzt_guest_read_link_map_pointer(
        link_map_addr, offsetof(struct link_map_x64, l_name),
        sizeof(((struct link_map_x64 *)0)->l_name), ops,
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
