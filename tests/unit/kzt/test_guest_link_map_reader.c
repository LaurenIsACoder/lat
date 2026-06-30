#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/kzt_guest_link_map_reader.h"
#include "target/i386/latx/include/kzt_guest_registry.h"

typedef struct fake_read_failure {
    uintptr_t addr;
    size_t size;
} fake_read_failure_t;

typedef struct fake_reader_memory {
    uintptr_t base;
    size_t size;
    const fake_read_failure_t *failures;
    size_t failure_count;
} fake_reader_memory_t;

static int failures;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_uintptr(const char *name, uintptr_t got, uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_string(const char *name, const char *got,
                         const char *expected)
{
    if ((!got && !expected) || (got && expected && !strcmp(got, expected))) {
        return;
    }

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static int ranges_overlap(uintptr_t left_addr, size_t left_size,
                          uintptr_t right_addr, size_t right_size)
{
    uintptr_t left_end = left_addr + left_size;
    uintptr_t right_end = right_addr + right_size;

    return left_addr < right_end && right_addr < left_end;
}

static int fake_read_memory(uintptr_t guest_addr, void *dst, size_t size,
                            void *opaque)
{
    fake_reader_memory_t *memory = opaque;
    size_t i;

    for (i = 0; i < memory->failure_count; ++i) {
        if (ranges_overlap(guest_addr, size,
                           memory->failures[i].addr,
                           memory->failures[i].size)) {
            return -1;
        }
    }

    if (guest_addr < memory->base ||
        size > memory->size ||
        guest_addr - memory->base > memory->size - size) {
        return -1;
    }

    memcpy(dst, (const void *)guest_addr, size);
    return 0;
}

static kzt_guest_link_map_reader_ops_t fake_ops(fake_reader_memory_t *memory)
{
    kzt_guest_link_map_reader_ops_t ops = {
        .read_memory = fake_read_memory,
        .opaque = memory,
    };

    return ops;
}

static fake_reader_memory_t fake_memory_for(void *base, size_t size,
                                            const fake_read_failure_t *failures,
                                            size_t failure_count)
{
    fake_reader_memory_t memory = {
        .base = (uintptr_t)base,
        .size = size,
        .failures = failures,
        .failure_count = failure_count,
    };

    return memory;
}

static void init_link_map(struct link_map_x64 *link_map, char *name)
{
    memset(link_map, 0, sizeof(*link_map));
    link_map->l_addr = 0x100000;
    link_map->l_name = name;
    link_map->l_ld = (Elf64_Dyn *)0x101000;
    link_map->l_ns = 7;
    link_map->l_map_start = 0x100000;
    link_map->l_map_end = 0x120000;
}

static void test_valid_link_map_reads_complete_observation(void)
{
    struct {
        struct link_map_x64 link_map;
        char guest_name[32];
    } guest = { 0 };
    kzt_guest_object_observation_t observation = { 0 };
    fake_reader_memory_t memory;
    kzt_guest_link_map_reader_ops_t ops;

    strcpy(guest.guest_name, "/guest/libfoo.so");
    init_link_map(&guest.link_map, guest.guest_name);
    memory = fake_memory_for(&guest, sizeof(guest), NULL, 0);
    ops = fake_ops(&memory);

    check_int("read_observation.valid",
              kzt_guest_link_map_read_observation((uintptr_t)&guest.link_map,
                                                  &ops,
                                                  &observation),
              0);
    check_uintptr("observation.link_map_addr",
                  observation.link_map_addr,
                  (uintptr_t)&guest.link_map);
    check_uintptr("observation.load_bias",
                  observation.load_bias.value,
                  0x100000);
    check_int("observation.load_bias.status",
              observation.load_bias.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("observation.dynamic_addr",
                  observation.dynamic_addr.value,
                  0x101000);
    check_int("observation.dynamic_addr.status",
              observation.dynamic_addr.status,
              KZT_GUEST_FIELD_OK);
    check_uintptr("observation.map_start",
                  observation.map_start.value,
                  0x100000);
    check_uintptr("observation.map_end",
                  observation.map_end.value,
                  0x120000);
    check_uintptr("observation.namespace_id",
                  observation.namespace_id.value,
                  7);
    check_string("observation.path", observation.path.value,
                 "/guest/libfoo.so");
    check_int("observation.path.status",
              observation.path.status,
              KZT_GUEST_FIELD_OK);
    check_int("observation.soname.status",
              observation.soname.status,
              KZT_GUEST_FIELD_NOT_PARSED);
    check_int("observation.dynamic_view_status",
              observation.dynamic_view_status,
              KZT_GUEST_FIELD_NOT_PARSED);

    kzt_guest_link_map_observation_clear(&observation);
}

static void test_invalid_link_map_is_identity_failure(void)
{
    char unrelated[16] = { 0 };
    kzt_guest_object_observation_t observation = { 0 };
    fake_reader_memory_t memory = fake_memory_for(unrelated,
                                                  sizeof(unrelated),
                                                  NULL,
                                                  0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);

    check_int("read_observation.null-link-map",
              kzt_guest_link_map_read_observation(0, &ops, &observation),
              -1);
    check_uintptr("null-link-map.identity", observation.link_map_addr, 0);

    check_int("read_observation.out-of-range-link-map",
              kzt_guest_link_map_read_observation((uintptr_t)unrelated - 8,
                                                  &ops,
                                                  &observation),
              -1);
    check_uintptr("out-of-range.identity", observation.link_map_addr, 0);
}

static void test_field_read_failure_forms_partial_observation(void)
{
    struct {
        struct link_map_x64 link_map;
        char guest_name[32];
    } guest = { 0 };
    fake_read_failure_t read_failures[] = {
        {
            .addr = (uintptr_t)&guest.link_map + offsetof(struct link_map_x64, l_ld),
            .size = sizeof(guest.link_map.l_ld),
        },
        {
            .addr = (uintptr_t)&guest.link_map + offsetof(struct link_map_x64, l_map_end),
            .size = sizeof(guest.link_map.l_map_end),
        },
    };
    fake_reader_memory_t memory;
    kzt_guest_link_map_reader_ops_t ops;
    kzt_guest_object_observation_t observation = { 0 };

    strcpy(guest.guest_name, "/guest/libpartial.so");
    init_link_map(&guest.link_map, guest.guest_name);
    memory = fake_memory_for(&guest,
                             sizeof(guest),
                             read_failures,
                             sizeof(read_failures) / sizeof(read_failures[0]));
    ops = fake_ops(&memory);

    check_int("read_observation.partial",
              kzt_guest_link_map_read_observation((uintptr_t)&guest.link_map,
                                                  &ops,
                                                  &observation),
              0);
    check_uintptr("partial.identity",
                  observation.link_map_addr,
                  (uintptr_t)&guest.link_map);
    check_int("partial.load-bias-ok",
              observation.load_bias.status,
              KZT_GUEST_FIELD_OK);
    check_int("partial.dynamic-read-error",
              observation.dynamic_addr.status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_int("partial.map-end-read-error",
              observation.map_end.status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_string("partial.path", observation.path.value,
                 "/guest/libpartial.so");

    kzt_guest_link_map_observation_clear(&observation);
}

static void test_name_snapshot_status_matrix(void)
{
    char storage[128];
    fake_read_failure_t read_failures[] = {
        {
            .addr = (uintptr_t)(storage + 98),
            .size = 1,
        },
    };
    fake_reader_memory_t memory;
    kzt_guest_link_map_reader_ops_t ops;
    kzt_guest_string_field_t name = { 0 };

    memset(storage, 0, sizeof(storage));
    memcpy(storage, "/guest/libok.so", sizeof("/guest/libok.so"));
    storage[32] = 0;
    memcpy(storage + 64, "abcd", 4);
    memcpy(storage + 96, "broken", sizeof("broken"));

    memory = fake_memory_for(storage,
                             sizeof(storage),
                             read_failures,
                             sizeof(read_failures) / sizeof(read_failures[0]));
    ops = fake_ops(&memory);

    check_int("name.valid",
              kzt_guest_link_map_read_name_snapshot((uintptr_t)storage,
                                                    &ops,
                                                    32,
                                                    &name),
              0);
    check_int("name.valid.status", name.status, KZT_GUEST_FIELD_OK);
    check_string("name.valid.value", name.value, "/guest/libok.so");
    kzt_guest_link_map_string_clear(&name);

    check_int("name.empty",
              kzt_guest_link_map_read_name_snapshot((uintptr_t)(storage + 32),
                                                    &ops,
                                                    32,
                                                    &name),
              0);
    check_int("name.empty.status", name.status, KZT_GUEST_FIELD_OK);
    check_string("name.empty.value", name.value, "");
    kzt_guest_link_map_string_clear(&name);

    check_int("name.truncated",
              kzt_guest_link_map_read_name_snapshot((uintptr_t)(storage + 64),
                                                    &ops,
                                                    4,
                                                    &name),
              0);
    check_int("name.truncated.status", name.status,
              KZT_GUEST_FIELD_TRUNCATED);
    check_string("name.truncated.value", name.value, "abcd");
    kzt_guest_link_map_string_clear(&name);

    check_int("name.read-error",
              kzt_guest_link_map_read_name_snapshot((uintptr_t)(storage + 96),
                                                    &ops,
                                                    32,
                                                    &name),
              0);
    check_int("name.read-error.status", name.status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_true("name.read-error.value", name.value == NULL);
    kzt_guest_link_map_string_clear(&name);

    check_int("name.unknown-null",
              kzt_guest_link_map_read_name_snapshot(0, &ops, 32, &name),
              0);
    check_int("name.unknown-null.status", name.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_true("name.unknown-null.value", name.value == NULL);
    kzt_guest_link_map_string_clear(&name);
}

static void test_allocation_failure_is_read_error_not_borrowed_pointer(void)
{
    char guest_name[] = "/guest/liballoc.so";
    fake_reader_memory_t memory = fake_memory_for(guest_name,
                                                  sizeof(guest_name),
                                                  NULL,
                                                  0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_string_field_t name = { 0 };

    kzt_guest_link_map_reader_test_set_alloc_failure_after(0);
    check_int("name.alloc-failure",
              kzt_guest_link_map_read_name_snapshot((uintptr_t)guest_name,
                                                    &ops,
                                                    64,
                                                    &name),
              0);
    kzt_guest_link_map_reader_test_set_alloc_failure_after(-1);

    check_int("name.alloc-failure.status", name.status,
              KZT_GUEST_FIELD_READ_ERROR);
    check_true("name.alloc-failure.value", name.value == NULL);
}

int main(void)
{
    test_valid_link_map_reads_complete_observation();
    test_invalid_link_map_is_identity_failure();
    test_field_read_failure_forms_partial_observation();
    test_name_snapshot_status_matrix();
    test_allocation_failure_is_read_error_not_borrowed_pointer();

    if (failures) {
        fprintf(stderr, "kzt-guest-link-map-reader: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-guest-link-map-reader: all contract tests passed");
    return 0;
}
