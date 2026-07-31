#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_link_map_reader.h"
#include "target/i386/latx/include/kzt_guest_registry.h"

typedef struct test_guest_link_map {
    uint64_t l_addr;
    uint64_t l_name;
    uint64_t l_ld;
    uint64_t l_next;
    uint64_t l_prev;
    uint64_t private_l_ns;
    uint64_t private_l_map_start;
    uint64_t private_l_map_end;
} test_guest_link_map_t;

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

static void init_link_map(test_guest_link_map_t *link_map, char *name)
{
    memset(link_map, 0, sizeof(*link_map));
    link_map->l_addr = 0x100000;
    link_map->l_name = (uintptr_t)name;
    link_map->l_ld = 0x101000;
    /* Poison private glibc fields: the reader must never trust them. */
    link_map->private_l_ns = 7;
    link_map->private_l_map_start = 0x100000;
    link_map->private_l_map_end = 0x120000;
}

static void test_valid_link_map_reads_complete_observation(void)
{
    struct {
        test_guest_link_map_t link_map;
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
    check_int("observation.map_start.status",
              observation.map_start.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_int("observation.map_end.status",
              observation.map_end.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_int("observation.namespace_id.status",
              observation.namespace_id.status,
              KZT_GUEST_FIELD_UNKNOWN);
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
              0);
    check_uintptr("out-of-range.identity", observation.link_map_addr,
                  (uintptr_t)unrelated - 8);
    check_int("out-of-range.load-bias", observation.load_bias.status,
              KZT_GUEST_FIELD_READ_ERROR);
    kzt_guest_link_map_observation_clear(&observation);
}

static void test_field_read_failure_forms_partial_observation(void)
{
    struct {
        test_guest_link_map_t link_map;
        char guest_name[32];
    } guest = { 0 };
    fake_read_failure_t read_failures[] = {
        {
            .addr = (uintptr_t)&guest.link_map +
                    offsetof(test_guest_link_map_t, l_ld),
            .size = sizeof(guest.link_map.l_ld),
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
    check_int("partial.map-end-unknown",
              observation.map_end.status,
              KZT_GUEST_FIELD_UNKNOWN);
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
    check_int("name.over-limit.status", name.status,
              KZT_GUEST_FIELD_UNKNOWN);
    check_string("name.over-limit.value", name.value, NULL);
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

static void test_main_namespace_walk_matches_verified_main_identity(void)
{
    test_guest_link_map_t maps[3] = { 0 };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_identity_t main_identity = {
        .load_bias = 0x400000,
        .dynamic_addr = 0x401000,
    };
    uintptr_t namespace_head = 0;

    maps[0].l_addr = 0x400000;
    maps[0].l_ld = 0x401000;
    maps[1].l_addr = 0x700000;
    maps[1].l_ld = 0x701000;
    maps[1].l_prev = (uintptr_t)&maps[0];
    maps[2].l_addr = 0x900000;
    maps[2].l_ld = 0x901000;
    maps[2].l_prev = (uintptr_t)&maps[1];

    check_int("namespace.main-current",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[0], &main_identity, 0, &ops,
                  &namespace_head),
              1);
    check_uintptr("namespace.main-head", namespace_head,
                  (uintptr_t)&maps[0]);
    check_int("namespace.main-via-prev",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[2], &main_identity, 0, &ops,
                  &namespace_head),
              1);
    maps[0].l_ld = 0x402000;
    check_int("namespace.same-bias-wrong-dynamic",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[2], &main_identity, 0, &ops,
                  &namespace_head),
              0);
}

static void test_cached_main_head_uses_identity_not_load_bias(void)
{
    test_guest_link_map_t maps[4] = { 0 };
    test_guest_link_map_t *main_maps = &maps[0];
    test_guest_link_map_t *other_maps = &maps[2];
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_identity_t main_identity = {
        .load_bias = 0x400000,
        .dynamic_addr = 0x401000,
    };
    uintptr_t main_head = (uintptr_t)&main_maps[0];
    uintptr_t namespace_head = 0;

    /* Both namespace heads deliberately use the same load bias. */
    main_maps[0].l_addr = main_identity.load_bias;
    main_maps[0].l_ld = main_identity.dynamic_addr;
    main_maps[1].l_prev = main_head;
    other_maps[0].l_addr = main_identity.load_bias;
    other_maps[0].l_ld = 0x501000;
    other_maps[1].l_prev = (uintptr_t)&other_maps[0];

    check_int("namespace.cached-main",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&main_maps[1], &main_identity, main_head, &ops,
                  &namespace_head),
              1);
    check_int("namespace.cached-same-bias-non-main",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&other_maps[1], &main_identity, main_head, &ops,
                  &namespace_head),
              0);
}

static void test_link_map_identity_rejects_wrong_dynamic_address(void)
{
    test_guest_link_map_t map = {
        .l_addr = 0x700000,
        .l_ld = 0x701000,
    };
    fake_reader_memory_t memory = fake_memory_for(&map, sizeof(map), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_identity_t identity = { 0 };

    check_int("identity.read",
              kzt_guest_link_map_read_identity((uintptr_t)&map, &ops,
                                               &identity),
              0);
    check_uintptr("identity.load-bias", identity.load_bias, map.l_addr);
    check_uintptr("identity.dynamic", identity.dynamic_addr, map.l_ld);
    check_int("identity.match",
              kzt_guest_link_map_identity_matches(&identity, map.l_addr,
                                                  map.l_ld),
              1);
    check_int("identity.wrong-dynamic",
              kzt_guest_link_map_identity_matches(&identity, map.l_addr,
                                                  map.l_ld + 0x1000),
              0);
}

static void test_predecessor_is_read_from_public_prefix(void)
{
    test_guest_link_map_t maps[2] = { 0 };
    fake_read_failure_t failure = {
        .addr = (uintptr_t)&maps[1] +
                offsetof(test_guest_link_map_t, l_prev),
        .size = sizeof(maps[1].l_prev),
    };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    uintptr_t predecessor = 0;

    maps[1].l_prev = (uintptr_t)&maps[0];
    check_int("predecessor.read",
              kzt_guest_link_map_read_predecessor(
                  (uintptr_t)&maps[1], &ops, &predecessor),
              0);
    check_uintptr("predecessor.value", predecessor,
                  (uintptr_t)&maps[0]);

    memory.failures = &failure;
    memory.failure_count = 1;
    predecessor = 1;
    check_int("predecessor.read-failure",
              kzt_guest_link_map_read_predecessor(
                  (uintptr_t)&maps[1], &ops, &predecessor),
              -1);
    check_uintptr("predecessor.failure-clears", predecessor, 0);
}

static void test_successor_is_read_from_public_prefix(void)
{
    test_guest_link_map_t maps[2] = { 0 };
    fake_read_failure_t failure = {
        .addr = (uintptr_t)&maps[0] +
                offsetof(test_guest_link_map_t, l_next),
        .size = sizeof(maps[0].l_next),
    };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    uintptr_t successor = 0;

    maps[0].l_next = (uintptr_t)&maps[1];
    check_int("successor.read",
              kzt_guest_link_map_read_successor(
                  (uintptr_t)&maps[0], &ops, &successor),
              0);
    check_uintptr("successor.value", successor, (uintptr_t)&maps[1]);

    memory.failures = &failure;
    memory.failure_count = 1;
    successor = 1;
    check_int("successor.read-failure",
              kzt_guest_link_map_read_successor(
                  (uintptr_t)&maps[0], &ops, &successor),
              -1);
    check_uintptr("successor.failure-clears", successor, 0);
}

static void test_fingerprint_is_stable_and_covers_public_chain_identity(void)
{
    test_guest_link_map_t maps[3] = { 0 };
    test_guest_link_map_t copies[3] = { 0 };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_fingerprint_t initial = { 0 };
    kzt_guest_link_map_fingerprint_t repeated = { 0 };
    kzt_guest_link_map_fingerprint_t changed = { 0 };
    uint64_t initial_value;
    size_t i;

    for (i = 0; i < 3; ++i) {
        maps[i].l_addr = 0x100000 + i * 0x10000;
        maps[i].l_ld = 0x101000 + i * 0x10000;
        if (i + 1 < 3) {
            maps[i].l_next = (uintptr_t)&maps[i + 1];
        }
    }

    check_int("fingerprint.read",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &initial),
              0);
    check_uintptr("fingerprint.head", initial.namespace_head,
                  (uintptr_t)&maps[0]);
    check_uintptr("fingerprint.count", initial.link_map_count, 3);
    check_true("fingerprint.nonzero", initial.value != 0);
    check_int("fingerprint.repeat",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &repeated),
              0);
    check_true("fingerprint.stable",
               repeated.value == initial.value &&
               repeated.link_map_count == initial.link_map_count);
    initial_value = initial.value;

    maps[1].l_addr += 0x1000;
    check_int("fingerprint.changed-load-bias",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &changed),
              0);
    check_true("fingerprint.mixes-load-bias",
               changed.value != initial_value);
    maps[1].l_addr -= 0x1000;

    maps[1].l_ld += 0x1000;
    check_int("fingerprint.changed-dynamic",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &changed),
              0);
    check_true("fingerprint.mixes-dynamic",
               changed.value != initial_value);
    maps[1].l_ld -= 0x1000;

    maps[0].l_next = (uintptr_t)&maps[2];
    maps[2].l_next = (uintptr_t)&maps[1];
    maps[1].l_next = 0;
    check_int("fingerprint.changed-order",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &changed),
              0);
    check_true("fingerprint.mixes-order", changed.value != initial_value);

    for (i = 0; i < 3; ++i) {
        copies[i].l_addr = 0x100000 + i * 0x10000;
        copies[i].l_ld = 0x101000 + i * 0x10000;
        if (i + 1 < 3) {
            copies[i].l_next = (uintptr_t)&copies[i + 1];
        }
    }
    memory = fake_memory_for(copies, sizeof(copies), NULL, 0);
    ops = fake_ops(&memory);
    check_int("fingerprint.changed-link-map-address",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&copies[0], &ops, &changed),
              0);
    check_true("fingerprint.mixes-link-map-address",
               changed.value != initial_value);
}

static void test_fingerprint_requires_complete_bounded_acyclic_chain(void)
{
    test_guest_link_map_t maps[257] = { 0 };
    fake_read_failure_t failure = {
        .addr = (uintptr_t)&maps[1] +
                offsetof(test_guest_link_map_t, l_ld),
        .size = sizeof(maps[1].l_ld),
    };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_fingerprint_t fingerprint = { 0 };
    size_t i;

    maps[0].l_next = (uintptr_t)&maps[1];
    maps[1].l_next = (uintptr_t)&maps[0];
    check_int("fingerprint.cycle",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &fingerprint),
              -1);
    check_uintptr("fingerprint.cycle-clears-head",
                  fingerprint.namespace_head, 0);
    check_uintptr("fingerprint.cycle-clears-count",
                  fingerprint.link_map_count, 0);
    check_true("fingerprint.cycle-clears-value", fingerprint.value == 0);

    maps[1].l_next = 0;
    memory.failures = &failure;
    memory.failure_count = 1;
    check_int("fingerprint.read-failure",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &fingerprint),
              -1);
    check_uintptr("fingerprint.read-failure-clears-count",
                  fingerprint.link_map_count, 0);

    memory.failures = NULL;
    memory.failure_count = 0;
    for (i = 0; i < 257; ++i) {
        maps[i].l_addr = 0x100000 + i * 0x1000;
        maps[i].l_ld = 0x101000 + i * 0x1000;
        maps[i].l_next = i + 1 < 257 ? (uintptr_t)&maps[i + 1] : 0;
    }
    check_int("fingerprint.unterminated-at-limit",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &fingerprint),
              -1);
    check_uintptr("fingerprint.limit-clears-count",
                  fingerprint.link_map_count, 0);

    maps[255].l_next = 0;
    check_int("fingerprint.exact-limit",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &fingerprint),
              0);
    check_uintptr("fingerprint.exact-limit-count",
                  fingerprint.link_map_count, 256);
}

static void test_fingerprint_revalidation_distinguishes_change_from_unknown(void)
{
    test_guest_link_map_t maps[2] = { 0 };
    fake_read_failure_t failure = {
        .addr = (uintptr_t)&maps[1] +
                offsetof(test_guest_link_map_t, l_next),
        .size = sizeof(maps[1].l_next),
    };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    kzt_guest_link_map_fingerprint_t fingerprint = { 0 };

    maps[0].l_addr = 0x100000;
    maps[0].l_ld = 0x101000;
    maps[0].l_next = (uintptr_t)&maps[1];
    maps[1].l_addr = 0x200000;
    maps[1].l_ld = 0x201000;

    check_int("revalidate.snapshot",
              kzt_guest_link_map_read_fingerprint(
                  (uintptr_t)&maps[0], &ops, &fingerprint),
              0);
    check_int("revalidate.unchanged",
              kzt_guest_link_map_revalidate_fingerprint(
                  &fingerprint, &ops),
              1);

    maps[1].l_ld += 0x1000;
    check_int("revalidate.changed",
              kzt_guest_link_map_revalidate_fingerprint(
                  &fingerprint, &ops),
              0);
    maps[1].l_ld -= 0x1000;

    memory.failures = &failure;
    memory.failure_count = 1;
    check_int("revalidate.unknown",
              kzt_guest_link_map_revalidate_fingerprint(
                  &fingerprint, &ops),
              -1);

    check_int("revalidate.invalid-fingerprint",
              kzt_guest_link_map_revalidate_fingerprint(
                  &(kzt_guest_link_map_fingerprint_t) { 0 }, &ops),
              -1);
}

static void test_main_namespace_walk_fails_open_on_bad_chain(void)
{
    test_guest_link_map_t maps[2] = { 0 };
    fake_read_failure_t failure = {
        .addr = (uintptr_t)&maps[0] +
                offsetof(test_guest_link_map_t, l_addr),
        .size = sizeof(maps[0].l_addr),
    };
    fake_reader_memory_t memory = fake_memory_for(
        maps, sizeof(maps), &failure, 1);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);

    maps[0].l_addr = 0x400000;
    maps[1].l_addr = 0x700000;
    maps[1].l_prev = (uintptr_t)&maps[0];

    check_int("namespace.read-failure",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[1],
                  &(kzt_guest_link_map_identity_t) { 0x400000, 0x401000 },
                  0, &ops, NULL),
              -1);

    memory.failures = NULL;
    memory.failure_count = 0;
    maps[0].l_prev = (uintptr_t)&maps[1];
    check_int("namespace.cycle",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[1],
                  &(kzt_guest_link_map_identity_t) { 0x500000, 0x501000 },
                  0, &ops, NULL),
              -1);

    check_int("namespace.invalid-args",
              kzt_guest_link_map_classify_namespace(
                  0, &(kzt_guest_link_map_identity_t) { 0x400000, 0x401000 },
                  0, &ops, NULL),
              -1);
}

static void test_main_namespace_walk_is_bounded(void)
{
    test_guest_link_map_t maps[257] = { 0 };
    fake_reader_memory_t memory = fake_memory_for(maps, sizeof(maps), NULL, 0);
    kzt_guest_link_map_reader_ops_t ops = fake_ops(&memory);
    size_t i;

    maps[0].l_addr = 0x400000;
    for (i = 1; i < sizeof(maps) / sizeof(maps[0]); ++i) {
        maps[i].l_addr = 0x500000 + i * 0x1000;
        maps[i].l_prev = (uintptr_t)&maps[i - 1];
    }

    check_int("namespace.walk-limit",
              kzt_guest_link_map_classify_namespace(
                  (uintptr_t)&maps[256],
                  &(kzt_guest_link_map_identity_t) { 0x400000, 0x401000 },
                  0, &ops, NULL),
              -1);
}

int main(void)
{
    test_valid_link_map_reads_complete_observation();
    test_invalid_link_map_is_identity_failure();
    test_field_read_failure_forms_partial_observation();
    test_name_snapshot_status_matrix();
    test_allocation_failure_is_read_error_not_borrowed_pointer();
    test_main_namespace_walk_matches_verified_main_identity();
    test_cached_main_head_uses_identity_not_load_bias();
    test_link_map_identity_rejects_wrong_dynamic_address();
    test_predecessor_is_read_from_public_prefix();
    test_successor_is_read_from_public_prefix();
    test_fingerprint_is_stable_and_covers_public_chain_identity();
    test_fingerprint_requires_complete_bounded_acyclic_chain();
    test_fingerprint_revalidation_distinguishes_change_from_unknown();
    test_main_namespace_walk_fails_open_on_bad_chain();
    test_main_namespace_walk_is_bounded();

    if (failures) {
        fprintf(stderr, "kzt-guest-link-map-reader: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-guest-link-map-reader: all contract tests passed");
    return 0;
}
