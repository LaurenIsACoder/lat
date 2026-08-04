#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_registry.h"

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

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
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

static void check_u64(const char *name, uint64_t got, uint64_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%llx expected 0x%llx\n", name,
            (unsigned long long)got, (unsigned long long)expected);
    ++failures;
}

static kzt_guest_object_observation_t make_observation(uintptr_t link_map_addr)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { 0x100000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x101000, KZT_GUEST_FIELD_OK },
        .map_start = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .map_end = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .namespace_id = { 0, KZT_GUEST_FIELD_UNKNOWN },
        .path = { "/guest/libfoo.so", KZT_GUEST_FIELD_OK },
        .soname = { NULL, KZT_GUEST_FIELD_NOT_PARSED },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_dynamic_field_t make_field(
    uint64_t value,
    kzt_guest_dynamic_address_semantics_t semantics)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = semantics,
    };
}

static kzt_guest_dynamic_view_t make_dynamic_view(uintptr_t dynamic_addr,
                                                  uintptr_t load_bias,
                                                  uint64_t symtab)
{
    kzt_guest_dynamic_view_t view = {
        .dynamic_addr = dynamic_addr,
        .load_bias = load_bias,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 8,
        .has_null = 1,
        .scan_limit = KZT_GUEST_DYNAMIC_SCAN_LIMIT,
        .unknown_tag_count = 1,
        .first_unknown_tag = 0x6000000d,
        .first_unknown_tag_index = 3,
        .symtab = make_field(symtab, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .strtab = make_field(symtab + 0x1000,
                             KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .strsz = make_field(0x240, KZT_GUEST_DYNAMIC_SCALAR),
        .gnu_hash = make_field(symtab + 0x2000,
                               KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .versym = make_field(symtab + 0x3000,
                             KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .jmprel = make_field(symtab + 0x4000,
                             KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .pltrelsz = make_field(0x30, KZT_GUEST_DYNAMIC_SCALAR),
        .pltgot = make_field(symtab + 0x5000,
                             KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
        .needed_offsets = { 0x10, 0x38 },
        .needed_count = 2,
        .needed_address_semantics = KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET,
    };

    return view;
}

static int dynamic_field_equal(const kzt_guest_dynamic_field_t *left,
                               const kzt_guest_dynamic_field_t *right)
{
    return left->present == right->present &&
           left->value == right->value &&
           left->address_semantics == right->address_semantics;
}

static void assert_dynamic_view_equal(const char *name,
                                      const kzt_guest_dynamic_view_t *got,
                                      const kzt_guest_dynamic_view_t *expected)
{
    char field_name[128];
    size_t i;

    check_uintptr(name, got->dynamic_addr, expected->dynamic_addr);
    check_uintptr(name, got->load_bias, expected->load_bias);
    check_int(name, got->status, expected->status);
    check_ulong(name, got->entry_count, expected->entry_count);
    check_int(name, got->has_null, expected->has_null);
    check_ulong("dynamic.scan_limit", got->scan_limit, expected->scan_limit);
    check_ulong("dynamic.unknown_tag_count", got->unknown_tag_count,
                expected->unknown_tag_count);
    check_ulong("dynamic.first_unknown_tag",
                (unsigned long)got->first_unknown_tag,
                (unsigned long)expected->first_unknown_tag);
    check_ulong("dynamic.first_unknown_tag_index",
                got->first_unknown_tag_index,
                expected->first_unknown_tag_index);
    check_true("dynamic.symtab", dynamic_field_equal(&got->symtab,
                                                     &expected->symtab));
    check_true("dynamic.strtab", dynamic_field_equal(&got->strtab,
                                                     &expected->strtab));
    check_true("dynamic.strsz", dynamic_field_equal(&got->strsz,
                                                    &expected->strsz));
    check_true("dynamic.gnu_hash", dynamic_field_equal(&got->gnu_hash,
                                                       &expected->gnu_hash));
    check_true("dynamic.versym", dynamic_field_equal(&got->versym,
                                                     &expected->versym));
    check_true("dynamic.jmprel", dynamic_field_equal(&got->jmprel,
                                                     &expected->jmprel));
    check_true("dynamic.pltrelsz", dynamic_field_equal(&got->pltrelsz,
                                                       &expected->pltrelsz));
    check_true("dynamic.pltgot", dynamic_field_equal(&got->pltgot,
                                                     &expected->pltgot));
    check_ulong("dynamic.needed_count", got->needed_count,
                expected->needed_count);
    check_int("dynamic.needed_semantics", got->needed_address_semantics,
              expected->needed_address_semantics);
    for (i = 0; i < expected->needed_count; ++i) {
        snprintf(field_name, sizeof(field_name), "%s.needed[%lu]", name,
                 (unsigned long)i);
        check_u64(field_name, got->needed_offsets[i],
                  expected->needed_offsets[i]);
    }
}

static kzt_guest_object_snapshot_t *find_snapshot(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;

    check_int("find_by_link_map", kzt_guest_registry_find_by_link_map(
                  registry, link_map_addr, &snapshot), 0);
    check_true("find_by_link_map.snapshot", snapshot != NULL);
    return snapshot;
}

static void test_commit_and_query_are_per_object(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t first = make_observation(0x1000);
    kzt_guest_object_observation_t second = make_observation(0x2000);
    kzt_guest_dynamic_view_t first_view =
        make_dynamic_view(0x101000, 0x100000, 0x7000010000);
    kzt_guest_dynamic_view_t queried = { 0 };
    kzt_guest_field_status_t queried_status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long generation = 0;
    kzt_guest_object_snapshot_t *snapshot;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    second.dynamic_addr.value = 0x201000;
    check_int("observe.first", kzt_guest_registry_observe(registry, &first),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("observe.second", kzt_guest_registry_observe(registry, &second),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("commit.first",
              kzt_guest_registry_commit_dynamic_view(registry, 0x1000, 1,
                                                     &first_view),
              KZT_GUEST_REGISTRY_UPDATED);

    snapshot = find_snapshot(registry, 0x1000);
    check_int("snapshot.first.status", snapshot->dynamic_view_status,
              KZT_GUEST_FIELD_OK);
    check_int("snapshot.first.state", snapshot->state,
              KZT_GUEST_OBJECT_PARSED);
    check_ulong("snapshot.first.generation", snapshot->generation, 1);
    assert_dynamic_view_equal("snapshot.first.view",
                              &snapshot->dynamic_view, &first_view);
    kzt_guest_object_snapshot_free(snapshot);

    snapshot = find_snapshot(registry, 0x2000);
    check_int("snapshot.second.status", snapshot->dynamic_view_status,
              KZT_GUEST_FIELD_NOT_PARSED);
    check_int("snapshot.second.state", snapshot->state,
              KZT_GUEST_OBJECT_DISCOVERED);
    check_ulong("snapshot.second.generation", snapshot->generation, 2);
    check_uintptr("snapshot.second.dynamic-view-zero",
                  snapshot->dynamic_view.dynamic_addr, 0);
    kzt_guest_object_snapshot_free(snapshot);

    check_int("find.dynamic-view",
              kzt_guest_registry_find_dynamic_view(registry, 0x1000,
                                                   &queried,
                                                   &queried_status,
                                                   &generation),
              0);
    check_int("queried.status", queried_status, KZT_GUEST_FIELD_OK);
    check_ulong("queried.generation", generation, 1);
    assert_dynamic_view_equal("queried.view", &queried, &first_view);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_repeated_commit_and_replacement_semantics(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x3000);
    kzt_guest_dynamic_view_t first_view =
        make_dynamic_view(0x301000, 0x300000, 0x7100010000);
    kzt_guest_dynamic_view_t replacement =
        make_dynamic_view(0x301000, 0x300000, 0x7200010000);
    kzt_guest_object_snapshot_t *snapshot;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("observe.object",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("commit.first",
              kzt_guest_registry_commit_dynamic_view(registry, 0x3000, 1,
                                                     &first_view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("commit.same",
              kzt_guest_registry_commit_dynamic_view(registry, 0x3000, 1,
                                                     &first_view),
              KZT_GUEST_REGISTRY_UNCHANGED);

    replacement.needed_offsets[1] = 0x58;
    replacement.entry_count = 9;
    replacement.unknown_tag_count = 2;
    replacement.first_unknown_tag = 0x6000000e;
    replacement.first_unknown_tag_index = 4;
    check_int("commit.replacement",
              kzt_guest_registry_commit_dynamic_view(registry, 0x3000, 1,
                                                     &replacement),
              KZT_GUEST_REGISTRY_UPDATED);

    snapshot = find_snapshot(registry, 0x3000);
    check_ulong("snapshot.generation-stable", snapshot->generation, 1);
    check_int("snapshot.status", snapshot->dynamic_view_status,
              KZT_GUEST_FIELD_OK);
    check_int("snapshot.state", snapshot->state, KZT_GUEST_OBJECT_PARSED);
    assert_dynamic_view_equal("snapshot.replacement",
                              &snapshot->dynamic_view, &replacement);
    kzt_guest_object_snapshot_free(snapshot);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
}

static void test_snapshots_survive_replacement_and_registry_destroy(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x4000);
    kzt_guest_dynamic_view_t first_view =
        make_dynamic_view(0x401000, 0x400000, 0x7300010000);
    kzt_guest_dynamic_view_t replacement =
        make_dynamic_view(0x401000, 0x400000, 0x7400010000);
    kzt_guest_object_snapshot_t *before_replace;
    kzt_guest_object_snapshot_t *after_replace;
    kzt_guest_registry_dump_t dump = { 0 };

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("observe.object",
              kzt_guest_registry_observe(registry, &observation),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("commit.first",
              kzt_guest_registry_commit_dynamic_view(registry, 0x4000, 1,
                                                     &first_view),
              KZT_GUEST_REGISTRY_UPDATED);
    before_replace = find_snapshot(registry, 0x4000);

    check_int("commit.replacement",
              kzt_guest_registry_commit_dynamic_view(registry, 0x4000, 1,
                                                     &replacement),
              KZT_GUEST_REGISTRY_UPDATED);
    after_replace = find_snapshot(registry, 0x4000);

    check_int("dump.snapshot",
              kzt_guest_registry_dump_snapshot(registry, &dump), 0);
    check_ulong("dump.count", dump.count, 1);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);

    assert_dynamic_view_equal("before_replace.still-first",
                              &before_replace->dynamic_view, &first_view);
    assert_dynamic_view_equal("after_replace.still-replacement",
                              &after_replace->dynamic_view, &replacement);
    assert_dynamic_view_equal("dump.still-replacement",
                              &dump.objects[0].dynamic_view, &replacement);

    kzt_guest_object_snapshot_free(before_replace);
    kzt_guest_object_snapshot_free(after_replace);
    kzt_guest_registry_dump_free(&dump);
}

static void test_missing_and_destroyed_registry_are_rejected(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_dynamic_view_t view =
        make_dynamic_view(0x501000, 0x500000, 0x7500010000);
    kzt_guest_dynamic_view_t queried = {
        .dynamic_addr = 0xdeadbeef,
    };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_OK;
    unsigned long generation = 99;

    check_true("registry.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("commit.missing",
              kzt_guest_registry_commit_dynamic_view(registry, 0x5000, 1,
                                                     &view),
              KZT_GUEST_REGISTRY_ERROR);
    check_int("find.missing",
              kzt_guest_registry_find_dynamic_view(registry, 0x5000,
                                                   &queried, &status,
                                                   &generation),
              -1);
    check_uintptr("find.missing.clears-view", queried.dynamic_addr, 0);
    check_int("find.missing.status", status, KZT_GUEST_FIELD_NOT_PARSED);
    check_ulong("find.missing.generation", generation, 0);

    kzt_guest_registry_destroy(&registry);
    check_true("registry.destroy", registry == NULL);
    check_int("commit.destroyed",
              kzt_guest_registry_commit_dynamic_view(registry, 0x5000, 1,
                                                     &view),
              KZT_GUEST_REGISTRY_DISABLED);
    check_int("find.destroyed",
              kzt_guest_registry_find_dynamic_view(registry, 0x5000,
                                                   &queried, &status,
                                                   &generation),
              -1);
}

static void test_stale_generation_cannot_revive_or_overwrite(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x6000);
    kzt_guest_dynamic_view_t stale =
        make_dynamic_view(0x601000, 0x600000, 0x7600010000);
    kzt_guest_dynamic_view_t fresh =
        make_dynamic_view(0x601000, 0x600000, 0x7700010000);
    kzt_guest_dynamic_view_t queried = { 0 };
    kzt_guest_field_status_t status;
    unsigned long generation;

    check_int("stale.observe.a", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    check_int("stale.retire.a", kzt_guest_registry_retire(
                  registry, observation.link_map_addr, 1), 0);
    check_int("stale.dead-commit", kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &stale),
              KZT_GUEST_REGISTRY_ERROR);
    check_int("stale.observe.b", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    check_int("stale.reused-commit", kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &stale),
              KZT_GUEST_REGISTRY_ERROR);
    check_int("stale.fresh-commit", kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 2, &fresh),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("stale.query", kzt_guest_registry_find_dynamic_view(
                  registry, observation.link_map_addr, &queried, &status,
                  &generation), 0);
    check_ulong("stale.generation", generation, 2);
    assert_dynamic_view_equal("stale.fresh-view", &queried, &fresh);
    kzt_guest_registry_destroy(&registry);
}

static void test_incomplete_dynamic_view_preserves_complete_view(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t observation = make_observation(0x7000);
    kzt_guest_dynamic_view_t complete =
        make_dynamic_view(0x701000, 0x700000, 0x7800010000);
    kzt_guest_dynamic_view_t incomplete = complete;
    kzt_guest_dynamic_view_t queried = { 0 };
    kzt_guest_field_status_t status = KZT_GUEST_FIELD_UNKNOWN;
    unsigned long generation = 0;

    check_true("preserve-complete.init", registry != NULL);
    if (!registry) {
        return;
    }

    check_int("preserve-complete.observe", kzt_guest_registry_observe(
                  registry, &observation), KZT_GUEST_REGISTRY_ADDED);
    check_int("preserve-complete.commit", kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &complete),
              KZT_GUEST_REGISTRY_UPDATED);

    incomplete.status = KZT_GUEST_DYNAMIC_READ_ERROR;
    incomplete.has_null = 0;
    incomplete.entry_count = 1;
    check_int("preserve-complete.read-error",
              kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &incomplete),
              KZT_GUEST_REGISTRY_UNCHANGED);
    incomplete.status = KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    incomplete.entry_count = KZT_GUEST_DYNAMIC_SCAN_LIMIT;
    check_int("preserve-complete.truncated",
              kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &incomplete),
              KZT_GUEST_REGISTRY_UNCHANGED);
    incomplete.status = KZT_GUEST_DYNAMIC_ERROR;
    incomplete.entry_count = 2;
    check_int("preserve-complete.error",
              kzt_guest_registry_commit_dynamic_view(
                  registry, observation.link_map_addr, 1, &incomplete),
              KZT_GUEST_REGISTRY_UNCHANGED);

    check_int("preserve-complete.find", kzt_guest_registry_find_dynamic_view(
                  registry, observation.link_map_addr, &queried, &status,
                  &generation), 0);
    check_int("preserve-complete.status", status, KZT_GUEST_FIELD_OK);
    check_ulong("preserve-complete.generation", generation, 1);
    assert_dynamic_view_equal("preserve-complete.view", &queried, &complete);

    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_commit_and_query_are_per_object();
    test_repeated_commit_and_replacement_semantics();
    test_snapshots_survive_replacement_and_registry_destroy();
    test_missing_and_destroyed_registry_are_rejected();
    test_stale_generation_cannot_revive_or_overwrite();
    test_incomplete_dynamic_view_preserves_complete_view();

    if (failures) {
        fprintf(stderr, "kzt-guest-dynamic-snapshot: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-guest-dynamic-snapshot: all contract tests passed");
    return 0;
}
