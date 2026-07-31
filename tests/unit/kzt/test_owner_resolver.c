#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_owner_resolver.h"

static int failures;

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

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got,
            expected);
    ++failures;
}

static void check_str(const char *name, const char *got,
                      const char *expected)
{
    if ((!got && !expected) || (got && expected && !strcmp(got, expected))) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static kzt_guest_object_observation_t observation(
    uintptr_t link_map_addr,
    uintptr_t map_start,
    uintptr_t map_end,
    const char *soname)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map_addr,
        .load_bias = { map_start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { map_start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { map_start, KZT_GUEST_FIELD_OK },
        .map_end = { map_end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { soname, KZT_GUEST_FIELD_OK },
        .soname = { soname, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_patch_object_ref_t object_ref(uintptr_t link_map_addr,
                                         unsigned long generation)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = link_map_addr,
        .map_start = 0x70000000,
        .map_end = 0x70001000,
        .generation = generation,
        .soname = "libexpected.so",
        .path = "/guest/libexpected.so",
    };
}

static void test_same_soname_different_ranges_resolves_by_address(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t first = observation(
        0x1000, 0x70000000, 0x70001000, "libsame.so");
    kzt_guest_object_observation_t second = observation(
        0x2000, 0x71000000, 0x71001000, "libsame.so");
    kzt_owner_resolution_t resolution;

    check_int("same.observe.first",
              kzt_guest_registry_observe(registry, &first),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("same.observe.second",
              kzt_guest_registry_observe(registry, &second),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("same.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x71000080, 0x71000090, &resolution), 0);
    check_int("same.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("same.match", resolution.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_ulong("same.current.link_map",
                resolution.current_owner.link_map_addr, 0x2000);
    check_ulong("same.expected.link_map",
                resolution.expected_owner.link_map_addr, 0x2000);
    check_ulong("same.current.generation",
                resolution.current_owner.generation, 2);
    check_str("same.current.soname", resolution.current_owner.soname,
              "libsame.so");
    check_int("same.current.matches", resolution.current_match_count, 1);
    check_int("same.expected.matches", resolution.expected_match_count, 1);

    kzt_guest_registry_destroy(&registry);
}

static void test_range_boundaries_are_start_inclusive_end_exclusive(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(
        0x3000, 0x72000000, 0x72001000, "libbounds.so");
    kzt_owner_resolution_t resolution;

    check_int("bounds.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("bounds.start.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x72000000, 0x72000008, &resolution), 0);
    check_int("bounds.start.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("bounds.start.match", resolution.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_ulong("bounds.start.owner",
                resolution.current_owner.link_map_addr, 0x3000);

    check_int("bounds.end.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x72001000, 0x72000008, &resolution), 0);
    check_int("bounds.end.status", resolution.status,
              KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND);
    check_int("bounds.end.match", resolution.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("bounds.end.current-known", resolution.current_owner.known, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_unknown_range_keeps_owner_unknown(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(
        0x4000, 0x73000000, 0x73001000, "libunknown-range.so");
    kzt_owner_resolution_t resolution;

    object.map_start.status = KZT_GUEST_FIELD_UNKNOWN;
    object.map_end.status = KZT_GUEST_FIELD_UNKNOWN;
    check_int("unknown-range.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("unknown-range.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x73000080, 0x73000090, &resolution), 0);
    check_int("unknown-range.status", resolution.status,
              KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND);
    check_int("unknown-range.match", resolution.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("unknown-range.current-known",
              resolution.current_owner.known, 0);

    kzt_guest_registry_destroy(&registry);
}

static void test_missing_registry_keeps_owner_unknown(void)
{
    kzt_owner_resolution_t resolution;

    check_int("missing-registry.resolve",
              kzt_owner_resolver_resolve_current(
                  NULL, 0x74000080, 0x74000090, &resolution), 0);
    check_int("missing-registry.status", resolution.status,
              KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE);
    check_int("missing-registry.match", resolution.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("missing-registry.current-known",
              resolution.current_owner.known, 0);
}

static void test_owner_mismatch_is_reported_but_not_matched(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t current = observation(
        0x5000, 0x75000000, 0x75001000, "libpreload.so");
    kzt_guest_object_observation_t expected = observation(
        0x6000, 0x76000000, 0x76001000, "libgtk-3.so");
    kzt_owner_resolution_t resolution;

    check_int("mismatch.observe.current",
              kzt_guest_registry_observe(registry, &current),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("mismatch.observe.expected",
              kzt_guest_registry_observe(registry, &expected),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("mismatch.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x75000020, 0x76000020, &resolution), 0);
    check_int("mismatch.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("mismatch.match", resolution.owner_match,
              KZT_PATCH_OWNER_MISMATCH);
    check_ulong("mismatch.current.owner",
                resolution.current_owner.link_map_addr, 0x5000);
    check_ulong("mismatch.expected.owner",
                resolution.expected_owner.link_map_addr, 0x6000);
    check_str("mismatch.current.soname", resolution.current_owner.soname,
              "libpreload.so");
    check_str("mismatch.expected.soname", resolution.expected_owner.soname,
              "libgtk-3.so");

    kzt_guest_registry_destroy(&registry);
}

static void test_generation_unknown_does_not_match(void)
{
    kzt_patch_object_ref_t current = object_ref(0x7000, 0);
    kzt_patch_object_ref_t expected = object_ref(0x7000, 1);

    check_int("generation-unknown.current",
              kzt_owner_resolver_match_refs(&current, &expected),
              KZT_PATCH_OWNER_UNKNOWN);

    current.generation = 1;
    expected.generation = 0;
    check_int("generation-unknown.expected",
              kzt_owner_resolver_match_refs(&current, &expected),
              KZT_PATCH_OWNER_UNKNOWN);
}

static void test_native_bridge_address_is_not_expected_owner_input(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t guest = observation(
        0xa000, 0x79000000, 0x79001000, "libguest-target.so");
    kzt_guest_object_observation_t bridge_like = observation(
        0xb000, 0x7a000000, 0x7a001000, "libbridge-like.so");
    kzt_owner_resolution_t resolution;

    check_int("bridge-role.observe.guest",
              kzt_guest_registry_observe(registry, &guest),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("bridge-role.observe.bridge-like",
              kzt_guest_registry_observe(registry, &bridge_like),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("bridge-role.guest-target.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x79000020, 0x79000080, &resolution), 0);
    check_int("bridge-role.guest-target.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("bridge-role.guest-target.match", resolution.owner_match,
              KZT_PATCH_OWNER_MATCH);

    check_int("bridge-role.native-bridge.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x79000020, 0x7a000080, &resolution), 0);
    check_int("bridge-role.native-bridge.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("bridge-role.native-bridge.match", resolution.owner_match,
              KZT_PATCH_OWNER_MISMATCH);

    kzt_guest_registry_destroy(&registry);
}

static void test_ambiguous_range_keeps_owner_unknown(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t first = observation(
        0x8000, 0x78000000, 0x78002000, "liboverlap-a.so");
    kzt_guest_object_observation_t second = observation(
        0x9000, 0x78001000, 0x78003000, "liboverlap-b.so");
    kzt_owner_resolution_t resolution;

    check_int("ambiguous.observe.first",
              kzt_guest_registry_observe(registry, &first),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("ambiguous.observe.second",
              kzt_guest_registry_observe(registry, &second),
              KZT_GUEST_REGISTRY_ADDED);

    check_int("ambiguous.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x78001800, 0x78000020, &resolution), 0);
    check_int("ambiguous.status", resolution.status,
              KZT_OWNER_RESOLVER_CURRENT_AMBIGUOUS);
    check_int("ambiguous.match", resolution.owner_match,
              KZT_PATCH_OWNER_UNKNOWN);
    check_int("ambiguous.matches", resolution.current_match_count, 2);

    kzt_guest_registry_destroy(&registry);
}

static void test_dead_objects_do_not_resolve_owner(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(
        0xc000, 0x7b000000, 0x7b001000, "libdead.so");
    kzt_owner_resolution_t resolution;

    check_int("dead.observe", kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("dead.retire", kzt_guest_registry_retire(
                  registry, object.link_map_addr, 1), 0);
    check_int("dead.resolve", kzt_owner_resolver_resolve_current(
                  registry, 0x7b000010, 0x7b000020, &resolution), 0);
    check_int("dead.status", resolution.status,
              KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND);
    check_int("dead.owner-unknown", resolution.current_owner.known, 0);
    kzt_guest_registry_destroy(&registry);
}

static void test_unique_owner_resolution_does_not_need_snapshot_allocation(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(
        0xd000, 0x7c000000, 0x7c001000, "libcompact-owner.so");
    kzt_owner_resolution_t resolution;

    check_int("compact-owner.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    kzt_guest_registry_test_set_alloc_failure_after(0);
    check_int("compact-owner.resolve",
              kzt_owner_resolver_resolve_current(
                  registry, 0x7c000010, 0x7c000020, &resolution), 0);
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    check_int("compact-owner.status", resolution.status,
              KZT_OWNER_RESOLVER_RESOLVED);
    check_int("compact-owner.match", resolution.owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_ulong("compact-owner.link-map",
                resolution.current_owner.link_map_addr, 0xd000);
    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_same_soname_different_ranges_resolves_by_address();
    test_range_boundaries_are_start_inclusive_end_exclusive();
    test_unknown_range_keeps_owner_unknown();
    test_missing_registry_keeps_owner_unknown();
    test_owner_mismatch_is_reported_but_not_matched();
    test_generation_unknown_does_not_match();
    test_native_bridge_address_is_not_expected_owner_input();
    test_ambiguous_range_keeps_owner_unknown();
    test_dead_objects_do_not_resolve_owner();
    test_unique_owner_resolution_does_not_need_snapshot_allocation();

    if (failures) {
        fprintf(stderr, "kzt-owner-resolver: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-owner-resolver: all resolver tests passed");
    return 0;
}
