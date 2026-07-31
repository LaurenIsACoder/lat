#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "kzt_guest_registry.h"

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got != expected) {
        fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
        ++failures;
    }
}

static kzt_guest_object_observation_t observation(uintptr_t link_map)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map,
        .load_bias = { 0x400000, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { 0x401000, KZT_GUEST_FIELD_OK },
        .map_start = { 0x400000, KZT_GUEST_FIELD_OK },
        .map_end = { 0x408000, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { "/guest/libfixture.so", KZT_GUEST_FIELD_OK },
        .soname = { "libfixture.so", KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_dynamic_view_t complete_view(void)
{
    return (kzt_guest_dynamic_view_t) {
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .dynamic_addr = 0x401000,
        .load_bias = 0x400000,
        .has_null = 1,
        .jmprel = { 1, 0x402000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
        .pltrelsz = { 1, sizeof(Elf64_Rela), KZT_GUEST_DYNAMIC_SCALAR },
        .pltrel = { 1, DT_RELA, KZT_GUEST_DYNAMIC_SCALAR },
        .pltgot = { 1, 0x403000, KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS },
    };
}

static void test_incomplete_evidence_fails_open(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(0x1000);
    kzt_guest_dynamic_view_t view = complete_view();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };

    if (!registry) {
        ++failures;
        return;
    }
    check_int("incomplete.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("incomplete.source",
              kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("incomplete.decision",
              kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);
    check_int("incomplete.claim",
              kzt_guest_registry_got_plt_injection_claim(
                  &decision, &view),
              KZT_GUEST_GOT_PLT_INJECTION_FAIL_OPEN);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    kzt_guest_registry_source_lease_release(&source);
    kzt_guest_registry_destroy(&registry);
}

static void test_exact_generation_claim_is_idempotent(void)
{
    kzt_guest_registry_t *registry = kzt_guest_registry_init();
    kzt_guest_object_observation_t object = observation(0x1000);
    kzt_guest_dynamic_view_t view = complete_view();
    kzt_guest_registry_source_lease_t source = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision = { 0 };

    if (!registry) {
        ++failures;
        return;
    }
    check_int("idempotent.observe",
              kzt_guest_registry_observe(registry, &object),
              KZT_GUEST_REGISTRY_ADDED);
    check_int("idempotent.view",
              kzt_guest_registry_commit_dynamic_view(registry, 0x1000, 1,
                                                     &view),
              KZT_GUEST_REGISTRY_UPDATED);
    check_int("idempotent.source",
              kzt_guest_registry_source_lease_acquire(
                  registry, 0x1000, 1, 0, &source), 0);
    check_int("idempotent.decision",
              kzt_guest_registry_patch_decision_lease_acquire(
                  &source, &decision), 0);
    check_int("idempotent.first-claim",
              kzt_guest_registry_got_plt_injection_claim(
                  &decision, &view),
              KZT_GUEST_GOT_PLT_INJECTION_GRANTED);
    check_int("idempotent.concurrent-claim",
              kzt_guest_registry_got_plt_injection_claim(
                  &decision, &view),
              KZT_GUEST_GOT_PLT_INJECTION_IN_PROGRESS);
    check_int("idempotent.finish",
              kzt_guest_registry_got_plt_injection_finish(
                  &decision, 1), 0);
    check_int("idempotent.replay",
              kzt_guest_registry_got_plt_injection_claim(
                  &decision, &view),
              KZT_GUEST_GOT_PLT_INJECTION_ALREADY_APPLIED);
    kzt_guest_registry_patch_decision_lease_release(&decision);
    kzt_guest_registry_source_lease_release(&source);
    kzt_guest_registry_destroy(&registry);
}

int main(void)
{
    test_incomplete_evidence_fails_open();
    test_exact_generation_claim_is_idempotent();
    if (failures) {
        fprintf(stderr, "kzt registry GOT/PLT injection: %d failure(s)\n",
                failures);
        return 1;
    }
    puts("kzt registry GOT/PLT injection: PASS");
    return 0;
}
