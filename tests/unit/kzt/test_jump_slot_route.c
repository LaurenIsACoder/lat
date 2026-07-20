#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_jump_slot_route.h"

struct library_s { int live; };

typedef struct fixture {
    uintptr_t slot;
    uintptr_t raw_expected;
    uintptr_t bridge;
    struct library_s provider;
    struct library_s other;
    int owner_available;
    int acquire_ok;
    int exact_conflict;
    int bridge_ok;
    int bridge_changes_owner_link_map;
    int bridge_changes_owner_generation;
    int source_identity_valid;
    kzt_jump_slot_route_writer_status_t writer_status;
    int writer_mutates;
    int writer_rollback_after_competitor;
    int force_cas_mismatch;
    int load_error;
    int cas_error;
    int acquired;
    int released;
    int enrich_calls;
    int acquire_calls;
    int bridge_calls;
    int source_recheck_calls;
    int provider_touched_after_release;
    int writer_calls;
    int cas_calls;
} fixture_t;

static int failures;

#define CHECK(name, condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__); \
        ++failures; \
    } \
} while (0)

static int enrich_base(kzt_rela_immediate_candidate_request_t *request,
                       void *opaque)
{
    fixture_t *f = opaque;
    ++f->enrich_calls;
    request->owner_match = f->owner_available ? KZT_PATCH_OWNER_MATCH :
                                               KZT_PATCH_OWNER_UNKNOWN;
    request->current_owner.known = f->owner_available;
    request->current_owner.link_map_addr = f->owner_available ? 0x1234 : 0;
    request->current_owner.generation = f->owner_available ? 7 : 0;
    return 0;
}

static int acquire_exact(const kzt_patch_object_ref_t *owner,
                         library_t *resolved_provider,
                         kzt_guest_library_handle_t *handle, void *opaque)
{
    fixture_t *f = opaque;
    if (f->released)
        ++f->provider_touched_after_release;
    ++f->acquire_calls;
    CHECK("acquire.owner", owner->link_map_addr == 0x1234);
    if (!f->acquire_ok) return -1;
    ++f->acquired;
    handle->entry = (void *)1;
    handle->library = f->exact_conflict ? (library_t *)&f->other :
                                         resolved_provider;
    return 0;
}

static void release_exact(kzt_guest_library_handle_t *handle, void *opaque)
{
    fixture_t *f = opaque;
    CHECK("release.handle", handle->entry != NULL);
    ++f->released;
    f->provider.live = 0;
    memset(handle, 0, sizeof(*handle));
}

static int enrich_bridge(kzt_rela_immediate_candidate_request_t *request,
                         library_t *held_provider, void *opaque)
{
    fixture_t *f = opaque;
    if (f->released)
        ++f->provider_touched_after_release;
    ++f->bridge_calls;
    CHECK("bridge.held", held_provider == (library_t *)&f->provider);
    CHECK("bridge.live", f->provider.live == 1);
    if (!f->bridge_ok) return -1;
    request->native_bridge_target = f->bridge;
    if (f->bridge_changes_owner_link_map)
        request->current_owner.link_map_addr = 0x5678;
    if (f->bridge_changes_owner_generation)
        request->current_owner.generation = 8;
    return 0;
}

static int validate_source_identity(
    const kzt_rela_immediate_candidate_request_t *request, void *opaque)
{
    fixture_t *f = opaque;
    ++f->source_recheck_calls;
    CHECK("source-recheck.source", request->source.known == 1);
    return f->source_identity_valid;
}

static int load_slot(uintptr_t slot_addr, uintptr_t *value, void *opaque)
{
    fixture_t *f = opaque;
    if (f->load_error) return -1;
    *value = *(uintptr_t *)slot_addr;
    return 0;
}

static int cas_slot(uintptr_t slot_addr, uintptr_t *expected,
                    uintptr_t replacement, void *opaque)
{
    fixture_t *f = opaque;
    uintptr_t *slot = (uintptr_t *)slot_addr;
    ++f->cas_calls;
    if (f->cas_error) return -1;
    if (f->force_cas_mismatch) {
        *slot = 0xfeedface;
        *expected = *slot;
        f->force_cas_mismatch = 0;
        return 0;
    }
    if (*slot != *expected) {
        *expected = *slot;
        return 0;
    }
    *slot = replacement;
    return 1;
}

static kzt_jump_slot_route_writer_status_t try_writer(
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_patch_spike_slot_ops_t *slot_ops, void *opaque)
{
    fixture_t *f = opaque;
    uintptr_t observed = 0;
    if (f->released)
        ++f->provider_touched_after_release;
    ++f->writer_calls;
    CHECK("writer.raw-preserved",
          request->expected_guest_target == f->raw_expected);
    CHECK("writer.provider-live", f->provider.live == 1);
    if (f->writer_mutates) {
        if (slot_ops->read_slot(request->slot_addr, &observed,
                                slot_ops->opaque) != 0 ||
            slot_ops->write_slot(request->slot_addr,
                                 request->native_bridge_target,
                                 slot_ops->opaque) != 0) {
            return KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
        }
    }
    if (f->writer_rollback_after_competitor) {
        if (slot_ops->read_slot(request->slot_addr, &observed,
                                slot_ops->opaque) != 0 ||
            slot_ops->write_slot(request->slot_addr,
                                 request->native_bridge_target,
                                 slot_ops->opaque) != 0) {
            return KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
        }
        f->slot = 0xfeedface;
        CHECK("rollback.must-not-overwrite-competitor",
              slot_ops->write_slot(request->slot_addr, observed,
                                   slot_ops->opaque) != 0);
        return KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
    }
    return f->writer_status;
}

static fixture_t fixture(void)
{
    return (fixture_t){
        .slot = 0x71000010,
        .raw_expected = 0x71000020,
        .bridge = 0x73000030,
        .provider = { .live = 1 },
        .owner_available = 1,
        .acquire_ok = 1,
        .bridge_ok = 1,
        .writer_status = KZT_JUMP_SLOT_ROUTE_WRITER_APPLIED,
        .writer_mutates = 1,
        .source_identity_valid = 1,
    };
}

static kzt_jump_slot_route_ops_t ops_for(fixture_t *f);

static kzt_jump_slot_route_input_t input_for(fixture_t *f)
{
    return (kzt_jump_slot_route_input_t){
        .enabled = 1,
        .expected_guest_target_present = 1,
        .resolved_target_matches_legacy = 1,
        .resolved_provider = (library_t *)&f->provider,
        .request = {
            .relocation_type = R_X86_64_JUMP_SLOT,
            .source = {
                .known = 1,
                .link_map_addr = 0x1111,
                .generation = 7,
            },
            .slot_addr = (uintptr_t)&f->slot,
            .slot_current_value_present = 1,
            .slot_current_value = f->slot,
            .expected_guest_target = f->raw_expected,
            .legacy_target = 0x72000040,
        },
    };
}

static void test_caller_observation_change_is_never_authorized(void)
{
    for (int expected_present = 0; expected_present < 2;
         ++expected_present) {
        fixture_t f = fixture();
        kzt_jump_slot_route_input_t input = input_for(&f);
        kzt_jump_slot_route_ops_t ops = ops_for(&f);
        kzt_jump_slot_route_result_t result;
        uintptr_t competing = expected_present ? 0x71000050 : 0x71000060;

        input.expected_guest_target_present = expected_present;
        if (!expected_present)
            input.request.expected_guest_target = 0;
        f.slot = competing;
        CHECK("caller-race.call",
              kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
        CHECK("caller-race.status",
              result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
        CHECK("caller-race.final", result.final_value == competing);
        CHECK("caller-race.preserve", f.slot == competing);
        CHECK("caller-race.no-enrich", f.enrich_calls == 0);
        CHECK("caller-race.no-acquire", f.acquire_calls == 0);
        CHECK("caller-race.no-bridge", f.bridge_calls == 0);
        CHECK("caller-race.no-writer", f.writer_calls == 0);
        CHECK("caller-race.no-cas", f.cas_calls == 0);
        CHECK("caller-race.no-fallback",
              result.legacy_fallback_attempted == 0);
    }
}

static void test_same_owner_competitor_cannot_authorize_native(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    uintptr_t competing = f.slot + 0x80;

    /* enrich_base would report the same exact owner/provider for this value. */
    f.slot = competing;
    CHECK("same-owner-race.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("same-owner-race.status",
          result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
    CHECK("same-owner-race.final", result.final_value == competing);
    CHECK("same-owner-race.preserve", f.slot == competing);
    CHECK("same-owner-race.no-enrich", f.enrich_calls == 0);
    CHECK("same-owner-race.no-acquire", f.acquire_calls == 0);
    CHECK("same-owner-race.no-writer", f.writer_calls == 0);
    CHECK("same-owner-race.no-cas", f.cas_calls == 0);
}

static void test_lazy_zero_competitor_is_preserved_without_write(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;

    input.expected_guest_target_present = 0;
    input.request.expected_guest_target = 0;
    f.slot = 0;
    CHECK("lazy-zero.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("lazy-zero.status",
          result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
    CHECK("lazy-zero.final", result.final_value == 0);
    CHECK("lazy-zero.preserve", f.slot == 0);
    CHECK("lazy-zero.no-enrich", f.enrich_calls == 0);
    CHECK("lazy-zero.no-acquire", f.acquire_calls == 0);
    CHECK("lazy-zero.no-writer", f.writer_calls == 0);
    CHECK("lazy-zero.no-cas", f.cas_calls == 0);
}

static void test_resolved_target_mismatch_uses_legacy(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;

    input.resolved_target_matches_legacy = 0;
    CHECK("target-mismatch.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("target-mismatch.status",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
    CHECK("target-mismatch.legacy", f.slot == input.request.legacy_target);
    CHECK("target-mismatch.no-enrich", f.enrich_calls == 0);
    CHECK("target-mismatch.no-acquire", f.acquire_calls == 0);
    CHECK("target-mismatch.no-bridge", f.bridge_calls == 0);
    CHECK("target-mismatch.no-writer", f.writer_calls == 0);
}

static void test_owner_identity_change_during_bridge_falls_back(void)
{
    for (int change_generation = 0; change_generation < 2;
         ++change_generation) {
        fixture_t f = fixture();
        kzt_jump_slot_route_input_t input = input_for(&f);
        kzt_jump_slot_route_ops_t ops = ops_for(&f);
        kzt_jump_slot_route_result_t result;

        f.bridge_changes_owner_link_map = !change_generation;
        f.bridge_changes_owner_generation = change_generation;
        CHECK("owner-refresh.call",
              kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
        CHECK("owner-refresh.status",
              result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
        CHECK("owner-refresh.legacy",
              f.slot == input.request.legacy_target);
        CHECK("owner-refresh.acquired", f.acquired == 1);
        CHECK("owner-refresh.released", f.released == 1);
        CHECK("owner-refresh.bridge", f.bridge_calls == 1);
        CHECK("owner-refresh.no-writer", f.writer_calls == 0);
    }
}

static kzt_jump_slot_route_ops_t ops_for(fixture_t *f)
{
    return (kzt_jump_slot_route_ops_t){
        .enrich_base = enrich_base,
        .acquire_exact_provider = acquire_exact,
        .release_exact_provider = release_exact,
        .enrich_bridge = enrich_bridge,
        .validate_source_identity = validate_source_identity,
        .try_native_writer = try_writer,
        .load_slot = load_slot,
        .compare_exchange_slot = cas_slot,
        .opaque = f,
    };
}

static void test_generation_change_before_writer_preserves_guest(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;

    input.preserve_observed_on_failure = 1;
    input.request.source.known = 1;
    input.request.source.link_map_addr = 0x1111;
    input.request.source.generation = 7;
    f.source_identity_valid = 0;
    CHECK("generation-race.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("generation-race.rechecked", f.source_recheck_calls == 1 &&
          result.source_identity_rechecked == 1);
    CHECK("generation-race.preserved",
          result.status == KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED);
    CHECK("generation-race.slot", f.slot == input.request.slot_current_value);
    CHECK("generation-race.no-writer", f.writer_calls == 0);
    CHECK("generation-race.no-cas", f.cas_calls == 0);
    CHECK("generation-race.no-legacy",
          result.legacy_fallback_attempted == 0);
}

static void test_exact_provider_bridge_success(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    CHECK("success.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("success.status", result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED);
    CHECK("success.slot", f.slot == f.bridge);
    CHECK("success.raw", result.expected_guest_target == f.raw_expected);
    CHECK("success.lease", f.acquired == 1 && f.released == 1);
    CHECK("success.no-post-release-deref", f.provider_touched_after_release == 0);
}

static void test_missing_or_stale_evidence_falls_back(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    f.acquire_ok = 0;
    CHECK("stale.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("stale.status", result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
    CHECK("stale.legacy", f.slot == input.request.legacy_target);
    CHECK("stale.no-writer", f.writer_calls == 0);
}

static void test_lazy_missing_evidence_preserves_observed_without_legacy_cas(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;

    input.preserve_observed_on_failure = 1;
    f.acquire_ok = 0;
    CHECK("preserve.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("preserve.status",
          result.status == KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED);
    CHECK("preserve.slot", f.slot == input.request.slot_current_value);
    CHECK("preserve.no-legacy", result.legacy_fallback_attempted == 0);
    CHECK("preserve.no-cas", f.cas_calls == 0);
}

static void test_conflicting_exact_provider_falls_back(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    f.exact_conflict = 1;
    CHECK("conflict.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("conflict.status", result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
    CHECK("conflict.lease", f.acquired == 1 && f.released == 1);
    CHECK("conflict.no-writer", f.writer_calls == 0);
}

static void test_lazy_missing_owner_explicitly_falls_back(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    input.expected_guest_target_present = 0;
    input.request.expected_guest_target = 0;
    f.owner_available = 0;
    CHECK("lazy.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("lazy.status", result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
    CHECK("lazy.no-acquire", f.acquired == 0);
    CHECK("lazy.no-writer", f.writer_calls == 0);
}

static void test_cas_mismatch_preserves_competing_value(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    f.acquire_ok = 0;
    f.force_cas_mismatch = 1;
    CHECK("cas.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("cas.status", result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
    CHECK("cas.competing", f.slot == 0xfeedface);
}

static void test_native_cas_mismatch_does_not_overwrite_competitor(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    f.force_cas_mismatch = 1;
    CHECK("native-cas.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("native-cas.status",
          result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
    CHECK("native-cas.competing", f.slot == 0xfeedface);
    CHECK("native-cas.release", f.released == 1);
    CHECK("native-cas.once", f.cas_calls == 1);
    CHECK("native-cas.report-competitor",
          result.selected_target == 0xfeedface &&
          result.final_value == 0xfeedface);
}

static void test_rollback_cas_does_not_overwrite_competitor(void)
{
    fixture_t f = fixture();
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    f.writer_mutates = 0;
    f.writer_rollback_after_competitor = 1;
    CHECK("rollback-race.call",
          kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("rollback-race.status",
          result.status == KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH);
    CHECK("rollback-race.competing", f.slot == 0xfeedface);
}

static void test_writer_decline_and_error_use_legacy(void)
{
    for (int error = 0; error < 2; ++error) {
        fixture_t f = fixture();
        kzt_jump_slot_route_input_t input = input_for(&f);
        kzt_jump_slot_route_ops_t ops = ops_for(&f);
        kzt_jump_slot_route_result_t result;
        f.writer_mutates = 0;
        f.writer_status = error ? KZT_JUMP_SLOT_ROUTE_WRITER_ERROR :
                                  KZT_JUMP_SLOT_ROUTE_WRITER_DECLINED;
        CHECK("writer-fallback.call",
              kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
        CHECK("writer-fallback.status",
              result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED);
        CHECK("writer-fallback.slot", f.slot == input.request.legacy_target);
        CHECK("writer-fallback.release", f.released == 1);
        CHECK("writer-fallback.no-post-release-provider-callback",
              f.provider_touched_after_release == 0);
    }
}

static void test_kzt_off_bypasses_route(void)
{
    fixture_t f = fixture();
    uintptr_t initial = f.slot;
    kzt_jump_slot_route_input_t input = input_for(&f);
    kzt_jump_slot_route_ops_t ops = ops_for(&f);
    kzt_jump_slot_route_result_t result;
    input.enabled = 0;
    CHECK("off.call", kzt_jump_slot_route_apply(&input, &ops, &result) == 0);
    CHECK("off.status", result.status == KZT_JUMP_SLOT_ROUTE_BYPASS);
    CHECK("off.untouched", f.slot == initial);
    CHECK("off.no-callbacks", f.acquired == 0 && f.cas_calls == 0);
}

int main(void)
{
    test_caller_observation_change_is_never_authorized();
    test_same_owner_competitor_cannot_authorize_native();
    test_lazy_zero_competitor_is_preserved_without_write();
    test_resolved_target_mismatch_uses_legacy();
    test_owner_identity_change_during_bridge_falls_back();
    test_generation_change_before_writer_preserves_guest();
    test_exact_provider_bridge_success();
    test_missing_or_stale_evidence_falls_back();
    test_lazy_missing_evidence_preserves_observed_without_legacy_cas();
    test_conflicting_exact_provider_falls_back();
    test_lazy_missing_owner_explicitly_falls_back();
    test_cas_mismatch_preserves_competing_value();
    test_native_cas_mismatch_does_not_overwrite_competitor();
    test_rollback_cas_does_not_overwrite_competitor();
    test_writer_decline_and_error_use_legacy();
    test_kzt_off_bypasses_route();
    if (failures) {
        fprintf(stderr, "%d jump-slot route checks failed\n", failures);
        return 1;
    }
    puts("KZT shared jump-slot route: PASS");
    return 0;
}
