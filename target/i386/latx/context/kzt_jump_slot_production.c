#include "qemu/osdep.h"

#include "kzt_jump_slot_production.h"

#ifdef CONFIG_LATX_KZT

#include <string.h>

#if defined(CONFIG_USER_ONLY) && !defined(KZT_JUMP_SLOT_PRODUCTION_TEST)
#include "qemu.h"
#endif

#include "box64context.h"
#include "debug.h"
#include "elfload_dump.h"
#include "elfloader_private.h"
#include "kzt_rela_diagnostics.h"
#include "library.h"
#include "librarian.h"
#include "kzt_rela_request_enricher.h"
#include "kzt_rela_runtime_bridge.h"
#include "kzt_owner_resolver.h"
#include "kzt_runtime_candidate_shadow.h"

typedef struct kzt_production_jump_slot_state {
    box64context_t *context;
    int slot_current_value_is_unresolved_stub;
    uintptr_t resolved_target;
    kzt_wrapper_bridge_provider_t wrapper_provider;
    kzt_rela_immediate_candidate_request_t initial_request;
    kzt_rela_request_enricher_result_t base_enrich_result;
    kzt_rela_request_enricher_result_t bridge_enrich_result;
    kzt_rela_immediate_candidate_request_t last_request;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_guest_registry_source_lease_t source_lease;
    kzt_patch_candidate_t runtime_candidate;
    kzt_runtime_got_plt_candidate_result_t runtime_candidate_result;
    char runtime_candidate_strings[512];
    uintptr_t required_source_link_map;
    unsigned long required_source_generation;
    int discover_bridge_from_provider;
    const char *failure_stage;
} kzt_production_jump_slot_state_t;

#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
void kzt_jump_slot_production_test_before_source_lease_acquire(void);
void kzt_jump_slot_production_test_before_source_memory_access(void);
void kzt_jump_slot_production_test_before_slot_load(void);
void kzt_jump_slot_production_test_after_slot_load(uintptr_t *value);
void kzt_jump_slot_production_test_after_slot_cas(int exchanged);
void kzt_jump_slot_production_test_shadow_run(void);
int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease);
int kzt_jump_slot_production_test_end_slot_write(
    kzt_patch_spike_permission_lease_t *lease);
#endif

static int production_read_guest_memory(uintptr_t address, void *dst,
                                        size_t size, void *opaque)
{
    (void)opaque;
    if (!address || !dst || !size) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    memcpy(dst, (const void *)address, size);
#else
    void *host_ptr;

    host_ptr = lock_user(VERIFY_READ, (abi_ulong)address, size, true);
    if (!host_ptr) {
        return -1;
    }
    memcpy(dst, host_ptr, size);
    unlock_user(host_ptr, (abi_ulong)address, 0);
#endif
    return 0;
}

static int production_shadow_expected_target(
    const kzt_patch_candidate_t *candidate, uintptr_t *expected,
    void *opaque)
{
    const kzt_production_jump_slot_state_t *state = opaque;

    if (!candidate || !expected || !state ||
        !state->last_request.expected_guest_target) {
        return -1;
    }
    *expected = state->last_request.expected_guest_target;
    return 0;
}

static kzt_runtime_candidate_shadow_stub_classification_t
production_shadow_classify_stub(const kzt_patch_candidate_t *candidate,
                                void *opaque)
{
    const kzt_production_jump_slot_state_t *state = opaque;

    (void)candidate;
    return state && state->slot_current_value_is_unresolved_stub ?
        KZT_RUNTIME_CANDIDATE_SHADOW_STUB_MATCH :
        KZT_RUNTIME_CANDIDATE_SHADOW_STUB_NO_MATCH;
}

static void production_shadow_runtime_candidate(
    kzt_production_jump_slot_state_t *state,
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_wrapper_bridge_provider_t *wrapper_provider)
{
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t status;
    unsigned long generation;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_patch_candidate_t candidate;
    kzt_runtime_candidate_shadow_record_t record;
    char strings[512];
    kzt_runtime_got_plt_candidate_request_t collector;
    kzt_runtime_candidate_shadow_input_t input;
    kzt_runtime_candidate_shadow_result_t result;

    /* Shadow is diagnostic-only. With diagnostics disabled, avoid a second
     * candidate read plus planner formatting and logging. */
    if (!kzt_registry_diagnostics_enabled() || !state || !request ||
        !request->source.known || !request->source.link_map_addr ||
        !request->source.generation || request->table_kind ==
            KZT_PATCH_TABLE_UNKNOWN || !request->entry_addr) {
        return;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_shadow_run();
#endif
    if (kzt_guest_registry_find_dynamic_view(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, &view, &status, &generation) != 0 ||
        status != KZT_GUEST_FIELD_OK || generation != request->source.generation ||
        view.status != KZT_GUEST_DYNAMIC_COMPLETE) {
        return;
    }

    memset(&candidate, 0, sizeof(candidate));
    memset(&record, 0, sizeof(record));
    memset(strings, 0, sizeof(strings));
    collector = (kzt_runtime_got_plt_candidate_request_t) {
        .view = &view,
        .reader_ops = &reader_ops,
        .source = &request->source,
        .dynamic_view_generation = generation,
        .only_entry = 1,
        .only_table_kind = request->table_kind,
        .only_entry_index = request->entry_index,
        .candidates = &candidate,
        .candidate_capacity = 1,
        .string_storage = strings,
        .string_storage_size = sizeof(strings),
    };
    input = (kzt_runtime_candidate_shadow_input_t) {
        .collector_request = &collector,
        .registry = KztGuestRegistryForContext(state->context),
        .wrapper_manifest = wrapper_provider ? &wrapper_provider->manifest :
                                               NULL,
        .bridge_ops = wrapper_provider ? &wrapper_provider->bridge_ops : NULL,
        .resolve_expected_guest_target = production_shadow_expected_target,
        .expected_target_opaque = state,
        .classify_stub = production_shadow_classify_stub,
        .stub_classifier_opaque = state,
        .records = &record,
        .record_capacity = 1,
    };
    (void)kzt_runtime_candidate_shadow_run(&input, &result);
}

static int production_slot_load(uintptr_t slot_addr, uintptr_t *value,
                                void *opaque)
{
    (void)opaque;
    if (!slot_addr || !value) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_slot_load();
#endif
    *value = __atomic_load_n((uintptr_t *)slot_addr, __ATOMIC_ACQUIRE);
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_load(value);
#endif
    return 0;
}

static int production_slot_cas(uintptr_t slot_addr, uintptr_t *expected,
                               uintptr_t replacement, void *opaque)
{
    int exchanged;

    (void)opaque;
    if (!slot_addr || !expected) {
        return -1;
    }
    exchanged = __atomic_compare_exchange_n(
               (uintptr_t *)slot_addr, expected, replacement, 0,
               __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
               ? 1
               : 0;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    return exchanged;
}

static int production_slot_fits_page(uintptr_t slot_addr, uintptr_t page_mask)
{
    uintptr_t slot_last;

    if (!slot_addr || (slot_addr & (sizeof(uintptr_t) - 1)) ||
        slot_addr > UINTPTR_MAX - (sizeof(uintptr_t) - 1)) {
        return 0;
    }
    slot_last = slot_addr + sizeof(uintptr_t) - 1;
    return (slot_addr & page_mask) == (slot_last & page_mask);
}

/* Use linux-user bookkeeping, never a host mprotect on a guest slot. */
static int production_slot_begin_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease,
    void *opaque)
{
    (void)opaque;
    if (!slot_addr || !lease) {
        return -1;
    }
    memset(lease, 0, sizeof(*lease));
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    if (!production_slot_fits_page(slot_addr, ~(uintptr_t)0xfff)) {
        return -1;
    }
    lease->guest_page_length = 0x1000;
    return kzt_jump_slot_production_test_begin_slot_write(slot_addr, lease);
#elif defined(CONFIG_USER_ONLY)
    {
        abi_ulong guest_addr;
        abi_ulong guest_last;
        int flags;
        int permissions;

        if (!production_slot_fits_page(slot_addr, TARGET_PAGE_MASK) ||
            !h2g_valid((void *)slot_addr) ||
            !h2g_valid((void *)(slot_addr + sizeof(uintptr_t) - 1))) {
            return -1;
        }
        guest_addr = h2g((void *)slot_addr);
        guest_last = h2g((void *)(slot_addr + sizeof(uintptr_t) - 1));
        if (guest_last < guest_addr ||
            guest_last - guest_addr != sizeof(uintptr_t) - 1 ||
            (guest_addr & TARGET_PAGE_MASK) !=
                (guest_last & TARGET_PAGE_MASK)) {
            return -1;
        }
        lease->guest_page = guest_addr & TARGET_PAGE_MASK;
        lease->guest_page_length = TARGET_PAGE_SIZE;
        flags = page_get_flags(guest_addr);
        permissions = flags & PAGE_BITS;
        lease->checked = 1;
        lease->original_permissions = permissions;
        lease->was_writable = (flags & PAGE_WRITE) != 0;
        if (!(flags & PAGE_VALID) || !permissions) {
            return -1;
        }
        if (lease->was_writable) {
            return 0;
        }
        if (target_mprotect(lease->guest_page, TARGET_PAGE_SIZE,
                            permissions | PAGE_WRITE) != 0) {
            return -1;
        }
        lease->write_enabled = 1;
        return 0;
    }
#else
    return -1;
#endif
}

static int production_slot_end_write(kzt_patch_spike_permission_lease_t *lease,
                                     void *opaque)
{
    (void)opaque;
    if (!lease) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    return kzt_jump_slot_production_test_end_slot_write(lease);
#elif defined(CONFIG_USER_ONLY)
    if (!lease->checked || !lease->guest_page_length ||
        (lease->guest_page & ~TARGET_PAGE_MASK) ||
        lease->guest_page_length != TARGET_PAGE_SIZE ||
        (lease->original_permissions & ~PAGE_BITS)) {
        return -1;
    }
    if (!lease->write_enabled) {
        return 0;
    }
    return target_mprotect(lease->guest_page, lease->guest_page_length,
                           lease->original_permissions);
#else
    return -1;
#endif
}

static int production_validate_write_generation(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_object_snapshot_t *owner_snapshot = NULL;
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t dynamic_status;
    unsigned long dynamic_generation = 0;
    int valid = 0;

    if (!state || !decision || !decision->source.known ||
        !decision->source.link_map_addr || !decision->source.generation ||
        !decision->current_owner.known ||
        !decision->current_owner.link_map_addr ||
        !decision->current_owner.generation ||
        !decision->dynamic_view_available ||
        !decision->dynamic_view_generation ||
        (state->required_source_link_map &&
         decision->source.link_map_addr != state->required_source_link_map) ||
        (state->required_source_generation &&
         decision->source.generation != state->required_source_generation) ||
        kzt_guest_registry_find_by_link_map(
            KztGuestRegistryForContext(state->context),
            decision->source.link_map_addr, &snapshot) != 0 || !snapshot ||
        snapshot->generation != decision->source.generation ||
        kzt_guest_registry_find_dynamic_view(
            KztGuestRegistryForContext(state->context),
            decision->source.link_map_addr, &view, &dynamic_status,
            &dynamic_generation) != 0 ||
        dynamic_status != KZT_GUEST_FIELD_OK ||
        dynamic_generation != decision->dynamic_view_generation ||
        kzt_guest_registry_find_by_link_map(
            KztGuestRegistryForContext(state->context),
            decision->current_owner.link_map_addr, &owner_snapshot) != 0 ||
        !owner_snapshot ||
        owner_snapshot->generation != decision->current_owner.generation) {
        goto out;
    }
    valid = 1;
out:
    kzt_guest_object_snapshot_free(snapshot);
    kzt_guest_object_snapshot_free(owner_snapshot);
    return valid ? 0 : -1;
}

static int production_enrich(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_wrapper_bridge_provider_t *wrapper_provider,
    kzt_rela_request_enricher_result_t *enrich_result,
    kzt_production_jump_slot_state_t *state)
{
    kzt_rela_request_enricher_input_t enrich_input = {
        .registry = KztGuestRegistryForContext(state->context),
        .slot_current_value_is_unresolved_stub =
            state->slot_current_value_is_unresolved_stub,
        .wrapper_manifest = wrapper_provider ? &wrapper_provider->manifest :
                                               NULL,
        .bridge_ops = wrapper_provider ? &wrapper_provider->bridge_ops : NULL,
    };
    return kzt_rela_immediate_request_enrich(request, &enrich_input,
                                             enrich_result);
}

static int production_request_is_main_namespace(
    kzt_production_jump_slot_state_t *state,
    const kzt_rela_immediate_candidate_request_t *request)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;
    int is_main = 0;

    if (!state || !request || !request->source.known ||
        !request->source.link_map_addr || !request->source.generation ||
        kzt_guest_registry_find_by_link_map(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, &snapshot) != 0 || !snapshot) {
        goto out;
    }
    is_main = snapshot->generation == request->source.generation &&
              snapshot->namespace_id.status == KZT_GUEST_FIELD_OK &&
              snapshot->namespace_id.value == 0;
out:
    kzt_guest_object_snapshot_free(snapshot);
    return is_main ? 0 : -1;
}

static int production_runtime_candidate_matches_request(
    const kzt_patch_candidate_t *candidate,
    const kzt_rela_immediate_candidate_request_t *request)
{
    return candidate && request &&
           request->relocation_type == R_X86_64_JUMP_SLOT &&
           candidate->reloc_type == KZT_PATCH_RELOCATION_JUMP_SLOT &&
           candidate->source.known && request->source.known &&
           candidate->source.link_map_addr == request->source.link_map_addr &&
           candidate->source.generation == request->source.generation &&
           candidate->dynamic_view_available &&
           candidate->dynamic_view_generation == request->source.generation &&
           candidate->table_kind == request->table_kind &&
           candidate->entry_index == request->entry_index &&
           candidate->entry_addr == request->entry_addr &&
           candidate->slot_addr == request->slot_addr &&
           candidate->slot_current_value_present &&
           request->slot_current_value_present &&
           candidate->slot_current_value == request->slot_current_value &&
           candidate->symbol_index == request->symbol_index &&
           candidate->symbol_name && request->symbol_name &&
           strcmp(candidate->symbol_name, request->symbol_name) == 0 &&
           kzt_symbol_version_evidence_matches(
               candidate->version_evidence, candidate->version,
               request->version_evidence, request->version);
}

static int production_collect_runtime_candidate(
    kzt_production_jump_slot_state_t *state,
    kzt_rela_immediate_candidate_request_t *request)
{
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t status;
    unsigned long generation;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_runtime_got_plt_candidate_request_t collector;

    if (!state || !request || !request->source.link_map_addr ||
        !request->source.generation ||
        kzt_guest_registry_find_dynamic_view(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, &view, &status, &generation) != 0 ||
        status != KZT_GUEST_FIELD_OK ||
        generation != request->source.generation ||
        view.status != KZT_GUEST_DYNAMIC_COMPLETE) {
        return -1;
    }

    memset(&state->runtime_candidate, 0, sizeof(state->runtime_candidate));
    memset(state->runtime_candidate_strings, 0,
           sizeof(state->runtime_candidate_strings));
    collector = (kzt_runtime_got_plt_candidate_request_t) {
        .view = &view,
        .reader_ops = &reader_ops,
        .source = &request->source,
        .dynamic_view_generation = generation,
        .only_entry = 1,
        .only_table_kind = request->table_kind,
        .only_entry_index = request->entry_index,
        .candidates = &state->runtime_candidate,
        .candidate_capacity = 1,
        .string_storage = state->runtime_candidate_strings,
        .string_storage_size = sizeof(state->runtime_candidate_strings),
    };
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_source_memory_access();
#endif
    if (kzt_runtime_got_plt_candidates_collect(
            &collector, &state->runtime_candidate_result) != 0 ||
        state->runtime_candidate_result.status !=
            KZT_RUNTIME_GOT_PLT_CANDIDATE_OK ||
        state->runtime_candidate_result.candidate_count != 1 ||
        !production_runtime_candidate_matches_request(
            &state->runtime_candidate, request)) {
        return -1;
    }

    request->dynamic_addr = state->runtime_candidate.dynamic_addr;
    request->load_bias = state->runtime_candidate.load_bias;
    request->dynamic_view_generation =
        state->runtime_candidate.dynamic_view_generation;
    request->dynamic_view_available = 1;
    request->entry_addr = state->runtime_candidate.entry_addr;
    request->slot_current_value =
        state->runtime_candidate.slot_current_value;
    request->symbol_name = state->runtime_candidate.symbol_name;
    request->version_evidence =
        state->runtime_candidate.version_evidence;
    request->version = state->runtime_candidate.version;
    return 0;
}

static int production_enrich_base(
    kzt_rela_immediate_candidate_request_t *request, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;

    state->failure_stage = "BASE_EVIDENCE";
    int status = production_enrich(request, NULL, &state->base_enrich_result,
                                  state);

    if (status == 0 &&
        production_request_is_main_namespace(state, request) != 0) {
        /* Namespace evidence is not optional: only namespace zero has a
         * binding/lease contract today, so other or unknown namespaces never
         * reach the planner or a native write. */
        status = -1;
    }
    if (status == 0 && state->required_source_link_map &&
        (request->source.link_map_addr != state->required_source_link_map ||
         request->source.generation != state->required_source_generation)) {
        status = -1;
    }
    if (status == 0 && !state->required_source_link_map) {
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
        kzt_jump_slot_production_test_before_source_lease_acquire();
#endif
        status = kzt_guest_registry_source_lease_acquire(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, request->source.generation, 0,
            &state->source_lease);
    }
    if (status == 0) {
        status = production_collect_runtime_candidate(state, request);
    }
    if (status == 0) {
        state->last_request = *request;
        state->failure_stage = "EXACT_LIBRARY_BINDING";
    }
    return status;
}

static int production_acquire_exact(
    const kzt_patch_object_ref_t *owner, library_t *resolved_provider,
    kzt_guest_library_handle_t *handle, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_guest_library_binding_key_t key;
    kzt_guest_object_snapshot_t *snapshot = NULL;
    int result = -1;

    state->failure_stage = "EXACT_LIBRARY_BINDING";
    if (!owner || !owner->known || !owner->link_map_addr ||
        !owner->generation || !resolved_provider || !handle) {
        return -1;
    }
    if (kzt_guest_registry_find_by_link_map(
            KztGuestRegistryForContext(state->context),
            owner->link_map_addr, &snapshot) != 0 || !snapshot ||
        snapshot->generation != owner->generation ||
        snapshot->namespace_id.status != KZT_GUEST_FIELD_OK ||
        snapshot->namespace_id.value != 0) {
        goto out;
    }
    key = (kzt_guest_library_binding_key_t){
        .link_map_addr = owner->link_map_addr,
        .generation = owner->generation,
        .namespace_id = snapshot->namespace_id.value,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    if (KztGuestLibraryLookupForContext(state->context, &key, handle) != 0) {
        goto out;
    }
    if (handle->library != resolved_provider) {
        kzt_guest_library_handle_release(handle);
        goto out;
    }
    result = 0;
    state->failure_stage = "BRIDGE_EVIDENCE";
out:
    kzt_guest_object_snapshot_free(snapshot);
    return result;
}

static void production_release_exact(kzt_guest_library_handle_t *handle,
                                     void *opaque)
{
    (void)opaque;
    kzt_guest_library_handle_release(handle);
}

static int production_enrich_bridge(
    kzt_rela_immediate_candidate_request_t *request,
    library_t *held_provider, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    int status;

    state->failure_stage = "BRIDGE_EVIDENCE";
    memset(&state->wrapper_provider, 0, sizeof(state->wrapper_provider));
    status = state->discover_bridge_from_provider ?
        kzt_rela_runtime_wrapper_provider_discover_with_version_evidence(
            state->context, held_provider, request->symbol_name,
            request->version_evidence, request->version,
            &state->wrapper_provider) :
        kzt_rela_runtime_wrapper_provider_prepare_with_version_evidence(
            state->context, held_provider, state->resolved_target,
            request->symbol_name, request->version_evidence,
            request->version,
            &state->wrapper_provider);

    if (status <= 0) {
        /* Keep source, dynamic, current-owner, and symbol evidence in the
         * same request. The planner records the missing wrapper/provider as
         * unsupported and the route performs the legacy fallback once. */
        status = production_enrich(request, NULL,
                                   &state->bridge_enrich_result, state);
        if (status == 0) {
            state->last_request = *request;
            production_shadow_runtime_candidate(state, request, NULL);
        }
        return status;
    }
    pthread_mutex_lock(&state->context->kzt_bridge_mutex);
    status = production_enrich(request, &state->wrapper_provider,
                               &state->bridge_enrich_result, state);
    pthread_mutex_unlock(&state->context->kzt_bridge_mutex);
    if (status == 0) {
        state->last_request = *request;
        state->failure_stage = "SOURCE_IDENTITY";
        production_shadow_runtime_candidate(
            state, request, &state->wrapper_provider);
    }
    return status;
}

static int production_validate_source_identity(
    const kzt_rela_immediate_candidate_request_t *request, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_guest_object_snapshot_t *snapshot = NULL;
    int valid = 0;

    state->failure_stage = "SOURCE_IDENTITY";
    if (!request || !request->source.known ||
        !request->source.link_map_addr || !request->source.generation ||
        (state->required_source_link_map &&
         (request->source.link_map_addr != state->required_source_link_map ||
          request->source.generation != state->required_source_generation)) ||
        kzt_guest_registry_find_by_link_map(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, &snapshot) != 0 || !snapshot ||
        snapshot->generation != request->source.generation ||
        snapshot->namespace_id.status != KZT_GUEST_FIELD_OK ||
        snapshot->namespace_id.value != 0) {
        goto out;
    }
    valid = 1;
    state->failure_stage = "WRITER";
out:
    kzt_guest_object_snapshot_free(snapshot);
    return valid;
}

static kzt_jump_slot_route_writer_status_t production_try_writer(
    const kzt_rela_immediate_candidate_request_t *request,
    const kzt_patch_spike_slot_ops_t *slot_ops, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_patch_spike_guard_t *guard =
        KztPatchSpikeGuardForContext(state->context);
    int status;

    if (!slot_ops || !slot_ops->begin_write || !slot_ops->end_write ||
        !slot_ops->validate_generation) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE;
    }
    if (kzt_rela_immediate_jump_slot_try_write(
            request, guard, slot_ops, &state->writer_result) != 0) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
    }
    state->last_request = *request;
    if (state->writer_result.record.action ==
        KZT_PATCH_SPIKE_ACTION_PRESERVE_GUEST) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE;
    }
    if (!state->writer_result.writer_called) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_DECLINED;
    }
    if (state->writer_result.record.failure ==
            KZT_PATCH_SPIKE_FAILURE_PERMISSION_ENABLE_FAILED ||
        state->writer_result.record.failure ==
            KZT_PATCH_SPIKE_FAILURE_PERMISSION_RESTORE_FAILED ||
        state->writer_result.record.failure ==
            KZT_PATCH_SPIKE_FAILURE_ROLLBACK_FAILED ||
        state->writer_result.record.failure ==
            KZT_PATCH_SPIKE_FAILURE_GENERATION_MISMATCH) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE;
    }
    status = state->writer_result.skip_legacy_write
                 ? KZT_JUMP_SLOT_ROUTE_WRITER_APPLIED
                 : KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
    return status;
}

static int production_diagnostic_sink(const char *line, size_t length,
                                      void *opaque)
{
    (void)opaque;
    printf_kzt_registry_diagnostics("%.*s\n", (int)length, line);
    return 0;
}

static void production_emit_diagnostic(
    kzt_production_jump_slot_state_t *state,
    const kzt_jump_slot_route_result_t *route_result)
{
    char buffer[KZT_RELA_DIAGNOSTIC_LINE_LIMIT];
    kzt_rela_diagnostic_throttle_t throttle;
    kzt_rela_immediate_diagnostic_input_t input;
    kzt_rela_immediate_diagnostic_result_t result;
    const kzt_rela_immediate_candidate_request_t *request;

    if (!kzt_registry_diagnostics_enabled() || !state || !route_result) {
        return;
    }
    request = state->last_request.slot_addr ? &state->last_request :
                                              &state->initial_request;
    if (!state->last_request.slot_addr) {
        printf_kzt_registry_diagnostics(
            "kzt_rela_fail_open stage=%s route_status=%d writer_status=%d "
            "source_link_map=0x%lx slot=0x%lx symbol=%s version=%s "
            "legacy_fallback=%d\n",
            state->failure_stage ? state->failure_stage : "UNKNOWN",
            route_result->status, route_result->writer_status,
            (unsigned long)(request ? request->source.link_map_addr : 0),
            (unsigned long)(request ? request->slot_addr : 0),
            request && request->symbol_name ? request->symbol_name : "(none)",
            request && request->version ? request->version : "(none)",
            route_result->legacy_fallback_attempted);
        return;
    }
    if (kzt_rela_diagnostic_throttle_init(&throttle, 1) != 0) {
        return;
    }
    input = (kzt_rela_immediate_diagnostic_input_t) {
        .mode = KZT_RELA_DIAGNOSTIC_MODE_DIAGNOSTICS_WRITE_ENABLED,
        .request = &state->last_request,
        .result = &state->writer_result,
        .legacy_fallback = route_result->legacy_fallback_attempted,
        .throttle = &throttle,
        .buffer = buffer,
        .buffer_size = sizeof(buffer),
        .sink = production_diagnostic_sink,
    };
    (void)kzt_rela_immediate_diagnostic_emit(&input, &result);
}

static int production_jump_slot_route(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, elfheader_t *head, int need_resolv_present,
    int entry_index, Elf64_Rela *rela, uint64_t *slot,
    uintptr_t slot_current_value,
    int slot_current_value_is_unresolved_stub, unsigned long symbol_index,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version,
    int expected_guest_target_present, uintptr_t expected_guest_target,
    uintptr_t legacy_target, int preserve_observed_on_failure,
    uintptr_t required_source_link_map,
    unsigned long required_source_generation,
    int discover_bridge_from_provider,
    kzt_jump_slot_route_result_t *route_result)
{
    kzt_jump_slot_route_input_t input;
    kzt_jump_slot_route_ops_t ops;
    kzt_production_jump_slot_state_t state;
    int status;

    if (!context || !head || !rela || !slot || !route_result) {
        return -1;
    }

    memset(&input, 0, sizeof(input));
    input.enabled = 1;
    input.preserve_observed_on_failure = preserve_observed_on_failure;
    input.expected_guest_target_present = expected_guest_target_present;
    input.resolved_target_matches_legacy =
        resolved_target == legacy_target;
    input.resolved_provider = resolved_provider;
    input.request.relocation_type = ELF64_R_TYPE(rela->r_info);
    input.request.table_kind = need_resolv_present ? KZT_PATCH_TABLE_PLT_RELA :
                                                   KZT_PATCH_TABLE_RELA;
    input.request.entry_index = entry_index;
    input.request.entry_addr = (uintptr_t)rela;
    input.request.source.known = 1;
    input.request.source.link_map_addr = required_source_link_map;
    input.request.source.generation = required_source_generation;
    input.request.source.map_start = (uintptr_t)head->memory;
    input.request.source.map_end = (uintptr_t)head->memory + head->memsz;
    input.request.source.soname = head->name;
    input.request.source.path = head->path;
    input.request.dynamic_addr = (uintptr_t)head->Dynamic;
    input.request.load_bias = head->delta;
    input.request.slot_addr = (uintptr_t)slot;
    input.request.slot_current_value_present = 1;
    input.request.slot_current_value = slot_current_value;
    input.request.expected_guest_target = expected_guest_target;
    input.request.legacy_target = legacy_target;
    input.request.symbol_index = symbol_index;
    input.request.symbol_name = symbol_name;
    input.request.version_evidence = version_evidence;
    input.request.version = version;
    state = (kzt_production_jump_slot_state_t){
        .context = context,
        .initial_request = input.request,
        .slot_current_value_is_unresolved_stub =
            slot_current_value_is_unresolved_stub,
        .resolved_target = resolved_target,
        .required_source_link_map = required_source_link_map,
        .required_source_generation = required_source_generation,
        .discover_bridge_from_provider = discover_bridge_from_provider,
        .failure_stage = "ROUTE_PRECONDITIONS",
    };
    ops = (kzt_jump_slot_route_ops_t){
        .enrich_base = production_enrich_base,
        .acquire_exact_provider = production_acquire_exact,
        .release_exact_provider = production_release_exact,
        .enrich_bridge = production_enrich_bridge,
        .validate_source_identity = production_validate_source_identity,
        .try_native_writer = production_try_writer,
        .load_slot = production_slot_load,
        .compare_exchange_slot = production_slot_cas,
        .begin_slot_write = production_slot_begin_write,
        .end_slot_write = production_slot_end_write,
        .validate_write_generation = production_validate_write_generation,
        .opaque = &state,
    };
    status = kzt_jump_slot_route_apply(&input, &ops, route_result);
    if (status != 0) {
        kzt_guest_registry_source_lease_release(&state.source_lease);
        return -1;
    }
    production_emit_diagnostic(&state, route_result);
    kzt_guest_registry_source_lease_release(&state.source_lease);

    printf_log(LOG_DEBUG,
               "KZT: shared JUMP_SLOT route status=%d writer=%d "
               "slot=%p observed=%p expected_guest=%p selected=%p "
               "legacy=%p exact=%d/%d sym=%s\n",
               route_result->status, route_result->writer_status,
               (void *)slot, (void *)route_result->observed_value,
               (void *)expected_guest_target,
               (void *)route_result->selected_target, (void *)legacy_target,
               route_result->exact_provider_acquired,
               route_result->exact_provider_matched,
               symbol_name ? symbol_name : "(none)");
    return 0;
}

int kzt_production_jump_slot_route(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, elfheader_t *head, int need_resolv_present,
    int entry_index, Elf64_Rela *rela, uint64_t *slot,
    uintptr_t slot_current_value,
    int slot_current_value_is_unresolved_stub, unsigned long symbol_index,
    const char *symbol_name, const char *version,
    int expected_guest_target_present, uintptr_t expected_guest_target,
    uintptr_t legacy_target, kzt_jump_slot_route_result_t *route_result)
{
    return production_jump_slot_route(
        context, resolved_provider, resolved_target, head,
        need_resolv_present, entry_index, rela, slot, slot_current_value,
        slot_current_value_is_unresolved_stub, symbol_index, symbol_name,
        version && version[0] ? KZT_SYMBOL_VERSION_VERSIONED :
                               KZT_SYMBOL_VERSION_UNKNOWN,
        version, expected_guest_target_present, expected_guest_target,
        legacy_target, 0, 0, 0, 0, route_result);
}

int kzt_production_jump_slot_route_with_version_evidence(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, elfheader_t *head, int need_resolv_present,
    int entry_index, Elf64_Rela *rela, uint64_t *slot,
    uintptr_t slot_current_value,
    int slot_current_value_is_unresolved_stub, unsigned long symbol_index,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *version, int expected_guest_target_present,
    uintptr_t expected_guest_target, uintptr_t legacy_target,
    kzt_jump_slot_route_result_t *route_result)
{
    return production_jump_slot_route(
        context, resolved_provider, resolved_target, head,
        need_resolv_present, entry_index, rela, slot, slot_current_value,
        slot_current_value_is_unresolved_stub, symbol_index, symbol_name,
        version_evidence, version, expected_guest_target_present,
        expected_guest_target, legacy_target, 0, 0, 0, 0, route_result);
}

static elfheader_t *production_find_source_head(
    box64context_t *context, uintptr_t link_map)
{
    int i;

    if (!context || !link_map) {
        return NULL;
    }
    for (i = 0; i < context->elfsize; ++i) {
        if (context->elfs[i] && context->elfs[i]->self_link_map == link_map) {
            return context->elfs[i];
        }
    }
    return NULL;
}

int kzt_production_lazy_route_guest_target_leased(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t guest_target,
    const kzt_guest_registry_source_lease_t *source_lease,
    kzt_lazy_binding_route_result_t *result)
{
    kzt_jump_slot_route_result_t route_result;
    elfheader_t *head;
    Elf64_Rela *rela;
    Elf64_Sym *sym;
    const char *symbol_name;
    const char *version_name;
    kzt_symbol_version_evidence_t version_evidence;
    kzt_owner_resolution_t owner_resolution;
    kzt_guest_library_binding_key_t provider_key;
    kzt_guest_library_handle_t provider_handle;
    library_t *resolved_provider = NULL;
    unsigned long symbol_index;
    int version;
    size_t count;

    if (!result) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED;
    result->selected_target = guest_target;
    result->final_value = guest_target;
    if (!context || !pending || !pending->armed || !guest_target ||
        !pending->symbol ||
        !kzt_symbol_version_evidence_valid(pending->version_evidence,
                                           pending->version)) {
        return 0;
    }
    if (!source_lease || !source_lease->active ||
        source_lease->registry != KztGuestRegistryForContext(context) ||
        source_lease->link_map_addr != pending->source_link_map ||
        source_lease->generation != pending->source_generation ||
        source_lease->namespace_id != pending->namespace_id ||
        pending->namespace_kind != KZT_GUEST_LIBRARY_NAMESPACE_MAIN ||
        pending->namespace_id != 0) {
        return 0;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_source_memory_access();
#endif
    head = production_find_source_head(context, pending->source_link_map);
    if (!head || !head->jmprel || !head->pltent || !head->DynSym) {
        return 0;
    }
    count = head->pltsz / head->pltent;
    if (pending->relocation_index >= count) {
        return 0;
    }
    rela = (Elf64_Rela *)(head->jmprel + head->delta) +
           pending->relocation_index;
    if (ELF64_R_TYPE(rela->r_info) != R_X86_64_JUMP_SLOT ||
        rela->r_offset + head->delta != pending->slot_addr) {
        return 0;
    }
    symbol_index = ELF64_R_SYM(rela->r_info);
    sym = &head->DynSym[symbol_index];
    symbol_name = SymName(head, sym);
    version = head->VerSym ?
        ((Elf64_Half *)((uintptr_t)head->VerSym + head->delta))[symbol_index] :
        -1;
    if (version == -1 || (version & 0x7fff) < 2) {
        version_evidence = KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
        version_name = NULL;
    } else {
        version &= 0x7fff;
        version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
        version_name = GetSymbolVersion(head, version);
    }
    if (!symbol_name || strcmp(symbol_name, pending->symbol) != 0 ||
        !kzt_symbol_version_evidence_matches(
            version_evidence, version_name, pending->version_evidence,
            pending->version)) {
        return 0;
    }

    kzt_owner_resolver_init(&owner_resolution);
    if (kzt_owner_resolver_resolve_current(
            KztGuestRegistryForContext(context), guest_target, guest_target,
            &owner_resolution) != 0 ||
        owner_resolution.status != KZT_OWNER_RESOLVER_RESOLVED ||
        owner_resolution.owner_match != KZT_PATCH_OWNER_MATCH ||
        !owner_resolution.current_owner.known) {
        return 0;
    }
    provider_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = owner_resolution.current_owner.link_map_addr,
        .generation = owner_resolution.current_owner.generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    memset(&provider_handle, 0, sizeof(provider_handle));
    if (KztGuestLibraryLookupForContext(context, &provider_key,
                                        &provider_handle) != 0 ||
        !provider_handle.library) {
        kzt_guest_library_handle_release(&provider_handle);
        return 0;
    }
    resolved_provider = provider_handle.library;
    /* guest_target is only the guest loader's observed bridge/CAS evidence.
     * Bridge enrichment resolves and verifies the provider's native symbol
     * independently with dlvsym. */
    if (production_jump_slot_route(
            context, resolved_provider, guest_target, head, 1,
            pending->relocation_index, rela,
            (uint64_t *)pending->slot_addr, guest_target, 0, symbol_index,
            symbol_name, version_evidence, version_name, 1, guest_target,
            guest_target, 1,
            pending->source_link_map, pending->source_generation,
            1,
            &route_result) != 0) {
        kzt_guest_library_handle_release(&provider_handle);
        result->status = KZT_LAZY_BINDING_ROUTE_ERROR;
        return -1;
    }
    kzt_guest_library_handle_release(&provider_handle);
    result->selected_target = route_result.selected_target;
    result->final_value = route_result.final_value;
    switch (route_result.status) {
    case KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED:
        result->status = KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED;
        break;
    case KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH:
        result->status = KZT_LAZY_BINDING_ROUTE_CAS_MISMATCH;
        break;
    case KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED:
    default:
        result->status = KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED;
        break;
    }
    return 0;
}

int kzt_production_lazy_source_lease_acquire(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    kzt_guest_registry_source_lease_t *source_lease)
{
    kzt_guest_registry_t *registry;

    if (!context || !pending || !source_lease || !pending->armed ||
        !pending->source_link_map || !pending->source_generation ||
        pending->namespace_kind != KZT_GUEST_LIBRARY_NAMESPACE_MAIN ||
        pending->namespace_id != 0) {
        return -1;
    }
    memset(source_lease, 0, sizeof(*source_lease));
    registry = KztGuestRegistryForContext(context);
    if (!registry) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_source_lease_acquire();
#endif
    return kzt_guest_registry_source_lease_acquire(
        registry, pending->source_link_map,
        pending->source_generation, pending->namespace_id, source_lease);
}

int kzt_production_lazy_load_slot_with_lease(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t slot_addr,
    uintptr_t *value,
    kzt_guest_registry_source_lease_t *source_lease)
{
    if (!slot_addr || !value || !source_lease ||
        kzt_production_lazy_source_lease_acquire(
            context, pending, source_lease) != 0) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_slot_load();
#endif
    *value = __atomic_load_n((uintptr_t *)slot_addr, __ATOMIC_ACQUIRE);
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_load(value);
#endif
    return 0;
}

int kzt_production_lazy_route_guest_target(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t guest_target,
    kzt_lazy_binding_route_result_t *result)
{
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    int status;

    if (!result) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED;
    result->selected_target = guest_target;
    result->final_value = guest_target;
    if (!context || !pending || !pending->armed || !guest_target ||
        kzt_production_lazy_source_lease_acquire(
            context, pending, &source_lease) != 0) {
        return 0;
    }
    status = kzt_production_lazy_route_guest_target_leased(
        context, pending, guest_target, &source_lease, result);
    kzt_guest_registry_source_lease_release(&source_lease);
    return status;
}

typedef struct kzt_lazy_completion_production_state {
    box64context_t *context;
    const kzt_lazy_binding_pending_t *pending;
    kzt_guest_registry_source_lease_t source_lease;
} kzt_lazy_completion_production_state_t;

static int kzt_lazy_production_load_slot(uintptr_t slot_addr,
                                         uintptr_t *value, void *opaque)
{
    kzt_lazy_completion_production_state_t *state = opaque;

    return state ? kzt_production_lazy_load_slot_with_lease(
                       state->context, state->pending, slot_addr, value,
                       &state->source_lease) :
                   -1;
}

static int kzt_lazy_production_validate(
    const kzt_lazy_binding_pending_t *pending, uintptr_t guest_target,
    void *opaque)
{
    kzt_lazy_completion_production_state_t *state = opaque;
    box64context_t *context = state ? state->context : NULL;
    kzt_guest_lazy_resolver_t resolver;

    if (!pending || !context || pending->context_id != (uintptr_t)context ||
        !guest_target || !state->source_lease.active ||
        state->source_lease.namespace_id != pending->namespace_id ||
        kzt_guest_registry_find_lazy_resolver(
            KztGuestRegistryForContext(context), pending->source_link_map,
            pending->source_generation, pending->namespace_id,
            &resolver) != 0) {
        return 0;
    }
    return resolver.guest_link_map == pending->source_link_map &&
           resolver.guest_resolver == pending->guest_resolver;
}

static int kzt_lazy_production_route(
    const kzt_lazy_binding_pending_t *pending, uintptr_t guest_target,
    kzt_lazy_binding_route_result_t *result, void *opaque)
{
    kzt_lazy_completion_production_state_t *state = opaque;

    return state ? kzt_production_lazy_route_guest_target_leased(
                       state->context, pending, guest_target,
                       &state->source_lease, result) :
                   -1;
}

int kzt_production_lazy_complete(
    box64context_t *context, kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result)
{
    kzt_lazy_completion_production_state_t state = {
        .context = context,
        .pending = pending,
    };
    kzt_lazy_binding_ops_t ops = {
        .load_slot = kzt_lazy_production_load_slot,
        .validate_post_bind = kzt_lazy_production_validate,
        .route_guest_target = kzt_lazy_production_route,
        .opaque = &state,
    };
    int status = kzt_lazy_binding_complete(pending, &ops, result);

    kzt_guest_registry_source_lease_release(&state.source_lease);
    return status;
}

#endif
