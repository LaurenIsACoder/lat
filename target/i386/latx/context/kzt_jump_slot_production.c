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
#include "kzt_guest_dl_api.h"
#include "kzt_guest_symbol_scope.h"
#include "kzt_lifecycle_diagnostics.h"
#include "kzt_lazy_direct_route.h"
#include "kzt_rela_diagnostics.h"
#include "library.h"
#include "librarian.h"
#include "kzt_rela_request_enricher.h"
#include "kzt_rela_runtime_bridge.h"
#include "kzt_rela_stub_detector.h"
#include "kzt_owner_resolver.h"
#include "kzt_runtime_candidate_shadow.h"
#include "kzt_wrapper_probe.h"

extern int option_kzt_lazy_diagnostics;

typedef struct kzt_production_jump_slot_state {
    box64context_t *context;
    library_t *resolved_provider;
    int slot_current_value_is_unresolved_stub;
    uintptr_t resolved_target;
    kzt_wrapper_bridge_provider_t wrapper_provider;
    kzt_rela_immediate_candidate_request_t initial_request;
    kzt_rela_request_enricher_result_t base_enrich_result;
    kzt_rela_request_enricher_result_t bridge_enrich_result;
    kzt_rela_immediate_candidate_request_t last_request;
    kzt_rela_immediate_writer_result_t writer_result;
    kzt_guest_registry_source_lease_t source_lease;
    const kzt_guest_registry_source_lease_t *held_source_lease;
    kzt_guest_registry_patch_decision_lease_t decision_lease;
    const kzt_guest_registry_patch_decision_lease_t *held_decision_lease;
    const kzt_guest_library_handle_t *retained_provider_handle;
    kzt_patch_object_ref_t exact_provider_owner;
    kzt_guest_library_loader_quiescence_lease_t loader_quiescence_lease;
    kzt_guest_symbol_scope_request_t symbol_scope_request;
    kzt_guest_symbol_scope_result_t symbol_scope_proof;
    kzt_patch_decision_t prevalidated_decision;
    int prevalidated_decision_valid;
    uintptr_t final_stale_slot_value;
    int preserve_guest_after_final_slot_stale;
    kzt_guest_dynamic_view_t runtime_view;
    uintptr_t owner_namespace_id;
    int runtime_view_valid;
    int lazy_completion;
    kzt_patch_candidate_t runtime_candidate;
    kzt_runtime_got_plt_candidate_result_t runtime_candidate_result;
    char runtime_candidate_strings[512];
    uintptr_t required_source_link_map;
    unsigned long required_source_generation;
    elfheader_t *head;
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
void kzt_jump_slot_production_test_full_enrich(void);
void kzt_jump_slot_production_test_wrapper_only_enrich(void);
void kzt_jump_slot_production_test_before_generation_validate(void);
void kzt_jump_slot_production_test_before_patch_decision_lease_acquire(void);
void kzt_jump_slot_production_test_after_patch_decision_lease_acquire(void);
void kzt_jump_slot_production_test_before_patch_decision_lease_release(void);
int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease);
int kzt_jump_slot_production_test_end_slot_write(
    kzt_patch_spike_permission_lease_t *lease);
void kzt_jump_slot_production_test_mapping_lock(void);
void kzt_jump_slot_production_test_mapping_unlock(void);
int kzt_jump_slot_production_test_read_guest_memory(
    uintptr_t address, void *dst, size_t size);
#endif

static int production_read_guest_memory(
    uintptr_t address, void *dst, size_t size, void *opaque)
{
    (void)opaque;
    if (!address || !dst || !size) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    return kzt_jump_slot_production_test_read_guest_memory(
        address, dst, size);
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

static int production_symbol_scope_request(
    box64context_t *context, elfheader_t *head, unsigned long generation,
    uintptr_t namespace_head, const kzt_guest_dynamic_view_t *dynamic_view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    unsigned long symbol_index, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_guest_symbol_scope_request_t *request)
{
    uintptr_t symbol_addr;
    Elf64_Sym reference;

    if (!context || !head || !head->self_link_map || !generation ||
        !namespace_head || !dynamic_view ||
        dynamic_view->status != KZT_GUEST_DYNAMIC_COMPLETE ||
        !dynamic_view->symtab.present || !dynamic_view->syment.present ||
        dynamic_view->syment.value != sizeof(reference) ||
        dynamic_view->symtab.value > UINTPTR_MAX ||
        symbol_index >
            (UINTPTR_MAX - (uintptr_t)dynamic_view->symtab.value) /
                sizeof(reference) ||
        !(symbol_addr = (uintptr_t)dynamic_view->symtab.value +
                         symbol_index * sizeof(reference)) ||
        !reader_ops || !reader_ops->read_memory ||
        reader_ops->read_memory(symbol_addr, &reference, sizeof(reference),
                                reader_ops->opaque) != 0 ||
        !symbol || !symbol[0] || !request ||
        context->kzt_guest_scope_layout ==
            KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED ||
        !kzt_symbol_version_evidence_valid(version_evidence, version)) {
        return -1;
    }
    *request = (kzt_guest_symbol_scope_request_t) {
        .source = {
            .link_map_addr = head->self_link_map,
            .generation = generation,
            .namespace_id = 0,
            .namespace_head = namespace_head,
            .layout = context->kzt_guest_scope_layout,
        },
        .symbol = symbol,
        .version_evidence = version_evidence,
        .version = version,
        .reference_binding = ELF64_ST_BIND(reference.st_info),
        .reference_type = ELF64_ST_TYPE(reference.st_info),
        .reference_visibility = reference.st_other & 0x3,
    };
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

static int production_slot_mapping_lock(
    kzt_patch_spike_permission_lease_t *lease)
{
    if (!lease || lease->mmap_lock_held) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_mapping_lock();
#elif defined(CONFIG_USER_ONLY)
    mmap_lock();
#else
    return -1;
#endif
    lease->mmap_lock_held = 1;
    return 0;
}

static void production_slot_mapping_unlock(
    kzt_patch_spike_permission_lease_t *lease)
{
    if (!lease || !lease->mmap_lock_held) {
        return;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_mapping_unlock();
#elif defined(CONFIG_USER_ONLY)
    mmap_unlock();
#endif
    lease->mmap_lock_held = 0;
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
    int result;

    if (!production_slot_fits_page(slot_addr, ~(uintptr_t)0xfff)) {
        return -1;
    }
    lease->guest_page_length = 0x1000;
    if (production_slot_mapping_lock(lease) != 0) {
        return -1;
    }
    result = kzt_jump_slot_production_test_begin_slot_write(slot_addr, lease);
    if (result != 0 && !lease->write_enabled) {
        production_slot_mapping_unlock(lease);
    }
    return result;
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
        if (production_slot_mapping_lock(lease) != 0) {
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
            goto fail;
        }
        if (lease->was_writable) {
            return 0;
        }
        if (target_mprotect(lease->guest_page, TARGET_PAGE_SIZE,
                            permissions | PAGE_WRITE) != 0) {
            goto fail;
        }
        lease->write_enabled = 1;
        return 0;
fail:
        production_slot_mapping_unlock(lease);
        return -1;
    }
#else
    return -1;
#endif
}

static int production_slot_end_write(kzt_patch_spike_permission_lease_t *lease,
                                     void *opaque)
{
    int result;

    (void)opaque;
    if (!lease || !lease->mmap_lock_held) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    result = kzt_jump_slot_production_test_end_slot_write(lease);
#elif defined(CONFIG_USER_ONLY)
    if (!lease->checked || !lease->guest_page_length ||
        (lease->guest_page & ~TARGET_PAGE_MASK) ||
        lease->guest_page_length != TARGET_PAGE_SIZE ||
        (lease->original_permissions & ~PAGE_BITS)) {
        result = -1;
    } else if (!lease->write_enabled) {
        result = 0;
    } else {
        result = target_mprotect(lease->guest_page,
                                 lease->guest_page_length,
                                 lease->original_permissions);
    }
#else
    result = -1;
#endif
    if (result == 0 || lease->restore_attempts >= 2) {
        production_slot_mapping_unlock(lease);
    }
    return result;
}

typedef enum kzt_production_slot_transaction_result {
    KZT_PRODUCTION_SLOT_TRANSACTION_ERROR = -1,
    KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH = 0,
    KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED = 1,
    KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK = 2,
    KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE = 3,
    KZT_PRODUCTION_SLOT_TRANSACTION_CIRCUIT_OPEN = 4,
} kzt_production_slot_transaction_result_t;

static const char *production_slot_transaction_result_name(
    kzt_production_slot_transaction_result_t result)
{
    switch (result) {
    case KZT_PRODUCTION_SLOT_TRANSACTION_ERROR:
        return "ERROR";
    case KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH:
        return "CAS_MISMATCH";
    case KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED:
        return "APPLIED";
    case KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK:
        return "ROLLED_BACK";
    case KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE:
        return "UNRECOVERABLE";
    case KZT_PRODUCTION_SLOT_TRANSACTION_CIRCUIT_OPEN:
        return "CIRCUIT_OPEN";
    }
    return "UNKNOWN";
}

static int production_slot_finish_write(
    kzt_patch_spike_permission_lease_t *permission_lease)
{
    int result;

    if (!permission_lease) {
        return -1;
    }
    permission_lease->restore_attempted = 1;
    ++permission_lease->restore_attempts;
    result = production_slot_end_write(permission_lease, NULL);
    if (result == 0) {
        permission_lease->restored = 1;
    }
    return result;
}

static kzt_production_slot_transaction_result_t
production_lazy_prebind_slot_cas(
    box64context_t *context, uintptr_t slot_addr, uintptr_t expected,
    uintptr_t replacement, uintptr_t *observed)
{
    kzt_patch_spike_permission_lease_t permission_lease = { 0 };
    uintptr_t current = expected;
    uintptr_t rollback_expected = replacement;
    int exchanged;
    int rollback_succeeded = 1;
    int restore_succeeded;

    if (observed) {
        *observed = 0;
    }
    if (!context || !slot_addr || !expected || !replacement) {
        return KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;
    }
    if (kzt_patch_spike_guard_circuit_open(
            KztPatchSpikeGuardForContext(context))) {
        return KZT_PRODUCTION_SLOT_TRANSACTION_CIRCUIT_OPEN;
    }
    if (
        production_slot_begin_write(slot_addr, &permission_lease, NULL) != 0) {
        if (permission_lease.mmap_lock_held &&
            production_slot_finish_write(&permission_lease) != 0 &&
            production_slot_finish_write(&permission_lease) != 0) {
            kzt_patch_spike_guard_trip(KztPatchSpikeGuardForContext(context));
            return KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
        }
        return KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;
    }
    exchanged = __atomic_compare_exchange_n(
        (uintptr_t *)slot_addr, &current, replacement, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 1 : 0;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    if (observed) {
        *observed = current;
    }
    if (production_slot_finish_write(&permission_lease) == 0) {
        return exchanged ? KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED :
                           KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
    }

    if (exchanged) {
        rollback_succeeded = __atomic_compare_exchange_n(
            (uintptr_t *)slot_addr, &rollback_expected, expected, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 1 : 0;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
        kzt_jump_slot_production_test_after_slot_cas(rollback_succeeded);
#endif
        if (observed) {
            *observed = rollback_succeeded ? expected : rollback_expected;
        }
    }
    restore_succeeded = production_slot_finish_write(&permission_lease) == 0;
    if (rollback_succeeded && restore_succeeded) {
        return exchanged ? KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK :
                           KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
    }

    kzt_patch_spike_guard_trip(KztPatchSpikeGuardForContext(context));
    return KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
}

static int production_prevalidate_write_evidence(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_guest_registry_address_match_t source_match;
    kzt_guest_registry_address_match_t owner_match;
    kzt_guest_dynamic_view_t view;
    kzt_guest_field_status_t dynamic_status;
    unsigned long dynamic_generation = 0;
    int valid = 0;

    kzt_owner_resolution_t owner_resolution;

#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_generation_validate();
#endif
    if (!state || !decision || !decision->source.known ||
        !decision->source.link_map_addr || !decision->source.generation ||
        !decision->current_owner.known ||
        !decision->current_owner.link_map_addr ||
        !decision->current_owner.generation ||
        !decision->dynamic_view_available ||
        !decision->dynamic_view_generation ||
        !state->runtime_view_valid ||
        !state->held_source_lease || !state->held_source_lease->active ||
        state->held_source_lease->registry !=
            KztGuestRegistryForContext(state->context) ||
        state->held_source_lease->link_map_addr !=
            decision->source.link_map_addr ||
        state->held_source_lease->generation != decision->source.generation ||
        state->held_source_lease->namespace_id != 0 ||
        !state->held_decision_lease ||
        !state->held_decision_lease->active ||
        state->held_decision_lease->registry !=
            KztGuestRegistryForContext(state->context) ||
        state->held_decision_lease->link_map_addr !=
            decision->source.link_map_addr ||
        state->held_decision_lease->generation != decision->source.generation ||
        state->held_decision_lease->namespace_id != 0 ||
        !state->retained_provider_handle ||
        !state->retained_provider_handle->bindings ||
        !state->retained_provider_handle->entry ||
        state->retained_provider_handle->library != state->resolved_provider ||
        !state->exact_provider_owner.known ||
        state->exact_provider_owner.link_map_addr !=
            decision->current_owner.link_map_addr ||
        state->exact_provider_owner.generation !=
            decision->current_owner.generation ||
        (state->required_source_link_map &&
         decision->source.link_map_addr != state->required_source_link_map) ||
        (state->required_source_generation &&
         decision->source.generation != state->required_source_generation) ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(state->context),
            decision->source.link_map_addr, &source_match) != 0 ||
        source_match.generation != decision->source.generation ||
        kzt_guest_registry_find_dynamic_view(
            KztGuestRegistryForContext(state->context),
            decision->source.link_map_addr, &view, &dynamic_status,
            &dynamic_generation) != 0 ||
        dynamic_status != KZT_GUEST_FIELD_OK ||
        dynamic_generation != decision->dynamic_view_generation ||
        view.status != KZT_GUEST_DYNAMIC_COMPLETE ||
        kzt_guest_registry_dynamic_view_matches(
            KztGuestRegistryForContext(state->context),
            decision->source.link_map_addr, decision->dynamic_view_generation,
            &state->runtime_view) != 0 ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(state->context),
            decision->current_owner.link_map_addr, &owner_match) != 0 ||
        owner_match.generation != decision->current_owner.generation ||
        owner_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        owner_match.namespace_id != state->owner_namespace_id) {
        goto out;
    }
    if (!decision->slot_current_value ||
        __atomic_load_n((uintptr_t *)decision->slot_addr,
                        __ATOMIC_ACQUIRE) != decision->slot_current_value) {
        goto out;
    }
    kzt_owner_resolver_init(&owner_resolution);
    if (kzt_owner_resolver_resolve_current(
            KztGuestRegistryForContext(state->context),
            decision->slot_current_value, decision->slot_current_value,
            &owner_resolution) != 0 ||
        owner_resolution.status != KZT_OWNER_RESOLVER_RESOLVED ||
        owner_resolution.owner_match != KZT_PATCH_OWNER_MATCH ||
        !owner_resolution.current_owner.known ||
        owner_resolution.current_owner.link_map_addr !=
            decision->current_owner.link_map_addr ||
        owner_resolution.current_owner.generation !=
            decision->current_owner.generation) {
        goto out;
    }
    valid = 1;
out:
    return valid ? 0 : -1;
}

static int production_decision_matches_prevalidated(
    const kzt_patch_decision_t *decision,
    const kzt_patch_decision_t *prevalidated)
{
    return decision && prevalidated &&
           decision->source.known == prevalidated->source.known &&
           decision->source.link_map_addr ==
               prevalidated->source.link_map_addr &&
           decision->source.generation == prevalidated->source.generation &&
           decision->dynamic_view_available ==
               prevalidated->dynamic_view_available &&
           decision->dynamic_view_generation ==
               prevalidated->dynamic_view_generation &&
           decision->slot_addr == prevalidated->slot_addr &&
           decision->slot_current_value_present &&
           decision->slot_current_value == prevalidated->slot_current_value &&
           decision->current_owner.known == prevalidated->current_owner.known &&
           decision->current_owner.link_map_addr ==
               prevalidated->current_owner.link_map_addr &&
           decision->current_owner.generation ==
               prevalidated->current_owner.generation &&
           decision->owner_match == prevalidated->owner_match;
}

/* The decision lease makes Registry evidence immutable.  The writer only
 * rechecks that the approved decision and the slot still match that evidence. */
static int production_validate_prevalidated_write(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_guest_symbol_scope_result_t revalidated;

    if (!state || !decision || !state->prevalidated_decision_valid ||
        !state->held_decision_lease || !state->held_decision_lease->active ||
        !state->retained_provider_handle ||
        state->retained_provider_handle->library != state->resolved_provider ||
        !production_decision_matches_prevalidated(
            decision, &state->prevalidated_decision) ||
        kzt_guest_symbol_scope_revalidate(
            &state->symbol_scope_proof, &state->symbol_scope_request,
            &reader_ops, &revalidated) != KZT_GUEST_SYMBOL_SCOPE_SAFE ||
        __atomic_load_n((uintptr_t *)decision->slot_addr,
                        __ATOMIC_ACQUIRE) != decision->slot_current_value) {
        return -1;
    }
    return 0;
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
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_full_enrich();
#endif
    return kzt_rela_immediate_request_enrich(request, &enrich_input,
                                             enrich_result);
}

static int production_enrich_wrapper_only(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_wrapper_bridge_provider_t *wrapper_provider,
    kzt_rela_request_enricher_result_t *enrich_result,
    kzt_production_jump_slot_state_t *state)
{
    kzt_rela_request_wrapper_only_input_t input = {
        .wrapper_manifest = wrapper_provider ? &wrapper_provider->manifest : NULL,
        .bridge_ops = wrapper_provider ? &wrapper_provider->bridge_ops : NULL,
    };

    kzt_rela_request_enricher_result_init(enrich_result);

#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_wrapper_only_enrich();
#endif
    return kzt_rela_immediate_request_enrich_wrapper_only(
        request, &input, enrich_result);
}

static int production_request_is_main_namespace(
    kzt_production_jump_slot_state_t *state,
    const kzt_rela_immediate_candidate_request_t *request)
{
    kzt_guest_registry_address_match_t match;
    int is_main = 0;

    if (!state || !request || !request->source.known ||
        !request->source.link_map_addr || !request->source.generation ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(state->context),
            request->source.link_map_addr, &match) != 0) {
        return -1;
    }
    is_main = match.generation == request->source.generation &&
              match.namespace_id_status == KZT_GUEST_FIELD_OK &&
              match.namespace_id == 0;
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
    state->runtime_view = view;
    state->runtime_view_valid = 1;
    request->entry_addr = state->runtime_candidate.entry_addr;
    request->slot_current_value =
        state->runtime_candidate.slot_current_value;
    request->symbol_name = state->runtime_candidate.symbol_name;
    request->version_evidence =
        state->runtime_candidate.version_evidence;
    request->version = state->runtime_candidate.version;
    return 0;
}

typedef struct kzt_lazy_direct_timing kzt_lazy_direct_timing_t;

typedef struct kzt_lazy_direct_production_state {
    box64context_t *context;
    kzt_guest_registry_t *registry;
    kzt_lazy_prebind_scope_t *prebind_scope;
    kzt_lazy_prebind_lease_t prebind_lease;
    library_t *resolved_provider;
    kzt_guest_registry_source_lease_t source_lease;
    kzt_guest_registry_patch_decision_lease_t decision_lease;
    kzt_guest_library_binding_key_t provider_key;
    kzt_guest_library_handle_t provider_handle;
    int provider_handle_owned;
    kzt_guest_library_loader_quiescence_lease_t loader_quiescence_lease;
    kzt_wrapper_bridge_provider_t wrapper_provider;
    kzt_wrapper_probe_result_t wrapper_probe;
    kzt_guest_symbol_scope_request_t symbol_scope_request;
    kzt_guest_symbol_scope_result_t preemption_proof;
    kzt_production_jump_slot_state_t evidence;
    kzt_lazy_direct_timing_t *timing;
    int timing_enabled;
    int prebind_hit;
} kzt_lazy_direct_production_state_t;

struct kzt_lazy_direct_timing {
    uint64_t start;
    uint64_t source;
    uint64_t candidate;
    uint64_t quiescence;
    uint64_t scope;
    uint64_t provider;
    uint64_t route_start;
    uint64_t bridge_start;
    uint64_t bridge_discover_done;
    uint64_t bridge_done;
    uint64_t decision_done;
    uint64_t final_done;
    uint64_t cas_done;
    uint64_t route;
    uint64_t done;
};

static uint64_t production_lazy_direct_timing_now(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000000000ULL +
           (uint64_t)value.tv_nsec;
}

static uint64_t production_lazy_direct_timing_delta(uint64_t start,
                                                    uint64_t end)
{
    return start && end >= start ? end - start : 0;
}

static int production_lazy_prebind_copy_text(char *dst, size_t size,
                                             const char *text)
{
    size_t length;

    if (!dst || !size) {
        return -1;
    }
    if (!text || !text[0]) {
        dst[0] = '\0';
        return 0;
    }
    length = strnlen(text, size);
    if (length == size) {
        return -1;
    }
    memcpy(dst, text, length + 1);
    return 0;
}

static int production_lazy_prebind_record_key(
    kzt_lazy_prebind_record_t *record, uintptr_t source_link_map,
    unsigned long source_generation, int entry_index, uintptr_t slot_addr,
    uintptr_t expected_slot, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version)
{
    if (!record || !source_link_map || !source_generation || entry_index < 0 ||
        !slot_addr || !expected_slot || !symbol || !symbol[0] ||
        !kzt_symbol_version_evidence_valid(version_evidence, version)) {
        return -1;
    }
    memset(record, 0, sizeof(*record));
    record->source = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = source_link_map,
        .generation = source_generation,
        .namespace_id = 0,
    };
    record->slot_addr = slot_addr;
    record->expected_slot = expected_slot;
    record->relocation_index = (unsigned long)entry_index;
    record->version_evidence = version_evidence;
    return production_lazy_prebind_copy_text(
               record->symbol, sizeof(record->symbol), symbol) == 0 &&
           production_lazy_prebind_copy_text(
               record->version, sizeof(record->version), version) == 0 ?
               0 : -1;
}

static int production_lazy_prebind_publish_record(
    box64context_t *context, kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *record,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque)
{
    kzt_lazy_prebind_lease_t lease = { 0 };
    uintptr_t observed = 0;
    int committed;
    kzt_production_slot_transaction_result_t writer_result;

    if (!context || !scope || !record ||
        kzt_lazy_prebind_scope_publish_acquire(scope, record, &lease) != 0) {
        return 0;
    }
    if (record->bridge_custom_wrapper &&
        strcmp(record->symbol, "dlerror") == 0 &&
        kzt_guest_dl_api_publish_dlerror_entry(
            context->dlprivate, record->symbol,
            record->scope_proof.selected_provider_address,
            record->bridge_custom_wrapper) != 0) {
        kzt_lazy_prebind_scope_publish_finish(&lease, 0);
        return 0;
    }
    writer_result = production_lazy_prebind_slot_cas(
        context, record->slot_addr, record->expected_slot,
        record->bridge_target, &observed);
    committed = writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED;
    kzt_lazy_prebind_scope_publish_finish(&lease, committed);
    if (committed && target_prepare) {
        (void)target_prepare(record->bridge_target, target_prepare_opaque);
        if (record->bridge_custom_wrapper &&
            strcmp(record->symbol, "dlerror") == 0 &&
            record->scope_proof.selected_provider_address) {
            (void)target_prepare(record->scope_proof.selected_provider_address,
                                 target_prepare_opaque);
        }
    }
    printf_kzt_registry_diagnostics(
        "kzt_lazy_prebind_publish schema=1 symbol=%s source=%p generation=%lu "
        "slot=%p bridge=%p result=%s writer=%s observed=%p\n",
        record->symbol, (void *)record->source.link_map_addr,
        record->source.generation,
        (void *)record->slot_addr, (void *)record->bridge_target,
        committed ? "APPLIED" : "SKIPPED",
        production_slot_transaction_result_name(writer_result),
        (void *)observed);
    return committed ? 1 : 0;
}

/* This runs under kzt_per_object_got_plt_apply's exact source and decision
 * leases.  It records already-proven facts only and deliberately has no slot
 * writer: the resolver retains the final Registry, fingerprint, and CAS gate. */
static int production_lazy_prebind_object_prepare(
    box64context_t *context, elfheader_t *head,
    unsigned long source_generation,
    const kzt_guest_dynamic_view_t *source_dynamic_view,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque)
{
    kzt_guest_registry_t *registry;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision_lease = { 0 };
    kzt_guest_library_loader_quiescence_lease_t loader_quiescence_lease = { 0 };
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_lazy_prebind_scope_t *scope;
    uintptr_t namespace_head = 0;
    size_t relocation_count;
    size_t index;
    size_t prepared = 0;
    kzt_patch_object_ref_t source_ref;

    if (!context || !head || !head->self_link_map || !source_generation ||
        !source_dynamic_view ||
        source_dynamic_view->status != KZT_GUEST_DYNAMIC_COMPLETE ||
        !source_dynamic_view->jmprel.present ||
        !source_dynamic_view->pltrelsz.present ||
        !source_dynamic_view->pltrel.present ||
        source_dynamic_view->pltrel.value != DT_RELA ||
        source_dynamic_view->pltrelsz.value > SIZE_MAX ||
        source_dynamic_view->pltrelsz.value % sizeof(Elf64_Rela) ||
        !(registry = KztGuestRegistryForContext(context)) ||
        !(scope = KztLazyPrebindScopeForContext(context)) ||
        kzt_guest_registry_dynamic_view_matches(
            registry, head->self_link_map, source_generation,
            source_dynamic_view) != 0 ||
        kzt_guest_registry_source_lease_acquire(
            registry, head->self_link_map, source_generation, 0,
            &source_lease) != 0 ||
        kzt_guest_registry_patch_decision_lease_acquire(
            &source_lease, &decision_lease) != 0 ||
        kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(context),
            &loader_quiescence_lease) != 0) {
        kzt_guest_library_loader_quiescence_release(
            &loader_quiescence_lease);
        kzt_guest_registry_patch_decision_lease_release(&decision_lease);
        kzt_guest_registry_source_lease_release(&source_lease);
        return 0;
    }
    if (kzt_guest_registry_context_get_main_namespace_head(
            &context->kzt_guest_registry_context, &namespace_head) != 0 ||
        !namespace_head) {
        goto done;
    }

    relocation_count =
        (size_t)source_dynamic_view->pltrelsz.value / sizeof(Elf64_Rela);
    source_ref = (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = head->self_link_map,
        .generation = source_generation,
        .map_start = (uintptr_t)head->memory,
        .map_end = (uintptr_t)head->memory + head->memsz,
        .soname = head->name,
        .path = head->path,
    };
    for (index = 0; index < relocation_count; ++index) {
        kzt_runtime_got_plt_candidate_request_t collector_request;
        kzt_runtime_got_plt_candidate_result_t collector_result;
        kzt_patch_candidate_t candidate;
        char candidate_strings[512];
        kzt_guest_symbol_scope_request_t scope_request;
        kzt_guest_symbol_scope_result_t scope_proof;
        kzt_guest_registry_address_match_t provider_match;
        kzt_guest_library_binding_key_t provider_key;
        kzt_guest_library_handle_t provider_handle = { 0 };
        kzt_wrapper_bridge_provider_t wrapper_provider;
        kzt_wrapper_probe_result_t wrapper_probe;
        kzt_wrapper_probe_request_t wrapper_request;
        kzt_lazy_prebind_record_t record;

        memset(&candidate, 0, sizeof(candidate));
        memset(candidate_strings, 0, sizeof(candidate_strings));
        collector_request = (kzt_runtime_got_plt_candidate_request_t) {
            .view = source_dynamic_view,
            .reader_ops = &reader_ops,
            .source = &source_ref,
            .dynamic_view_generation = source_generation,
            .only_entry = 1,
            .only_table_kind = KZT_PATCH_TABLE_PLT_RELA,
            .only_entry_index = index,
            .candidates = &candidate,
            .candidate_capacity = 1,
            .string_storage = candidate_strings,
            .string_storage_size = sizeof(candidate_strings),
        };
        if (kzt_runtime_got_plt_candidates_collect(
                &collector_request, &collector_result) != 0 ||
            collector_result.status != KZT_RUNTIME_GOT_PLT_CANDIDATE_OK ||
            collector_result.candidate_count != 1 ||
            candidate.reloc_type != KZT_PATCH_RELOCATION_JUMP_SLOT ||
            candidate.source.link_map_addr != head->self_link_map ||
            candidate.source.generation != source_generation ||
            candidate.dynamic_view_generation != source_generation ||
            !candidate.slot_addr || !candidate.slot_current_value ||
            !kzt_rela_slot_current_is_unresolved_stub(
                candidate.slot_current_value,
                KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                head->delta, head->plt, head->plt_end, head->gotplt,
                head->gotplt_end) ||
            !candidate.symbol_name || !candidate.symbol_name[0] ||
            kzt_patch_symbol_must_stay_guest(candidate.symbol_name) ||
            production_symbol_scope_request(
                context, head, source_generation, namespace_head,
                source_dynamic_view, &reader_ops, candidate.symbol_index,
                candidate.symbol_name, candidate.version_evidence,
                candidate.version,
                &scope_request) != 0 ||
            kzt_guest_symbol_scope_discover(
                &scope_request, &reader_ops, &scope_proof) !=
                KZT_GUEST_SYMBOL_SCOPE_SAFE ||
            kzt_guest_registry_find_live_object(
                registry, scope_proof.selected_provider_link_map,
                &provider_match) != 0 ||
            !provider_match.generation ||
            provider_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
            provider_match.namespace_id != 0) {
            continue;
        }
        provider_key = (kzt_guest_library_binding_key_t) {
            .link_map_addr = scope_proof.selected_provider_link_map,
            .generation = provider_match.generation,
            .namespace_id = 0,
            .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        };
        if (kzt_guest_library_access_lookup(
                &context->kzt_guest_library_access, &provider_key,
                &provider_handle) != 0 || !provider_handle.library ||
            provider_handle.object_type != KZT_GUEST_LIBRARY_OBJECT_WRAPPED ||
            kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
                context, &provider_handle, candidate.symbol_name,
                candidate.version_evidence, candidate.version,
                &wrapper_provider) <= 0) {
            kzt_guest_library_handle_release(&provider_handle);
            continue;
        }
        wrapper_request = (kzt_wrapper_probe_request_t) {
            .symbol_name = candidate.symbol_name,
            .symbol_version_evidence = candidate.version_evidence,
            .symbol_version = candidate.version,
        };
        if (kzt_wrapper_probe_minimal_manifest(
                &wrapper_provider.manifest, &wrapper_request,
                &wrapper_provider.bridge_ops, &wrapper_probe) != 0 ||
            (wrapper_probe.wrapper_match != KZT_PATCH_WRAPPER_VERSION_MATCH &&
             wrapper_probe.wrapper_match != KZT_PATCH_WRAPPER_UNVERSIONED_MATCH) ||
            !wrapper_probe.bridge_target ||
            !kzt_symbol_version_evidence_matches(
                candidate.version_evidence, candidate.version,
                wrapper_probe.wrapper_version_evidence,
                wrapper_probe.wrapper_symbol_version) ||
            production_lazy_prebind_record_key(
                &record, head->self_link_map, source_generation, (int)index,
                candidate.slot_addr, candidate.slot_current_value,
                candidate.symbol_name, candidate.version_evidence,
                candidate.version) != 0) {
            kzt_guest_library_handle_release(&provider_handle);
            continue;
        }
        record.provider = (kzt_lazy_prebind_identity_t) {
            .link_map_addr = provider_key.link_map_addr,
            .generation = provider_key.generation,
            .namespace_id = provider_key.namespace_id,
        };
        record.bridge_target = wrapper_probe.bridge_target;
        record.bridge_generation = provider_key.generation;
        record.bridge_custom_wrapper = wrapper_provider.match.custom_wrapper;
        record.scope_proof = scope_proof;
        kzt_lazy_prebind_claim_result_t claim =
            kzt_lazy_prebind_scope_claim(scope, &record);

        if (claim == KZT_LAZY_PREBIND_CLAIM_CREATED) {
            ++prepared;
        }
        if (claim == KZT_LAZY_PREBIND_CLAIM_CREATED ||
            claim == KZT_LAZY_PREBIND_CLAIM_REUSED) {
            (void)production_lazy_prebind_publish_record(context, scope,
                                                          &record,
                                                          target_prepare,
                                                          target_prepare_opaque);
        }
        kzt_guest_library_handle_release(&provider_handle);
    }

    if (prepared) {
        printf_kzt_registry_diagnostics(
            "kzt_lazy_prebind schema=1 source=%p generation=%lu "
            "records=%zu result=READY\n",
            (void *)head->self_link_map, source_generation, prepared);
    }
done:
    kzt_guest_library_loader_quiescence_release(&loader_quiescence_lease);
    kzt_guest_registry_patch_decision_lease_release(&decision_lease);
    kzt_guest_registry_source_lease_release(&source_lease);
    return 0;
}

int kzt_production_lazy_prebind_object(
    box64context_t *context, elfheader_t *head,
    unsigned long source_generation,
    const kzt_guest_dynamic_view_t *source_dynamic_view,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque)
{
    return production_lazy_prebind_object_prepare(
        context, head, source_generation, source_dynamic_view, target_prepare,
        target_prepare_opaque);
}

static int production_lazy_prebind_revoke_closed(
    box64context_t *context, kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *identity)
{
    int result = 0;

    if (!context || !scope) {
        return -1;
    }
    for (;;) {
        kzt_lazy_prebind_lease_t lease = { 0 };
        kzt_lazy_prebind_record_t record;
        uintptr_t observed = 0;
        kzt_production_slot_transaction_result_t writer_result;
        int acquire_result = kzt_lazy_prebind_scope_revoke_acquire(
            scope, identity, &lease);
        int revoked;

        if (acquire_result == 1) {
            break;
        }
        if (acquire_result != 0) {
            return -1;
        }
        record = lease.record;
        writer_result = production_lazy_prebind_slot_cas(
            context, record.slot_addr, record.bridge_target,
            record.expected_slot, &observed);
        revoked =
            writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED ||
            (writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH &&
             observed != record.bridge_target);
        kzt_lazy_prebind_scope_revoke_finish(&lease, revoked);
        printf_kzt_registry_diagnostics(
            "kzt_lazy_prebind_revoke schema=1 source=%p generation=%lu "
            "slot=%p bridge=%p stub=%p result=%s writer=%s observed=%p\n",
            (void *)record.source.link_map_addr, record.source.generation,
            (void *)record.slot_addr, (void *)record.bridge_target,
            (void *)record.expected_slot,
            writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED ?
                "RESTORED" : (revoked ? "SUPERSEDED" : "FAILED"),
            production_slot_transaction_result_name(writer_result),
            (void *)observed);
        if (!revoked) {
            result = -1;
            break;
        }
    }
    return result;
}

int kzt_production_lazy_prebind_invalidate(
    box64context_t *context, kzt_lazy_prebind_mutation_t mutation)
{
    kzt_lazy_prebind_scope_t *scope;
    uint64_t timing_start = kzt_lifecycle_diagnostics_enabled()
                                ? kzt_lifecycle_diagnostics_now()
                                : 0;
    int result;

    if (!context || !(scope = KztLazyPrebindScopeForContext(context)) ||
        !kzt_lazy_prebind_scope_mutate(scope, mutation)) {
        result = -1;
    } else {
        result = production_lazy_prebind_revoke_closed(context, scope, NULL);
    }
    if (timing_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_SCOPE_INVALIDATE,
            kzt_lifecycle_diagnostics_now() - timing_start);
    }
    return result;
}

int kzt_production_lazy_prebind_retire(
    box64context_t *context,
    const kzt_lazy_prebind_identity_t *identity)
{
    kzt_lazy_prebind_scope_t *scope;

    if (!context || !identity ||
        !(scope = KztLazyPrebindScopeForContext(context)) ||
        kzt_lazy_prebind_scope_retire(scope, identity) != 0) {
        return -1;
    }
    return production_lazy_prebind_revoke_closed(context, scope, identity);
}

/* A later loader event invalidates every previous scope epoch.  Refresh from
 * a copied Registry snapshot so the final event leaves every live resolver
 * with only currently-proven records. */
void kzt_production_lazy_prebind_refresh(
    box64context_t *context,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque)
{
    kzt_guest_registry_t *registry;
    kzt_guest_registry_dump_t dump = { 0 };
    size_t index;
    uint64_t timing_start = kzt_lifecycle_diagnostics_enabled()
                                ? kzt_lifecycle_diagnostics_now()
                                : 0;

    if (!context || !(registry = KztGuestRegistryForContext(context)) ||
        kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        goto out;
    }
    for (index = 0; index < dump.count; ++index) {
        const kzt_guest_object_snapshot_t *object = &dump.objects[index];
        kzt_guest_registry_source_lease_t source_lease = { 0 };
        elfheader_t *head;

        if (!object->link_map_addr || !object->generation ||
            object->namespace_id.status != KZT_GUEST_FIELD_OK ||
            object->namespace_id.value != 0 ||
            object->dynamic_view_status != KZT_GUEST_FIELD_OK ||
            object->dynamic_view.status != KZT_GUEST_DYNAMIC_COMPLETE ||
            !object->lazy_resolver.valid ||
            !object->lazy_resolver.registry_owned_head ||
            !object->lazy_resolver.object_head ||
            object->state == KZT_GUEST_OBJECT_UNLOADING ||
            object->state == KZT_GUEST_OBJECT_DEAD ||
            kzt_guest_registry_source_lease_acquire(
                registry, object->link_map_addr, object->generation, 0,
                &source_lease) != 0) {
            continue;
        }
        head = (elfheader_t *)object->lazy_resolver.object_head;
        (void)production_lazy_prebind_object_prepare(
            context, head, object->generation, &object->dynamic_view,
            target_prepare, target_prepare_opaque);
        kzt_guest_registry_source_lease_release(&source_lease);
    }
    kzt_guest_registry_dump_free(&dump);
out:
    if (timing_start) {
        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_PREBIND_REFRESH,
            kzt_lifecycle_diagnostics_now() - timing_start);
    }
}

static int production_lazy_direct_validate_source(
    const kzt_lazy_direct_route_input_t *input, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    kzt_guest_registry_address_match_t match;

    return state && input && state->source_lease.active &&
           state->source_lease.registry == state->registry &&
           state->source_lease.link_map_addr == input->source.link_map_addr &&
           state->source_lease.generation == input->source.generation &&
           state->source_lease.namespace_id == input->namespace_id &&
           state->evidence.runtime_view_valid &&
           input->source_dynamic_view == &state->evidence.runtime_view &&
           kzt_guest_registry_find_live_object(
               state->registry, input->source.link_map_addr, &match) == 0 &&
           match.generation == input->source.generation &&
           match.namespace_id_status == KZT_GUEST_FIELD_OK &&
           match.namespace_id == 0 &&
           kzt_guest_registry_dynamic_view_matches(
               state->registry, input->source.link_map_addr,
               input->source.generation,
               input->source_dynamic_view) == 0;
}

static int production_lazy_direct_acquire_provider(
    const kzt_lazy_direct_route_input_t *input,
    kzt_lazy_direct_route_provider_t *provider, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;

    if (!state || !input || !provider || !state->provider_handle_owned ||
        !state->provider_handle.bindings || !state->provider_handle.entry ||
        state->provider_handle.library != state->resolved_provider ||
        state->provider_key.link_map_addr != input->provider.link_map_addr ||
        state->provider_key.generation != input->provider.generation) {
        return -1;
    }
    *provider = (kzt_lazy_direct_route_provider_t) {
        .handle = &state->provider_handle,
        .link_map_addr = state->provider_key.link_map_addr,
        .generation = state->provider_key.generation,
        .namespace_id = state->provider_key.namespace_id,
        .namespace_kind = state->provider_key.namespace_kind,
    };
    return 0;
}

static void production_lazy_direct_release_provider(
    kzt_lazy_direct_route_provider_t *provider, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;

    if (state && state->provider_handle_owned) {
        kzt_guest_library_handle_release(&state->provider_handle);
        state->provider_handle_owned = 0;
    }
    if (provider) {
        memset(provider, 0, sizeof(*provider));
    }
}

static int production_lazy_direct_find_bridge(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    kzt_lazy_direct_route_bridge_t *bridge, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    kzt_wrapper_probe_request_t request;
    int status;

    if (!state || !input || !provider || !bridge ||
        provider->handle != &state->provider_handle ||
        !state->provider_handle_owned || !state->resolved_provider) {
        return -1;
    }
    if (state->timing_enabled) {
        state->timing->bridge_start = production_lazy_direct_timing_now();
    }
    if (state->prebind_hit && state->prebind_lease.active) {
        const kzt_lazy_prebind_record_t *record =
            &state->prebind_lease.record;

        if (!kzt_lazy_prebind_scope_lease_valid(&state->prebind_lease) ||
            record->bridge_generation != input->provider.generation ||
            record->bridge_target == 0 ||
            record->version_evidence != input->version_evidence ||
            !kzt_symbol_version_evidence_matches(
                input->version_evidence, input->version,
                record->version_evidence,
                record->version[0] ? record->version : NULL)) {
            return -1;
        }
        state->wrapper_provider.match.retained_provider_handle =
            &state->provider_handle;
        state->wrapper_provider.match.custom_wrapper =
            record->bridge_custom_wrapper;
        state->wrapper_provider.match.resolved_bridge_target =
            record->bridge_target;
        state->wrapper_provider.match.resolved_bridge_exact = 1;
        state->wrapper_probe = (kzt_wrapper_probe_result_t) {
            .wrapper_match = input->version_evidence ==
                             KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED ?
                             KZT_PATCH_WRAPPER_UNVERSIONED_MATCH :
                             KZT_PATCH_WRAPPER_VERSION_MATCH,
            .wrapper_version_evidence = record->version_evidence,
            .wrapper_symbol_version = record->version[0] ?
                                      record->version : NULL,
            .bridge_target = record->bridge_target,
        };
        *bridge = (kzt_lazy_direct_route_bridge_t) {
            .target = record->bridge_target,
            .version_evidence = record->version_evidence,
            .version = record->version[0] ? record->version : NULL,
        };
        if (state->timing_enabled) {
            state->timing->bridge_discover_done =
                production_lazy_direct_timing_now();
            state->timing->bridge_done =
                state->timing->bridge_discover_done;
        }
        return 0;
    }
    memset(&state->wrapper_provider, 0, sizeof(state->wrapper_provider));
    status =
        kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
            state->context, &state->provider_handle, input->symbol,
            input->version_evidence, input->version,
            &state->wrapper_provider);
    if (status <= 0) {
        return -1;
    }
    if (state->timing_enabled) {
        state->timing->bridge_discover_done =
            production_lazy_direct_timing_now();
    }
    request = (kzt_wrapper_probe_request_t) {
        .symbol_name = input->symbol,
        .symbol_version_evidence = input->version_evidence,
        .symbol_version = input->version,
    };
    if (kzt_wrapper_probe_minimal_manifest(
            &state->wrapper_provider.manifest, &request,
            &state->wrapper_provider.bridge_ops,
            &state->wrapper_probe) != 0 ||
        (state->wrapper_probe.wrapper_match !=
             KZT_PATCH_WRAPPER_VERSION_MATCH &&
         state->wrapper_probe.wrapper_match !=
             KZT_PATCH_WRAPPER_UNVERSIONED_MATCH) ||
        !state->wrapper_probe.bridge_target) {
        return -1;
    }
    *bridge = (kzt_lazy_direct_route_bridge_t) {
        .target = state->wrapper_probe.bridge_target,
        .version_evidence = state->wrapper_probe.wrapper_version_evidence,
        .version = state->wrapper_probe.wrapper_symbol_version,
    };
    if (state->timing_enabled) {
        state->timing->bridge_done = production_lazy_direct_timing_now();
    }
    return 0;
}

static int production_lazy_direct_acquire_decision_lease(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    kzt_lazy_direct_route_lease_t *lease, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;

    if (!state || !input || !provider || !lease ||
        provider->handle != &state->provider_handle ||
        kzt_guest_registry_patch_decision_lease_acquire(
            &state->source_lease, &state->decision_lease) != 0) {
        return -1;
    }
    lease->handle = &state->decision_lease;
    lease->active = state->decision_lease.active;
    if (state->timing_enabled) {
        state->timing->decision_done = production_lazy_direct_timing_now();
    }
    return lease->active ? 0 : -1;
}

static void production_lazy_direct_release_decision_lease(
    kzt_lazy_direct_route_lease_t *lease, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;

    if (state && state->decision_lease.active) {
        kzt_guest_registry_patch_decision_lease_release(
            &state->decision_lease);
    }
    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
}

static int production_lazy_direct_validate_final(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider,
    const kzt_lazy_direct_route_bridge_t *bridge,
    const kzt_lazy_direct_route_lease_t *lease, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    kzt_guest_registry_address_match_t source_match;
    kzt_guest_registry_address_match_t provider_match;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_guest_symbol_scope_result_t revalidated;
    int valid = 0;

    if (!state || !input || !provider || !bridge || !lease ||
        !lease->active || lease->handle != &state->decision_lease ||
        !state->decision_lease.active ||
        state->decision_lease.registry != state->registry ||
        state->decision_lease.link_map_addr !=
            input->source.link_map_addr ||
        state->decision_lease.generation != input->source.generation ||
        state->decision_lease.namespace_id != 0 ||
        (state->prebind_hit &&
         !kzt_lazy_prebind_scope_lease_valid(&state->prebind_lease)) ||
        !state->provider_handle_owned ||
        provider->handle != &state->provider_handle ||
        state->provider_handle.library != state->resolved_provider ||
        state->loader_quiescence_lease.bindings !=
            state->provider_handle.bindings ||
        !state->loader_quiescence_lease.cookie ||
        state->wrapper_provider.match.retained_provider_handle !=
            &state->provider_handle ||
        bridge->target != state->wrapper_probe.bridge_target ||
        kzt_guest_registry_find_live_object(
            state->registry, input->source.link_map_addr,
            &source_match) != 0 ||
        source_match.generation != input->source.generation ||
        source_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        source_match.namespace_id != 0 ||
        kzt_guest_registry_find_live_object(
            state->registry, input->provider.link_map_addr,
            &provider_match) != 0 ||
        provider_match.generation != input->provider.generation ||
        provider_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        provider_match.namespace_id != 0 ||
        kzt_guest_registry_dynamic_view_matches(
            state->registry, input->source.link_map_addr,
            input->source.generation,
            input->source_dynamic_view) != 0 ||
        kzt_guest_symbol_scope_revalidate(
            &state->preemption_proof, &state->symbol_scope_request,
            &reader_ops, &revalidated) !=
            KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        goto out;
    }
    valid = __atomic_load_n((uintptr_t *)input->slot_addr,
                            __ATOMIC_ACQUIRE) ==
            input->expected_current_slot;
out:
    if (state && state->timing_enabled) {
        state->timing->final_done = production_lazy_direct_timing_now();
    }
    return valid;
}

static kzt_lazy_direct_route_cas_status_t
production_lazy_direct_cas_slot(
    uintptr_t slot_addr, uintptr_t expected, uintptr_t replacement,
    const kzt_lazy_direct_route_lease_t *lease, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    uintptr_t observed = expected;
    int exchanged;

    if (!state || !lease || !lease->active ||
        lease->handle != &state->decision_lease ||
        !state->decision_lease.active || !slot_addr || !replacement) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    }
    if (kzt_patch_spike_guard_circuit_open(
            KztPatchSpikeGuardForContext(state->context))) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    }
    if (state->wrapper_provider.match.custom_wrapper &&
        strcmp(state->evidence.runtime_candidate.symbol_name,
               "dlerror") == 0 &&
        kzt_guest_dl_api_publish_dlerror_entry(
            state->context->dlprivate,
            state->evidence.runtime_candidate.symbol_name,
            state->preemption_proof.selected_provider_address,
            state->wrapper_provider.match.custom_wrapper) != 0) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    }
    exchanged = __atomic_compare_exchange_n(
        (uintptr_t *)slot_addr, &observed, replacement, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    if (state->timing_enabled) {
        state->timing->cas_done = production_lazy_direct_timing_now();
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    return exchanged ? KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED :
                       KZT_LAZY_DIRECT_ROUTE_CAS_MISMATCH;
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
        if (status == 0) {
            state->held_source_lease = &state->source_lease;
        }
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
    kzt_guest_registry_address_match_t match;
    int result = -1;

    state->failure_stage = "EXACT_LIBRARY_BINDING";
    if (!owner || !owner->known || !owner->link_map_addr ||
        !owner->generation || !handle) {
        return -1;
    }
    if (kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(state->context),
            owner->link_map_addr, &match) != 0 ||
        match.generation != owner->generation ||
        match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        match.namespace_id != 0) {
        goto out;
    }
    key = (kzt_guest_library_binding_key_t){
        .link_map_addr = owner->link_map_addr,
        .generation = owner->generation,
        .namespace_id = match.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    if (KztGuestLibraryLookupForContext(state->context, &key, handle) != 0) {
        goto out;
    }
    if (!handle->library ||
        (resolved_provider && handle->library != resolved_provider)) {
        kzt_guest_library_handle_release(handle);
        goto out;
    }
    state->resolved_provider = handle->library;
    state->retained_provider_handle = handle;
    state->exact_provider_owner = *owner;
    state->owner_namespace_id = match.namespace_id;
    result = 0;
    state->failure_stage = "BRIDGE_EVIDENCE";
out:
    return result;
}

static void production_release_exact(kzt_guest_library_handle_t *handle,
                                     void *opaque)
{
    (void)opaque;
    kzt_guest_library_handle_release(handle);
}

static void production_release_decision_lease(
    kzt_production_jump_slot_state_t *state)
{
    if (!state || !state->decision_lease.active) {
        return;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_patch_decision_lease_release();
#endif
    kzt_guest_registry_patch_decision_lease_release(&state->decision_lease);
    state->held_decision_lease = NULL;
}

static int production_acquire_and_validate_bridge_evidence(
    kzt_production_jump_slot_state_t *state,
    kzt_rela_immediate_candidate_request_t *request)
{
    kzt_patch_decision_t decision;
    kzt_owner_resolution_t owner_resolution;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    uintptr_t namespace_head = 0;
    uintptr_t fresh_value;
    uintptr_t prepared_value;

    if (!state || !request || !state->held_source_lease) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_patch_decision_lease_acquire();
#endif
    if (kzt_guest_registry_patch_decision_lease_acquire(
            state->held_source_lease, &state->decision_lease) != 0) {
        return -1;
    }
    state->held_decision_lease = &state->decision_lease;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_patch_decision_lease_acquire();
#endif
    prepared_value = state->lazy_completion ? state->resolved_target :
                                              request->slot_current_value;
    if (!prepared_value ||
        production_slot_load(request->slot_addr, &fresh_value, state) != 0) {
        production_release_decision_lease(state);
        return -1;
    }
    if (fresh_value != prepared_value) {
        state->final_stale_slot_value = fresh_value;
        state->preserve_guest_after_final_slot_stale = 1;
        production_release_decision_lease(state);
        return -1;
    }
    request->slot_current_value_present = 1;
    request->slot_current_value = fresh_value;
    kzt_owner_resolver_init(&owner_resolution);
    if (kzt_owner_resolver_resolve_current(
            KztGuestRegistryForContext(state->context), fresh_value,
            request->expected_guest_target, &owner_resolution) != 0 ||
        owner_resolution.status != KZT_OWNER_RESOLVER_RESOLVED ||
        owner_resolution.owner_match != KZT_PATCH_OWNER_MATCH) {
        production_release_decision_lease(state);
        return -1;
    }
    request->current_owner = owner_resolution.current_owner;
    request->owner_match = owner_resolution.owner_match;
    if (kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(state->context),
            &state->loader_quiescence_lease) != 0 ||
        kzt_guest_registry_context_get_main_namespace_head(
            &state->context->kzt_guest_registry_context,
            &namespace_head) != 0 ||
        !state->runtime_view_valid ||
        production_symbol_scope_request(
            state->context, state->head, request->source.generation,
            namespace_head, &state->runtime_view, &reader_ops,
            request->symbol_index, request->symbol_name,
            request->version_evidence, request->version,
            &state->symbol_scope_request) != 0 ||
        kzt_guest_symbol_scope_check(
            &state->symbol_scope_request,
            owner_resolution.current_owner.link_map_addr,
            fresh_value,
            &reader_ops, &state->symbol_scope_proof) !=
            KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        production_release_decision_lease(state);
        return -1;
    }
    memset(&decision, 0, sizeof(decision));
    decision.source = request->source;
    decision.dynamic_view_available = request->dynamic_view_available;
    decision.dynamic_view_generation = request->dynamic_view_generation;
    decision.slot_addr = request->slot_addr;
    decision.slot_current_value = request->slot_current_value;
    decision.current_owner = request->current_owner;
    decision.owner_match = request->owner_match;
    if (production_prevalidate_write_evidence(&decision, state) != 0) {
        production_release_decision_lease(state);
        return -1;
    }
    state->prevalidated_decision = decision;
    state->prevalidated_decision_valid = 1;
    return 0;
}

static int production_preserve_guest_after_bridge_failure(
    uintptr_t *value, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;

    if (!state || !value || !state->preserve_guest_after_final_slot_stale) {
        return 0;
    }
    *value = state->final_stale_slot_value;
    return 1;
}

static int production_enrich_bridge(
    kzt_rela_immediate_candidate_request_t *request,
    library_t *held_provider, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    int status;
    int provider_prepared;

    if (production_acquire_and_validate_bridge_evidence(state, request) != 0) {
        return -1;
    }

    state->failure_stage = "BRIDGE_EVIDENCE";
    memset(&state->wrapper_provider, 0, sizeof(state->wrapper_provider));
    status = kzt_rela_runtime_wrapper_provider_discover_with_version_evidence(
        state->context, held_provider, request->symbol_name,
        request->version_evidence, request->version,
        &state->wrapper_provider);
    provider_prepared = status > 0;
    if (provider_prepared &&
        kzt_rela_runtime_wrapper_provider_bind_retained_handle(
            &state->wrapper_provider, state->retained_provider_handle) != 0) {
        production_release_decision_lease(state);
        return -1;
    }
    /* A created bridge can remain cached when a later permission or CAS
     * step fails; it was created only after the evidence was valid. */
    /* The base enrichment already established Registry, Dynamic View, and
     * owner evidence.  Reuse it for one post-validation wrapper enrichment. */
    status = production_enrich_wrapper_only(
        request, provider_prepared ? &state->wrapper_provider : NULL,
        &state->bridge_enrich_result, state);
    if (status != 0) {
        production_release_decision_lease(state);
        return -1;
    }
    state->last_request = *request;
    state->failure_stage = "SOURCE_IDENTITY";
    production_shadow_runtime_candidate(
        state, request,
        provider_prepared ? &state->wrapper_provider : NULL);
    return 0;
}

static int production_validate_source_identity(
    const kzt_rela_immediate_candidate_request_t *request, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    state->failure_stage = "SOURCE_IDENTITY";
    if (!request || !request->source.known ||
        !request->source.link_map_addr || !request->source.generation ||
        !state->held_decision_lease || !state->held_decision_lease->active ||
        !state->prevalidated_decision_valid ||
        state->held_decision_lease->link_map_addr !=
            request->source.link_map_addr ||
        state->held_decision_lease->generation != request->source.generation ||
        request->dynamic_view_generation != request->source.generation ||
        request->owner_match != KZT_PATCH_OWNER_MATCH ||
        !request->current_owner.known ||
        (state->required_source_link_map &&
         (request->source.link_map_addr != state->required_source_link_map ||
          request->source.generation != state->required_source_generation))) {
        return 0;
    }
    state->failure_stage = "WRITER";
    return 1;
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
    if (!state->held_decision_lease || !state->held_decision_lease->active) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_PRESERVE;
    }
    status = kzt_rela_immediate_jump_slot_try_write(
        request, guard, slot_ops, &state->writer_result);
    production_release_decision_lease(state);
    if (status != 0) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_ERROR;
    }
    state->last_request = *request;
    if (state->writer_result.record.result ==
        KZT_PATCH_SPIKE_RESULT_ROLLED_BACK) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_ROLLED_BACK;
    }
    if (state->writer_result.record.result ==
        KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_UNRECOVERABLE;
    }
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
    const kzt_guest_registry_source_lease_t *held_source_lease,
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
        .resolved_provider = resolved_provider,
        .initial_request = input.request,
        .slot_current_value_is_unresolved_stub =
            slot_current_value_is_unresolved_stub,
        .resolved_target = resolved_target,
        .required_source_link_map = required_source_link_map,
        .required_source_generation = required_source_generation,
        .head = head,
        .discover_bridge_from_provider = discover_bridge_from_provider,
        .held_source_lease = held_source_lease,
        .lazy_completion = held_source_lease != NULL,
        .failure_stage = "ROUTE_PRECONDITIONS",
    };
    ops = (kzt_jump_slot_route_ops_t){
        .enrich_base = production_enrich_base,
        .acquire_exact_provider = production_acquire_exact,
        .release_exact_provider = production_release_exact,
        .enrich_bridge = production_enrich_bridge,
        .validate_source_identity = production_validate_source_identity,
        .preserve_guest_after_bridge_failure =
            production_preserve_guest_after_bridge_failure,
        .try_native_writer = production_try_writer,
        .load_slot = production_slot_load,
        .compare_exchange_slot = production_slot_cas,
        .begin_slot_write = production_slot_begin_write,
        .end_slot_write = production_slot_end_write,
        .validate_write_generation = production_validate_prevalidated_write,
        .opaque = &state,
    };
    status = kzt_jump_slot_route_apply(&input, &ops, route_result);
    state.retained_provider_handle = NULL;
    production_release_decision_lease(&state);
    if (status != 0) {
        kzt_guest_library_loader_quiescence_release(
            &state.loader_quiescence_lease);
        kzt_guest_registry_source_lease_release(&state.source_lease);
        return -1;
    }
    production_emit_diagnostic(&state, route_result);
    kzt_guest_library_loader_quiescence_release(
        &state.loader_quiescence_lease);
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
                               KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
        version, expected_guest_target_present, expected_guest_target,
        legacy_target, 0, 0, 0, 0, NULL, route_result);
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
        expected_guest_target, legacy_target, 0, 0, 0, 0, NULL, route_result);
}

int kzt_production_lazy_direct_route(
    box64context_t *context, elfheader_t *head, int entry_index,
    Elf64_Rela *rela, uint64_t *slot, uintptr_t slot_current_value,
    unsigned long symbol_index, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_lazy_direct_route_result_t *result)
{
    kzt_lazy_direct_production_state_t state;
    kzt_guest_registry_lazy_source_t source;
    kzt_guest_registry_address_match_t provider_match;
    kzt_rela_immediate_candidate_request_t request;
    kzt_lazy_prebind_record_t prebind_key;
    kzt_guest_dynamic_view_t cached_view;
    kzt_guest_field_status_t cached_view_status;
    kzt_lazy_direct_route_input_t input;
    kzt_lazy_direct_route_ops_t ops;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_lazy_direct_timing_t timing = { 0 };
    uintptr_t namespace_head = 0;
    size_t relocation_count;
    unsigned long cached_view_generation;
    int quiescence_status;
    int timing_enabled;

    if (!result) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED;
    result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_INPUT;
    if (!context || !head ||
        !head->self_link_map || !head->jmprel || head->pltent <= 0 ||
        !head->DynSym || !head->numDynSym || !rela || !slot ||
        !slot_current_value ||
        !symbol_name || !symbol_name[0] ||
        ELF64_R_TYPE(rela->r_info) != R_X86_64_JUMP_SLOT ||
        symbol_index >= head->numDynSym ||
        ELF64_R_SYM(rela->r_info) != symbol_index ||
        rela->r_offset + head->delta != (uintptr_t)slot ||
        !kzt_symbol_version_evidence_valid(version_evidence, version) ||
        !kzt_rela_slot_current_is_unresolved_stub(
            slot_current_value, KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
            head->delta, head->plt, head->plt_end, head->gotplt,
            head->gotplt_end)) {
        return 0;
    }
    relocation_count = head->pltsz / head->pltent;
    if (entry_index < 0 || (size_t)entry_index >= relocation_count) {
        return 0;
    }
    if (!kzt_lazy_direct_symbol_binding_supported(
            head->DynSym[symbol_index].st_info)) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_UNSUPPORTED_SYMBOL_BINDING;
        return 0;
    }
    if (kzt_patch_symbol_must_stay_guest(symbol_name)) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_GUEST_OWNED_SYMBOL;
        return 0;
    }

    memset(&state, 0, sizeof(state));
    timing_enabled = unlikely(option_kzt_lazy_diagnostics);
    if (timing_enabled) {
        timing.start = production_lazy_direct_timing_now();
    }
    state.context = context;
    state.registry = KztGuestRegistryForContext(context);
    state.timing = &timing;
    state.timing_enabled = timing_enabled;
    state.evidence.context = context;
    state.evidence.slot_current_value_is_unresolved_stub = 1;
    if (!state.registry ||
        kzt_guest_registry_find_lazy_source(
            state.registry, head->self_link_map, &source) != 0 ||
        !source.generation || source.namespace_id != 0 ||
        kzt_guest_registry_source_lease_acquire(
            state.registry, head->self_link_map, source.generation,
            source.namespace_id, &state.source_lease) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_SOURCE_REJECTED;
        return 0;
    }
    if (timing_enabled) {
        timing.source = production_lazy_direct_timing_now();
    }
    if (kzt_guest_registry_context_get_main_namespace_head(
            &context->kzt_guest_registry_context, &namespace_head) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        goto done;
    }

    state.prebind_scope = KztLazyPrebindScopeForContext(context);
    if (production_lazy_prebind_record_key(
            &prebind_key, head->self_link_map, source.generation,
            entry_index, (uintptr_t)slot, slot_current_value, symbol_name,
            version_evidence, version) == 0 &&
        kzt_lazy_prebind_scope_acquire(
            state.prebind_scope, &prebind_key, &state.prebind_lease) == 0) {
        cached_view_status = KZT_GUEST_FIELD_NOT_PARSED;
        cached_view_generation = 0;
        if (kzt_guest_registry_find_dynamic_view(
                state.registry, head->self_link_map, &cached_view,
                &cached_view_status, &cached_view_generation) == 0 &&
            cached_view_status == KZT_GUEST_FIELD_OK &&
            cached_view_generation == source.generation &&
            cached_view.status == KZT_GUEST_DYNAMIC_COMPLETE &&
            kzt_guest_registry_dynamic_view_matches(
                state.registry, head->self_link_map, source.generation,
                &cached_view) == 0) {
            state.prebind_hit = 1;
            state.preemption_proof = state.prebind_lease.record.scope_proof;
            state.evidence.runtime_view = cached_view;
            state.evidence.runtime_view_valid = 1;
            state.evidence.runtime_candidate.symbol_name = symbol_name;
            state.evidence.runtime_candidate.version_evidence =
                version_evidence;
            state.evidence.runtime_candidate.version = version;
            state.evidence.runtime_candidate.dynamic_view_generation =
                source.generation;
        } else {
            kzt_lazy_prebind_scope_release(&state.prebind_lease);
        }
    }
    if (!state.prebind_hit) {
        memset(&request, 0, sizeof(request));
        request.relocation_type = R_X86_64_JUMP_SLOT;
        request.table_kind = KZT_PATCH_TABLE_PLT_RELA;
        request.entry_index = (size_t)entry_index;
        request.entry_addr = (uintptr_t)rela;
        request.source.known = 1;
        request.source.link_map_addr = head->self_link_map;
        request.source.generation = source.generation;
        request.source.map_start = (uintptr_t)head->memory;
        request.source.map_end = (uintptr_t)head->memory + head->memsz;
        request.source.soname = head->name;
        request.source.path = head->path;
        request.slot_addr = (uintptr_t)slot;
        request.slot_current_value_present = 1;
        request.slot_current_value = slot_current_value;
        request.symbol_index = symbol_index;
        request.symbol_name = symbol_name;
        request.version_evidence = version_evidence;
        request.version = version;
        if (production_collect_runtime_candidate(
                &state.evidence, &request) != 0) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_INCOMPLETE_DYNAMIC_VIEW;
            goto done;
        }
    }
    if (!state.evidence.runtime_view_valid ||
        production_symbol_scope_request(
            context, head, source.generation, namespace_head,
            &state.evidence.runtime_view, &reader_ops, symbol_index,
            state.evidence.runtime_candidate.symbol_name,
            state.evidence.runtime_candidate.version_evidence,
            state.evidence.runtime_candidate.version,
            &state.symbol_scope_request) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        goto done;
    }
    if (timing_enabled) {
        timing.candidate = production_lazy_direct_timing_now();
    }
    quiescence_status = kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(context),
            &state.loader_quiescence_lease);
    if (timing_enabled) {
        timing.quiescence = production_lazy_direct_timing_now();
    }
    if (quiescence_status != 0) {
        if (!state.prebind_hit) {
            (void)kzt_guest_symbol_scope_discover(
                &state.symbol_scope_request, &reader_ops,
                &state.preemption_proof);
        }
        if (timing_enabled) {
            timing.scope = production_lazy_direct_timing_now();
        }
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        goto preemption_diagnostic;
    }

    if (!state.prebind_hit) {
        if (kzt_guest_symbol_scope_discover(
                &state.symbol_scope_request, &reader_ops,
                &state.preemption_proof) != KZT_GUEST_SYMBOL_SCOPE_SAFE) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        }
    }
    if (timing_enabled) {
        timing.scope = production_lazy_direct_timing_now();
    }

preemption_diagnostic:
    printf_kzt_registry_diagnostics(
        "kzt_lazy_preemption schema=1 symbol=%s version=%s "
        "candidate_count=%zu scope_complete=%d lookup_order_known=%d "
        "reason=%s selected_provider=%p\n",
        state.evidence.runtime_candidate.symbol_name,
        state.evidence.runtime_candidate.version ?
            state.evidence.runtime_candidate.version : "",
        state.preemption_proof.candidate_count,
        state.preemption_proof.scope_complete,
        state.preemption_proof.lookup_order_known,
        kzt_guest_symbol_scope_reason_name(
            state.preemption_proof.reason),
        (void *)state.preemption_proof.selected_provider_link_map);
    if (quiescence_status != 0 ||
        state.preemption_proof.status != KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        goto done;
    }

    memset(&provider_match, 0, sizeof(provider_match));
    if (kzt_guest_registry_find_live_object(
            state.registry,
            state.preemption_proof.selected_provider_link_map,
            &provider_match) != 0 ||
        !provider_match.generation ||
        provider_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        provider_match.namespace_id != 0) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
        goto done;
    }
    if (state.prebind_hit &&
        (!kzt_lazy_prebind_scope_lease_valid(&state.prebind_lease) ||
         state.preemption_proof.selected_provider_link_map !=
             state.prebind_lease.record.provider.link_map_addr ||
         provider_match.generation !=
             state.prebind_lease.record.provider.generation)) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_MISMATCH;
        goto done;
    }
    state.provider_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr =
            state.preemption_proof.selected_provider_link_map,
        .generation = provider_match.generation,
        .namespace_id = provider_match.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    if (kzt_guest_library_access_lookup(
            &context->kzt_guest_library_access, &state.provider_key,
            &state.provider_handle) != 0 ||
        !state.provider_handle.library ||
        state.provider_handle.object_type !=
            KZT_GUEST_LIBRARY_OBJECT_WRAPPED) {
        kzt_guest_library_handle_release(&state.provider_handle);
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
        goto done;
    }
    state.provider_handle_owned = 1;
    state.resolved_provider = state.provider_handle.library;
    state.evidence.resolved_provider = state.resolved_provider;
    if (timing_enabled) {
        timing.provider = production_lazy_direct_timing_now();
    }

    input = (kzt_lazy_direct_route_input_t) {
        .enabled = 1,
        .preemption_safe = 1,
        .namespace_id = source.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        .source = {
            .link_map_addr = head->self_link_map,
            .generation = source.generation,
        },
        .provider = {
            .link_map_addr = state.provider_key.link_map_addr,
            .generation = state.provider_key.generation,
        },
        .source_dynamic_view = &state.evidence.runtime_view,
        .source_dynamic_view_generation =
            state.evidence.runtime_candidate.dynamic_view_generation,
        .symbol = state.evidence.runtime_candidate.symbol_name,
        .version_evidence =
            state.evidence.runtime_candidate.version_evidence,
        .version = state.evidence.runtime_candidate.version,
        .slot_addr = (uintptr_t)slot,
        .guest_unresolved_slot = slot_current_value,
        .expected_current_slot = slot_current_value,
    };
    ops = (kzt_lazy_direct_route_ops_t) {
        .validate_source = production_lazy_direct_validate_source,
        .acquire_provider = production_lazy_direct_acquire_provider,
        .release_provider = production_lazy_direct_release_provider,
        .find_wrapper_bridge = production_lazy_direct_find_bridge,
        .acquire_decision_lease =
            production_lazy_direct_acquire_decision_lease,
        .release_decision_lease =
            production_lazy_direct_release_decision_lease,
        .validate_final = production_lazy_direct_validate_final,
        .cas_slot = production_lazy_direct_cas_slot,
        .opaque = &state,
    };
    if (timing_enabled) {
        timing.route_start = production_lazy_direct_timing_now();
    }
    (void)kzt_lazy_direct_route_apply(&input, &ops, result);
    if (timing_enabled) {
        timing.route = production_lazy_direct_timing_now();
    }
    if (result->status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED) {
        uintptr_t slot_after =
            __atomic_load_n((uintptr_t *)slot, __ATOMIC_ACQUIRE);
        printf_kzt_registry_diagnostics(
            "kzt_lazy_direct schema=1 symbol=%s "
            "route_status=NATIVE_APPLIED writer_result=APPLIED "
            "slot_before=%p slot_after=%p selected_target=%p\n",
            input.symbol, (void *)slot_current_value, (void *)slot_after,
            (void *)result->selected_target);
    }

done:
    if (state.decision_lease.active) {
        kzt_guest_registry_patch_decision_lease_release(
            &state.decision_lease);
    }
    if (state.provider_handle_owned) {
        kzt_guest_library_handle_release(&state.provider_handle);
    }
    kzt_lazy_prebind_scope_release(&state.prebind_lease);
    kzt_guest_library_loader_quiescence_release(
        &state.loader_quiescence_lease);
    kzt_guest_registry_source_lease_release(&state.source_lease);
    if (timing_enabled) {
        timing.done = production_lazy_direct_timing_now();
        fprintf(
            stderr,
            "kzt_lazy_timing schema=1 symbol=%s "
            "source_ns=%" PRIu64 " candidate_ns=%" PRIu64 " "
            "quiescence_ns=%" PRIu64 " scope_ns=%" PRIu64 " "
            "provider_ns=%" PRIu64 " route_ns=%" PRIu64 " "
            "route_prepare_ns=%" PRIu64 " bridge_ns=%" PRIu64 " "
            "bridge_discover_ns=%" PRIu64 " bridge_probe_ns=%" PRIu64 " "
            "decision_ns=%" PRIu64 " final_ns=%" PRIu64 " "
            "cas_ns=%" PRIu64 " "
            "cleanup_ns=%" PRIu64 " total_ns=%" PRIu64 " "
            "status=%d reason=%d\n",
            symbol_name,
            production_lazy_direct_timing_delta(
                timing.start, timing.source),
            production_lazy_direct_timing_delta(
                timing.source, timing.candidate),
            production_lazy_direct_timing_delta(
                timing.candidate, timing.quiescence),
            production_lazy_direct_timing_delta(
                timing.quiescence, timing.scope),
            production_lazy_direct_timing_delta(
                timing.scope, timing.provider),
            production_lazy_direct_timing_delta(
                timing.route_start, timing.route),
            production_lazy_direct_timing_delta(
                timing.route_start, timing.bridge_start),
            production_lazy_direct_timing_delta(
                timing.bridge_start, timing.bridge_done),
            production_lazy_direct_timing_delta(
                timing.bridge_start, timing.bridge_discover_done),
            production_lazy_direct_timing_delta(
                timing.bridge_discover_done, timing.bridge_done),
            production_lazy_direct_timing_delta(
                timing.bridge_done, timing.decision_done),
            production_lazy_direct_timing_delta(
                timing.decision_done, timing.final_done),
            production_lazy_direct_timing_delta(
                timing.final_done, timing.cas_done),
            production_lazy_direct_timing_delta(
                timing.route, timing.done),
            production_lazy_direct_timing_delta(
                timing.start, timing.done),
            result->status, result->reason);
    }
    return 0;
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
            1, source_lease,
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
    case KZT_JUMP_SLOT_ROUTE_WRITE_ROLLED_BACK:
        result->status = KZT_LAZY_BINDING_ROUTE_WRITE_ROLLED_BACK;
        break;
    case KZT_JUMP_SLOT_ROUTE_UNRECOVERABLE:
        result->status = KZT_LAZY_BINDING_ROUTE_UNRECOVERABLE;
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
