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
#include "kzt_guest_dynsym_lookup.h"
#include "kzt_guest_library_adapter.h"
#include "kzt_guest_symbol_scope.h"
#include "kzt_lifecycle_diagnostics.h"
#include "kzt_lazy_direct_route.h"
#include "kzt_loader_event_hook.h"
#include "kzt_rela_diagnostics.h"
#include "library.h"
#include "library_private.h"
#include "librarian.h"
#include "kzt_rela_request_enricher.h"
#include "kzt_rela_runtime_bridge.h"
#include "kzt_xcb_route_policy.h"
#include "kzt_rela_stub_detector.h"
#include "kzt_owner_resolver.h"
#include "kzt_runtime_candidate_shadow.h"
#include "kzt_wrapper_probe.h"

extern int option_kzt_lazy_diagnostics;

static int production_symbol_uses_guarded_xcb_bridge(
    const char *symbol_name)
{
    return kzt_xcb_route_is_guarded_consumer(symbol_name);
}

typedef struct kzt_production_alias_proof {
    kzt_guest_library_binding_key_t owner_key;
    kzt_guest_library_binding_key_t provider_key;
    kzt_guest_library_bindings_t *provider_bindings;
    void *provider_entry;
    library_t *provider_library;
    kzt_guest_field_status_t owner_path_status;
    kzt_guest_field_status_t owner_soname_status;
    kzt_guest_field_status_t provider_path_status;
    kzt_guest_field_status_t provider_soname_status;
    char owner_path[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    char owner_soname[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    char provider_path[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    char provider_soname[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
    int valid;
} kzt_production_alias_proof_t;

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
    kzt_guest_registry_source_lease_t owner_source_lease;
    kzt_guest_registry_patch_decision_lease_t decision_lease;
    const kzt_guest_registry_patch_decision_lease_t *held_decision_lease;
    const kzt_guest_library_handle_t *retained_provider_handle;
    kzt_guest_library_binding_key_t exact_provider_key;
    kzt_guest_library_bindings_t *exact_provider_bindings;
    void *exact_provider_entry;
    library_t *exact_provider_library;
    kzt_patch_object_ref_t exact_provider_owner;
    kzt_guest_library_loader_quiescence_lease_t loader_quiescence_lease;
    kzt_guest_symbol_scope_request_t symbol_scope_request;
    kzt_guest_symbol_scope_result_t symbol_scope_proof;
    kzt_guest_registry_symbol_candidate_t exact_owner_candidate;
    kzt_production_alias_proof_t alias_proof;
    int exact_owner_symbol_proof;
    int exact_owner_without_map_range;
    int wrapper_alias_borrowed;
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

static int production_exact_provider_handle_matches(
    const kzt_production_jump_slot_state_t *state)
{
    const kzt_guest_library_handle_t *handle =
        state ? state->retained_provider_handle : NULL;

    return handle && handle->bindings && handle->entry && handle->library &&
           handle->bindings == state->exact_provider_bindings &&
           handle->entry == state->exact_provider_entry &&
           handle->library == state->exact_provider_library &&
           handle->library == state->resolved_provider &&
           handle->object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
           kzt_guest_library_handle_matches_key(
               handle, &state->exact_provider_key);
}

#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
void kzt_jump_slot_production_test_before_source_lease_acquire(void);
void kzt_jump_slot_production_test_before_source_memory_access(void);
void kzt_jump_slot_production_test_before_owner_memory_access(
    int source_lease_active, int decision_lease_active,
    int quiescence_active, int retained_provider_active,
    int owner_lease_active);
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

static int production_exact_owner_symbol_matches(
    kzt_production_jump_slot_state_t *state,
    const kzt_patch_object_ref_t *owner, uintptr_t target,
    const char *symbol, kzt_symbol_version_evidence_t version_evidence,
    const char *version)
{
    kzt_guest_dynamic_view_t owner_view;
    kzt_guest_dynsym_lookup_result_t lookup = { 0 };
    kzt_guest_field_status_t dynamic_status;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    unsigned long dynamic_generation = 0;

    if (!state || !owner || !owner->known || !owner->link_map_addr ||
        !owner->generation || !target || !symbol || !symbol[0] ||
        !state->held_source_lease || !state->held_source_lease->active ||
        !state->held_decision_lease || !state->held_decision_lease->active ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie ||
        !production_exact_provider_handle_matches(state) ||
        !state->owner_source_lease.active ||
        state->owner_source_lease.registry !=
            KztGuestRegistryForContext(state->context) ||
        state->owner_source_lease.link_map_addr != owner->link_map_addr ||
        state->owner_source_lease.generation != owner->generation ||
        state->owner_source_lease.namespace_id != 0 ||
        (state->exact_owner_without_map_range &&
         !kzt_loader_lifecycle_runtime_healthy(state->context)) ||
        !kzt_symbol_version_evidence_valid(version_evidence, version)) {
        return 0;
    }
    if (kzt_guest_registry_find_dynamic_view(
            KztGuestRegistryForContext(state->context), owner->link_map_addr,
            &owner_view, &dynamic_status, &dynamic_generation) != 0 ||
        dynamic_status != KZT_GUEST_FIELD_OK ||
        dynamic_generation != owner->generation ||
        owner_view.status != KZT_GUEST_DYNAMIC_COMPLETE ||
        (state->exact_owner_without_map_range &&
         (state->exact_owner_candidate.link_map_addr !=
              owner->link_map_addr ||
          state->exact_owner_candidate.generation != owner->generation ||
          state->exact_owner_candidate.dynamic_view_revision == 0 ||
          kzt_guest_registry_dynamic_view_matches(
              KztGuestRegistryForContext(state->context),
              owner->link_map_addr, owner->generation,
              &state->exact_owner_candidate.dynamic_view) != 0))) {
        return 0;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_owner_memory_access(
        state->held_source_lease && state->held_source_lease->active,
        state->held_decision_lease && state->held_decision_lease->active,
        state->loader_quiescence_lease.bindings != NULL &&
            state->loader_quiescence_lease.cookie != 0,
        state->retained_provider_handle != NULL &&
            state->retained_provider_handle->bindings != NULL &&
            state->retained_provider_handle->entry != NULL,
        state->owner_source_lease.active);
#endif
    if (kzt_guest_dynsym_lookup(
            &owner_view, &reader_ops, symbol, version_evidence, version,
            &lookup) != KZT_GUEST_DYNSYM_LOOKUP_FOUND) {
        return 0;
    }
    return lookup.runtime_address == target && lookup.binding == STB_GLOBAL &&
           lookup.type == STT_FUNC && lookup.visibility == STV_DEFAULT;
}

static int production_dynamic_view_needs_library(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const char *required_name)
{
    size_t i;

    if (!view || view->status != KZT_GUEST_DYNAMIC_COMPLETE ||
        !view->strtab.present ||
        view->strtab.address_semantics !=
            KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS ||
        view->strtab.value > UINTPTR_MAX ||
        !view->strsz.present ||
        view->strsz.address_semantics != KZT_GUEST_DYNAMIC_SCALAR ||
        !view->strsz.value || view->strsz.value > SIZE_MAX ||
        view->needed_address_semantics !=
            KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET ||
        !view->needed_count ||
        view->needed_count > KZT_GUEST_DYNAMIC_NEEDED_LIMIT ||
        !reader_ops || !reader_ops->read_memory || !required_name ||
        !required_name[0]) {
        return 0;
    }
    for (i = 0; i < view->needed_count; ++i) {
        char needed[KZT_GUEST_REGISTRY_ADDRESS_TEXT_LIMIT];
        uint64_t offset = view->needed_offsets[i];
        size_t remaining;
        size_t length;

        if (offset >= view->strsz.value ||
            view->strtab.value > UINTPTR_MAX - offset) {
            return 0;
        }
        remaining = (size_t)(view->strsz.value - offset);
        for (length = 0;
             length < remaining && length < sizeof(needed);
             ++length) {
            if (reader_ops->read_memory(
                    (uintptr_t)view->strtab.value + (uintptr_t)offset +
                        length,
                    &needed[length], 1, reader_ops->opaque) != 0) {
                return 0;
            }
            if (needed[length] == '\0') {
                if (strcmp(needed, required_name) == 0) {
                    return 1;
                }
                break;
            }
        }
        if (length == remaining || length == sizeof(needed)) {
            return 0;
        }
    }
    return 0;
}

static int production_custom_dlsym_boundary_proven(
    const kzt_production_jump_slot_state_t *state, const char *symbol)
{
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    uintptr_t main_namespace_head = 0;

    if (!symbol || strcmp(symbol, "dlsym") != 0) {
        return 1;
    }
    if (!state || !state->context ||
        kzt_guest_registry_context_get_main_namespace_head(
            &state->context->kzt_guest_registry_context,
            &main_namespace_head) != 0 ||
        !main_namespace_head) {
        return 0;
    }
    return state->head &&
           state->head->latx_type != LATX_ELF_TYPE_MAIN &&
           state->head->self_link_map == state->last_request.source.link_map_addr &&
           state->last_request.source.link_map_addr != main_namespace_head &&
           state->wrapper_alias_borrowed && state->runtime_view_valid &&
           state->owner_namespace_id == 0 &&
           state->exact_provider_key.namespace_id == 0 &&
           state->exact_provider_key.namespace_kind ==
               KZT_GUEST_LIBRARY_NAMESPACE_MAIN &&
           state->exact_provider_key.link_map_addr !=
               state->last_request.source.link_map_addr &&
           state->wrapper_provider.match.custom_wrapper &&
           state->wrapper_provider.match.resolved_bridge_exact &&
           state->wrapper_provider.match.resolved_bridge_target != 0 &&
           production_dynamic_view_needs_library(
               &state->runtime_view, &reader_ops, "libdl.so.2");
}

static int production_symbol_candidate_has_exact_name(
    const kzt_guest_registry_symbol_candidate_t *candidate,
    const char *required_name)
{
    const char *basename;

    if (!candidate || !required_name || !required_name[0] ||
        candidate->path_status != KZT_GUEST_FIELD_OK ||
        !candidate->path[0] ||
        (candidate->soname_status != KZT_GUEST_FIELD_OK &&
         candidate->soname_status != KZT_GUEST_FIELD_NOT_PARSED)) {
        return 0;
    }
    basename = strrchr(candidate->path, '/');
    basename = basename ? basename + 1 : candidate->path;
    return strcmp(basename, required_name) == 0 &&
           (candidate->soname_status != KZT_GUEST_FIELD_OK ||
            strcmp(candidate->soname, required_name) == 0);
}

static int production_exact_owner_candidate_semantics_supported(
    const kzt_guest_dynsym_lookup_result_t *lookup)
{
    if (!lookup || lookup->binding == STB_WEAK) {
        return 0;
    }
    if (lookup->binding == KZT_ELF_STB_GNU_UNIQUE) {
        return 0;
    }
    if (lookup->type == KZT_ELF_STT_GNU_IFUNC) {
        return 0;
    }
    return 1;
}

static int production_resolve_exact_symbol_owner(
    kzt_production_jump_slot_state_t *state, uintptr_t target,
    const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    const char *required_owner_name,
    kzt_owner_resolution_t *resolution, uintptr_t *resolved_target)
{
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = production_read_guest_memory,
    };
    kzt_guest_registry_symbol_candidate_t candidate = { 0 };
    kzt_patch_object_ref_t owner = { 0 };
    uintptr_t matched_target = 0;
    size_t match_count = 0;
    size_t cursor = 0;
    int candidate_status;

    if (resolved_target) {
        *resolved_target = 0;
    }
    if (!state || !state->context || !symbol || !symbol[0] ||
        !resolution || !state->held_decision_lease ||
        !state->held_decision_lease->active ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie ||
        !kzt_loader_lifecycle_runtime_healthy(state->context) ||
        !kzt_symbol_version_evidence_valid(version_evidence, version) ||
        state->owner_source_lease.active) {
        return -1;
    }
    kzt_owner_resolver_init(resolution);
    while ((candidate_status =
                kzt_guest_registry_symbol_candidate_acquire_next(
                    state->held_decision_lease, &cursor, &candidate)) == 1) {
        kzt_guest_dynsym_lookup_result_t lookup = { 0 };
        kzt_guest_dynsym_lookup_status_t lookup_status;
        int target_outside_candidate =
            target && candidate.map_start && candidate.map_end &&
            (target < candidate.map_start || target >= candidate.map_end);

        if (!target && state->held_source_lease &&
            candidate.link_map_addr ==
                state->held_source_lease->link_map_addr &&
            candidate.generation == state->held_source_lease->generation) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            continue;
        }
        if (candidate.dynamic_view_status != KZT_GUEST_FIELD_OK ||
            candidate.dynamic_view.status != KZT_GUEST_DYNAMIC_COMPLETE ||
            !candidate.dynamic_view_revision) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            if (target_outside_candidate) {
                continue;
            }
            goto fail;
        }
        lookup_status = kzt_guest_dynsym_lookup(
            &candidate.dynamic_view, &reader_ops, symbol,
            version_evidence, version, &lookup);
        if (lookup_status == KZT_GUEST_DYNSYM_LOOKUP_FOUND &&
            !production_exact_owner_candidate_semantics_supported(&lookup)) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            goto fail;
        }
        if (target_outside_candidate) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            continue;
        }
        if (lookup_status == KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            goto fail;
        }
        if (lookup_status != KZT_GUEST_DYNSYM_LOOKUP_FOUND ||
            (target && lookup.runtime_address != target) ||
            lookup.binding != STB_GLOBAL || lookup.type != STT_FUNC ||
            lookup.visibility != STV_DEFAULT) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            continue;
        }
        if (required_owner_name &&
            !production_symbol_candidate_has_exact_name(
                &candidate, required_owner_name)) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            goto fail;
        }
        owner = (kzt_patch_object_ref_t) {
            .known = 1,
            .link_map_addr = candidate.link_map_addr,
            .map_start = candidate.map_start,
            .map_end = candidate.map_end,
            .generation = candidate.generation,
        };
        if (++match_count != 1) {
            kzt_guest_registry_symbol_candidate_release(&candidate);
            goto fail;
        }
        matched_target = lookup.runtime_address;
        if (candidate.soname_status == KZT_GUEST_FIELD_OK &&
            candidate.soname[0]) {
            snprintf(resolution->current_text.soname,
                     sizeof(resolution->current_text.soname), "%s",
                     candidate.soname);
        }
        if (candidate.path_status == KZT_GUEST_FIELD_OK &&
            candidate.path[0]) {
            snprintf(resolution->current_text.path,
                     sizeof(resolution->current_text.path), "%s",
                     candidate.path);
        }
        state->exact_owner_candidate = candidate;
        state->owner_source_lease = candidate.lease;
        memset(&state->exact_owner_candidate.lease, 0,
               sizeof(state->exact_owner_candidate.lease));
        memset(&candidate, 0, sizeof(candidate));
    }
    if (candidate_status != 0 || match_count != 1) {
        goto fail;
    }
    resolution->status = KZT_OWNER_RESOLVER_RESOLVED;
    resolution->current_owner = owner;
    resolution->expected_owner = owner;
    resolution->current_match_count = 1;
    resolution->expected_match_count = 1;
    resolution->owner_match = KZT_PATCH_OWNER_MATCH;
    resolution->current_owner.soname = resolution->current_text.soname[0]
                                           ? resolution->current_text.soname
                                           : NULL;
    resolution->current_owner.path = resolution->current_text.path[0]
                                         ? resolution->current_text.path
                                         : NULL;
    snprintf(resolution->expected_text.soname,
             sizeof(resolution->expected_text.soname), "%s",
             resolution->current_text.soname);
    snprintf(resolution->expected_text.path,
             sizeof(resolution->expected_text.path), "%s",
             resolution->current_text.path);
    resolution->expected_owner.soname = resolution->expected_text.soname[0]
                                            ? resolution->expected_text.soname
                                            : NULL;
    resolution->expected_owner.path = resolution->expected_text.path[0]
                                          ? resolution->expected_text.path
                                          : NULL;
    state->exact_owner_symbol_proof = 1;
    state->exact_owner_without_map_range = 1;
    if (resolved_target) {
        *resolved_target = matched_target;
    }
    return 0;
fail:
    kzt_guest_registry_symbol_candidate_release(&candidate);
    kzt_guest_registry_source_lease_release(&state->owner_source_lease);
    memset(&state->exact_owner_candidate, 0,
           sizeof(state->exact_owner_candidate));
    kzt_owner_resolver_init(resolution);
    return -1;
}

static int production_resolve_current_owner(
    box64context_t *context, uintptr_t current_target,
    uintptr_t expected_target, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_owner_resolution_t *resolution)
{
    if (!context || !resolution) {
        return -1;
    }
    kzt_owner_resolver_init(resolution);
    if (kzt_owner_resolver_resolve_current(
            KztGuestRegistryForContext(context), current_target,
            expected_target, resolution) == 0 &&
        resolution->status == KZT_OWNER_RESOLVER_RESOLVED &&
        resolution->owner_match == KZT_PATCH_OWNER_MATCH &&
        resolution->current_owner.known) {
        return 0;
    }
    (void)current_target;
    (void)expected_target;
    (void)symbol;
    (void)version_evidence;
    (void)version;
    return -1;
}

static int production_acquire_wrapper_alias_provider(
    kzt_production_jump_slot_state_t *state,
    const kzt_patch_object_ref_t *owner,
    kzt_guest_library_handle_t *handle)
{
    kzt_guest_wrapper_source_proof_t source_proof = { 0 };
    kzt_guest_library_binding_key_t provider_key = { 0 };
    kzt_guest_registry_address_match_t owner_match = { 0 };
    kzt_guest_registry_address_match_t provider_match = { 0 };
    box64context_t *context = state ? state->context : NULL;
    const char *guest_name;
    const char *provider_name;
    const char *wrapper_name;
    int status = -1;

    if (handle) {
        memset(handle, 0, sizeof(*handle));
    }
    if (!state || !context || !owner || !owner->known ||
        !owner->link_map_addr ||
        !owner->generation || !owner->path || !owner->path[0] || !handle ||
        !state->held_decision_lease || !state->held_decision_lease->active ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie ||
        !context->libclib || !context->libclib->active ||
        context->libclib->type != LIB_WRAPPED ||
        !context->libclib->name || !context->libclib->name[0]) {
        return -1;
    }
    guest_name = strrchr(owner->path, '/');
    guest_name = guest_name ? guest_name + 1 : owner->path;
    wrapper_name = kzt_guest_library_wrapper_name_for_guest(guest_name);
    if (!wrapper_name || strcmp(wrapper_name, guest_name) == 0 ||
        strcmp(wrapper_name, context->libclib->name) != 0 ||
        kzt_guest_library_wrapper_source_acquire(
            context, owner->link_map_addr, owner->path, wrapper_name,
            &source_proof) != 0 ||
        source_proof.key.generation != owner->generation ||
        kzt_guest_library_access_lookup_by_library(
            &context->kzt_guest_library_access, context->libclib,
            &provider_key, handle) != 0 ||
        !handle->library || handle->library != context->libclib ||
        handle->object_type != KZT_GUEST_LIBRARY_OBJECT_WRAPPED ||
        provider_key.namespace_kind != KZT_GUEST_LIBRARY_NAMESPACE_MAIN ||
        provider_key.namespace_id != 0 ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(context), owner->link_map_addr,
            &owner_match) != 0 ||
        owner_match.generation != owner->generation ||
        owner_match.path_status != KZT_GUEST_FIELD_OK ||
        (owner_match.soname_status != KZT_GUEST_FIELD_OK &&
         owner_match.soname_status != KZT_GUEST_FIELD_NOT_PARSED) ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(context), provider_key.link_map_addr,
            &provider_match) != 0 ||
        provider_match.generation != provider_key.generation ||
        provider_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        provider_match.namespace_id != provider_key.namespace_id ||
        provider_match.path_status != KZT_GUEST_FIELD_OK ||
        (provider_match.soname_status != KZT_GUEST_FIELD_OK &&
         provider_match.soname_status != KZT_GUEST_FIELD_NOT_PARSED)) {
        goto out;
    }
    provider_name = strrchr(provider_match.path, '/');
    provider_name = provider_name ? provider_name + 1 : provider_match.path;
    if (strcmp(provider_name, wrapper_name) != 0 ||
        (provider_match.soname_status == KZT_GUEST_FIELD_OK &&
         strcmp(provider_match.soname, wrapper_name) != 0)) {
        goto out;
    }
    state->alias_proof = (kzt_production_alias_proof_t) {
        .owner_key = source_proof.key,
        .provider_key = provider_key,
        .provider_bindings = handle->bindings,
        .provider_entry = handle->entry,
        .provider_library = handle->library,
        .owner_path_status = owner_match.path_status,
        .owner_soname_status = owner_match.soname_status,
        .provider_path_status = provider_match.path_status,
        .provider_soname_status = provider_match.soname_status,
        .valid = 1,
    };
    snprintf(state->alias_proof.owner_path,
             sizeof(state->alias_proof.owner_path), "%s", owner_match.path);
    snprintf(state->alias_proof.owner_soname,
             sizeof(state->alias_proof.owner_soname), "%s",
             owner_match.soname);
    snprintf(state->alias_proof.provider_path,
             sizeof(state->alias_proof.provider_path), "%s",
             provider_match.path);
    snprintf(state->alias_proof.provider_soname,
             sizeof(state->alias_proof.provider_soname), "%s",
             provider_match.soname);
    if (!state->owner_source_lease.active) {
        state->owner_source_lease = source_proof.lease;
        memset(&source_proof.lease, 0, sizeof(source_proof.lease));
    } else if (state->owner_source_lease.link_map_addr !=
                   source_proof.key.link_map_addr ||
               state->owner_source_lease.generation !=
                   source_proof.key.generation) {
        goto out;
    }
    status = 0;
out:
    kzt_guest_library_wrapper_source_release(&source_proof);
    if (status != 0) {
        memset(&state->alias_proof, 0, sizeof(state->alias_proof));
        kzt_guest_library_handle_release(handle);
    }
    return status;
}

static int production_wrapper_alias_provider_matches(
    kzt_production_jump_slot_state_t *state,
    const kzt_patch_object_ref_t *owner)
{
    kzt_guest_registry_address_match_t owner_match = { 0 };
    kzt_guest_registry_address_match_t provider_match = { 0 };
    const kzt_production_alias_proof_t *proof =
        state ? &state->alias_proof : NULL;

    return proof && proof->valid && state->retained_provider_handle &&
           owner && owner->known &&
           proof->owner_key.link_map_addr == owner->link_map_addr &&
           proof->owner_key.generation == owner->generation &&
           state->owner_source_lease.active &&
           state->owner_source_lease.link_map_addr == owner->link_map_addr &&
           state->owner_source_lease.generation == owner->generation &&
           state->retained_provider_handle->bindings ==
               proof->provider_bindings &&
           state->retained_provider_handle->entry == proof->provider_entry &&
           state->retained_provider_handle->library == proof->provider_library &&
           state->retained_provider_handle->object_type ==
               KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
           kzt_guest_registry_find_live_object(
               KztGuestRegistryForContext(state->context),
               proof->owner_key.link_map_addr, &owner_match) == 0 &&
           owner_match.generation == proof->owner_key.generation &&
           owner_match.path_status == proof->owner_path_status &&
           owner_match.soname_status == proof->owner_soname_status &&
           strcmp(owner_match.path, proof->owner_path) == 0 &&
           strcmp(owner_match.soname, proof->owner_soname) == 0 &&
           kzt_guest_registry_find_live_object(
               KztGuestRegistryForContext(state->context),
               proof->provider_key.link_map_addr, &provider_match) == 0 &&
           provider_match.generation == proof->provider_key.generation &&
           provider_match.namespace_id_status == KZT_GUEST_FIELD_OK &&
           provider_match.namespace_id == proof->provider_key.namespace_id &&
           provider_match.path_status == proof->provider_path_status &&
           provider_match.soname_status == proof->provider_soname_status &&
           strcmp(provider_match.path, proof->provider_path) == 0 &&
           strcmp(provider_match.soname, proof->provider_soname) == 0;
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

static int production_mandatory_finish_slot(
    kzt_patch_spike_permission_lease_t *permission)
{
    if (!permission || !permission->mmap_lock_held) {
        return -1;
    }
    permission->restore_attempted = 1;
    ++permission->restore_attempts;
    if (production_slot_end_write(permission, NULL) != 0) {
        return -1;
    }
    permission->restored = 1;
    return 0;
}

static kzt_production_slot_transaction_result_t
production_mandatory_slot_transaction(
    uintptr_t slot_addr, uintptr_t expected, uintptr_t replacement,
    uintptr_t *final_value)
{
    kzt_patch_spike_permission_lease_t permission = { 0 };
    uintptr_t observed = expected;
    uintptr_t compare;
    int wrote = 0;

    if (final_value) {
        *final_value = expected;
    }
    if (!slot_addr || !replacement ||
        production_slot_begin_write(slot_addr, &permission, NULL) != 0) {
        if (permission.mmap_lock_held) {
            (void)production_mandatory_finish_slot(&permission);
            if (permission.mmap_lock_held) {
                (void)production_mandatory_finish_slot(&permission);
            }
        }
        return KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;
    }
    if (production_slot_load(slot_addr, &observed, NULL) != 0) {
        goto fail_before_write;
    }
    if (observed != expected) {
        if (final_value) {
            *final_value = observed;
        }
        if (production_mandatory_finish_slot(&permission) != 0 &&
            permission.mmap_lock_held) {
            (void)production_mandatory_finish_slot(&permission);
        }
        return permission.mmap_lock_held ?
            KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE :
            KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
    }
    compare = expected;
    if (production_slot_cas(slot_addr, &compare, replacement, NULL) != 1) {
        observed = compare;
        goto fail_before_write;
    }
    wrote = 1;
    if (production_slot_load(slot_addr, &observed, NULL) != 0 ||
        observed != replacement) {
        goto rollback;
    }
    if (production_mandatory_finish_slot(&permission) == 0) {
        if (final_value) {
            *final_value = replacement;
        }
        return KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED;
    }

rollback:
    compare = replacement;
    if (!wrote ||
        production_slot_cas(slot_addr, &compare, expected, NULL) != 1 ||
        production_slot_load(slot_addr, &observed, NULL) != 0 ||
        observed != expected) {
        if (permission.mmap_lock_held) {
            (void)production_mandatory_finish_slot(&permission);
        }
        if (final_value) {
            *final_value = __atomic_load_n(
                (uintptr_t *)slot_addr, __ATOMIC_ACQUIRE);
        }
        return KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
    }
    if (permission.mmap_lock_held &&
        production_mandatory_finish_slot(&permission) != 0) {
        if (permission.mmap_lock_held) {
            (void)production_mandatory_finish_slot(&permission);
        }
        if (final_value) {
            *final_value = expected;
        }
        return KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
    }
    if (final_value) {
        *final_value = expected;
    }
    return KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK;

fail_before_write:
    if (production_mandatory_finish_slot(&permission) != 0 &&
        permission.mmap_lock_held) {
        (void)production_mandatory_finish_slot(&permission);
    }
    if (final_value) {
        *final_value = observed;
    }
    return permission.mmap_lock_held ?
        KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE :
        KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
}

kzt_production_slot_transaction_result_t
kzt_production_guest_relocation_write(
    box64context_t *context, uintptr_t source_link_map,
    kzt_patch_relocation_type_t reloc_type, uintptr_t slot_addr,
    uintptr_t expected, uintptr_t replacement, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    uintptr_t *final_value)
{
    kzt_guest_registry_t *registry;
    kzt_guest_registry_address_match_t source_match;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_production_slot_transaction_result_t result =
        KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;

    if (final_value) {
        *final_value = expected;
    }
    if (!context || !source_link_map || !slot_addr || !replacement ||
        !symbol_name || !symbol_name[0] ||
        (reloc_type != KZT_PATCH_RELOCATION_GLOB_DAT &&
         reloc_type != KZT_PATCH_RELOCATION_JUMP_SLOT) ||
        !kzt_symbol_version_evidence_valid(version_evidence, version)) {
        return result;
    }
    registry = KztGuestRegistryForContext(context);
    if (!registry ||
        kzt_guest_registry_find_live_object(
            registry, source_link_map, &source_match) != 0 ||
        !source_match.generation ||
        source_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        source_match.namespace_id != 0 ||
        kzt_guest_registry_source_lease_acquire(
            registry, source_link_map, source_match.generation,
            source_match.namespace_id, &source_lease) != 0) {
        return result;
    }
    result = production_mandatory_slot_transaction(
        slot_addr, expected, replacement, final_value);
    kzt_guest_registry_source_lease_release(&source_lease);
    return result;
}

typedef struct kzt_production_eager_write_state {
    const kzt_guest_registry_patch_decision_lease_t *decision_lease;
    uintptr_t expected;
    uintptr_t replacement;
    uintptr_t observed;
    int cas_mismatch;
} kzt_production_eager_write_state_t;

static int production_eager_write_validate(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_production_eager_write_state_t *state = opaque;
    const kzt_guest_registry_patch_decision_lease_t *lease =
        state ? state->decision_lease : NULL;

    return state && decision && lease && lease->active &&
           decision->source.link_map_addr == lease->link_map_addr &&
           decision->source.generation == lease->generation &&
           decision->slot_current_value == state->expected &&
           decision->bridge_target == state->replacement ? 0 : -1;
}

static int production_eager_write_cas(uintptr_t slot_addr, uintptr_t value,
                                      void *opaque)
{
    kzt_production_eager_write_state_t *state = opaque;
    uintptr_t expected;
    int exchanged;

    if (!state || !slot_addr) {
        return -1;
    }
    expected = value == state->replacement ? state->expected :
                                              state->replacement;
    exchanged = __atomic_compare_exchange_n(
        (uintptr_t *)slot_addr, &expected, value, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 1 : 0;
    state->observed = expected;
    state->cas_mismatch = !exchanged;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    return exchanged ? 0 : -1;
}

kzt_production_slot_transaction_result_t
kzt_production_eager_relocation_write(
    box64context_t *context, uintptr_t source_link_map,
    const kzt_patch_object_ref_t *owner,
    kzt_patch_relocation_type_t reloc_type, uintptr_t slot_addr,
    uintptr_t expected, uintptr_t replacement, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    uintptr_t *final_value)
{
    kzt_guest_registry_t *registry;
    kzt_guest_registry_address_match_t source_match;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_guest_registry_patch_decision_lease_t decision_lease = { 0 };
    kzt_patch_object_ref_t current_owner;
    kzt_patch_decision_t decision;
    kzt_patch_spike_record_t record;
    kzt_production_eager_write_state_t state;
    kzt_patch_spike_slot_ops_t slot_ops;
    kzt_production_slot_transaction_result_t result =
        KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;

    if (final_value) {
        *final_value = expected;
    }
    if (!context || !source_link_map || !slot_addr || !replacement ||
        !symbol_name || !symbol_name[0] ||
        (reloc_type != KZT_PATCH_RELOCATION_GLOB_DAT &&
         reloc_type != KZT_PATCH_RELOCATION_JUMP_SLOT) ||
        !kzt_symbol_version_evidence_valid(version_evidence, version)) {
        return result;
    }
    registry = KztGuestRegistryForContext(context);
    if (!registry ||
        kzt_guest_registry_find_live_object(
            registry, source_link_map, &source_match) != 0 ||
        !source_match.generation ||
        source_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        source_match.namespace_id != 0 ||
        kzt_guest_registry_source_lease_acquire(
            registry, source_link_map, source_match.generation,
            source_match.namespace_id, &source_lease) != 0 ||
        kzt_guest_registry_patch_decision_lease_acquire(
            &source_lease, &decision_lease) != 0) {
        kzt_guest_registry_source_lease_release(&source_lease);
        return result;
    }
    current_owner = owner && owner->known && owner->link_map_addr &&
                            owner->generation ? *owner :
        (kzt_patch_object_ref_t) {
            .known = 1,
            .link_map_addr = source_lease.link_map_addr,
            .generation = source_lease.generation,
        };
    decision = (kzt_patch_decision_t) {
        .kind = KZT_PATCH_DECISION_APPROVED,
        .reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
        .allow_native_bridge = 1,
        .source = {
            .known = 1,
            .link_map_addr = source_lease.link_map_addr,
            .generation = source_lease.generation,
        },
        .dynamic_view_generation = source_lease.generation,
        .dynamic_view_available = 1,
        .table_kind = reloc_type == KZT_PATCH_RELOCATION_JUMP_SLOT ?
            KZT_PATCH_TABLE_PLT_RELA : KZT_PATCH_TABLE_RELA,
        .reloc_type = reloc_type,
        .slot_addr = slot_addr,
        .slot_current_value_present = 1,
        .slot_current_value = expected,
        .symbol_name = symbol_name,
        .version_evidence = version_evidence,
        .version = version,
        .current_owner = current_owner,
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .bridge_target = replacement,
    };
    state = (kzt_production_eager_write_state_t) {
        .decision_lease = &decision_lease,
        .expected = expected,
        .replacement = replacement,
        .observed = expected,
    };
    slot_ops = (kzt_patch_spike_slot_ops_t) {
        .read_slot = production_slot_load,
        .write_slot = production_eager_write_cas,
        .begin_write = production_slot_begin_write,
        .end_write = production_slot_end_write,
        .validate_generation = production_eager_write_validate,
        .opaque = &state,
    };
    if (kzt_patch_spike_writer_try_apply_with_slot_ops(
            KztPatchSpikeGuardForContext(context), &decision,
            &slot_ops, &record) == 0) {
        if (record.result == KZT_PATCH_SPIKE_RESULT_APPLIED) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED;
        } else if (record.result == KZT_PATCH_SPIKE_RESULT_ROLLED_BACK) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK;
        } else if (record.result == KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
        } else if (record.result == KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_CIRCUIT_OPEN;
        } else if (state.cas_mismatch) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
        }
    }
    if (final_value) {
        *final_value = __atomic_load_n(
            (uintptr_t *)slot_addr, __ATOMIC_ACQUIRE);
    }
    kzt_guest_registry_patch_decision_lease_release(&decision_lease);
    kzt_guest_registry_source_lease_release(&source_lease);
    return result;
}

typedef struct kzt_production_prebind_write_state {
    const kzt_lazy_prebind_lease_t *lease;
    uintptr_t expected;
    uintptr_t replacement;
    uintptr_t observed;
    int cas_mismatch;
} kzt_production_prebind_write_state_t;

static int production_lazy_prebind_guard_validate(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_production_prebind_write_state_t *state = opaque;
    const kzt_lazy_prebind_lease_t *lease = state ? state->lease : NULL;
    const kzt_lazy_prebind_record_t *record = lease ? &lease->record : NULL;

    if (!state || !decision || !lease || !lease->active || !record ||
        (lease->operation != KZT_LAZY_PREBIND_LEASE_PUBLISH &&
         lease->operation != KZT_LAZY_PREBIND_LEASE_REVOKE) ||
        decision->source.link_map_addr != record->source.link_map_addr ||
        decision->source.generation != record->source.generation ||
        decision->slot_addr != record->slot_addr ||
        decision->slot_current_value != state->expected ||
        decision->bridge_target != state->replacement) {
        return -1;
    }
    return lease->operation == KZT_LAZY_PREBIND_LEASE_REVOKE ||
           kzt_lazy_prebind_scope_lease_valid(lease) ? 0 : -1;
}

static int production_lazy_prebind_guard_write(
    uintptr_t slot_addr, uintptr_t value, void *opaque)
{
    kzt_production_prebind_write_state_t *state = opaque;
    uintptr_t expected;
    int exchanged;

    if (!state || !slot_addr || !value) {
        return -1;
    }
    expected = value == state->replacement ? state->expected :
                                              state->replacement;
    exchanged = __atomic_compare_exchange_n(
        (uintptr_t *)slot_addr, &expected, value, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 1 : 0;
    state->observed = expected;
    state->cas_mismatch = !exchanged;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    return exchanged ? 0 : -1;
}

static kzt_production_slot_transaction_result_t
production_lazy_prebind_slot_cas(
    box64context_t *context, const kzt_lazy_prebind_lease_t *lease,
    uintptr_t expected, uintptr_t replacement, uintptr_t *observed)
{
    const kzt_lazy_prebind_record_t *record = lease ? &lease->record : NULL;
    const kzt_lazy_prebind_identity_t *owner_identity;
    kzt_patch_decision_t decision;
    kzt_patch_spike_record_t writer_record;
    kzt_production_prebind_write_state_t state;
    kzt_patch_spike_slot_ops_t slot_ops;
    kzt_production_slot_transaction_result_t result =
        KZT_PRODUCTION_SLOT_TRANSACTION_ERROR;

    if (observed) {
        *observed = expected;
    }
    if (!context || !lease || !lease->active || !record ||
        !record->source.link_map_addr || !record->source.generation ||
        !record->slot_addr || !expected || !replacement ||
        !record->symbol[0]) {
        return result;
    }
    owner_identity = replacement == record->bridge_target ?
        &record->provider : &record->source;
    decision = (kzt_patch_decision_t) {
        .kind = KZT_PATCH_DECISION_APPROVED,
        .reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
        .allow_native_bridge = 1,
        .source = {
            .known = 1,
            .link_map_addr = record->source.link_map_addr,
            .generation = record->source.generation,
        },
        .dynamic_view_generation = record->source.generation,
        .dynamic_view_available = 1,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = record->relocation_index,
        .reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT,
        .slot_addr = record->slot_addr,
        .slot_current_value_present = 1,
        .slot_current_value = expected,
        .symbol_name = record->symbol,
        .version_evidence = record->version_evidence,
        .version = record->version[0] ? record->version : NULL,
        .current_owner = {
            .known = 1,
            .link_map_addr = owner_identity->link_map_addr,
            .generation = owner_identity->generation,
        },
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .bridge_target = replacement,
    };
    state = (kzt_production_prebind_write_state_t) {
        .lease = lease,
        .expected = expected,
        .replacement = replacement,
        .observed = expected,
    };
    slot_ops = (kzt_patch_spike_slot_ops_t) {
        .read_slot = production_slot_load,
        .write_slot = production_lazy_prebind_guard_write,
        .begin_write = production_slot_begin_write,
        .end_write = production_slot_end_write,
        .validate_generation = production_lazy_prebind_guard_validate,
        .opaque = &state,
    };
    if (kzt_patch_spike_writer_try_apply_with_slot_ops(
            KztPatchSpikeGuardForContext(context), &decision,
            &slot_ops, &writer_record) == 0) {
        if (writer_record.result == KZT_PATCH_SPIKE_RESULT_APPLIED) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED;
        } else if (writer_record.result ==
                   KZT_PATCH_SPIKE_RESULT_ROLLED_BACK) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK;
        } else if (writer_record.result ==
                   KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_UNRECOVERABLE;
        } else if (writer_record.result ==
                   KZT_PATCH_SPIKE_RESULT_CIRCUIT_OPEN) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_CIRCUIT_OPEN;
        } else if (state.cas_mismatch) {
            result = KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
        }
    }
    if (observed) {
        *observed = __atomic_load_n(
            (uintptr_t *)record->slot_addr, __ATOMIC_ACQUIRE);
    }
    return result;
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
        !production_exact_provider_handle_matches(state) ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie ||
        (state->wrapper_alias_borrowed &&
         (!state->alias_proof.valid ||
          !kzt_guest_library_wrapper_alias_symbol_allowed(
              decision->symbol_name))) ||
        (state->wrapper_alias_borrowed &&
         !production_wrapper_alias_provider_matches(
             state, &state->exact_provider_owner)) ||
        (!state->wrapper_alias_borrowed &&
         (state->exact_provider_key.link_map_addr !=
              decision->current_owner.link_map_addr ||
          state->exact_provider_key.generation !=
              decision->current_owner.generation ||
          state->exact_provider_key.namespace_id != state->owner_namespace_id ||
          state->exact_provider_key.namespace_kind !=
              KZT_GUEST_LIBRARY_NAMESPACE_MAIN)) ||
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
    if (state->exact_owner_symbol_proof) {
        if (!production_exact_owner_symbol_matches(
                state, &decision->current_owner,
                decision->slot_current_value,
                state->initial_request.symbol_name,
                state->initial_request.version_evidence,
                state->initial_request.version)) {
            goto out;
        }
    } else {
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
           decision->symbol_index == prevalidated->symbol_index &&
           decision->symbol_name && prevalidated->symbol_name &&
           strcmp(decision->symbol_name, prevalidated->symbol_name) == 0 &&
           kzt_symbol_version_evidence_matches(
               decision->version_evidence, decision->version,
               prevalidated->version_evidence, prevalidated->version) &&
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
        !state->held_source_lease || !state->held_source_lease->active ||
        !state->held_decision_lease || !state->held_decision_lease->active ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie ||
        !production_exact_provider_handle_matches(state) ||
        (state->wrapper_alias_borrowed &&
         (!state->alias_proof.valid ||
          !kzt_guest_library_wrapper_alias_symbol_allowed(
              decision->symbol_name))) ||
        (!state->wrapper_alias_borrowed &&
         (state->exact_provider_key.link_map_addr !=
              decision->current_owner.link_map_addr ||
          state->exact_provider_key.generation !=
              decision->current_owner.generation ||
          state->exact_provider_key.namespace_id != state->owner_namespace_id ||
          state->exact_provider_key.namespace_kind !=
              KZT_GUEST_LIBRARY_NAMESPACE_MAIN)) ||
        !production_decision_matches_prevalidated(
            decision, &state->prevalidated_decision) ||
        __atomic_load_n((uintptr_t *)decision->slot_addr,
                        __ATOMIC_ACQUIRE) != decision->slot_current_value) {
        return -1;
    }
    if (state->wrapper_alias_borrowed &&
        !production_wrapper_alias_provider_matches(
            state, &decision->current_owner)) {
        return -1;
    }
    if (state->exact_owner_symbol_proof) {
        if (!production_exact_owner_symbol_matches(
                state, &decision->current_owner,
                decision->slot_current_value, decision->symbol_name,
                decision->version_evidence, decision->version)) {
            return -1;
        }
    } else if (kzt_guest_symbol_scope_revalidate(
                   &state->symbol_scope_proof, &state->symbol_scope_request,
                   &reader_ops, &revalidated) !=
               KZT_GUEST_SYMBOL_SCOPE_SAFE) {
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
    int status;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_full_enrich();
#endif
    status = kzt_rela_immediate_request_enrich(
        request, &enrich_input, enrich_result);
    return status;
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
    kzt_wrapper_bridge_provider_t wrapper_provider;
    kzt_wrapper_probe_result_t wrapper_probe;
    kzt_guest_symbol_scope_request_t symbol_scope_request;
    kzt_guest_symbol_scope_result_t preemption_proof;
    kzt_production_jump_slot_state_t evidence;
    kzt_lazy_direct_timing_t *timing;
    int timing_enabled;
    int prebind_hit;
    int exact_symbol_provider;
    const kzt_lazy_direct_route_input_t *guard_input;
    const kzt_lazy_direct_route_provider_t *guard_provider;
    const kzt_lazy_direct_route_bridge_t *guard_bridge;
    const kzt_lazy_direct_route_lease_t *guard_lease;
    uintptr_t guard_expected;
    uintptr_t guard_replacement;
    int guard_cas_mismatch;
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
        context, &lease, record->expected_slot,
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

static size_t production_lazy_prebind_find_symbol_index(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    const kzt_patch_object_ref_t *source,
    unsigned long dynamic_view_generation,
    size_t relocation_count, const char *symbol_name)
{
    size_t index;

    if (!view || !reader_ops || !source || !dynamic_view_generation ||
        !symbol_name || !symbol_name[0]) {
        return relocation_count;
    }
    for (index = 0; index < relocation_count; ++index) {
        kzt_patch_candidate_t candidate = { 0 };
        char candidate_strings[512] = { 0 };
        kzt_runtime_got_plt_candidate_result_t result;
        kzt_runtime_got_plt_candidate_request_t request = {
            .view = view,
            .reader_ops = reader_ops,
            .source = source,
            .dynamic_view_generation = dynamic_view_generation,
            .only_entry = 1,
            .only_table_kind = KZT_PATCH_TABLE_PLT_RELA,
            .only_entry_index = index,
            .candidates = &candidate,
            .candidate_capacity = 1,
            .string_storage = candidate_strings,
            .string_storage_size = sizeof(candidate_strings),
        };

        if (kzt_runtime_got_plt_candidates_collect(&request, &result) == 0 &&
            result.status == KZT_RUNTIME_GOT_PLT_CANDIDATE_OK &&
            result.candidate_count == 1 && candidate.symbol_name &&
            strcmp(candidate.symbol_name, symbol_name) == 0) {
            return index;
        }
    }
    return relocation_count;
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
    size_t iteration;
    size_t dlerror_index;
    size_t prepared = 0;
    int source_dlerror_native = 0;
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
    dlerror_index = production_lazy_prebind_find_symbol_index(
        source_dynamic_view, &reader_ops, &source_ref, source_generation,
        relocation_count, "dlerror");
    for (iteration = 0; iteration < relocation_count; ++iteration) {
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
        int provider_status;
        int published;

        if (dlerror_index < relocation_count) {
            if (iteration == 0) {
                index = dlerror_index;
            } else {
                index = iteration - 1;
                if (index >= dlerror_index) {
                    ++index;
                }
            }
        } else {
            index = iteration;
        }

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
            (kzt_patch_symbol_requires_dlerror_prebind(
                 candidate.symbol_name) &&
             !source_dlerror_native) ||
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
            provider_handle.object_type != KZT_GUEST_LIBRARY_OBJECT_WRAPPED) {
            kzt_guest_library_handle_release(&provider_handle);
            continue;
        }
        if (production_symbol_uses_guarded_xcb_bridge(
                candidate.symbol_name)) {
            provider_status =
                kzt_rela_runtime_wrapper_provider_discover_guarded_retained_with_version_evidence(
                    context, &provider_handle, candidate.symbol_name,
                    candidate.version_evidence, candidate.version,
                    scope_proof.selected_provider_address,
                    KZT_BRIDGE_GUARD_XCB_CONNECTION, &wrapper_provider);
        } else {
            provider_status =
                kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
                    context, &provider_handle, candidate.symbol_name,
                    candidate.version_evidence, candidate.version,
                    &wrapper_provider);
        }
        if (provider_status <= 0) {
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
        record.loader_mutation_invariant =
            record.bridge_custom_wrapper &&
            kzt_patch_symbol_is_loader_route_family(record.symbol) &&
            record.source.link_map_addr == namespace_head;
        record.scope_proof = scope_proof;
        kzt_lazy_prebind_claim_result_t claim =
            kzt_lazy_prebind_scope_claim(scope, &record);

        if (claim == KZT_LAZY_PREBIND_CLAIM_CREATED) {
            ++prepared;
        }
        if (claim == KZT_LAZY_PREBIND_CLAIM_CREATED ||
            claim == KZT_LAZY_PREBIND_CLAIM_REUSED) {
            published = production_lazy_prebind_publish_record(
                context, scope, &record, target_prepare,
                target_prepare_opaque);
            if (strcmp(record.symbol, "dlerror") == 0 &&
                (published ||
                 __atomic_load_n(
                     (uintptr_t *)record.slot_addr, __ATOMIC_ACQUIRE) ==
                     record.bridge_target)) {
                source_dlerror_native = 1;
            }
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
        writer_result = production_mandatory_slot_transaction(
            record.slot_addr, record.bridge_target,
            record.expected_slot, &observed);
        revoked =
            writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED ||
            (writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH &&
             observed != record.bridge_target);
        kzt_lazy_prebind_scope_revoke_finish(&lease, revoked);
        printf_kzt_registry_diagnostics(
            "kzt_lazy_prebind_revoke schema=1 source=%p generation=%lu "
            "provider=%p provider_generation=%lu slot=%p bridge=%p stub=%p "
            "result=%s writer=%s observed=%p\n",
            (void *)record.source.link_map_addr, record.source.generation,
            (void *)record.provider.link_map_addr,
            record.provider.generation,
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

    if (!context || !identity) {
        return -1;
    }
    if (!(scope = KztLazyPrebindScopeForContext(context)) ||
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
        state->evidence.retained_provider_handle != &state->provider_handle ||
        !production_exact_provider_handle_matches(&state->evidence) ||
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
        state->evidence.wrapper_provider = state->wrapper_provider;
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
            .transient_safe = record->bridge_custom_wrapper,
        };
        if (!production_custom_dlsym_boundary_proven(
                &state->evidence, input->symbol)) {
            return -1;
        }
        if (state->timing_enabled) {
            state->timing->bridge_discover_done =
                production_lazy_direct_timing_now();
            state->timing->bridge_done =
                state->timing->bridge_discover_done;
        }
        return 0;
    }
    memset(&state->wrapper_provider, 0, sizeof(state->wrapper_provider));
    if (production_symbol_uses_guarded_xcb_bridge(input->symbol)) {
        status =
            kzt_rela_runtime_wrapper_provider_discover_guarded_retained_with_version_evidence(
                state->context, &state->provider_handle, input->symbol,
                input->version_evidence, input->version,
                state->preemption_proof.selected_provider_address,
                KZT_BRIDGE_GUARD_XCB_CONNECTION,
                &state->wrapper_provider);
    } else {
        status =
            kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
                state->context, &state->provider_handle, input->symbol,
                input->version_evidence, input->version,
                &state->wrapper_provider);
    }
    if (status <= 0) {
        return -1;
    }
    state->evidence.wrapper_provider = state->wrapper_provider;
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
    if (!production_custom_dlsym_boundary_proven(
            &state->evidence, input->symbol)) {
        return -1;
    }
    *bridge = (kzt_lazy_direct_route_bridge_t) {
        .target = state->wrapper_probe.bridge_target,
        .version_evidence = state->wrapper_probe.wrapper_version_evidence,
        .version = state->wrapper_probe.wrapper_symbol_version,
        .transient_safe = state->wrapper_provider.match.custom_wrapper,
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
        provider->handle != &state->provider_handle) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_before_patch_decision_lease_acquire();
#endif
    if (!state->decision_lease.active &&
        kzt_guest_registry_patch_decision_lease_acquire(
            &state->source_lease, &state->decision_lease) != 0) {
        return -1;
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_patch_decision_lease_acquire();
#endif
    state->evidence.held_decision_lease = &state->decision_lease;
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
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
        kzt_jump_slot_production_test_before_patch_decision_lease_release();
#endif
        kzt_guest_registry_patch_decision_lease_release(
            &state->decision_lease);
        state->evidence.held_decision_lease = NULL;
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
    uintptr_t slot_value = 0;
    int valid = 0;

    if (state) {
        state->guard_input = input;
        state->guard_provider = provider;
        state->guard_bridge = bridge;
        state->guard_lease = lease;
    }
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
        state->evidence.retained_provider_handle != &state->provider_handle ||
        !production_exact_provider_handle_matches(&state->evidence) ||
        state->evidence.loader_quiescence_lease.bindings !=
            state->provider_handle.bindings ||
        !state->evidence.loader_quiescence_lease.cookie ||
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
            input->source_dynamic_view) != 0) {
        goto out;
    }
    if (state->exact_symbol_provider) {
        const kzt_patch_object_ref_t *owner =
            &state->evidence.base_enrich_result.owner_resolution.current_owner;

        if (!kzt_loader_lifecycle_runtime_healthy(state->context) ||
            (state->evidence.wrapper_alias_borrowed
                 ? (!kzt_guest_library_wrapper_alias_symbol_allowed(
                        input->symbol) ||
                    !production_wrapper_alias_provider_matches(
                        &state->evidence, owner))
                 : (state->provider_key.link_map_addr !=
                        owner->link_map_addr ||
                    state->provider_key.generation != owner->generation)) ||
            !production_exact_owner_symbol_matches(
                &state->evidence, owner,
                state->preemption_proof.selected_provider_address,
                input->symbol, input->version_evidence, input->version)) {
            goto out;
        }
    } else if (kzt_guest_symbol_scope_revalidate(
                   &state->preemption_proof, &state->symbol_scope_request,
                   &reader_ops, &revalidated) !=
               KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        goto out;
    }
    valid = production_slot_load(input->slot_addr, &slot_value, state) == 0 &&
            slot_value == input->expected_current_slot;
out:
    if (state && state->timing_enabled) {
        state->timing->final_done = production_lazy_direct_timing_now();
    }
    return valid;
}

static int production_lazy_direct_guard_validate(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;

    if (!state || !decision || !state->guard_input ||
        !state->guard_provider || !state->guard_bridge ||
        !state->guard_lease ||
        decision->source.link_map_addr !=
            state->guard_input->source.link_map_addr ||
        decision->source.generation !=
            state->guard_input->source.generation ||
        decision->slot_addr != state->guard_input->slot_addr ||
        decision->slot_current_value != state->guard_expected ||
        decision->bridge_target != state->guard_replacement ||
        !decision->symbol_name || !state->guard_input->symbol ||
        strcmp(decision->symbol_name, state->guard_input->symbol) != 0) {
        return -1;
    }
    return production_lazy_direct_validate_final(
               state->guard_input, state->guard_provider,
               state->guard_bridge, state->guard_lease, state) > 0 ? 0 : -1;
}

static int production_lazy_direct_guard_write(uintptr_t slot_addr,
                                               uintptr_t value,
                                               void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    uintptr_t expected;
    int exchanged;

    if (!state || !slot_addr || !value) {
        return -1;
    }
    expected = value == state->guard_replacement ? state->guard_expected :
                                                   state->guard_replacement;
    if (value == state->guard_replacement &&
        state->wrapper_provider.match.custom_wrapper &&
        strcmp(state->evidence.runtime_candidate.symbol_name,
               "dlerror") == 0 &&
        kzt_guest_dl_api_publish_dlerror_entry(
            state->context->dlprivate,
            state->evidence.runtime_candidate.symbol_name,
            state->preemption_proof.selected_provider_address,
            state->wrapper_provider.match.custom_wrapper) != 0) {
        return -1;
    }
    exchanged = __atomic_compare_exchange_n(
        (uintptr_t *)slot_addr, &expected, value, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    state->guard_cas_mismatch = !exchanged;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_jump_slot_production_test_after_slot_cas(exchanged);
#endif
    return exchanged ? 0 : -1;
}

static kzt_lazy_direct_route_cas_status_t
production_lazy_direct_cas_slot(
    uintptr_t slot_addr, uintptr_t expected, uintptr_t replacement,
    const kzt_lazy_direct_route_lease_t *lease, void *opaque)
{
    kzt_lazy_direct_production_state_t *state = opaque;
    kzt_patch_decision_t decision = { 0 };
    kzt_patch_spike_record_t record;
    kzt_patch_spike_slot_ops_t slot_ops = {
        .read_slot = production_slot_load,
        .write_slot = production_lazy_direct_guard_write,
        .begin_write = production_slot_begin_write,
        .end_write = production_slot_end_write,
        .validate_generation = production_lazy_direct_guard_validate,
        .opaque = state,
    };

    if (!state || !lease || !lease->active ||
        lease->handle != &state->decision_lease ||
        !state->decision_lease.active || !state->guard_input ||
        !state->guard_provider || !state->guard_bridge ||
        !slot_addr || !replacement) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    }
    state->guard_lease = lease;
    state->guard_expected = expected;
    state->guard_replacement = replacement;
    state->guard_cas_mismatch = 0;
    decision = (kzt_patch_decision_t) {
        .kind = KZT_PATCH_DECISION_APPROVED,
        .reason = KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
        .allow_native_bridge = 1,
        .source = {
            .known = 1,
            .link_map_addr = state->guard_input->source.link_map_addr,
            .generation = state->guard_input->source.generation,
        },
        .dynamic_view_generation =
            state->guard_input->source_dynamic_view_generation,
        .dynamic_view_available = 1,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT,
        .slot_addr = slot_addr,
        .slot_current_value_present = 1,
        .slot_current_value = expected,
        .symbol_name = state->guard_input->symbol,
        .version_evidence = state->guard_input->version_evidence,
        .version = state->guard_input->version,
        .current_owner = state->evidence.exact_provider_owner,
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .wrapper_match = state->wrapper_probe.wrapper_match,
        .wrapper_name = state->wrapper_provider.entry.wrapper_name ?
                            state->wrapper_provider.entry.wrapper_name :
                            state->resolved_provider->name,
        .wrapper_version_evidence =
            state->wrapper_probe.wrapper_version_evidence,
        .wrapper_symbol_version =
            state->wrapper_probe.wrapper_symbol_version,
        .bridge_target = replacement,
    };
    if (kzt_patch_spike_writer_try_apply_with_slot_ops(
            KztPatchSpikeGuardForContext(state->context), &decision,
            &slot_ops, &record) != 0) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
    }
    if (state->timing_enabled) {
        state->timing->cas_done = production_lazy_direct_timing_now();
    }
    if (record.result == KZT_PATCH_SPIKE_RESULT_APPLIED) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED;
    }
    if (record.result == KZT_PATCH_SPIKE_RESULT_BUDGET_EXHAUSTED) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_BUDGET_EXHAUSTED;
    }
    if (record.result == KZT_PATCH_SPIKE_RESULT_ROLLED_BACK) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_ROLLED_BACK;
    }
    if (record.result == KZT_PATCH_SPIKE_RESULT_UNRECOVERABLE) {
        return KZT_LAZY_DIRECT_ROUTE_CAS_UNRECOVERABLE;
    }
    return state->guard_cas_mismatch ? KZT_LAZY_DIRECT_ROUTE_CAS_MISMATCH :
                                      KZT_LAZY_DIRECT_ROUTE_CAS_ERROR;
}

static int production_enrich_base(
    kzt_rela_immediate_candidate_request_t *request, void *opaque)
{
    kzt_production_jump_slot_state_t *state = opaque;
    kzt_patch_object_ref_t address_owner = { 0 };
    int exact_symbol_scan_required;
    int status;

    state->failure_stage = "BASE_EVIDENCE";
    status = production_enrich(request, NULL, &state->base_enrich_result,
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
    if (status == 0 && (!state->held_source_lease ||
                        !state->held_source_lease->active)) {
        status = -1;
    }
    if (status == 0 && !state->held_decision_lease) {
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
        kzt_jump_slot_production_test_before_patch_decision_lease_acquire();
#endif
        status = kzt_guest_registry_patch_decision_lease_acquire(
            state->held_source_lease, &state->decision_lease);
        if (status == 0) {
            state->held_decision_lease = &state->decision_lease;
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
            kzt_jump_slot_production_test_after_patch_decision_lease_acquire();
#endif
        }
    }
    if (status == 0 &&
        kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(state->context),
            &state->loader_quiescence_lease) != 0) {
        status = -1;
    }
    if (status == 0) {
        kzt_guest_dynamic_view_t current_view;
        kzt_guest_field_status_t current_status;
        unsigned long current_generation = 0;

        if (kzt_guest_registry_find_dynamic_view(
                KztGuestRegistryForContext(state->context),
                request->source.link_map_addr, &current_view,
                &current_status, &current_generation) != 0 ||
            current_status != KZT_GUEST_FIELD_OK ||
            current_generation != request->dynamic_view_generation ||
            current_view.dynamic_addr != request->dynamic_addr ||
            current_view.load_bias != request->load_bias) {
            status = -1;
        }
    }
    if (status == 0) {
        status = production_collect_runtime_candidate(state, request);
    }
    exact_symbol_scan_required =
        status == 0 &&
        (state->context->kzt_guest_scope_layout ==
             KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED ||
         (state->lazy_completion &&
          (request->owner_match != KZT_PATCH_OWNER_MATCH ||
           !request->current_owner.known)));
    if (exact_symbol_scan_required) {
        address_owner = request->current_owner;
        if ((state->lazy_completion &&
             request->slot_current_value !=
                 request->expected_guest_target) ||
            production_resolve_exact_symbol_owner(
                state, request->slot_current_value, request->symbol_name,
                request->version_evidence, request->version,
                NULL,
                &state->base_enrich_result.owner_resolution, NULL) != 0) {
            status = -1;
        } else {
            request->current_owner =
                state->base_enrich_result.owner_resolution.current_owner;
            request->owner_match =
                state->base_enrich_result.owner_resolution.owner_match;
            state->base_enrich_result.owner_present =
                request->current_owner.known;
            if (address_owner.known &&
                (address_owner.link_map_addr !=
                     request->current_owner.link_map_addr ||
                 address_owner.generation !=
                     request->current_owner.generation)) {
                status = -1;
            }
        }
    }
    if (status == 0 &&
        (request->owner_match != KZT_PATCH_OWNER_MATCH ||
         !request->current_owner.known)) {
        status = -1;
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
        if (production_acquire_wrapper_alias_provider(
                state, owner, handle) != 0) {
            goto out;
        }
        state->wrapper_alias_borrowed = 1;
        key = state->alias_proof.provider_key;
    }
    if ((state->wrapper_alias_borrowed &&
         (!state->alias_proof.valid ||
          !kzt_guest_library_wrapper_alias_symbol_allowed(
              state->last_request.symbol_name))) ||
        !handle->library ||
        (resolved_provider && handle->library != resolved_provider)) {
        kzt_guest_library_handle_release(handle);
        goto out;
    }
    state->resolved_provider = handle->library;
    state->retained_provider_handle = handle;
    state->exact_provider_key = key;
    state->exact_provider_bindings = handle->bindings;
    state->exact_provider_entry = handle->entry;
    state->exact_provider_library = handle->library;
    state->exact_provider_owner = *owner;
    state->owner_namespace_id = match.namespace_id;
    if (!production_exact_provider_handle_matches(state)) {
        state->retained_provider_handle = NULL;
        kzt_guest_library_handle_release(handle);
        goto out;
    }
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
    if (!state->held_decision_lease ||
        !state->held_decision_lease->active ||
        !state->loader_quiescence_lease.bindings ||
        !state->loader_quiescence_lease.cookie) {
        return -1;
    }
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
    if (state->exact_owner_without_map_range) {
        owner_resolution = state->base_enrich_result.owner_resolution;
        if (fresh_value != request->expected_guest_target ||
            owner_resolution.status != KZT_OWNER_RESOLVER_RESOLVED ||
            owner_resolution.owner_match != KZT_PATCH_OWNER_MATCH ||
            !owner_resolution.current_owner.known) {
            production_release_decision_lease(state);
            return -1;
        }
    } else if (production_resolve_current_owner(
                   state->context, fresh_value,
                   request->expected_guest_target, request->symbol_name,
                   request->version_evidence, request->version,
                   &owner_resolution) != 0) {
        production_release_decision_lease(state);
        return -1;
    }
    request->current_owner = owner_resolution.current_owner;
    request->owner_match = owner_resolution.owner_match;
    if (!state->runtime_view_valid) {
        production_release_decision_lease(state);
        return -1;
    }
    if (state->context->kzt_guest_scope_layout ==
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED) {
        if (!state->owner_source_lease.active &&
            kzt_guest_registry_source_lease_acquire(
                KztGuestRegistryForContext(state->context),
                owner_resolution.current_owner.link_map_addr,
                owner_resolution.current_owner.generation, 0,
                &state->owner_source_lease) != 0) {
            production_release_decision_lease(state);
            return -1;
        }
        if (!production_exact_owner_symbol_matches(
                state, &owner_resolution.current_owner, fresh_value,
                request->symbol_name, request->version_evidence,
                request->version)) {
            production_release_decision_lease(state);
            return -1;
        }
        state->exact_owner_symbol_proof = 1;
    } else if (
        kzt_guest_registry_context_get_main_namespace_head(
            &state->context->kzt_guest_registry_context,
            &namespace_head) != 0 ||
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
    decision.symbol_index = request->symbol_index;
    decision.symbol_name = request->symbol_name;
    decision.version_evidence = request->version_evidence;
    decision.version = request->version;
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

    if (!request ||
        kzt_patch_symbol_must_stay_guest(request->symbol_name)) {
        return -1;
    }
    if (production_acquire_and_validate_bridge_evidence(state, request) != 0) {
        return -1;
    }

    state->failure_stage = "BRIDGE_EVIDENCE";
    memset(&state->wrapper_provider, 0, sizeof(state->wrapper_provider));
    if (production_symbol_uses_guarded_xcb_bridge(request->symbol_name)) {
        status =
            kzt_rela_runtime_wrapper_provider_discover_guarded_with_version_evidence(
                state->context, held_provider, request->symbol_name,
                request->version_evidence, request->version,
                request->slot_current_value,
                KZT_BRIDGE_GUARD_XCB_CONNECTION,
                &state->wrapper_provider);
    } else {
        status =
            kzt_rela_runtime_wrapper_provider_discover_with_version_evidence(
                state->context, held_provider, request->symbol_name,
                request->version_evidence, request->version,
                &state->wrapper_provider);
    }
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
    if (!production_custom_dlsym_boundary_proven(
            state, request->symbol_name)) {
        production_release_decision_lease(state);
        return -1;
    }
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
    if (state->writer_result.record.result ==
        KZT_PATCH_SPIKE_RESULT_APPLIED) {
        return KZT_JUMP_SLOT_ROUTE_WRITER_APPLIED;
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
        kzt_guest_registry_source_lease_release(
            &state.owner_source_lease);
        kzt_guest_registry_source_lease_release(&state.source_lease);
        return -1;
    }
    production_emit_diagnostic(&state, route_result);
    kzt_guest_library_loader_quiescence_release(
        &state.loader_quiescence_lease);
    kzt_guest_registry_source_lease_release(
        &state.owner_source_lease);
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
    int scope_supported;
    int loader_route_family;
    int loader_write_enabled;

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
    loader_route_family =
        kzt_patch_symbol_is_loader_route_family(symbol_name);
    loader_write_enabled = loader_route_family &&
        KztPatchSpikeGuardForContext(context) &&
        KztPatchSpikeGuardForContext(context)->config.write_enabled;
    if (!kzt_patch_spike_guard_should_plan(
            KztPatchSpikeGuardForContext(context))) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_DISABLED;
        return 0;
    }

    memset(&state, 0, sizeof(state));
    state.preemption_proof.status = KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    timing_enabled = unlikely(option_kzt_lazy_diagnostics);
    if (timing_enabled) {
        timing.start = production_lazy_direct_timing_now();
    }
    state.context = context;
    state.registry = KztGuestRegistryForContext(context);
    state.timing = &timing;
    state.timing_enabled = timing_enabled;
    state.evidence.context = context;
    state.evidence.head = head;
    state.evidence.slot_current_value_is_unresolved_stub = 1;
    scope_supported = context->kzt_guest_scope_layout !=
                      KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    if (!scope_supported &&
        head->DynSym[symbol_index].st_shndx != SHN_UNDEF) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_UNSUPPORTED_SYMBOL_BINDING;
        return 0;
    }
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
    state.evidence.held_source_lease = &state.source_lease;
    if (timing_enabled) {
        timing.source = production_lazy_direct_timing_now();
    }
    if (scope_supported &&
        kzt_guest_registry_context_get_main_namespace_head(
            &context->kzt_guest_registry_context, &namespace_head) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        goto done;
    }

    state.prebind_scope = KztLazyPrebindScopeForContext(context);
    if (kzt_patch_symbol_requires_dlerror_prebind(symbol_name) &&
        !kzt_lazy_prebind_scope_has_native_dlerror(
            state.prebind_scope,
            &(const kzt_lazy_prebind_identity_t) {
                .link_map_addr = head->self_link_map,
                .generation = source.generation,
                .namespace_id = source.namespace_id,
            })) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_DLERROR_PREBIND_REQUIRED;
        goto done;
    }
    if (scope_supported && production_lazy_prebind_record_key(
            &prebind_key, head->self_link_map, source.generation,
            entry_index, (uintptr_t)slot, slot_current_value, symbol_name,
            version_evidence, version) == 0 &&
        kzt_lazy_prebind_scope_acquire(
            state.prebind_scope, &prebind_key, &state.prebind_lease) == 0) {
        cached_view_status = KZT_GUEST_FIELD_NOT_PARSED;
        cached_view_generation = 0;
        if (kzt_lazy_prebind_scope_lease_published(
                &state.prebind_lease) &&
            kzt_guest_registry_find_dynamic_view(
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
    state.evidence.last_request.symbol_index = symbol_index;
    state.evidence.last_request.source = (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = head->self_link_map,
        .generation = source.generation,
        .map_start = (uintptr_t)head->memory,
        .map_end = (uintptr_t)head->memory + head->memsz,
        .soname = head->name,
        .path = head->path,
    };
    state.evidence.last_request.symbol_name =
        state.evidence.runtime_candidate.symbol_name;
    state.evidence.last_request.version_evidence =
        state.evidence.runtime_candidate.version_evidence;
    state.evidence.last_request.version =
        state.evidence.runtime_candidate.version;
    state.evidence.initial_request = state.evidence.last_request;
    if (!state.evidence.runtime_view_valid ||
        (scope_supported && production_symbol_scope_request(
            context, head, source.generation, namespace_head,
            &state.evidence.runtime_view, &reader_ops, symbol_index,
            state.evidence.runtime_candidate.symbol_name,
            state.evidence.runtime_candidate.version_evidence,
            state.evidence.runtime_candidate.version,
            &state.symbol_scope_request) != 0)) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        goto done;
    }
    if (timing_enabled) {
        timing.candidate = production_lazy_direct_timing_now();
    }
    quiescence_status = kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(context),
            &state.evidence.loader_quiescence_lease);
    if (timing_enabled) {
        timing.quiescence = production_lazy_direct_timing_now();
    }
    if (quiescence_status != 0) {
        if (scope_supported && !state.prebind_hit) {
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

    if (!scope_supported) {
        uintptr_t provider_address = 0;
        kzt_owner_resolution_t *owner_resolution =
            &state.evidence.base_enrich_result.owner_resolution;

        if (!kzt_guest_library_wrapper_alias_symbol_allowed(
                state.evidence.runtime_candidate.symbol_name) ||
            !production_dynamic_view_needs_library(
                &state.evidence.runtime_view, &reader_ops,
                "libdl.so.2")) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
            goto preemption_diagnostic;
        }
        if (kzt_guest_registry_patch_decision_lease_acquire(
                &state.source_lease, &state.decision_lease) != 0) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
            goto preemption_diagnostic;
        }
        state.evidence.held_decision_lease = &state.decision_lease;
        if (production_resolve_exact_symbol_owner(
                &state.evidence, 0,
                state.evidence.runtime_candidate.symbol_name,
                state.evidence.runtime_candidate.version_evidence,
                state.evidence.runtime_candidate.version,
                "libdl.so.2",
                owner_resolution, &provider_address) != 0 ||
            !provider_address) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
            goto preemption_diagnostic;
        }
        state.exact_symbol_provider = 1;
        state.preemption_proof = (kzt_guest_symbol_scope_result_t) {
            .status = KZT_GUEST_SYMBOL_SCOPE_SAFE,
            .reason = KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER,
            .candidate_count = 1,
            .scope_complete = 1,
            .lookup_order_known = 1,
            .selected_provider_link_map =
                owner_resolution->current_owner.link_map_addr,
            .selected_provider_address = provider_address,
            .selected_provider_binding = STB_GLOBAL,
            .selected_provider_type = STT_FUNC,
            .selected_provider_visibility = STV_DEFAULT,
        };
    } else if (!state.prebind_hit) {
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
    if (state.exact_symbol_provider) {
        const kzt_patch_object_ref_t *owner =
            &state.evidence.base_enrich_result.owner_resolution.current_owner;
        int acquire_status;

        acquire_status = production_acquire_exact(
            owner, NULL, &state.provider_handle, &state.evidence);
        if (acquire_status != 0) {
            result->reason =
                KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
            goto done;
        }
        state.provider_key = state.evidence.exact_provider_key;
    } else if (kzt_guest_library_access_lookup(
                   &context->kzt_guest_library_access, &state.provider_key,
                   &state.provider_handle) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
        goto done;
    }
    if (!state.provider_handle.library ||
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
    if (!state.exact_symbol_provider) {
        state.evidence.retained_provider_handle = &state.provider_handle;
        state.evidence.exact_provider_key = state.provider_key;
        state.evidence.exact_provider_bindings =
            state.provider_handle.bindings;
        state.evidence.exact_provider_entry = state.provider_handle.entry;
        state.evidence.exact_provider_library = state.provider_handle.library;
        state.evidence.exact_provider_owner = (kzt_patch_object_ref_t) {
            .known = 1,
            .link_map_addr = state.provider_key.link_map_addr,
            .generation = state.provider_key.generation,
        };
        state.evidence.owner_namespace_id = state.provider_key.namespace_id;
    }
    if (!production_exact_provider_handle_matches(&state.evidence)) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
        goto done;
    }
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
        .allow_budget_transient_native = loader_write_enabled,
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
    if (result->status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED ||
        result->status == KZT_LAZY_DIRECT_ROUTE_NATIVE_TRANSIENT) {
        uintptr_t slot_after =
            __atomic_load_n((uintptr_t *)slot, __ATOMIC_ACQUIRE);
        printf_kzt_registry_diagnostics(
            "kzt_lazy_direct schema=1 symbol=%s "
            "route_status=%s writer_result=%s "
            "slot_before=%p slot_after=%p selected_target=%p\n",
            input.symbol,
            result->status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED ?
                "NATIVE_APPLIED" : "NATIVE_TRANSIENT",
            result->status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED ?
                "APPLIED" : "NOT_WRITTEN",
            (void *)slot_current_value, (void *)slot_after,
            (void *)result->selected_target);
    }

done:
    if (state.decision_lease.active) {
        kzt_guest_registry_patch_decision_lease_release(
            &state.decision_lease);
        state.evidence.held_decision_lease = NULL;
    }
    if (state.provider_handle_owned) {
        kzt_guest_library_handle_release(&state.provider_handle);
    }
    kzt_lazy_prebind_scope_release(&state.prebind_lease);
    kzt_guest_library_loader_quiescence_release(
        &state.evidence.loader_quiescence_lease);
    kzt_guest_registry_symbol_candidate_release(
        &state.evidence.exact_owner_candidate);
    kzt_guest_registry_source_lease_release(
        &state.evidence.owner_source_lease);
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

#endif
