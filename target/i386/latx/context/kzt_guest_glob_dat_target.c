#include <string.h>

#include "box64context.h"
#include "elfloader_private.h"
#include "kzt_guest_glob_dat_target.h"
#include "kzt_owner_resolver.h"
#include "kzt_rela_runtime_bridge.h"
#include "kzt_xcb_route_policy.h"

void kzt_guest_glob_dat_target_release(
    kzt_guest_glob_dat_target_t *target)
{
    if (!target) {
        return;
    }
    kzt_guest_registry_patch_decision_lease_release(&target->decision_lease);
    kzt_guest_library_loader_quiescence_release(
        &target->loader_quiescence_lease);
    kzt_guest_registry_source_lease_release(&target->source_lease);
}

int kzt_guest_glob_dat_target_resolve(
    box64context_t *context, elfheader_t *head, uintptr_t guest_target,
    unsigned long symbol_index, const Elf64_Sym *symbol,
    const char *symbol_name, int version, const char *version_name,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_glob_dat_target_t *target)
{
    kzt_owner_resolution_t resolution;
    kzt_guest_registry_address_match_t source_match;
    kzt_guest_registry_address_match_t owner_match;
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t handle;
    uintptr_t namespace_head = 0;
    uintptr_t bridge_target = 0;

    if (!context || !head || !head->self_link_map || !guest_target ||
        symbol_index >= head->numDynSym || !symbol || !symbol_name ||
        !symbol_name[0] || !reader_ops || !reader_ops->read_memory ||
        !target) {
        return 0;
    }
    memset(target, 0, sizeof(*target));
    target->guest_target = guest_target;
    target->selected_target = guest_target;
    if (kzt_xcb_route_classify(symbol_name) != KZT_XCB_ROUTE_NOT_XCB) {
        return 1;
    }
    kzt_owner_resolver_init(&resolution);
    if (kzt_owner_resolver_resolve_current(
            KztGuestRegistryForContext(context), guest_target,
            guest_target, &resolution) != 0 ||
        resolution.status != KZT_OWNER_RESOLVER_RESOLVED ||
        resolution.owner_match != KZT_PATCH_OWNER_MATCH ||
        !resolution.current_owner.known ||
        !resolution.current_owner.link_map_addr ||
        !resolution.current_owner.generation) {
        return 0;
    }
    target->owner = resolution.current_owner;

    if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC ||
        version >= 2 || (version_name && version_name[0]) ||
        context->kzt_guest_scope_layout ==
            KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(context), head->self_link_map,
            &source_match) != 0 ||
        !source_match.generation ||
        source_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        source_match.namespace_id != 0 ||
        kzt_guest_registry_find_live_object(
            KztGuestRegistryForContext(context),
            target->owner.link_map_addr, &owner_match) != 0 ||
        owner_match.generation != target->owner.generation ||
        owner_match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        owner_match.namespace_id != 0 ||
        kzt_guest_registry_source_lease_acquire(
            KztGuestRegistryForContext(context), head->self_link_map,
            source_match.generation, source_match.namespace_id,
            &target->source_lease) != 0 ||
        kzt_guest_registry_patch_decision_lease_acquire(
            &target->source_lease, &target->decision_lease) != 0 ||
        kzt_guest_library_loader_quiescence_try_acquire(
            KztGuestLibraryBindingsForContext(context),
            &target->loader_quiescence_lease) != 0 ||
        kzt_guest_registry_context_get_main_namespace_head(
            &context->kzt_guest_registry_context, &namespace_head) != 0) {
        kzt_guest_glob_dat_target_release(target);
        return 1;
    }
    target->scope_request = (kzt_guest_symbol_scope_request_t) {
        .source = {
            .link_map_addr = head->self_link_map,
            .generation = source_match.generation,
            .namespace_id = source_match.namespace_id,
            .namespace_head = namespace_head,
            .layout = context->kzt_guest_scope_layout,
        },
        .symbol = symbol_name,
        .version_evidence = KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
        .version = NULL,
        .reference_binding = ELF64_ST_BIND(symbol->st_info),
        .reference_type = ELF64_ST_TYPE(symbol->st_info),
        .reference_visibility = symbol->st_other & 0x3,
    };
    if (kzt_guest_symbol_scope_check(
            &target->scope_request, target->owner.link_map_addr,
            guest_target, reader_ops, &target->scope_proof) !=
            KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        kzt_guest_glob_dat_target_release(target);
        return 1;
    }
    key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = target->owner.link_map_addr,
        .generation = target->owner.generation,
        .namespace_id = owner_match.namespace_id,
        .namespace_kind = owner_match.namespace_id == 0 ?
            KZT_GUEST_LIBRARY_NAMESPACE_MAIN :
            KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT,
    };
    memset(&handle, 0, sizeof(handle));
    if (KztGuestLibraryLookupForContext(context, &key, &handle) != 0 ||
        !handle.library ||
        handle.object_type != KZT_GUEST_LIBRARY_OBJECT_WRAPPED) {
        kzt_guest_library_handle_release(&handle);
        kzt_guest_glob_dat_target_release(target);
        return 1;
    }
    bridge_target = kzt_rela_runtime_select_exact_wrapper_bridge_retained(
        context, &handle, symbol_name,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL);
    if (bridge_target) {
        target->selected_target = bridge_target;
        target->exact_bridge = bridge_target != guest_target;
    }
    kzt_guest_library_handle_release(&handle);
    if (!target->exact_bridge) {
        kzt_guest_glob_dat_target_release(target);
    }
    return 1;
}

int kzt_guest_glob_dat_route(
    box64context_t *context, elfheader_t *head, uintptr_t slot_addr,
    uintptr_t guest_target, unsigned long symbol_index,
    const Elf64_Sym *symbol, const char *symbol_name, int version,
    const char *version_name,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_glob_dat_route_result_t *result)
{
    kzt_guest_glob_dat_target_t target;
    kzt_guest_symbol_scope_result_t revalidated_scope;

    if (!result || !slot_addr) {
        return 0;
    }
    *result = (kzt_guest_glob_dat_route_result_t) {
        .guest_target = guest_target,
        .selected_target = guest_target,
        .final_value = guest_target,
        .writer_result = KZT_PRODUCTION_SLOT_TRANSACTION_ERROR,
    };
    if (!kzt_guest_glob_dat_target_resolve(
            context, head, guest_target, symbol_index, symbol, symbol_name,
            version, version_name, reader_ops, &target)) {
        return 0;
    }
    result->selected_target = target.selected_target;
    if (target.exact_bridge &&
        kzt_guest_symbol_scope_revalidate(
            &target.scope_proof, &target.scope_request, reader_ops,
            &revalidated_scope) == KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        result->writer_result = kzt_production_eager_relocation_write(
            context, head->self_link_map, &target.owner,
            KZT_PATCH_RELOCATION_GLOB_DAT, slot_addr, guest_target,
            target.selected_target, symbol_name,
            KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
            &result->final_value);
    }
    kzt_guest_glob_dat_target_release(&target);
    return 1;
}
