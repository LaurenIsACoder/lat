#include "kzt_lazy_direct_route.h"

#include <string.h>

#include "elf.h"

int kzt_lazy_direct_symbol_binding_supported(unsigned char st_info)
{
    return ELF64_ST_BIND(st_info) == STB_GLOBAL;
}

static void kzt_lazy_direct_route_result_init(
    kzt_lazy_direct_route_result_t *result)
{
    if (!result) {
        return;
    }
    memset(result, 0, sizeof(*result));
    result->status = KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED;
    result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_INPUT;
}

static int kzt_lazy_direct_route_address_field_valid(
    const kzt_guest_dynamic_field_t *field)
{
    return field && field->present && field->value &&
           field->address_semantics == KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS;
}

static int kzt_lazy_direct_route_scalar_field_valid(
    const kzt_guest_dynamic_field_t *field)
{
    return field && field->present && field->value &&
           field->address_semantics == KZT_GUEST_DYNAMIC_SCALAR;
}

static int kzt_lazy_direct_route_dynamic_view_complete(
    const kzt_lazy_direct_route_input_t *input)
{
    const kzt_guest_dynamic_view_t *view;

    if (!input || !input->source_dynamic_view) {
        return 0;
    }
    view = input->source_dynamic_view;
    if (!view->dynamic_addr ||
        view->status != KZT_GUEST_DYNAMIC_COMPLETE ||
        !view->entry_count || !view->has_null ||
        !kzt_lazy_direct_route_address_field_valid(&view->symtab) ||
        !kzt_lazy_direct_route_address_field_valid(&view->strtab) ||
        !kzt_lazy_direct_route_scalar_field_valid(&view->syment) ||
        !kzt_lazy_direct_route_address_field_valid(&view->jmprel) ||
        !kzt_lazy_direct_route_scalar_field_valid(&view->pltrelsz) ||
        !kzt_lazy_direct_route_scalar_field_valid(&view->pltrel) ||
        !kzt_lazy_direct_route_address_field_valid(&view->pltgot)) {
        return 0;
    }
    if (input->version_evidence != KZT_SYMBOL_VERSION_VERSIONED) {
        return 1;
    }
    return kzt_lazy_direct_route_address_field_valid(&view->versym) &&
           kzt_lazy_direct_route_address_field_valid(&view->verneed) &&
           kzt_lazy_direct_route_scalar_field_valid(&view->verneednum);
}

static int kzt_lazy_direct_route_ops_complete(
    const kzt_lazy_direct_route_ops_t *ops)
{
    return ops && ops->validate_source && ops->acquire_provider &&
           ops->release_provider && ops->find_wrapper_bridge &&
           ops->acquire_decision_lease &&
           ops->release_decision_lease && ops->validate_final &&
           ops->cas_slot;
}

static int kzt_lazy_direct_route_provider_exact(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_provider_t *provider)
{
    return input && provider && provider->handle &&
           provider->link_map_addr == input->provider.link_map_addr &&
           provider->generation == input->provider.generation &&
           provider->namespace_id == input->namespace_id &&
           provider->namespace_kind == input->namespace_kind;
}

kzt_lazy_direct_route_status_t kzt_lazy_direct_route_apply(
    const kzt_lazy_direct_route_input_t *input,
    const kzt_lazy_direct_route_ops_t *ops,
    kzt_lazy_direct_route_result_t *result)
{
    kzt_lazy_direct_route_provider_t provider = { 0 };
    kzt_lazy_direct_route_bridge_t bridge = { 0 };
    kzt_lazy_direct_route_lease_t lease = { 0 };
    kzt_lazy_direct_route_cas_status_t cas_status;
    int provider_acquired = 0;
    int lease_acquired = 0;

    kzt_lazy_direct_route_result_init(result);
    if (!input || !result || !kzt_lazy_direct_route_ops_complete(ops)) {
        return KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED;
    }
    if (!input->enabled) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_DISABLED;
        return result->status;
    }
    if (!input->preemption_safe) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_PREEMPTION_UNPROVEN;
        return result->status;
    }
    if (input->namespace_kind != KZT_GUEST_LIBRARY_NAMESPACE_MAIN ||
        input->namespace_id != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_NON_MAIN_NAMESPACE;
        return result->status;
    }
    if (!input->source.link_map_addr || !input->source.generation ||
        !input->provider.link_map_addr || !input->provider.generation ||
        input->source_dynamic_view_generation != input->source.generation ||
        !input->symbol || !input->symbol[0] || !input->slot_addr ||
        !input->guest_unresolved_slot || !input->expected_current_slot) {
        return result->status;
    }
    if (kzt_patch_symbol_must_stay_guest(input->symbol)) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_GUEST_OWNED_SYMBOL;
        return result->status;
    }
    if (!kzt_lazy_direct_route_dynamic_view_complete(input)) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_INCOMPLETE_DYNAMIC_VIEW;
        return result->status;
    }
    if (!kzt_symbol_version_evidence_valid(input->version_evidence,
                                           input->version)) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_INVALID_VERSION;
        return result->status;
    }
    if (ops->validate_source(input, ops->opaque) <= 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_SOURCE_REJECTED;
        return result->status;
    }
    if (ops->acquire_provider(input, &provider, ops->opaque) != 0) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_UNAVAILABLE;
        return result->status;
    }
    provider_acquired = 1;
    if (!kzt_lazy_direct_route_provider_exact(input, &provider)) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_PROVIDER_MISMATCH;
        goto done;
    }
    if (ops->find_wrapper_bridge(input, &provider, &bridge,
                                 ops->opaque) != 0 ||
        !bridge.target) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_UNAVAILABLE;
        goto done;
    }
    if (!kzt_symbol_version_evidence_matches(
            input->version_evidence, input->version,
            bridge.version_evidence, bridge.version)) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_BRIDGE_VERSION_MISMATCH;
        goto done;
    }
    if (ops->acquire_decision_lease(
            input, &provider, &lease, ops->opaque) != 0) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_LEASE_UNAVAILABLE;
        goto done;
    }
    lease_acquired = 1;
    if (!lease.active) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_LEASE_UNAVAILABLE;
        goto done;
    }
    if (ops->validate_final(
            input, &provider, &bridge, &lease, ops->opaque) <= 0) {
        result->reason =
            KZT_LAZY_DIRECT_ROUTE_REASON_FINAL_VALIDATION_FAILED;
        goto done;
    }
    cas_status = ops->cas_slot(
        input->slot_addr, input->expected_current_slot,
        bridge.target, &lease, ops->opaque);
    if (cas_status == KZT_LAZY_DIRECT_ROUTE_CAS_APPLIED) {
        result->status = KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED;
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_NATIVE_APPLIED;
        result->selected_target = bridge.target;
    } else if (cas_status == KZT_LAZY_DIRECT_ROUTE_CAS_MISMATCH) {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_CAS_MISMATCH;
    } else if (cas_status == KZT_LAZY_DIRECT_ROUTE_CAS_BUDGET_EXHAUSTED) {
        if (input->allow_budget_transient_native && bridge.transient_safe &&
            kzt_patch_symbol_is_loader_route_family(input->symbol)) {
            result->status = KZT_LAZY_DIRECT_ROUTE_NATIVE_TRANSIENT;
            result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_NATIVE_TRANSIENT;
            result->selected_target = bridge.target;
        } else {
            result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_BUDGET_EXHAUSTED;
        }
    } else if (cas_status == KZT_LAZY_DIRECT_ROUTE_CAS_ROLLED_BACK) {
        result->status = KZT_LAZY_DIRECT_ROUTE_WRITE_ROLLED_BACK;
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_WRITE_ROLLED_BACK;
    } else if (cas_status == KZT_LAZY_DIRECT_ROUTE_CAS_UNRECOVERABLE) {
        result->status = KZT_LAZY_DIRECT_ROUTE_UNRECOVERABLE;
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_UNRECOVERABLE;
    } else {
        result->reason = KZT_LAZY_DIRECT_ROUTE_REASON_CAS_ERROR;
    }

done:
    if (lease_acquired) {
        ops->release_decision_lease(&lease, ops->opaque);
    }
    if (provider_acquired) {
        ops->release_provider(&provider, ops->opaque);
    }
    return result->status;
}
