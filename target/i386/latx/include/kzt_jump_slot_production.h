#ifndef KZT_JUMP_SLOT_PRODUCTION_H
#define KZT_JUMP_SLOT_PRODUCTION_H

#include <stdint.h>

#include "elf.h"
#include "kzt_guest_registry.h"
#include "kzt_jump_slot_route.h"
#include "kzt_lazy_binding.h"
#include "kzt_lazy_direct_route.h"
#include "kzt_lazy_prebind_scope.h"

typedef struct box64context_s box64context_t;
typedef struct elfheader_s elfheader_t;
typedef int (*kzt_lazy_prebind_target_prepare_fn)(uintptr_t target,
                                                  void *opaque);

/* A nonzero return guarantees that no slot write was previously attempted or
 * committed by this route, so callers may safely use their legacy write. */
int kzt_production_jump_slot_route(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, elfheader_t *head, int need_resolv_present,
    int entry_index, Elf64_Rela *rela, uint64_t *slot,
    uintptr_t slot_current_value,
    int slot_current_value_is_unresolved_stub, unsigned long symbol_index,
    const char *symbol_name, const char *version,
    int expected_guest_target_present, uintptr_t expected_guest_target,
    uintptr_t legacy_target, kzt_jump_slot_route_result_t *route_result);

/* The same no-slot-write-on-nonzero-return contract applies here. */
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
    kzt_jump_slot_route_result_t *route_result);

/* Tries the evidence-backed direct bridge before guest lazy binding.  A
 * GUEST_REQUIRED result guarantees that the unresolved slot was preserved. */
int kzt_production_lazy_direct_route(
    box64context_t *context, elfheader_t *head, int entry_index,
    Elf64_Rela *rela, uint64_t *slot, uintptr_t slot_current_value,
    unsigned long symbol_index, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_lazy_direct_route_result_t *result);

/* Called while the per-object source and decision transaction is held.  It
 * publishes only already-proven lazy facts; it never changes a guest slot. */
int kzt_production_lazy_prebind_object(
    box64context_t *context, elfheader_t *head,
    unsigned long source_generation,
    const kzt_guest_dynamic_view_t *source_dynamic_view,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque);
void kzt_production_lazy_prebind_refresh(
    box64context_t *context,
    kzt_lazy_prebind_target_prepare_fn target_prepare,
    void *target_prepare_opaque);
int kzt_production_lazy_prebind_invalidate(
    box64context_t *context, kzt_lazy_prebind_mutation_t mutation);
int kzt_production_lazy_prebind_retire(
    box64context_t *context,
    const kzt_lazy_prebind_identity_t *identity);

int kzt_production_lazy_route_guest_target(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t guest_target,
    kzt_lazy_binding_route_result_t *result);

/* Production resolver orchestration.  One exact source lease covers the
 * first slot load, post-bind validation, route transaction, and final
 * release. */
int kzt_production_lazy_complete(
    box64context_t *context,
    kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result);

int kzt_production_lazy_source_lease_acquire(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    kzt_guest_registry_source_lease_t *source_lease);

int kzt_production_lazy_load_slot_with_lease(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t slot_addr,
    uintptr_t *value,
    kzt_guest_registry_source_lease_t *source_lease);

/* The caller-held exact (link_map, generation, namespace) source lease must
 * cover the first source slot read through the complete route transaction. */
int kzt_production_lazy_route_guest_target_leased(
    box64context_t *context,
    const kzt_lazy_binding_pending_t *pending,
    uintptr_t guest_target,
    const kzt_guest_registry_source_lease_t *source_lease,
    kzt_lazy_binding_route_result_t *result);

#endif
