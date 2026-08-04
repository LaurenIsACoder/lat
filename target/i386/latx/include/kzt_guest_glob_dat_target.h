#ifndef KZT_GUEST_GLOB_DAT_TARGET_H
#define KZT_GUEST_GLOB_DAT_TARGET_H

#include <stdint.h>

#include "elf.h"
#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"
#include "kzt_guest_symbol_scope.h"
#include "kzt_jump_slot_production.h"
#include "kzt_patch_planner.h"

typedef struct box64context_s box64context_t;
typedef struct elfheader_s elfheader_t;

typedef struct kzt_guest_glob_dat_target {
    uintptr_t guest_target;
    uintptr_t selected_target;
    kzt_patch_object_ref_t owner;
    kzt_guest_registry_source_lease_t source_lease;
    kzt_guest_registry_patch_decision_lease_t decision_lease;
    kzt_guest_library_loader_quiescence_lease_t loader_quiescence_lease;
    kzt_guest_symbol_scope_request_t scope_request;
    kzt_guest_symbol_scope_result_t scope_proof;
    int exact_bridge;
} kzt_guest_glob_dat_target_t;

typedef struct kzt_guest_glob_dat_route_result {
    uintptr_t guest_target;
    uintptr_t selected_target;
    uintptr_t final_value;
    kzt_production_slot_transaction_result_t writer_result;
} kzt_guest_glob_dat_route_result_t;

void kzt_guest_glob_dat_target_release(
    kzt_guest_glob_dat_target_t *target);

int kzt_guest_glob_dat_target_resolve(
    box64context_t *context, elfheader_t *head, uintptr_t guest_target,
    unsigned long symbol_index, const Elf64_Sym *symbol,
    const char *symbol_name, int version, const char *version_name,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_glob_dat_target_t *target);

int kzt_guest_glob_dat_route(
    box64context_t *context, elfheader_t *head, uintptr_t slot_addr,
    uintptr_t guest_target, unsigned long symbol_index,
    const Elf64_Sym *symbol, const char *symbol_name, int version,
    const char *version_name,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_glob_dat_route_result_t *result);

#endif
