#ifndef KZT_RELA_IMMEDIATE_CANDIDATE_H
#define KZT_RELA_IMMEDIATE_CANDIDATE_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_patch_planner.h"

typedef enum kzt_rela_immediate_candidate_status {
    KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED = 0,
    KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED,
    KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN,
} kzt_rela_immediate_candidate_status_t;

typedef enum kzt_rela_immediate_candidate_reason {
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE = 0,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_INVALID_ARGUMENT,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SLOT,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_CURRENT_VALUE,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_NAME,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_VERSION,
    KZT_RELA_IMMEDIATE_CANDIDATE_REASON_PLANNER_ERROR,
} kzt_rela_immediate_candidate_reason_t;

typedef struct kzt_rela_immediate_candidate_request {
    unsigned int relocation_type;
    kzt_patch_table_kind_t table_kind;
    size_t entry_index;
    uintptr_t entry_addr;

    kzt_patch_object_ref_t source;
    uintptr_t dynamic_addr;
    uintptr_t load_bias;
    unsigned long dynamic_view_generation;
    int dynamic_view_available;

    uintptr_t slot_addr;
    int slot_current_value_present;
    uintptr_t slot_current_value;
    int lazy_binding_deferred;

    unsigned long symbol_index;
    const char *symbol_name;
    const char *version;

    kzt_patch_object_ref_t current_owner;
    kzt_patch_owner_match_t owner_match;
    kzt_patch_wrapper_match_t wrapper_match;
    const char *wrapper_name;
    const char *wrapper_symbol_version;
    uintptr_t bridge_target;
} kzt_rela_immediate_candidate_request_t;

typedef struct kzt_rela_immediate_candidate_result {
    kzt_rela_immediate_candidate_status_t status;
    kzt_rela_immediate_candidate_reason_t reason;
    int candidate_present;
    kzt_patch_candidate_t candidate;
    int decision_present;
    kzt_patch_decision_t decision;
} kzt_rela_immediate_candidate_result_t;

int kzt_rela_immediate_jump_slot_plan(
    const kzt_rela_immediate_candidate_request_t *request,
    kzt_rela_immediate_candidate_result_t *result);

#endif
