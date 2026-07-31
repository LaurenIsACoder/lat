#ifndef KZT_PATCH_PLANNER_H
#define KZT_PATCH_PLANNER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef enum kzt_patch_table_kind {
    KZT_PATCH_TABLE_UNKNOWN = 0,
    KZT_PATCH_TABLE_RELA,
    KZT_PATCH_TABLE_REL,
    KZT_PATCH_TABLE_PLT_RELA,
    KZT_PATCH_TABLE_PLT_REL,
    KZT_PATCH_TABLE_OTHER,
} kzt_patch_table_kind_t;

typedef enum kzt_patch_relocation_type {
    KZT_PATCH_RELOCATION_UNKNOWN = 0,
    KZT_PATCH_RELOCATION_JUMP_SLOT,
    KZT_PATCH_RELOCATION_GLOB_DAT,
    KZT_PATCH_RELOCATION_RELATIVE,
    KZT_PATCH_RELOCATION_COPY,
    KZT_PATCH_RELOCATION_IRELATIVE,
    KZT_PATCH_RELOCATION_OTHER,
} kzt_patch_relocation_type_t;

typedef enum kzt_patch_owner_match {
    KZT_PATCH_OWNER_UNKNOWN = 0,
    KZT_PATCH_OWNER_MATCH,
    KZT_PATCH_OWNER_MISMATCH,
} kzt_patch_owner_match_t;

typedef enum kzt_patch_wrapper_match {
    KZT_PATCH_WRAPPER_NO_MANIFEST = 0,
    KZT_PATCH_WRAPPER_NO_WRAPPER,
    KZT_PATCH_WRAPPER_SYMBOL_ONLY,
    KZT_PATCH_WRAPPER_VERSION_MISMATCH,
    KZT_PATCH_WRAPPER_VERSION_MATCH,
    KZT_PATCH_WRAPPER_UNVERSIONED_MATCH,
} kzt_patch_wrapper_match_t;

typedef enum kzt_symbol_version_evidence {
    /* Keep VERSIONED as zero so existing versioned initializers retain their
     * meaning.  Producers must still validate that a version string exists. */
    KZT_SYMBOL_VERSION_VERSIONED = 0,
    KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED,
    KZT_SYMBOL_VERSION_UNKNOWN,
    KZT_SYMBOL_VERSION_ERROR,
} kzt_symbol_version_evidence_t;

typedef enum kzt_patch_decision_kind {
    KZT_PATCH_DECISION_ERROR = 0,
    KZT_PATCH_DECISION_UNSUPPORTED,
    KZT_PATCH_DECISION_REJECTED,
    KZT_PATCH_DECISION_DEFERRED,
    KZT_PATCH_DECISION_APPROVED,
} kzt_patch_decision_kind_t;

typedef enum kzt_patch_reason {
    KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT = 0,
    KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION,
    KZT_PATCH_REASON_INPUT_MALFORMED_TABLE,
    KZT_PATCH_REASON_INPUT_MALFORMED_SLOT,
    KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME,
    KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION,
    KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW,
    KZT_PATCH_REASON_INPUT_UNAVAILABLE_CURRENT_GOT,
    KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER,
    KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST,
    KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET,
    KZT_PATCH_REASON_POLICY_KEEP_GUEST,
    KZT_PATCH_REASON_POLICY_OWNER_MISMATCH,
    KZT_PATCH_REASON_POLICY_NO_WRAPPER,
    KZT_PATCH_REASON_POLICY_WRAPPER_SYMBOL_ONLY,
    KZT_PATCH_REASON_POLICY_VERSION_MISMATCH,
    KZT_PATCH_REASON_DEFERRED_LAZY_BINDING,
    KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE,
} kzt_patch_reason_t;

typedef struct kzt_patch_object_ref {
    int known;
    uintptr_t link_map_addr;
    uintptr_t map_start;
    uintptr_t map_end;
    unsigned long generation;
    const char *soname;
    const char *path;
} kzt_patch_object_ref_t;

typedef struct kzt_patch_candidate {
    kzt_patch_object_ref_t source;
    uintptr_t dynamic_addr;
    uintptr_t load_bias;
    unsigned long dynamic_view_generation;
    int dynamic_view_available;

    kzt_patch_table_kind_t table_kind;
    size_t entry_index;
    uintptr_t entry_addr;
    kzt_patch_relocation_type_t reloc_type;
    uintptr_t slot_addr;

    int slot_current_value_present;
    uintptr_t slot_current_value;
    int lazy_binding_deferred;

    unsigned long symbol_index;
    const char *symbol_name;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;

    kzt_patch_object_ref_t current_owner;
    kzt_patch_owner_match_t owner_match;

    kzt_patch_wrapper_match_t wrapper_match;
    const char *wrapper_name;
    kzt_symbol_version_evidence_t wrapper_version_evidence;
    const char *wrapper_symbol_version;
    uintptr_t bridge_target;
} kzt_patch_candidate_t;

typedef struct kzt_patch_decision {
    kzt_patch_decision_kind_t kind;
    kzt_patch_reason_t reason;
    int allow_native_bridge;

    kzt_patch_object_ref_t source;
    uintptr_t dynamic_addr;
    uintptr_t load_bias;
    unsigned long dynamic_view_generation;
    int dynamic_view_available;

    kzt_patch_table_kind_t table_kind;
    size_t entry_index;
    uintptr_t entry_addr;
    kzt_patch_relocation_type_t reloc_type;
    uintptr_t slot_addr;

    int slot_current_value_present;
    uintptr_t slot_current_value;
    int lazy_binding_deferred;

    unsigned long symbol_index;
    const char *symbol_name;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;

    kzt_patch_object_ref_t current_owner;
    kzt_patch_owner_match_t owner_match;

    kzt_patch_wrapper_match_t wrapper_match;
    const char *wrapper_name;
    kzt_symbol_version_evidence_t wrapper_version_evidence;
    const char *wrapper_symbol_version;
    uintptr_t bridge_target;
} kzt_patch_decision_t;

int kzt_patch_planner_decide(const kzt_patch_candidate_t *candidate,
                             kzt_patch_decision_t *decision);

static inline int kzt_patch_symbol_must_stay_guest(
    const char *symbol_name)
{
    return symbol_name && strcmp(symbol_name, "dlclose") == 0;
}

const char *kzt_patch_decision_kind_name(kzt_patch_decision_kind_t kind);
const char *kzt_patch_reason_name(kzt_patch_reason_t reason);
const char *kzt_patch_table_kind_name(kzt_patch_table_kind_t table_kind);
const char *kzt_patch_relocation_type_name(
    kzt_patch_relocation_type_t reloc_type);
const char *kzt_patch_owner_match_name(kzt_patch_owner_match_t match);
const char *kzt_patch_wrapper_match_name(kzt_patch_wrapper_match_t match);
const char *kzt_symbol_version_evidence_name(
    kzt_symbol_version_evidence_t evidence);

static inline int kzt_symbol_version_evidence_valid(
    kzt_symbol_version_evidence_t evidence, const char *version)
{
    switch (evidence) {
    case KZT_SYMBOL_VERSION_VERSIONED:
        return version && version[0];
    case KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED:
        return !version || !version[0];
    case KZT_SYMBOL_VERSION_UNKNOWN:
    case KZT_SYMBOL_VERSION_ERROR:
        return 0;
    }
    return 0;
}

static inline int kzt_symbol_version_evidence_matches(
    kzt_symbol_version_evidence_t left_evidence, const char *left_version,
    kzt_symbol_version_evidence_t right_evidence, const char *right_version)
{
    if (left_evidence != right_evidence ||
        !kzt_symbol_version_evidence_valid(left_evidence, left_version) ||
        !kzt_symbol_version_evidence_valid(right_evidence, right_version)) {
        return 0;
    }
    return left_evidence == KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED ||
           strcmp(left_version, right_version) == 0;
}

int kzt_patch_decision_format_summary(
    const kzt_patch_decision_t *decision,
    char *buffer,
    size_t buffer_size);

#endif
