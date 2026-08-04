#include "kzt_patch_planner.h"

#include <stdio.h>
#include <string.h>

static int kzt_patch_string_is_empty(const char *value)
{
    return !value || value[0] == '\0';
}

static const char *kzt_patch_string_or_none(const char *value)
{
    return kzt_patch_string_is_empty(value) ? "(none)" : value;
}

static int kzt_patch_relocation_is_supported(
    kzt_patch_relocation_type_t reloc_type)
{
    return reloc_type == KZT_PATCH_RELOCATION_JUMP_SLOT ||
           reloc_type == KZT_PATCH_RELOCATION_GLOB_DAT;
}

static void kzt_patch_decision_copy_candidate(
    const kzt_patch_candidate_t *candidate,
    kzt_patch_decision_t *decision)
{
    decision->source = candidate->source;
    decision->dynamic_addr = candidate->dynamic_addr;
    decision->load_bias = candidate->load_bias;
    decision->dynamic_view_generation = candidate->dynamic_view_generation;
    decision->dynamic_view_available = candidate->dynamic_view_available;
    decision->table_kind = candidate->table_kind;
    decision->entry_index = candidate->entry_index;
    decision->entry_addr = candidate->entry_addr;
    decision->reloc_type = candidate->reloc_type;
    decision->slot_addr = candidate->slot_addr;
    decision->slot_current_value_present =
        candidate->slot_current_value_present;
    decision->slot_current_value = candidate->slot_current_value;
    decision->lazy_binding_deferred = candidate->lazy_binding_deferred;
    decision->symbol_index = candidate->symbol_index;
    decision->symbol_name = candidate->symbol_name;
    decision->version_evidence = candidate->version_evidence;
    decision->version = candidate->version;
    decision->current_owner = candidate->current_owner;
    decision->owner_match = candidate->owner_match;
    decision->wrapper_match = candidate->wrapper_match;
    decision->wrapper_name = candidate->wrapper_name;
    decision->wrapper_version_evidence =
        candidate->wrapper_version_evidence;
    decision->wrapper_symbol_version = candidate->wrapper_symbol_version;
    decision->bridge_target = candidate->bridge_target;
}

static int kzt_patch_decision_set(kzt_patch_decision_t *decision,
                                  kzt_patch_decision_kind_t kind,
                                  kzt_patch_reason_t reason)
{
    decision->kind = kind;
    decision->reason = reason;
    decision->allow_native_bridge = kind == KZT_PATCH_DECISION_APPROVED;
    return 0;
}

const char *kzt_patch_decision_kind_name(kzt_patch_decision_kind_t kind)
{
    switch (kind) {
    case KZT_PATCH_DECISION_APPROVED:
        return "APPROVED";
    case KZT_PATCH_DECISION_REJECTED:
        return "REJECTED";
    case KZT_PATCH_DECISION_UNSUPPORTED:
        return "UNSUPPORTED";
    case KZT_PATCH_DECISION_DEFERRED:
        return "DEFERRED";
    case KZT_PATCH_DECISION_ERROR:
        return "ERROR";
    }

    return "UNKNOWN";
}

const char *kzt_patch_reason_name(kzt_patch_reason_t reason)
{
    switch (reason) {
    case KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE:
        return "APPROVED_NATIVE_BRIDGE";
    case KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT:
        return "ERROR_INVALID_ARGUMENT";
    case KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION:
        return "INPUT_UNSUPPORTED_RELOCATION";
    case KZT_PATCH_REASON_INPUT_MALFORMED_TABLE:
        return "INPUT_MALFORMED_TABLE";
    case KZT_PATCH_REASON_INPUT_MALFORMED_SLOT:
        return "INPUT_MALFORMED_SLOT";
    case KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME:
        return "INPUT_MALFORMED_SYMBOL_NAME";
    case KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION:
        return "INPUT_MALFORMED_SYMBOL_VERSION";
    case KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW:
        return "INPUT_UNAVAILABLE_DYNAMIC_VIEW";
    case KZT_PATCH_REASON_INPUT_UNAVAILABLE_CURRENT_GOT:
        return "INPUT_UNAVAILABLE_CURRENT_GOT";
    case KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER:
        return "INPUT_UNAVAILABLE_OWNER";
    case KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST:
        return "INPUT_UNAVAILABLE_WRAPPER_MANIFEST";
    case KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET:
        return "INPUT_UNAVAILABLE_BRIDGE_TARGET";
    case KZT_PATCH_REASON_POLICY_KEEP_GUEST:
        return "POLICY_KEEP_GUEST";
    case KZT_PATCH_REASON_POLICY_OWNER_MISMATCH:
        return "POLICY_OWNER_MISMATCH";
    case KZT_PATCH_REASON_POLICY_NO_WRAPPER:
        return "POLICY_NO_WRAPPER";
    case KZT_PATCH_REASON_POLICY_WRAPPER_SYMBOL_ONLY:
        return "POLICY_WRAPPER_SYMBOL_ONLY";
    case KZT_PATCH_REASON_POLICY_VERSION_MISMATCH:
        return "POLICY_VERSION_MISMATCH";
    case KZT_PATCH_REASON_DEFERRED_LAZY_BINDING:
        return "DEFERRED_LAZY_BINDING";
    }

    return "UNKNOWN";
}

const char *kzt_patch_table_kind_name(kzt_patch_table_kind_t table_kind)
{
    switch (table_kind) {
    case KZT_PATCH_TABLE_UNKNOWN:
        return "UNKNOWN";
    case KZT_PATCH_TABLE_RELA:
        return "RELA";
    case KZT_PATCH_TABLE_REL:
        return "REL";
    case KZT_PATCH_TABLE_PLT_RELA:
        return "PLT_RELA";
    case KZT_PATCH_TABLE_PLT_REL:
        return "PLT_REL";
    case KZT_PATCH_TABLE_OTHER:
        return "OTHER";
    }

    return "UNKNOWN";
}

const char *kzt_patch_relocation_type_name(
    kzt_patch_relocation_type_t reloc_type)
{
    switch (reloc_type) {
    case KZT_PATCH_RELOCATION_UNKNOWN:
        return "UNKNOWN";
    case KZT_PATCH_RELOCATION_JUMP_SLOT:
        return "JUMP_SLOT";
    case KZT_PATCH_RELOCATION_GLOB_DAT:
        return "GLOB_DAT";
    case KZT_PATCH_RELOCATION_RELATIVE:
        return "RELATIVE";
    case KZT_PATCH_RELOCATION_COPY:
        return "COPY";
    case KZT_PATCH_RELOCATION_IRELATIVE:
        return "IRELATIVE";
    case KZT_PATCH_RELOCATION_OTHER:
        return "OTHER";
    }

    return "UNKNOWN";
}

const char *kzt_patch_owner_match_name(kzt_patch_owner_match_t match)
{
    switch (match) {
    case KZT_PATCH_OWNER_UNKNOWN:
        return "UNKNOWN";
    case KZT_PATCH_OWNER_MATCH:
        return "MATCH";
    case KZT_PATCH_OWNER_MISMATCH:
        return "MISMATCH";
    }

    return "UNKNOWN";
}

const char *kzt_patch_wrapper_match_name(kzt_patch_wrapper_match_t match)
{
    switch (match) {
    case KZT_PATCH_WRAPPER_NO_MANIFEST:
        return "NO_MANIFEST";
    case KZT_PATCH_WRAPPER_NO_WRAPPER:
        return "NO_WRAPPER";
    case KZT_PATCH_WRAPPER_SYMBOL_ONLY:
        return "SYMBOL_ONLY";
    case KZT_PATCH_WRAPPER_VERSION_MISMATCH:
        return "VERSION_MISMATCH";
    case KZT_PATCH_WRAPPER_VERSION_MATCH:
        return "VERSION_MATCH";
    case KZT_PATCH_WRAPPER_UNVERSIONED_MATCH:
        return "UNVERSIONED_MATCH";
    }

    return "UNKNOWN";
}

const char *kzt_symbol_version_evidence_name(
    kzt_symbol_version_evidence_t evidence)
{
    switch (evidence) {
    case KZT_SYMBOL_VERSION_VERSIONED:
        return "VERSIONED";
    case KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED:
        return "CONFIRMED_UNVERSIONED";
    case KZT_SYMBOL_VERSION_UNKNOWN:
        return "UNKNOWN";
    case KZT_SYMBOL_VERSION_ERROR:
        return "ERROR";
    }
    return "UNKNOWN";
}

int kzt_patch_planner_decide(const kzt_patch_candidate_t *candidate,
                             kzt_patch_decision_t *decision)
{
    if (!decision) {
        return -1;
    }

    memset(decision, 0, sizeof(*decision));
    if (!candidate) {
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_ERROR,
                                      KZT_PATCH_REASON_ERROR_INVALID_ARGUMENT);
    }
    kzt_patch_decision_copy_candidate(candidate, decision);

    if (!kzt_patch_relocation_is_supported(candidate->reloc_type)) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION);
    }

    if (!candidate->dynamic_view_available) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW);
    }

    if (candidate->table_kind == KZT_PATCH_TABLE_UNKNOWN) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_MALFORMED_TABLE);
    }

    if (candidate->slot_addr == 0) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_MALFORMED_SLOT);
    }

    if (kzt_patch_string_is_empty(candidate->symbol_name)) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_NAME);
    }

    if (kzt_patch_symbol_must_stay_guest(candidate->symbol_name)) {
        return kzt_patch_decision_set(decision,
                                      KZT_PATCH_DECISION_REJECTED,
                                      KZT_PATCH_REASON_POLICY_KEEP_GUEST);
    }

    if (!kzt_symbol_version_evidence_valid(candidate->version_evidence,
                                           candidate->version)) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION);
    }

    if (!candidate->slot_current_value_present) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_CURRENT_GOT);
    }

    if (candidate->lazy_binding_deferred) {
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_DEFERRED,
                                      KZT_PATCH_REASON_DEFERRED_LAZY_BINDING);
    }

    if (!candidate->current_owner.known ||
        candidate->owner_match == KZT_PATCH_OWNER_UNKNOWN) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);
    }

    if (candidate->owner_match == KZT_PATCH_OWNER_MISMATCH) {
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_REJECTED,
                                      KZT_PATCH_REASON_POLICY_OWNER_MISMATCH);
    }

    switch (candidate->wrapper_match) {
    case KZT_PATCH_WRAPPER_NO_MANIFEST:
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST);
    case KZT_PATCH_WRAPPER_NO_WRAPPER:
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_REJECTED,
                                      KZT_PATCH_REASON_POLICY_NO_WRAPPER);
    case KZT_PATCH_WRAPPER_SYMBOL_ONLY:
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_REJECTED,
            KZT_PATCH_REASON_POLICY_WRAPPER_SYMBOL_ONLY);
    case KZT_PATCH_WRAPPER_VERSION_MISMATCH:
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_REJECTED,
                                      KZT_PATCH_REASON_POLICY_VERSION_MISMATCH);
    case KZT_PATCH_WRAPPER_VERSION_MATCH:
    case KZT_PATCH_WRAPPER_UNVERSIONED_MATCH:
        break;
    }

    if (!kzt_symbol_version_evidence_matches(
            candidate->version_evidence, candidate->version,
            candidate->wrapper_version_evidence,
            candidate->wrapper_symbol_version) ||
        (candidate->version_evidence == KZT_SYMBOL_VERSION_VERSIONED &&
         candidate->wrapper_match != KZT_PATCH_WRAPPER_VERSION_MATCH) ||
        (candidate->version_evidence ==
             KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED &&
         candidate->wrapper_match !=
             KZT_PATCH_WRAPPER_UNVERSIONED_MATCH)) {
        return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_REJECTED,
                                      KZT_PATCH_REASON_POLICY_VERSION_MISMATCH);
    }

    if (candidate->bridge_target == 0) {
        return kzt_patch_decision_set(
            decision, KZT_PATCH_DECISION_UNSUPPORTED,
            KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET);
    }

    return kzt_patch_decision_set(decision, KZT_PATCH_DECISION_APPROVED,
                                  KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE);
}

int kzt_patch_decision_format_summary(const kzt_patch_decision_t *decision,
                                      char *buffer,
                                      size_t buffer_size)
{
    int written;

    if (!decision || !buffer || buffer_size == 0) {
        return -1;
    }

    written = snprintf(
        buffer, buffer_size,
        "kzt_patch_decision kind=%s reason=%s allow=%d "
        "link_map=0x%lx source_generation=%lu dynamic_addr=0x%lx "
        "load_bias=0x%lx dynamic_view_generation=%lu "
        "dynamic_view_available=%d table=%s entry_index=%lu "
        "entry_addr=0x%lx reloc=%s slot=0x%lx "
        "slot_current_present=%d slot_current=0x%lx lazy_deferred=%d "
        "symbol_index=%lu symbol=%s version_evidence=%s version=%s "
        "current_owner=0x%lx "
        "current_owner_generation=%lu owner_match=%s wrapper=%s "
        "wrapper_match=%s wrapper_version_evidence=%s "
        "wrapper_version=%s bridge=0x%lx",
        kzt_patch_decision_kind_name(decision->kind),
        kzt_patch_reason_name(decision->reason),
        decision->allow_native_bridge,
        (unsigned long)decision->source.link_map_addr,
        decision->source.generation,
        (unsigned long)decision->dynamic_addr,
        (unsigned long)decision->load_bias,
        decision->dynamic_view_generation,
        decision->dynamic_view_available,
        kzt_patch_table_kind_name(decision->table_kind),
        (unsigned long)decision->entry_index,
        (unsigned long)decision->entry_addr,
        kzt_patch_relocation_type_name(decision->reloc_type),
        (unsigned long)decision->slot_addr,
        decision->slot_current_value_present,
        (unsigned long)decision->slot_current_value,
        decision->lazy_binding_deferred,
        decision->symbol_index,
        kzt_patch_string_or_none(decision->symbol_name),
        kzt_symbol_version_evidence_name(decision->version_evidence),
        kzt_patch_string_or_none(decision->version),
        (unsigned long)decision->current_owner.link_map_addr,
        decision->current_owner.generation,
        kzt_patch_owner_match_name(decision->owner_match),
        kzt_patch_string_or_none(decision->wrapper_name),
        kzt_patch_wrapper_match_name(decision->wrapper_match),
        kzt_symbol_version_evidence_name(
            decision->wrapper_version_evidence),
        kzt_patch_string_or_none(decision->wrapper_symbol_version),
        (unsigned long)decision->bridge_target);

    if (written < 0 || (size_t)written >= buffer_size) {
        return -1;
    }

    return 0;
}
