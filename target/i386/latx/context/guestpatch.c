#include "guestpatch.h"

#include <stdio.h>
#include <string.h>

static const char *KztPatchStringOrNone(const char *value)
{
    return value ? value : "(none)";
}

/*
 * A patch decision is the audit record for a GOT write.  Defaults keep maplib
 * as the selected target so new guest-owner data can first be attached and
 * compared without changing behavior.
 */
void KztPatchDecisionInit(KztPatchDecision *decision)
{
    memset(decision, 0, sizeof(*decision));
    decision->symbol_version = -1;
    decision->reason = KZT_PATCH_REASON_NONE;
    decision->owner_relation = KZT_PATCH_OWNER_RELATION_UNKNOWN;
    decision->shadow_result = KZT_PATCH_SHADOW_DISABLED;
    decision->target_source = KZT_PATCH_TARGET_MAPLIB;
}

void KztPatchDecisionSelectGuestOwnerTarget(KztPatchDecision *decision)
{
    decision->new_bridge = decision->guest_owner_bridge;
    decision->new_owner = decision->guest_owner;
    decision->new_owner_base = decision->guest_owner_base;
    decision->target_source = KZT_PATCH_TARGET_GUEST_OWNER;
}

const char *KztPatchDecisionReasonName(KztPatchDecisionReason reason)
{
    switch (reason) {
        case KZT_PATCH_REASON_NONE:
            return "none";
        case KZT_PATCH_REASON_LOCAL_SYMBOL:
            return "local-symbol";
        case KZT_PATCH_REASON_GLOBAL_SYMBOL:
            return "global-symbol";
        case KZT_PATCH_REASON_LAZY_BINDING_DEFERRED:
            return "lazy-binding-deferred";
        case KZT_PATCH_REASON_LAZY_BINDING_RESOLVED:
            return "lazy-binding-resolved";
        case KZT_PATCH_REASON_PLT_RESOLVER:
            return "plt-resolver";
        case KZT_PATCH_REASON_SYMBOL_MISSING:
            return "symbol-missing";
        case KZT_PATCH_REASON_UNSUPPORTED_RELOCATION:
            return "unsupported-relocation";
    }
    return "unknown";
}

const char *KztPatchOwnerRelationName(KztPatchOwnerRelation relation)
{
    switch (relation) {
        case KZT_PATCH_OWNER_RELATION_UNKNOWN:
            return "unknown";
        case KZT_PATCH_OWNER_RELATION_GUEST_ONLY:
            return "guest-only";
        case KZT_PATCH_OWNER_RELATION_MAPLIB_ONLY:
            return "maplib-only";
        case KZT_PATCH_OWNER_RELATION_MATCH:
            return "match";
        case KZT_PATCH_OWNER_RELATION_MISMATCH:
            return "mismatch";
    }
    return "unknown";
}

const char *KztPatchShadowResultName(KztPatchShadowResult result)
{
    switch (result) {
        case KZT_PATCH_SHADOW_DISABLED:
            return "disabled";
        case KZT_PATCH_SHADOW_NO_MAPLIB_TARGET:
            return "no-maplib-target";
        case KZT_PATCH_SHADOW_NO_GUEST_OWNER:
            return "no-guest-owner";
        case KZT_PATCH_SHADOW_SELF_PLT:
            return "self-plt";
        case KZT_PATCH_SHADOW_NO_WRAPPER:
            return "no-wrapper";
        case KZT_PATCH_SHADOW_NO_LIBRARY:
            return "no-library";
        case KZT_PATCH_SHADOW_SYMBOL_MISSING:
            return "symbol-missing";
        case KZT_PATCH_SHADOW_MATCH:
            return "match";
        case KZT_PATCH_SHADOW_MISMATCH:
            return "mismatch";
    }
    return "unknown";
}

const char *KztPatchTargetSourceName(KztPatchTargetSource source)
{
    switch (source) {
        case KZT_PATCH_TARGET_MAPLIB:
            return "maplib";
        case KZT_PATCH_TARGET_GUEST_OWNER:
            return "guest-owner";
    }
    return "unknown";
}

const char *KztPatchRelocationTypeName(int relocation_type)
{
    switch (relocation_type) {
        case R_X86_64_GLOB_DAT:
            return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT:
            return "R_X86_64_JUMP_SLOT";
    }
    return "unknown";
}

size_t KztFormatPatchDecision(char *buffer, size_t buffer_size,
                              const KztPatchDecision *decision)
{
    int written = snprintf(
        buffer, buffer_size,
        "object=%s base=0x%lx relocation=%p index=%zu type=%s symbol=%s "
        "version=%d/%s slot=0x%lx old=0x%lx old_owner=%s old_owner_base=0x%lx "
        "old_guest_object=%s old_guest_object_base=0x%lx "
        "maplib_bridge=0x%lx maplib_owner=%s maplib_owner_base=0x%lx "
        "new_bridge=0x%lx new_owner=%s new_owner_base=0x%lx reason=%s "
        "owner_relation=%s guest_owner_bridge=0x%lx guest_owner=%s "
        "guest_owner_base=0x%lx shadow_result=%s target_source=%s",
        KztPatchStringOrNone(decision->object),
        decision->object_base,
        decision->relocation,
        decision->relocation_index,
        KztPatchRelocationTypeName(decision->relocation_type),
        KztPatchStringOrNone(decision->symbol),
        decision->symbol_version,
        KztPatchStringOrNone(decision->symbol_version_name),
        decision->slot,
        decision->old_target,
        KztPatchStringOrNone(decision->old_owner),
        decision->old_owner_base,
        KztPatchStringOrNone(decision->old_guest_object),
        decision->old_guest_object_base,
        decision->maplib_bridge,
        KztPatchStringOrNone(decision->maplib_owner),
        decision->maplib_owner_base,
        decision->new_bridge,
        KztPatchStringOrNone(decision->new_owner),
        decision->new_owner_base,
        KztPatchDecisionReasonName(decision->reason),
        KztPatchOwnerRelationName(decision->owner_relation),
        decision->guest_owner_bridge,
        KztPatchStringOrNone(decision->guest_owner),
        decision->guest_owner_base,
        KztPatchShadowResultName(decision->shadow_result),
        KztPatchTargetSourceName(decision->target_source));

    if (written < 0)
        return 0;
    return (size_t)written;
}
