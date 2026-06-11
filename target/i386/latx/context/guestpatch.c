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
        "new_bridge=0x%lx new_owner=%s new_owner_base=0x%lx reason=%s",
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
        decision->new_bridge,
        KztPatchStringOrNone(decision->new_owner),
        decision->new_owner_base,
        KztPatchDecisionReasonName(decision->reason));

    if (written < 0)
        return 0;
    return (size_t)written;
}
