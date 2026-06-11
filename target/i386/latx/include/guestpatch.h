#ifndef __GUESTPATCH_H_
#define __GUESTPATCH_H_

#include <stddef.h>
#include <stdint.h>

#include "elf.h"

typedef enum KztPatchDecisionReason {
    KZT_PATCH_REASON_NONE,
    KZT_PATCH_REASON_LOCAL_SYMBOL,
    KZT_PATCH_REASON_GLOBAL_SYMBOL,
    KZT_PATCH_REASON_LAZY_BINDING_DEFERRED,
    KZT_PATCH_REASON_LAZY_BINDING_RESOLVED,
    KZT_PATCH_REASON_PLT_RESOLVER,
    KZT_PATCH_REASON_SYMBOL_MISSING,
    KZT_PATCH_REASON_UNSUPPORTED_RELOCATION,
} KztPatchDecisionReason;

typedef struct KztPatchDecision {
    const char *object;
    uintptr_t object_base;
    const void *relocation;
    size_t relocation_index;
    int relocation_type;
    const char *symbol;
    int symbol_version;
    const char *symbol_version_name;
    uintptr_t slot;
    uintptr_t old_target;
    const char *old_owner;
    uintptr_t old_owner_base;
    uintptr_t new_bridge;
    const char *new_owner;
    uintptr_t new_owner_base;
    KztPatchDecisionReason reason;
} KztPatchDecision;

void KztPatchDecisionInit(KztPatchDecision *decision);
const char *KztPatchDecisionReasonName(KztPatchDecisionReason reason);
const char *KztPatchRelocationTypeName(int relocation_type);
size_t KztFormatPatchDecision(char *buffer, size_t buffer_size,
                              const KztPatchDecision *decision);

#endif //__GUESTPATCH_H_
