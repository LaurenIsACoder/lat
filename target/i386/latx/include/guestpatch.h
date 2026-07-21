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
    KZT_PATCH_REASON_LAZY_BINDING_CURRENT_TARGET,
    KZT_PATCH_REASON_PLT_RESOLVER,
    KZT_PATCH_REASON_GUEST_OWNER_TARGET,
    KZT_PATCH_REASON_SYMBOL_MISSING,
    KZT_PATCH_REASON_UNSUPPORTED_RELOCATION,
} KztPatchDecisionReason;

typedef enum KztPatchOwnerRelation {
    KZT_PATCH_OWNER_RELATION_UNKNOWN,
    KZT_PATCH_OWNER_RELATION_GUEST_ONLY,
    KZT_PATCH_OWNER_RELATION_MAPLIB_ONLY,
    KZT_PATCH_OWNER_RELATION_MATCH,
    KZT_PATCH_OWNER_RELATION_MISMATCH,
} KztPatchOwnerRelation;

typedef enum KztPatchShadowResult {
    KZT_PATCH_SHADOW_DISABLED,
    KZT_PATCH_SHADOW_NO_MAPLIB_TARGET,
    KZT_PATCH_SHADOW_NO_GUEST_OWNER,
    KZT_PATCH_SHADOW_SELF_PLT,
    KZT_PATCH_SHADOW_NO_WRAPPER,
    KZT_PATCH_SHADOW_NO_LIBRARY,
    KZT_PATCH_SHADOW_SYMBOL_MISSING,
    KZT_PATCH_SHADOW_MATCH,
    KZT_PATCH_SHADOW_MISMATCH,
} KztPatchShadowResult;

typedef enum KztPatchTargetSource {
    KZT_PATCH_TARGET_MAPLIB,
    KZT_PATCH_TARGET_GUEST_OWNER,
} KztPatchTargetSource;

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
    const char *old_guest_object;
    uintptr_t old_guest_object_base;
    uintptr_t maplib_bridge;
    const char *maplib_owner;
    uintptr_t maplib_owner_base;
    KztPatchOwnerRelation maplib_owner_relation;
    uintptr_t new_bridge;
    const char *new_owner;
    uintptr_t new_owner_base;
    uintptr_t guest_owner_bridge;
    const char *guest_owner_library;
    const char *guest_owner;
    uintptr_t guest_owner_base;
    KztPatchOwnerRelation guest_owner_relation;
    KztPatchDecisionReason reason;
    KztPatchOwnerRelation owner_relation;
    KztPatchShadowResult shadow_result;
    KztPatchTargetSource target_source;
} KztPatchDecision;

void KztPatchDecisionInit(KztPatchDecision *decision);
int KztPatchDecisionHasTarget(const KztPatchDecision *decision);
void KztPatchDecisionSetMaplibTarget(KztPatchDecision *decision,
                                     uintptr_t bridge,
                                     const char *owner,
                                     uintptr_t owner_base);
void KztPatchDecisionSetGuestOwnerFailure(KztPatchDecision *decision,
                                          KztPatchShadowResult failure);
void KztPatchDecisionSetGuestOwnerTarget(KztPatchDecision *decision,
                                         uintptr_t bridge,
                                         const char *library,
                                         const char *owner,
                                         uintptr_t owner_base,
                                         int select_target);
void KztPatchDecisionSelectGuestOwnerTarget(KztPatchDecision *decision);
KztPatchOwnerRelation KztPatchOwnerRelationForNames(const char *guest_object,
                                                    const char *owner);
const char *KztPatchDecisionReasonName(KztPatchDecisionReason reason);
const char *KztPatchOwnerRelationName(KztPatchOwnerRelation relation);
const char *KztPatchShadowResultName(KztPatchShadowResult result);
const char *KztPatchTargetSourceName(KztPatchTargetSource source);
const char *KztPatchRelocationTypeName(int relocation_type);
size_t KztFormatPatchDecision(char *buffer, size_t buffer_size,
                              const KztPatchDecision *decision);

#endif //__GUESTPATCH_H_
