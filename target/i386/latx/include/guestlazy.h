#ifndef __GUESTLAZY_H_
#define __GUESTLAZY_H_

#include <stdint.h>

#include "elf.h"
#include "guestpatch.h"

typedef struct elfheader_s elfheader_t;
typedef struct CPUX86State CPUX86State;
typedef struct bridge_s bridge_t;

typedef struct KztLazyBinding_s KztLazyBinding;

typedef struct KztLazyResolvePlan_s {
    int opaque_policy;
    int opaque_reason;
} KztLazyResolvePlan;

typedef struct KztLazyResolveResult_s {
    int opaque_policy;
    int opaque_reason;
    uintptr_t opaque_target;
} KztLazyResolveResult;

typedef struct KztLazyRelocationSymbolArgs_s {
    elfheader_t *head;
    Elf64_Sym *symbol_entry;
    const char *symbol;
    int bind;
    int relocation_type;
    uintptr_t current_target;
    int version;
    const char *version_name;
} KztLazyRelocationSymbolArgs;

typedef struct KztLazyPltSymbolArgs_s {
    elfheader_t *head;
    const char *symbol;
    int version;
    const char *version_name;
} KztLazyPltSymbolArgs;

typedef struct KztLazySymbolLookupPlan_s {
    int has_relocation_symbol;
    KztLazyRelocationSymbolArgs relocation_args;
    KztLazyPltSymbolArgs plt_args;
} KztLazySymbolLookupPlan;

typedef struct KztLazyPatchArgs_s {
    elfheader_t *head;
    const Elf64_Rela *relocation;
    size_t relocation_index;
    int relocation_type;
    const char *symbol;
    int version;
    const char *version_name;
    uintptr_t slot;
    uintptr_t old_target;
} KztLazyPatchArgs;

typedef struct KztLazyResolverInstallPlan_s {
    KztLazyPatchArgs resolver_args;
    uintptr_t resolver_bridge;
    KztLazyPatchArgs link_map_args;
    uintptr_t link_map;
    const char *table_name;
    uintptr_t resolver_slot;
} KztLazyResolverInstallPlan;

typedef struct KztLazyTargetPatchPlan_s {
    KztLazyPatchArgs args;
    uintptr_t target;
    KztPatchDecisionReason reason;
    int has_target_slot;
} KztLazyTargetPatchPlan;

typedef struct KztLazyRelocationPatchPlan_s {
    KztLazyPatchArgs args;
    long addend;
    KztPatchDecisionReason reason;
    const char *scope_name;
} KztLazyRelocationPatchPlan;

typedef KztLazyResolveResult (*KztLazyPatchCurrentTargetFn)(
    KztLazyBinding *binding);
typedef void (*KztLazyRelocationHandlerFn)(
    void *opaque, const KztLazyBinding *binding);

void KztLazyHandleRelocation(elfheader_t *head,
                             const Elf64_Rela *relocation,
                             int slot,
                             int bind,
                             const char *symbol,
                             int version,
                             const char *version_name,
                             uint64_t *target_slot,
                             int bindnow,
                             const int *need_resolv,
                             KztLazyRelocationHandlerFn handler,
                             void *opaque);
KztLazySymbolLookupPlan KztLazyPrepareSymbolLookup(
    const KztLazyBinding *binding);
void KztLazyLogRelocationPatch(
    const KztLazyRelocationPatchPlan *patch_plan,
    uintptr_t bridge);
void KztLazyLogDeferredRelocation(const KztLazyBinding *binding);
void KztLazyLogMissingRelocationSlot(const KztLazyBinding *binding);
void KztLazyLogResolvePatch(const KztLazyBinding *binding,
                            uintptr_t target,
                            const char *owner,
                            const KztLazyResolvePlan *plan);
void KztLazyLogResolveMissingSlot(const KztLazyBinding *binding,
                                  const KztLazyResolvePlan *plan);
void KztLazyLogResolveGuestFallback(const KztLazyBinding *binding,
                                    const KztLazyResolvePlan *plan);
int KztLazyRefreshCurrentBinding(KztLazyBinding *binding);
int KztLazyBindingShouldDefer(const KztLazyBinding *binding);
uintptr_t KztLazyEnsureResolverBridge(
    bridge_t *bridge, KztLazyPatchCurrentTargetFn callback);
int KztLazyPrepareResolverInstall(
    elfheader_t *head,
    KztLazyResolverInstallPlan *plan);
KztLazyResolveResult KztLazyResolveResultFromPlan(
    const KztLazyResolvePlan *plan);
KztLazyResolveResult KztLazyResolveResultFromBridgePatch(
    const KztLazyBinding *binding,
    const KztLazyResolvePlan *plan,
    uintptr_t bridge,
    KztLazyTargetPatchPlan *patch_plan);
KztLazyResolvePlan KztLazySelectResolvePlan(
    const KztLazyBinding *binding, int has_bridge);
int KztLazyResolvePlanUsesGuestFallback(
    const KztLazyResolvePlan *plan);
int KztLazyPrepareRelocationPatch(
    const KztLazyBinding *binding,
    KztLazyRelocationPatchPlan *patch_plan);
int KztLazyPrepareDeferredPatch(
    const KztLazyBinding *binding,
    KztLazyTargetPatchPlan *patch_plan);
int KztLazyPrepareUnresolvedPatch(
    const KztLazyBinding *binding,
    KztPatchDecisionReason reason,
    KztLazyTargetPatchPlan *patch_plan);

#endif //__GUESTLAZY_H_
