#include "qemu/osdep.h"
#include "cpu.h"

#include "guestlazy.h"

#include "bridge.h"
#include "debug.h"
#include "elfload_dump.h"
#include "elfloader.h"
#include "elfloader_private.h"
#include "lsenv.h"
#include "wrapper.h"

static uintptr_t pltResolver = ~0LL;
static uintptr_t dl_runtime_resolver = ~0LL;
static KztLazyPatchCurrentTargetFn kzt_lazy_patch_current_target;

typedef enum KztLazySlotState {
    KZT_LAZY_SLOT_BOUND,
    KZT_LAZY_SLOT_UNBOUND,
} KztLazySlotState;

typedef enum KztLazyResolvePolicy {
    KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK,
    KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE,
} KztLazyResolvePolicy;

typedef enum KztLazyResolveReason {
    KZT_LAZY_RESOLVE_REASON_NO_BRIDGE,
    KZT_LAZY_RESOLVE_REASON_RESOLVED_BRIDGE,
    KZT_LAZY_RESOLVE_REASON_CURRENT_TARGET_BRIDGE,
} KztLazyResolveReason;

typedef enum KztLazyRelocationLog {
    KZT_LAZY_RELOCATION_LOG_DEFERRED,
    KZT_LAZY_RELOCATION_LOG_PATCH,
    KZT_LAZY_RELOCATION_LOG_MISSING_SLOT,
} KztLazyRelocationLog;

typedef enum KztLazyResolveLog {
    KZT_LAZY_RESOLVE_LOG_PATCH,
    KZT_LAZY_RESOLVE_LOG_MISSING_SLOT,
    KZT_LAZY_RESOLVE_LOG_GUEST_FALLBACK,
} KztLazyResolveLog;

typedef enum KztLazyRelocationAction {
    KZT_LAZY_RELOCATION_ACTION_PATCH,
    KZT_LAZY_RELOCATION_ACTION_DEFER,
} KztLazyRelocationAction;

typedef enum KztLazyResolveAction {
    KZT_LAZY_RESOLVE_ACTION_GUEST_FALLBACK,
    KZT_LAZY_RESOLVE_ACTION_PATCH_BRIDGE,
} KztLazyResolveAction;

typedef struct KztLazyPatchSite_s {
    elfheader_t *head;
    Elf64_Rela *relocation;
    Elf64_Sym *symbol_entry;
    size_t relocation_index;
    int relocation_type;
    const char *symbol;
    int bind;
    int version;
    const char *version_name;
    uintptr_t slot;
    uintptr_t old_target;
    uintptr_t current_target;
    uintptr_t relocated_target;
    long addend;
    int has_target_slot;
    const char *scope_name;
} KztLazyPatchSite;

typedef struct KztLazyResolverTable_s {
    uintptr_t table;
    const char *table_name;
    uintptr_t resolver_slot;
    uintptr_t link_map_slot;
    uintptr_t resolver;
    uintptr_t link_map;
} KztLazyResolverTable;

struct KztLazyBinding_s {
    elfheader_t *head;
    Elf64_Rela *relocation;
    int slot;
    int bind;
    const char *symbol;
    int version;
    const char *version_name;
    uint64_t *target_slot;
    uintptr_t current_target;
    KztLazySlotState slot_state;
};

typedef struct KztLazyResolverFrame_s {
    elfheader_t *head;
    int slot;
    uintptr_t return_address;
} KztLazyResolverFrame;

typedef struct KztLazySymbolLookup_s {
    elfheader_t *head;
    Elf64_Sym *symbol_entry;
    const char *symbol;
    int bind;
    int relocation_type;
    uintptr_t current_target;
    int version;
    const char *version_name;
} KztLazySymbolLookup;

static void PltResolver(void);
static int kzt_lazy_refresh_binding(KztLazyBinding *binding,
                                    int bindnow,
                                    const int *need_resolv);
static KztLazySlotState kzt_lazy_classify_jump_slot(
    const elfheader_t *head,
    const uint64_t *slot,
    int bind,
    int bindnow,
    const int *need_resolv);
static const char *kzt_lazy_resolve_plan_policy_name(
    const KztLazyResolvePlan *plan);
static const char *kzt_lazy_resolve_plan_reason_name(
    const KztLazyResolvePlan *plan);
static uintptr_t kzt_lazy_patch_site_prepare_deferred(
    KztLazyPatchSite *site);
static KztPatchDecisionReason kzt_lazy_resolve_plan_patch_reason(
    const KztLazyResolvePlan *plan);
static int kzt_lazy_patch_site_has_target_slot(
    const KztLazyPatchSite *site);
static long kzt_lazy_patch_site_addend(const KztLazyPatchSite *site);
static KztPatchDecisionReason kzt_lazy_symbol_patch_reason(
    const KztLazyBinding *binding);

/*
 * Stage 6 keeps the current first-call KZT PLT resolver behavior, but moves
 * guest lazy-binding frame handling out of the generic relocation code.  The
 * remaining policy switch can now be changed here without reworking
 * RelocateElfRELA().
 */
static KztLazySlotState kzt_lazy_classify_jump_slot(
    const elfheader_t *head,
    const uint64_t *slot,
    int bind,
    int bindnow,
    const int *need_resolv)
{
    uintptr_t target = slot ? (uintptr_t)*slot : 0;

    if (bind == STB_LOCAL || !target || !need_resolv || bindnow)
        return KZT_LAZY_SLOT_BOUND;
    if ((target >= head->plt && target < head->plt_end)
        || (target >= head->gotplt && target < head->gotplt_end)) {
        return KZT_LAZY_SLOT_UNBOUND;
    }
    return KZT_LAZY_SLOT_BOUND;
}

static KztLazyBinding kzt_lazy_binding_from_relocation(
    elfheader_t *head,
    const Elf64_Rela *relocation,
    int slot,
    int bind,
    const char *symbol,
    int version,
    const char *version_name,
    uint64_t *target_slot,
    int bindnow,
    const int *need_resolv)
{
    KztLazyBinding binding = {
        .head = head,
        .relocation = (Elf64_Rela *)relocation,
        .slot = slot,
        .bind = bind,
        .symbol = symbol,
        .version = version,
        .version_name = version_name,
        .target_slot = target_slot,
    };

    kzt_lazy_refresh_binding(&binding, bindnow, need_resolv);
    return binding;
}

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
                             void *opaque)
{
    if (!handler)
        return;

    KztLazyBinding binding = kzt_lazy_binding_from_relocation(
        head, relocation, slot, bind, symbol, version, version_name,
        target_slot, bindnow, need_resolv);
    handler(opaque, &binding);
}

static KztLazyBinding kzt_lazy_binding_from_slot(elfheader_t *head, int slot)
{
    KztLazyBinding binding = {
        .head = head,
        .slot = slot,
        .version = -1,
    };

    binding.relocation = (Elf64_Rela *)(head->jmprel + head->delta) + slot;
    Elf64_Sym *sym = &head->DynSym[ELF64_R_SYM(binding.relocation->r_info)];
    binding.bind = ELF64_ST_BIND(sym->st_info);
    binding.symbol = SymName(head, sym);
    binding.version = head->VerSym
        ? ((Elf64_Half *)((uintptr_t)head->VerSym + head->delta))[
              ELF64_R_SYM(binding.relocation->r_info)]
        : -1;
    if (binding.version != -1)
        binding.version &= 0x7fff;
    binding.version_name = GetSymbolVersion(head, binding.version);
    binding.target_slot =
        (uint64_t *)(binding.relocation->r_offset + head->delta);
    kzt_lazy_refresh_binding(&binding, 0, &binding.slot);
    return binding;
}

static const char *kzt_lazy_symbol_name(const KztLazyBinding *binding);

static int kzt_lazy_has_target_slot(const KztLazyBinding *binding)
{
    return binding && binding->target_slot;
}

static uintptr_t kzt_lazy_target_slot_address(const KztLazyBinding *binding)
{
    if (!kzt_lazy_has_target_slot(binding))
        return 0;

    return (uintptr_t)binding->target_slot;
}

static uintptr_t kzt_lazy_read_target_slot(const KztLazyBinding *binding)
{
    if (!kzt_lazy_has_target_slot(binding))
        return 0;

    return *binding->target_slot;
}

static uintptr_t kzt_lazy_current_target(const KztLazyBinding *binding)
{
    if (!binding)
        return 0;

    return binding->current_target;
}

static uintptr_t kzt_lazy_current_target_with_delta(
    const KztLazyBinding *binding)
{
    if (!binding || !binding->head)
        return 0;

    return kzt_lazy_current_target(binding) + binding->head->delta;
}

static KztLazyPatchSite kzt_lazy_patch_site_from_binding(
    const KztLazyBinding *binding)
{
    KztLazyPatchSite site = {
        .head = binding ? binding->head : NULL,
        .relocation = binding ? binding->relocation : NULL,
        .symbol_entry = NULL,
        .relocation_index = binding ? binding->slot : 0,
        .relocation_type = R_X86_64_JUMP_SLOT,
        .symbol = kzt_lazy_symbol_name(binding),
        .bind = binding ? binding->bind : STB_GLOBAL,
        .version = binding ? binding->version : -1,
        .version_name = binding ? binding->version_name : NULL,
        .slot = kzt_lazy_target_slot_address(binding),
        .old_target = kzt_lazy_read_target_slot(binding),
        .current_target = kzt_lazy_current_target(binding),
        .relocated_target = kzt_lazy_current_target_with_delta(binding),
        .addend = binding && binding->relocation
            ? binding->relocation->r_addend
            : 0,
        .has_target_slot = kzt_lazy_has_target_slot(binding),
        .scope_name = binding && binding->bind == STB_LOCAL
            ? "Local"
            : "Global",
    };

    if (site.head && site.relocation) {
        site.symbol_entry =
            &site.head->DynSym[ELF64_R_SYM(site.relocation->r_info)];
    }

    return site;
}

static KztLazyPatchSite kzt_lazy_deferred_patch_site_from_binding(
    const KztLazyBinding *binding)
{
    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    kzt_lazy_patch_site_prepare_deferred(&site);
    return site;
}

static int kzt_lazy_patch_site_has_target_slot(
    const KztLazyPatchSite *site)
{
    return site && site->has_target_slot;
}

static uintptr_t kzt_lazy_patch_site_prepare_deferred(
    KztLazyPatchSite *site)
{
    if (!site)
        return 0;

    site->old_target = site->current_target;
    return site->relocated_target;
}

static uintptr_t kzt_lazy_patch_site_deferred_target(
    const KztLazyPatchSite *site)
{
    return site ? site->relocated_target : 0;
}

static long kzt_lazy_patch_site_addend(const KztLazyPatchSite *site)
{
    return site ? site->addend : 0;
}

static KztLazyPatchArgs kzt_lazy_patch_args_from_site(
    const KztLazyPatchSite *site)
{
    KztLazyPatchArgs args = {
        .head = site ? site->head : NULL,
        .relocation = site ? site->relocation : NULL,
        .relocation_index = site ? site->relocation_index : 0,
        .relocation_type = site
            ? site->relocation_type
            : R_X86_64_JUMP_SLOT,
        .symbol = site ? site->symbol : NULL,
        .version = site ? site->version : -1,
        .version_name = site ? site->version_name : NULL,
        .slot = site ? site->slot : 0,
        .old_target = site ? site->old_target : 0,
    };

    return args;
}

static KztLazySymbolLookup kzt_lazy_symbol_lookup_from_binding(
    const KztLazyBinding *binding)
{
    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);
    KztLazySymbolLookup lookup = {
        .head = site.head,
        .symbol_entry = site.symbol_entry,
        .symbol = site.symbol,
        .bind = site.bind,
        .relocation_type = site.relocation_type,
        .current_target = site.current_target,
        .version = site.version,
        .version_name = site.version_name,
    };

    return lookup;
}

static int kzt_lazy_symbol_lookup_has_relocation_symbol(
    const KztLazySymbolLookup *lookup)
{
    return lookup && lookup->symbol_entry;
}

static KztLazyRelocationSymbolArgs kzt_lazy_symbol_lookup_relocation_args(
    const KztLazySymbolLookup *lookup)
{
    KztLazyRelocationSymbolArgs args = {
        .head = lookup ? lookup->head : NULL,
        .symbol_entry = lookup ? lookup->symbol_entry : NULL,
        .symbol = lookup ? lookup->symbol : NULL,
        .bind = lookup ? lookup->bind : STB_GLOBAL,
        .relocation_type = lookup
            ? lookup->relocation_type
            : R_X86_64_JUMP_SLOT,
        .current_target = lookup ? lookup->current_target : 0,
        .version = lookup ? lookup->version : -1,
        .version_name = lookup ? lookup->version_name : NULL,
    };

    return args;
}

static KztLazyPltSymbolArgs kzt_lazy_symbol_lookup_plt_args(
    const KztLazySymbolLookup *lookup)
{
    KztLazyPltSymbolArgs args = {
        .head = lookup ? lookup->head : NULL,
        .symbol = lookup ? lookup->symbol : NULL,
        .version = lookup ? lookup->version : -1,
        .version_name = lookup ? lookup->version_name : NULL,
    };

    return args;
}

static int kzt_lazy_binding_has_relocation_symbol(
    const KztLazyBinding *binding)
{
    KztLazySymbolLookup lookup =
        kzt_lazy_symbol_lookup_from_binding(binding);

    return kzt_lazy_symbol_lookup_has_relocation_symbol(&lookup);
}

static KztLazyRelocationSymbolArgs kzt_lazy_relocation_symbol_args_from_binding(
    const KztLazyBinding *binding)
{
    KztLazySymbolLookup lookup =
        kzt_lazy_symbol_lookup_from_binding(binding);

    return kzt_lazy_symbol_lookup_relocation_args(&lookup);
}

static KztLazyPltSymbolArgs kzt_lazy_plt_symbol_args_from_binding(
    const KztLazyBinding *binding)
{
    KztLazySymbolLookup lookup =
        kzt_lazy_symbol_lookup_from_binding(binding);

    return kzt_lazy_symbol_lookup_plt_args(&lookup);
}

KztLazySymbolLookupPlan KztLazyPrepareSymbolLookup(
    const KztLazyBinding *binding)
{
    KztLazySymbolLookupPlan plan = {
        .has_relocation_symbol =
            kzt_lazy_binding_has_relocation_symbol(binding),
        .relocation_args =
            kzt_lazy_relocation_symbol_args_from_binding(binding),
        .plt_args = kzt_lazy_plt_symbol_args_from_binding(binding),
    };

    return plan;
}

static void kzt_lazy_log_deferred_binding(const KztLazyPatchSite *site)
{
    printf_log(LOG_INFO,
               "Preparing (if needed) %s R_X86_64_JUMP_SLOT @%p "
               "(0x%lx->0x%0lx) with sym=%s to be apply later "
               "(addend=%ld)\n",
               site->scope_name,
               (void *)site->slot, site->current_target,
               site->relocated_target, site->symbol, site->addend);
}

static void kzt_lazy_log_relocation_patch(const KztLazyPatchSite *site,
                                          uintptr_t bridge)
{
    printf_log(LOG_INFO,
               "RelocateElfRELA : Apply %s R_X86_64_JUMP_SLOT "
               "@%p with sym=%s (%p -> %p)\n",
               site->scope_name,
               (void *)site->slot, site->symbol,
               (void *)site->old_target, (void *)bridge);
}

static void kzt_lazy_log_missing_relocation_slot(
    const KztLazyPatchSite *site)
{
    printf_log(LOG_INFO,
               "Warning, Symbol %s found, but Jump Slot Offset is "
               "NULL \n",
               site->symbol);
}

static void kzt_lazy_log_resolved_target(const KztLazyPatchSite *site,
                                         uintptr_t target,
                                         const char *owner,
                                         const KztLazyResolvePlan *plan)
{
    printf_log(LOG_INFO,
               "            Apply %s R_X86_64_JUMP_SLOT %p with "
               "sym=%s(ver %d: %s%s%s) (%p -> %p / %s, reason=%s)\n",
               site->scope_name, (void *)site->slot,
               site->symbol, site->version, site->symbol,
               site->version_name ? "@" : "",
               site->version_name ? site->version_name : "",
               (void *)site->old_target, (void *)target, owner,
               kzt_lazy_resolve_plan_reason_name(plan));
}

static void kzt_lazy_log_missing_resolved_slot(
    const KztLazyPatchSite *site)
{
    printf_log(LOG_INFO,
               "PltResolver: Warning, Symbol %s(ver %d: %s%s%s) found, "
               "but Jump Slot Offset is NULL \n",
               site->symbol, site->version, site->symbol,
               site->version_name ? "@" : "",
               site->version_name ? site->version_name : "");
}

static void kzt_lazy_log_guest_fallback(const KztLazyPatchSite *site,
                                        const KztLazyResolvePlan *plan)
{
    printf_log(LOG_INFO,
               "PltResolver: keep guest resolver for %s "
               "(policy=%s reason=%s)\n",
               site->symbol,
               kzt_lazy_resolve_plan_policy_name(plan),
               kzt_lazy_resolve_plan_reason_name(plan));
}

static void kzt_lazy_log_relocation(const KztLazyPatchSite *site,
                                    KztLazyRelocationLog type,
                                    uintptr_t bridge)
{
    switch (type) {
    case KZT_LAZY_RELOCATION_LOG_DEFERRED:
        kzt_lazy_log_deferred_binding(site);
        return;
    case KZT_LAZY_RELOCATION_LOG_PATCH:
        kzt_lazy_log_relocation_patch(site, bridge);
        return;
    case KZT_LAZY_RELOCATION_LOG_MISSING_SLOT:
        kzt_lazy_log_missing_relocation_slot(site);
        return;
    }
}

static void kzt_lazy_log_binding_relocation(
    const KztLazyBinding *binding,
    KztLazyRelocationLog type,
    uintptr_t bridge)
{
    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    kzt_lazy_log_relocation(&site, type, bridge);
}

void KztLazyLogDeferredRelocation(const KztLazyBinding *binding)
{
    kzt_lazy_log_binding_relocation(
        binding, KZT_LAZY_RELOCATION_LOG_DEFERRED, 0);
}

void KztLazyLogMissingRelocationSlot(const KztLazyBinding *binding)
{
    kzt_lazy_log_binding_relocation(
        binding, KZT_LAZY_RELOCATION_LOG_MISSING_SLOT, 0);
}

void KztLazyLogRelocationPatch(
    const KztLazyRelocationPatchPlan *patch_plan,
    uintptr_t bridge)
{
    if (!patch_plan)
        return;

    KztLazyPatchSite site = {
        .symbol = patch_plan->args.symbol,
        .slot = patch_plan->args.slot,
        .old_target = patch_plan->args.old_target,
        .scope_name = patch_plan->scope_name,
    };

    kzt_lazy_log_relocation(
        &site, KZT_LAZY_RELOCATION_LOG_PATCH, bridge);
}

static void kzt_lazy_log_resolve(const KztLazyPatchSite *site,
                                 KztLazyResolveLog type,
                                 uintptr_t target,
                                 const char *owner,
                                 const KztLazyResolvePlan *plan)
{
    switch (type) {
    case KZT_LAZY_RESOLVE_LOG_PATCH:
        kzt_lazy_log_resolved_target(site, target, owner, plan);
        return;
    case KZT_LAZY_RESOLVE_LOG_MISSING_SLOT:
        kzt_lazy_log_missing_resolved_slot(site);
        return;
    case KZT_LAZY_RESOLVE_LOG_GUEST_FALLBACK:
        kzt_lazy_log_guest_fallback(site, plan);
        return;
    }
}

static void kzt_lazy_log_binding_resolve(
    const KztLazyBinding *binding,
    KztLazyResolveLog type,
    uintptr_t target,
    const char *owner,
    const KztLazyResolvePlan *plan)
{
    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    kzt_lazy_log_resolve(&site, type, target, owner, plan);
}

void KztLazyLogResolvePatch(const KztLazyBinding *binding,
                            uintptr_t target,
                            const char *owner,
                            const KztLazyResolvePlan *plan)
{
    kzt_lazy_log_binding_resolve(
        binding, KZT_LAZY_RESOLVE_LOG_PATCH, target, owner, plan);
}

void KztLazyLogResolveMissingSlot(const KztLazyBinding *binding,
                                  const KztLazyResolvePlan *plan)
{
    kzt_lazy_log_binding_resolve(
        binding, KZT_LAZY_RESOLVE_LOG_MISSING_SLOT, 0, NULL, plan);
}

void KztLazyLogResolveGuestFallback(const KztLazyBinding *binding,
                                    const KztLazyResolvePlan *plan)
{
    kzt_lazy_log_binding_resolve(
        binding, KZT_LAZY_RESOLVE_LOG_GUEST_FALLBACK, 0, NULL, plan);
}

static const char *kzt_lazy_symbol_name(const KztLazyBinding *binding)
{
    return binding && binding->symbol ? binding->symbol : "";
}

static KztPatchDecisionReason kzt_lazy_symbol_patch_reason(
    const KztLazyBinding *binding)
{
    return binding && binding->bind == STB_LOCAL
        ? KZT_PATCH_REASON_LOCAL_SYMBOL
        : KZT_PATCH_REASON_GLOBAL_SYMBOL;
}

static int kzt_lazy_refresh_binding(KztLazyBinding *binding,
                                    int bindnow,
                                    const int *need_resolv)
{
    uintptr_t previous_target;

    if (!binding)
        return 0;

    previous_target = binding->current_target;
    binding->current_target = kzt_lazy_read_target_slot(binding);
    binding->slot_state = kzt_lazy_classify_jump_slot(
        binding->head, binding->target_slot, binding->bind, bindnow,
        need_resolv);

    return previous_target != binding->current_target;
}

int KztLazyRefreshCurrentBinding(KztLazyBinding *binding)
{
    if (!binding)
        return 0;

    return kzt_lazy_refresh_binding(binding, 0, &binding->slot);
}

static int kzt_lazy_binding_needs_guest_resolver(
    const KztLazyBinding *binding)
{
    return binding && binding->slot_state == KZT_LAZY_SLOT_UNBOUND;
}

static int kzt_lazy_binding_has_bound_target(const KztLazyBinding *binding)
{
    return binding && binding->slot_state == KZT_LAZY_SLOT_BOUND
        && binding->current_target;
}

static KztLazyRelocationAction kzt_lazy_select_relocation_action(
    const KztLazyBinding *binding)
{
    return kzt_lazy_binding_needs_guest_resolver(binding)
        ? KZT_LAZY_RELOCATION_ACTION_DEFER
        : KZT_LAZY_RELOCATION_ACTION_PATCH;
}

int KztLazyBindingShouldDefer(const KztLazyBinding *binding)
{
    return kzt_lazy_select_relocation_action(binding)
        == KZT_LAZY_RELOCATION_ACTION_DEFER;
}

static uintptr_t kzt_lazy_bridge_target(uintptr_t bridge)
{
    return (uintptr_t)getAlternate((void *)bridge);
}

static void kzt_lazy_observe_bound_target(const KztLazyBinding *binding,
                                          uintptr_t target)
{
    uintptr_t current_target;

    if (!kzt_lazy_binding_has_bound_target(binding))
        return;

    current_target = kzt_lazy_current_target(binding);
    if (current_target == target)
        return;

    addAlternate((void *)current_target, (void *)target);
}

static uintptr_t kzt_lazy_target_from_bridge(
    const KztLazyBinding *binding, uintptr_t bridge)
{
    uintptr_t target = kzt_lazy_bridge_target(bridge);

    kzt_lazy_observe_bound_target(binding, target);
    return target;
}

static uint64_t kzt_lazy_pop64(CPUX86State *cpu)
{
    uint64_t *stack = (uint64_t *)cpu->regs[R_ESP];
    cpu->regs[R_ESP] += 8;

    return *stack;
}

static void kzt_lazy_push64(CPUX86State *cpu, uint64_t value)
{
    cpu->regs[R_ESP] -= 8;
    *(uint64_t *)cpu->regs[R_ESP] = value;
}

static KztLazyResolverFrame kzt_lazy_read_resolver_frame(CPUX86State *cpu)
{
    uintptr_t addr = kzt_lazy_pop64(cpu);
    KztLazyResolverFrame frame = {
        .head = (elfheader_t *)addr,
        .slot = (int)kzt_lazy_pop64(cpu),
        .return_address = *(uintptr_t *)cpu->regs[R_ESP],
    };

    return frame;
}

static KztLazyResolverTable kzt_lazy_read_resolver_table(
    uintptr_t table, const char *table_name)
{
    KztLazyResolverTable resolver_table = {
        .table = table,
        .table_name = table_name,
        .resolver_slot = table + 16,
        .link_map_slot = table + 8,
    };

    resolver_table.resolver = *(uintptr_t *)resolver_table.resolver_slot;
    resolver_table.link_map = *(uintptr_t *)resolver_table.link_map_slot;
    return resolver_table;
}

static int kzt_lazy_find_resolver_table(
    elfheader_t *head, KztLazyResolverTable *resolver_table)
{
    if (!head || !resolver_table)
        return 0;

    if (head->pltgot) {
        *resolver_table = kzt_lazy_read_resolver_table(
            head->pltgot + head->delta, "plt.got");
        return 1;
    }
    if (head->got) {
        *resolver_table = kzt_lazy_read_resolver_table(
            head->got + head->delta, "got");
        return 1;
    }

    return 0;
}

static uintptr_t kzt_lazy_get_resolver_bridge(void)
{
    return pltResolver;
}

static int kzt_lazy_has_resolver_bridge(void)
{
    return pltResolver != ~0LL;
}

static void kzt_lazy_set_resolver_bridge(uintptr_t bridge)
{
    pltResolver = bridge;
}

static void kzt_lazy_set_patch_current_target_callback(
    KztLazyPatchCurrentTargetFn callback)
{
    kzt_lazy_patch_current_target = callback;
}

uintptr_t KztLazyEnsureResolverBridge(
    bridge_t *bridge, KztLazyPatchCurrentTargetFn callback)
{
    kzt_lazy_set_patch_current_target_callback(callback);

    if (!kzt_lazy_has_resolver_bridge()) {
        kzt_lazy_set_resolver_bridge(
            AddBridge(bridge, vFE, PltResolver, 0, "PltResolver"));
    }

    return kzt_lazy_get_resolver_bridge();
}

static uintptr_t kzt_lazy_remember_guest_resolver(uintptr_t resolver)
{
    if (dl_runtime_resolver == ~0LL)
        dl_runtime_resolver = resolver;

    return dl_runtime_resolver;
}

static uintptr_t kzt_lazy_activate_resolver_table(
    const KztLazyResolverTable *resolver_table)
{
    if (!resolver_table)
        return 0;

    kzt_lazy_remember_guest_resolver(resolver_table->resolver);
    return kzt_lazy_get_resolver_bridge();
}

static KztLazyPatchSite kzt_lazy_resolver_table_resolver_site(
    elfheader_t *head, const KztLazyResolverTable *resolver_table)
{
    KztLazyPatchSite site = {
        .head = head,
        .symbol = "plt-resolver",
        .version = -1,
        .slot = resolver_table ? resolver_table->resolver_slot : 0,
        .old_target = resolver_table ? resolver_table->resolver : 0,
        .has_target_slot = resolver_table != NULL,
        .scope_name = "Global",
    };

    return site;
}

static KztLazyPatchSite kzt_lazy_resolver_table_link_map_site(
    elfheader_t *head, const KztLazyResolverTable *resolver_table)
{
    KztLazyPatchSite site = {
        .head = head,
        .symbol = "plt-link-map",
        .version = -1,
        .slot = resolver_table ? resolver_table->link_map_slot : 0,
        .old_target = resolver_table ? resolver_table->link_map : 0,
        .has_target_slot = resolver_table != NULL,
        .scope_name = "Global",
    };

    return site;
}

static const char *kzt_lazy_resolver_table_name(
    const KztLazyResolverTable *resolver_table)
{
    return resolver_table ? resolver_table->table_name : "";
}

static uintptr_t kzt_lazy_resolver_table_link_map(
    const KztLazyResolverTable *resolver_table)
{
    return resolver_table ? resolver_table->link_map : 0;
}

static uintptr_t kzt_lazy_resolver_table_resolver_slot(
    const KztLazyResolverTable *resolver_table)
{
    return resolver_table ? resolver_table->resolver_slot : 0;
}

int KztLazyPrepareResolverInstall(
    elfheader_t *head,
    KztLazyResolverInstallPlan *plan)
{
    KztLazyResolverTable resolver_table;

    if (!plan)
        return 0;
    if (!kzt_lazy_find_resolver_table(head, &resolver_table))
        return 0;

    plan->resolver_bridge = kzt_lazy_activate_resolver_table(&resolver_table);
    KztLazyPatchSite resolver_site =
        kzt_lazy_resolver_table_resolver_site(head, &resolver_table);
    KztLazyPatchSite link_map_site =
        kzt_lazy_resolver_table_link_map_site(head, &resolver_table);
    plan->resolver_args = kzt_lazy_patch_args_from_site(&resolver_site);
    plan->link_map_args = kzt_lazy_patch_args_from_site(&link_map_site);
    plan->link_map = kzt_lazy_resolver_table_link_map(&resolver_table);
    plan->table_name = kzt_lazy_resolver_table_name(&resolver_table);
    plan->resolver_slot =
        kzt_lazy_resolver_table_resolver_slot(&resolver_table);
    return 1;
}

static void kzt_lazy_return_to_guest_resolver(
    CPUX86State *cpu,
    const KztLazyBinding *binding,
    uintptr_t dl_runtime_resolver)
{
    kzt_lazy_push64(cpu, binding->slot);
    kzt_lazy_push64(cpu, binding->head->self_link_map);
    kzt_lazy_push64(cpu, dl_runtime_resolver);
}

static KztLazyResolveResult kzt_lazy_resolve_result_return_to_guest(
    KztLazyResolveReason reason)
{
    KztLazyResolveResult result = {
        .opaque_policy = KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK,
        .opaque_reason = reason,
        .opaque_target = 0,
    };

    return result;
}

static KztLazyResolveResult kzt_lazy_resolve_result_call_bridge(
    uintptr_t target, KztLazyResolveReason reason)
{
    KztLazyResolveResult result = {
        .opaque_policy = KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE,
        .opaque_reason = reason,
        .opaque_target = target,
    };

    return result;
}

static KztLazyResolveReason kzt_lazy_select_bridge_reason(
    const KztLazyBinding *binding)
{
    if (kzt_lazy_binding_has_bound_target(binding))
        return KZT_LAZY_RESOLVE_REASON_CURRENT_TARGET_BRIDGE;

    return KZT_LAZY_RESOLVE_REASON_RESOLVED_BRIDGE;
}

static KztPatchDecisionReason kzt_lazy_patch_reason_for_resolve_reason(
    KztLazyResolveReason reason)
{
    if (reason == KZT_LAZY_RESOLVE_REASON_CURRENT_TARGET_BRIDGE)
        return KZT_PATCH_REASON_LAZY_BINDING_CURRENT_TARGET;

    return KZT_PATCH_REASON_LAZY_BINDING_RESOLVED;
}

KztLazyResolvePlan KztLazySelectResolvePlan(
    const KztLazyBinding *binding, int has_bridge)
{
    if (!has_bridge) {
        KztLazyResolvePlan plan = {
            .opaque_policy = KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK,
            .opaque_reason = KZT_LAZY_RESOLVE_REASON_NO_BRIDGE,
        };
        return plan;
    }

    KztLazyResolvePlan plan = {
        .opaque_policy = KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE,
        .opaque_reason = kzt_lazy_select_bridge_reason(binding),
    };
    return plan;
}

static KztLazyResolveAction kzt_lazy_resolve_plan_action(
    const KztLazyResolvePlan *plan)
{
    return plan
        && plan->opaque_policy == KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE
        ? KZT_LAZY_RESOLVE_ACTION_PATCH_BRIDGE
        : KZT_LAZY_RESOLVE_ACTION_GUEST_FALLBACK;
}

int KztLazyResolvePlanUsesGuestFallback(
    const KztLazyResolvePlan *plan)
{
    return kzt_lazy_resolve_plan_action(plan)
        == KZT_LAZY_RESOLVE_ACTION_GUEST_FALLBACK;
}

static KztLazyResolvePolicy kzt_lazy_resolve_plan_policy(
    const KztLazyResolvePlan *plan)
{
    return plan
        ? plan->opaque_policy
        : KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK;
}

static KztLazyResolveReason kzt_lazy_resolve_plan_reason(
    const KztLazyResolvePlan *plan)
{
    return plan ? plan->opaque_reason : KZT_LAZY_RESOLVE_REASON_NO_BRIDGE;
}

static KztLazyResolveResult kzt_lazy_resolve_result_from_bridge(
    const KztLazyBinding *binding,
    const KztLazyResolvePlan *plan,
    uintptr_t bridge)
{
    uintptr_t target = kzt_lazy_target_from_bridge(binding, bridge);

    return kzt_lazy_resolve_result_call_bridge(
        target, kzt_lazy_resolve_plan_reason(plan));
}

KztLazyResolveResult KztLazyResolveResultFromPlan(
    const KztLazyResolvePlan *plan)
{
    return kzt_lazy_resolve_result_return_to_guest(
        kzt_lazy_resolve_plan_reason(plan));
}

static uintptr_t kzt_lazy_resolve_result_target(
    const KztLazyResolveResult *result)
{
    return result ? result->opaque_target : 0;
}

static KztLazyResolvePolicy kzt_lazy_resolve_result_policy(
    const KztLazyResolveResult *result)
{
    return result
        ? result->opaque_policy
        : KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK;
}

static KztLazyResolveReason kzt_lazy_resolve_result_reason(
    const KztLazyResolveResult *result)
{
    return result
        ? result->opaque_reason
        : KZT_LAZY_RESOLVE_REASON_NO_BRIDGE;
}

static KztPatchDecisionReason kzt_lazy_resolve_plan_patch_reason(
    const KztLazyResolvePlan *plan)
{
    return kzt_lazy_patch_reason_for_resolve_reason(
        kzt_lazy_resolve_plan_reason(plan));
}

static int kzt_lazy_prepare_resolve_patch(
    const KztLazyBinding *binding,
    const KztLazyResolvePlan *resolve_plan,
    uintptr_t target,
    KztLazyTargetPatchPlan *patch_plan)
{
    if (!patch_plan)
        return 0;

    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    patch_plan->args = kzt_lazy_patch_args_from_site(&site);
    patch_plan->target = target;
    patch_plan->reason =
        kzt_lazy_resolve_plan_patch_reason(resolve_plan);
    patch_plan->has_target_slot =
        kzt_lazy_patch_site_has_target_slot(&site);
    return patch_plan->has_target_slot;
}

KztLazyResolveResult KztLazyResolveResultFromBridgePatch(
    const KztLazyBinding *binding,
    const KztLazyResolvePlan *plan,
    uintptr_t bridge,
    KztLazyTargetPatchPlan *patch_plan)
{
    KztLazyResolveResult result =
        kzt_lazy_resolve_result_from_bridge(binding, plan, bridge);

    kzt_lazy_prepare_resolve_patch(
        binding, plan, kzt_lazy_resolve_result_target(&result),
        patch_plan);
    return result;
}

int KztLazyPrepareDeferredPatch(
    const KztLazyBinding *binding,
    KztLazyTargetPatchPlan *patch_plan)
{
    if (!patch_plan)
        return 0;

    KztLazyPatchSite site = kzt_lazy_deferred_patch_site_from_binding(binding);

    patch_plan->args = kzt_lazy_patch_args_from_site(&site);
    patch_plan->target =
        kzt_lazy_patch_site_deferred_target(&site);
    patch_plan->reason = KZT_PATCH_REASON_LAZY_BINDING_DEFERRED;
    patch_plan->has_target_slot =
        kzt_lazy_patch_site_has_target_slot(&site);
    return 1;
}

int KztLazyPrepareUnresolvedPatch(
    const KztLazyBinding *binding,
    KztPatchDecisionReason reason,
    KztLazyTargetPatchPlan *patch_plan)
{
    if (!patch_plan)
        return 0;

    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    patch_plan->args = kzt_lazy_patch_args_from_site(&site);
    patch_plan->target = 0;
    patch_plan->reason = reason;
    patch_plan->has_target_slot =
        kzt_lazy_patch_site_has_target_slot(&site);
    return 1;
}

int KztLazyPrepareRelocationPatch(
    const KztLazyBinding *binding,
    KztLazyRelocationPatchPlan *patch_plan)
{
    if (!patch_plan)
        return 0;

    KztLazyPatchSite site = kzt_lazy_patch_site_from_binding(binding);

    patch_plan->args = kzt_lazy_patch_args_from_site(&site);
    patch_plan->addend = kzt_lazy_patch_site_addend(&site);
    patch_plan->reason = kzt_lazy_symbol_patch_reason(binding);
    patch_plan->scope_name = site.scope_name;
    return kzt_lazy_patch_site_has_target_slot(&site);
}

static const char *kzt_lazy_resolve_policy_name(
    KztLazyResolvePolicy policy)
{
    switch (policy) {
    case KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK:
        return "guest-fallback";
    case KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE:
        return "direct-bridge";
    }
    return "unknown";
}

static const char *kzt_lazy_resolve_reason_name(
    KztLazyResolveReason reason)
{
    switch (reason) {
    case KZT_LAZY_RESOLVE_REASON_NO_BRIDGE:
        return "no-bridge";
    case KZT_LAZY_RESOLVE_REASON_RESOLVED_BRIDGE:
        return "resolved-bridge";
    case KZT_LAZY_RESOLVE_REASON_CURRENT_TARGET_BRIDGE:
        return "current-target-bridge";
    }
    return "unknown";
}

static const char *kzt_lazy_resolve_plan_policy_name(
    const KztLazyResolvePlan *plan)
{
    return kzt_lazy_resolve_policy_name(kzt_lazy_resolve_plan_policy(plan));
}

static const char *kzt_lazy_resolve_plan_reason_name(
    const KztLazyResolvePlan *plan)
{
    return kzt_lazy_resolve_reason_name(kzt_lazy_resolve_plan_reason(plan));
}

static KztLazyResolveResult kzt_lazy_patch_current_target_binding(
    KztLazyBinding *binding)
{
    if (!kzt_lazy_patch_current_target) {
        printf_log(LOG_INFO,
                   "PltResolver: no lazy patch callback for %s\n",
                   kzt_lazy_symbol_name(binding));
        return kzt_lazy_resolve_result_return_to_guest(
            KZT_LAZY_RESOLVE_REASON_NO_BRIDGE);
    }

    return kzt_lazy_patch_current_target(binding);
}

static void kzt_lazy_apply_resolve_result(
    CPUX86State *cpu,
    const KztLazyBinding *binding,
    const KztLazyResolveResult *result,
    uintptr_t dl_runtime_resolver)
{
    switch (kzt_lazy_resolve_result_policy(result)) {
    case KZT_LAZY_RESOLVE_POLICY_GUEST_FALLBACK:
        printf_log(LOG_INFO,
                   "PltResolver: return to guest resolver "
                   "(reason=%s)\n",
                   kzt_lazy_resolve_reason_name(
                       kzt_lazy_resolve_result_reason(result)));
        kzt_lazy_return_to_guest_resolver(
            cpu, binding, dl_runtime_resolver);
        return;
    case KZT_LAZY_RESOLVE_POLICY_DIRECT_BRIDGE:
        printf_log(LOG_INFO,
                   "PltResolver: call bridge %p "
                   "(reason=%s)\n",
                   (void *)kzt_lazy_resolve_result_target(result),
                   kzt_lazy_resolve_reason_name(
                       kzt_lazy_resolve_result_reason(result)));
        kzt_lazy_push64(cpu, kzt_lazy_resolve_result_target(result));
        return;
    }
}

static void PltResolver(void)
{
    CPUX86State *cpu = (CPUX86State *)lsenv->cpu_state;
    KztLazyResolverFrame frame = kzt_lazy_read_resolver_frame(cpu);
    printf_log(LOG_INFO,
               "PltResolver: Addr=%p, Slot=%d Return=%p: elf is %s "
               "(VerSym=%p)\n",
               (void *)frame.head, frame.slot,
               (void *)frame.return_address, frame.head->name,
               frame.head->VerSym);

    KztLazyBinding binding = kzt_lazy_binding_from_slot(frame.head, frame.slot);
    KztLazyResolveResult result =
        kzt_lazy_patch_current_target_binding(&binding);

    kzt_lazy_apply_resolve_result(
        cpu, &binding, &result, dl_runtime_resolver);
}
