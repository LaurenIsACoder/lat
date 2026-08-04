#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/elfloader_private.h"
#include "target/i386/latx/include/kzt_guest_glob_dat_target.h"
#include "target/i386/latx/include/kzt_owner_resolver.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"

#define SOURCE_LINK_MAP UINT64_C(0x1000)
#define OWNER_LINK_MAP UINT64_C(0x2000)
#define GUEST_TARGET UINT64_C(0x3000)
#define BRIDGE_TARGET UINT64_C(0x4000)

static int failures;
static int source_release_count;
static int decision_release_count;
static int quiescence_release_count;
static int handle_release_count;
static int scope_check_count;
static int lookup_count;
static int selector_count;
static int revalidate_count;
static int writer_count;
static int scope_safe;
static int revalidate_safe;
static uintptr_t selector_result;
static kzt_production_slot_transaction_result_t writer_result;
static kzt_guest_library_object_type_t lookup_object_type;
static char events[16];
static size_t event_count;

#define CHECK(label, condition)                                             \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s: FAIL\n", label);                         \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void note_event(char event)
{
    if (event_count + 1 < sizeof(events)) {
        events[event_count++] = event;
        events[event_count] = '\0';
    }
}

static int read_guest_memory(uintptr_t address, void *destination,
                             size_t size, void *opaque)
{
    (void)address;
    (void)destination;
    (void)size;
    (void)opaque;
    return 0;
}

kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    return context ? (kzt_guest_registry_t *)(uintptr_t)1 : NULL;
}

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(
    box64context_t *context)
{
    return context ? (kzt_guest_library_bindings_t *)(uintptr_t)2 : NULL;
}

void kzt_owner_resolver_init(kzt_owner_resolution_t *resolution)
{
    memset(resolution, 0, sizeof(*resolution));
}

int kzt_owner_resolver_resolve_current(
    kzt_guest_registry_t *registry, uintptr_t current_address,
    uintptr_t expected_address, kzt_owner_resolution_t *resolution)
{
    CHECK("owner registry", registry != NULL);
    CHECK("owner current address", current_address == GUEST_TARGET);
    CHECK("owner expected address", expected_address == GUEST_TARGET);
    resolution->status = KZT_OWNER_RESOLVER_RESOLVED;
    resolution->owner_match = KZT_PATCH_OWNER_MATCH;
    resolution->current_owner = (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = OWNER_LINK_MAP,
        .generation = 22,
    };
    return 0;
}

int kzt_guest_registry_find_live_object(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    kzt_guest_registry_address_match_t *match)
{
    CHECK("live registry", registry != NULL);
    memset(match, 0, sizeof(*match));
    match->link_map_addr = link_map_addr;
    match->generation = link_map_addr == SOURCE_LINK_MAP ? 11 : 22;
    match->namespace_id_status = KZT_GUEST_FIELD_OK;
    CHECK("live exact object", link_map_addr == SOURCE_LINK_MAP ||
          link_map_addr == OWNER_LINK_MAP);
    return 0;
}

int kzt_guest_registry_source_lease_acquire(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation, uintptr_t namespace_id,
    kzt_guest_registry_source_lease_t *lease)
{
    CHECK("source lease registry", registry != NULL);
    CHECK("source lease identity", link_map_addr == SOURCE_LINK_MAP &&
          generation == 11 && namespace_id == 0);
    *lease = (kzt_guest_registry_source_lease_t) {
        .registry = registry,
        .link_map_addr = link_map_addr,
        .generation = generation,
        .namespace_id = namespace_id,
        .active = 1,
    };
    return 0;
}

void kzt_guest_registry_source_lease_release(
    kzt_guest_registry_source_lease_t *lease)
{
    if (lease && lease->active) {
        lease->active = 0;
        ++source_release_count;
        note_event('S');
    }
}

int kzt_guest_registry_patch_decision_lease_acquire(
    const kzt_guest_registry_source_lease_t *source_lease,
    kzt_guest_registry_patch_decision_lease_t *lease)
{
    CHECK("decision source active", source_lease && source_lease->active);
    *lease = (kzt_guest_registry_patch_decision_lease_t) {
        .registry = source_lease->registry,
        .link_map_addr = source_lease->link_map_addr,
        .generation = source_lease->generation,
        .namespace_id = source_lease->namespace_id,
        .active = 1,
    };
    return 0;
}

void kzt_guest_registry_patch_decision_lease_release(
    kzt_guest_registry_patch_decision_lease_t *lease)
{
    if (lease && lease->active) {
        lease->active = 0;
        ++decision_release_count;
        note_event('D');
    }
}

int kzt_guest_library_loader_quiescence_try_acquire(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_quiescence_lease_t *lease)
{
    CHECK("quiescence bindings", bindings != NULL);
    lease->bindings = bindings;
    lease->cookie = 1;
    return 0;
}

void kzt_guest_library_loader_quiescence_release(
    kzt_guest_library_loader_quiescence_lease_t *lease)
{
    if (lease && lease->bindings) {
        lease->bindings = NULL;
        ++quiescence_release_count;
        note_event('Q');
    }
}

int kzt_guest_registry_context_get_main_namespace_head(
    const kzt_guest_registry_context_t *context, uintptr_t *head)
{
    CHECK("namespace context", context != NULL);
    *head = SOURCE_LINK_MAP;
    return 0;
}

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_check(
    const kzt_guest_symbol_scope_request_t *request,
    uintptr_t selected_provider_link_map,
    uintptr_t selected_provider_address,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    ++scope_check_count;
    CHECK("scope source", request->source.link_map_addr == SOURCE_LINK_MAP &&
          request->source.generation == 11 &&
          request->source.namespace_id == 0);
    CHECK("scope symbol", strcmp(request->symbol, "glob_symbol") == 0);
    CHECK("scope version", request->version_evidence ==
          KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED && !request->version);
    CHECK("scope provider", selected_provider_link_map == OWNER_LINK_MAP &&
          selected_provider_address == GUEST_TARGET);
    CHECK("scope reader", reader_ops && reader_ops->read_memory ==
          read_guest_memory);
    memset(result, 0, sizeof(*result));
    result->status = scope_safe ? KZT_GUEST_SYMBOL_SCOPE_SAFE :
                                  KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    return result->status;
}

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_revalidate(
    const kzt_guest_symbol_scope_result_t *proof,
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result)
{
    ++revalidate_count;
    note_event('R');
    CHECK("revalidate proof", proof != NULL);
    CHECK("revalidate request", request &&
          strcmp(request->symbol, "glob_symbol") == 0);
    CHECK("revalidate reader", reader_ops &&
          reader_ops->read_memory == read_guest_memory);
    memset(result, 0, sizeof(*result));
    result->status = revalidate_safe ? KZT_GUEST_SYMBOL_SCOPE_SAFE :
                                       KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED;
    return result->status;
}

int KztGuestLibraryLookupForContext(
    box64context_t *context, const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    ++lookup_count;
    CHECK("lookup context", context != NULL);
    CHECK("lookup exact key", key->link_map_addr == OWNER_LINK_MAP &&
          key->generation == 22 && key->namespace_id == 0 &&
          key->namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN);
    *handle = (kzt_guest_library_handle_t) {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)2,
        .entry = (void *)(uintptr_t)3,
        .library = (library_t *)(uintptr_t)4,
        .object_type = lookup_object_type,
    };
    return 0;
}

void kzt_guest_library_handle_release(kzt_guest_library_handle_t *handle)
{
    if (handle && handle->entry) {
        ++handle_release_count;
        note_event('H');
        memset(handle, 0, sizeof(*handle));
    }
}

uintptr_t kzt_rela_runtime_select_exact_wrapper_bridge_retained(
    box64context_t *context,
    const kzt_guest_library_handle_t *retained_provider_handle,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version)
{
    ++selector_count;
    CHECK("selector context", context != NULL);
    CHECK("selector retained handle", retained_provider_handle &&
          retained_provider_handle->entry);
    CHECK("selector symbol", strcmp(symbol_name, "glob_symbol") == 0);
    CHECK("selector unversioned", version_evidence ==
          KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED && !symbol_version);
    return selector_result;
}

kzt_production_slot_transaction_result_t
kzt_production_eager_relocation_write(
    box64context_t *context, uintptr_t source_link_map,
    const kzt_patch_object_ref_t *owner,
    kzt_patch_relocation_type_t reloc_type, uintptr_t slot_addr,
    uintptr_t expected, uintptr_t replacement, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    uintptr_t *final_value)
{
    uintptr_t *slot = (uintptr_t *)slot_addr;

    ++writer_count;
    note_event('W');
    CHECK("writer context", context != NULL);
    CHECK("writer source", source_link_map == SOURCE_LINK_MAP);
    CHECK("writer owner", owner && owner->known &&
          owner->link_map_addr == OWNER_LINK_MAP && owner->generation == 22);
    CHECK("writer relocation", reloc_type == KZT_PATCH_RELOCATION_GLOB_DAT);
    CHECK("writer target", slot && *slot == expected &&
          expected == GUEST_TARGET && replacement == BRIDGE_TARGET);
    CHECK("writer symbol", strcmp(symbol_name, "glob_symbol") == 0);
    CHECK("writer version", version_evidence ==
          KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED && !version);
    if (writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED) {
        *slot = replacement;
        *final_value = replacement;
    } else {
        *final_value = expected;
    }
    return writer_result;
}

static void reset_fixture(box64context_t *context, elfheader_t *head,
                          Elf64_Sym *symbol)
{
    memset(context, 0, sizeof(*context));
    memset(head, 0, sizeof(*head));
    memset(symbol, 0, sizeof(*symbol));
    context->kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF;
    head->self_link_map = SOURCE_LINK_MAP;
    head->numDynSym = 1;
    symbol->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    source_release_count = 0;
    decision_release_count = 0;
    quiescence_release_count = 0;
    handle_release_count = 0;
    scope_check_count = 0;
    lookup_count = 0;
    selector_count = 0;
    revalidate_count = 0;
    writer_count = 0;
    scope_safe = 1;
    revalidate_safe = 1;
    selector_result = BRIDGE_TARGET;
    writer_result = KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED;
    lookup_object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED;
    memset(events, 0, sizeof(events));
    event_count = 0;
}

static int resolve(box64context_t *context, elfheader_t *head,
                   Elf64_Sym *symbol, int version,
                   const char *version_name,
                   kzt_guest_glob_dat_target_t *target)
{
    const kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = read_guest_memory,
    };

    return kzt_guest_glob_dat_target_resolve(
        context, head, GUEST_TARGET, 0, symbol, "glob_symbol", version,
        version_name, &reader_ops, target);
}

static int route(box64context_t *context, elfheader_t *head,
                 Elf64_Sym *symbol, int version,
                 const char *version_name, uintptr_t *slot,
                 kzt_guest_glob_dat_route_result_t *result)
{
    const kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = read_guest_memory,
    };

    return kzt_guest_glob_dat_route(
        context, head, (uintptr_t)slot, *slot, 0, symbol, "glob_symbol",
        version, version_name, &reader_ops, result);
}

static void test_unversioned_selects_exact_bridge_and_holds_leases(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    kzt_guest_glob_dat_target_t target;

    reset_fixture(&context, &head, &symbol);
    CHECK("unversioned resolver handled",
          resolve(&context, &head, &symbol, 1, NULL, &target) == 1);
    CHECK("unversioned bridge selected",
          target.guest_target == GUEST_TARGET &&
          target.selected_target == BRIDGE_TARGET && target.exact_bridge);
    CHECK("unversioned exact path", scope_check_count == 1 &&
          lookup_count == 1 && selector_count == 1 &&
          handle_release_count == 1);
    CHECK("success leases remain held", source_release_count == 0 &&
          decision_release_count == 0 && quiescence_release_count == 0);
    kzt_guest_glob_dat_target_release(&target);
    CHECK("caller releases success leases", source_release_count == 1 &&
          decision_release_count == 1 && quiescence_release_count == 1);
}

static void test_versioned_preserves_guest_without_native_lookup(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    kzt_guest_glob_dat_target_t target;

    reset_fixture(&context, &head, &symbol);
    CHECK("versioned resolver handled",
          resolve(&context, &head, &symbol, 2, "VERS_1", &target) == 1);
    CHECK("versioned guest preserved",
          target.selected_target == GUEST_TARGET && !target.exact_bridge);
    CHECK("versioned skips native route", scope_check_count == 0 &&
          lookup_count == 0 && selector_count == 0);
    CHECK("versioned owns no leases", source_release_count == 0 &&
          decision_release_count == 0 && quiescence_release_count == 0);
}

static void test_missing_bridge_preserves_guest_and_releases_leases(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    kzt_guest_glob_dat_target_t target;

    reset_fixture(&context, &head, &symbol);
    selector_result = 0;
    CHECK("missing bridge resolver handled",
          resolve(&context, &head, &symbol, 1, NULL, &target) == 1);
    CHECK("missing bridge guest preserved",
          target.selected_target == GUEST_TARGET && !target.exact_bridge);
    CHECK("missing bridge route attempted", scope_check_count == 1 &&
          lookup_count == 1 && selector_count == 1 &&
          handle_release_count == 1);
    CHECK("missing bridge releases leases", source_release_count == 1 &&
          decision_release_count == 1 && quiescence_release_count == 1);
}

static void test_scope_failure_preserves_guest_and_releases_leases(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    kzt_guest_glob_dat_target_t target;

    reset_fixture(&context, &head, &symbol);
    scope_safe = 0;
    CHECK("scope failure resolver handled",
          resolve(&context, &head, &symbol, 1, NULL, &target) == 1);
    CHECK("scope failure guest preserved",
          target.selected_target == GUEST_TARGET && !target.exact_bridge);
    CHECK("scope failure stops native route", scope_check_count == 1 &&
          lookup_count == 0 && selector_count == 0);
    CHECK("scope failure releases leases", source_release_count == 1 &&
          decision_release_count == 1 && quiescence_release_count == 1);
}

static void test_route_revalidates_and_writes_exact_bridge(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    uintptr_t slot = GUEST_TARGET;
    kzt_guest_glob_dat_route_result_t result;

    reset_fixture(&context, &head, &symbol);
    CHECK("route success handled",
          route(&context, &head, &symbol, 1, NULL, &slot, &result) == 1);
    CHECK("route success writes bridge",
          slot == BRIDGE_TARGET && result.guest_target == GUEST_TARGET &&
          result.selected_target == BRIDGE_TARGET &&
          result.final_value == BRIDGE_TARGET &&
          result.writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED);
    CHECK("route success calls", selector_count == 1 &&
          revalidate_count == 1 && writer_count == 1);
    CHECK("route success release order", strcmp(events, "HRWDQS") == 0);
}

static void test_route_revalidation_failure_preserves_guest(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    uintptr_t slot = GUEST_TARGET;
    kzt_guest_glob_dat_route_result_t result;

    reset_fixture(&context, &head, &symbol);
    revalidate_safe = 0;
    CHECK("route stale scope handled",
          route(&context, &head, &symbol, 1, NULL, &slot, &result) == 1);
    CHECK("route stale scope preserves guest",
          slot == GUEST_TARGET && result.final_value == GUEST_TARGET &&
          result.writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_ERROR);
    CHECK("route stale scope stops writer",
          revalidate_count == 1 && writer_count == 0);
    CHECK("route stale scope releases", strcmp(events, "HRDQS") == 0);
}

static void test_route_writer_failure_preserves_guest_and_releases(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    uintptr_t slot = GUEST_TARGET;
    kzt_guest_glob_dat_route_result_t result;

    reset_fixture(&context, &head, &symbol);
    writer_result = KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH;
    CHECK("route writer failure handled",
          route(&context, &head, &symbol, 1, NULL, &slot, &result) == 1);
    CHECK("route writer failure preserves guest",
          slot == GUEST_TARGET && result.final_value == GUEST_TARGET &&
          result.writer_result == KZT_PRODUCTION_SLOT_TRANSACTION_CAS_MISMATCH);
    CHECK("route writer failure calls",
          revalidate_count == 1 && writer_count == 1);
    CHECK("route writer failure releases", strcmp(events, "HRWDQS") == 0);
}

static void test_route_versioned_symbol_never_reaches_writer(void)
{
    box64context_t context;
    elfheader_t head;
    Elf64_Sym symbol;
    uintptr_t slot = GUEST_TARGET;
    kzt_guest_glob_dat_route_result_t result;

    reset_fixture(&context, &head, &symbol);
    CHECK("route versioned handled",
          route(&context, &head, &symbol, 2, "VERS_1", &slot, &result) == 1);
    CHECK("route versioned preserves guest",
          slot == GUEST_TARGET && result.selected_target == GUEST_TARGET &&
          result.final_value == GUEST_TARGET);
    CHECK("route versioned skips native path",
          selector_count == 0 && revalidate_count == 0 && writer_count == 0);
}

int main(void)
{
    test_unversioned_selects_exact_bridge_and_holds_leases();
    test_versioned_preserves_guest_without_native_lookup();
    test_missing_bridge_preserves_guest_and_releases_leases();
    test_scope_failure_preserves_guest_and_releases_leases();
    test_route_revalidates_and_writes_exact_bridge();
    test_route_revalidation_failure_preserves_guest();
    test_route_writer_failure_preserves_guest_and_releases();
    test_route_versioned_symbol_never_reaches_writer();
    if (failures) fprintf(stderr, "%d failure(s)\n", failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
