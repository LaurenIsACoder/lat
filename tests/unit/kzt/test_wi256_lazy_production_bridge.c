#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge_private.h"
#include "target/i386/latx/include/elfloader_private.h"
#include "target/i386/latx/include/khash.h"
#include "target/i386/latx/include/kzt_guest_dl_api.h"
#include "target/i386/latx/include/kzt_guest_dynsym_lookup.h"
#include "target/i386/latx/include/kzt_guest_library_adapter.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/kzt_guest_symbol_scope.h"
#include "target/i386/latx/include/kzt_jump_slot_production.h"
#include "target/i386/latx/include/kzt_loader_event_hook.h"
#include "target/i386/latx/include/kzt_patch_spike_writer.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"
#include "target/i386/latx/include/librarian_private.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

#define FIXTURE_SYMBOL "uname"
#define FIXTURE_VERSION "GLIBC_2.2.5"
#define SOURCE_LINK_MAP 0x1000
#define PROVIDER_LINK_MAP 0x2000
#define ALIAS_PROVIDER_LINK_MAP 0x3000
#define SOURCE_START 0x70000000
#define GUEST_TARGET 0x71000020
#define STRESS_ITERATIONS 1000

static int failures;
static uintptr_t fixture_native_symbol;
static uintptr_t fixture_native_bridge;
static const char *fixture_symbol_name = FIXTURE_SYMBOL;
static int loader_lifecycle_healthy = 1;
int relocation_log;
int kzt_registry_diagnostics;

const char *kzt_guest_library_wrapper_name_for_guest(const char *guest_name)
{
    if (!guest_name || !guest_name[0]) {
        return NULL;
    }
    return strcmp(guest_name, "libdl.so.2") == 0 ? "libc.so.6" : NULL;
}

int kzt_guest_library_wrapper_alias_symbol_allowed(const char *symbol)
{
    return symbol &&
           (strcmp(symbol, "dlsym") == 0 || strcmp(symbol, "dlvsym") == 0);
}

int kzt_loader_lifecycle_runtime_healthy(box64context_t *context)
{
    return context && loader_lifecycle_healthy;
}

int kzt_guest_library_wrapper_source_acquire(
    box64context_t *context, uintptr_t link_map_addr,
    const char *requested_path, const char *wrapper_name,
    kzt_guest_wrapper_source_proof_t *proof)
{
    kzt_guest_registry_address_match_t match = { 0 };
    const char *guest_name;
    const char *approved_wrapper;

    if (proof) {
        memset(proof, 0, sizeof(*proof));
    }
    if (!context || !link_map_addr || !requested_path || !wrapper_name ||
        !proof || kzt_guest_registry_find_live_object(
                      context->kzt_guest_registry_context.registry,
                      link_map_addr, &match) != 0 ||
        !match.generation ||
        match.namespace_id_status != KZT_GUEST_FIELD_OK ||
        match.namespace_id != 0) {
        return -1;
    }
    guest_name = strrchr(requested_path, '/');
    guest_name = guest_name ? guest_name + 1 : requested_path;
    approved_wrapper =
        kzt_guest_library_wrapper_name_for_guest(guest_name);
    if (!approved_wrapper || strcmp(approved_wrapper, wrapper_name) != 0 ||
        kzt_guest_registry_source_lease_acquire(
            context->kzt_guest_registry_context.registry, link_map_addr,
            match.generation, match.namespace_id, &proof->lease) != 0) {
        return -1;
    }
    proof->key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = link_map_addr,
        .generation = match.generation,
        .namespace_id = match.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    return 0;
}

void kzt_guest_library_wrapper_source_release(
    kzt_guest_wrapper_source_proof_t *proof)
{
    if (!proof) {
        return;
    }
    kzt_guest_registry_source_lease_release(&proof->lease);
    memset(proof, 0, sizeof(*proof));
}

KHASH_MAP_IMPL_STR(symbolmap, wrapper_t)
KHASH_MAP_IMPL_STR(symbol2map, symbol2_t)

#define CHECK(name, condition) do {                                  \
    if (!(condition)) {                                              \
        fprintf(stderr, "%s failed at line %d\n", name, __LINE__); \
        ++failures;                                                  \
    }                                                               \
} while (0)

typedef struct fixture_bridge_map {
    void *native_symbol;
    uintptr_t target;
    onebridge_t *entry;
    int add_calls;
    int force_inexact_add;
    int check_calls;
} fixture_bridge_map_t;

typedef struct fixture_version_need {
    Elf64_Verneed need;
    Elf64_Vernaux aux;
} fixture_version_need_t;

typedef struct fixture_scope_link_map {
    uint64_t l_addr;
    uint64_t l_name;
    uint64_t l_ld;
    uint64_t l_next;
    uint64_t l_prev;
    uint64_t l_real;
    uint64_t l_ns;
    unsigned char private_before_audit_flags[
        0x350 - 7 * sizeof(uint64_t)];
    uint64_t audit_flags;
    unsigned char private_before_reloc_result[0x378 - 0x358];
    uint64_t reloc_result;
    unsigned char private_before_scope_max[0x3c0 - 0x380];
    uint64_t l_scope_max;
    uint64_t l_scope;
    uint64_t l_local_scope[2];
} fixture_scope_link_map_t;

typedef struct fixture_scope_elem {
    uint64_t r_list;
    uint32_t r_nlist;
    uint32_t padding;
} fixture_scope_elem_t;

typedef struct fixture_sysv_hash {
    uint32_t nbucket;
    uint32_t nchain;
    uint32_t buckets[1];
    uint32_t chains[2];
} fixture_sysv_hash_t;

typedef struct fixture_version_def {
    Elf64_Verdef definition;
    Elf64_Verdaux auxiliary;
} fixture_version_def_t;

typedef struct fixture_lazy_source {
    unsigned long generation;
    uintptr_t guest_resolver;
    uintptr_t unresolved_stub;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
} fixture_lazy_source_t;

typedef struct fixture {
    box64context_t context;
    library_t provider;
    lib_t scope;
    library_t *scope_libraries[1];
    fixture_bridge_map_t bridge_map;
    onebridge_t bridge_entry;
    elfheader_t head;
    elfheader_t *elfs[1];
    Elf64_Rela rela;
    Elf64_Sym sym;
    Elf64_Half versym;
    fixture_version_need_t version_need;
    fixture_scope_link_map_t source_map;
    fixture_scope_link_map_t provider_map;
    Elf64_Dyn source_scope_dynamic[6];
    Elf64_Dyn provider_scope_dynamic[9];
    Elf64_Dyn alias_provider_dynamic[6];
    Elf64_Sym source_scope_symbols[1];
    Elf64_Sym provider_scope_symbols[2];
    Elf64_Sym alias_provider_symbols[2];
    char dynamic_strings[128];
    char source_scope_strings[1];
    char provider_scope_strings[32];
    char alias_provider_strings[32];
    fixture_sysv_hash_t source_scope_hash;
    fixture_sysv_hash_t provider_scope_hash;
    fixture_sysv_hash_t alias_provider_hash;
    Elf64_Half provider_scope_versym[2];
    Elf64_Half alias_provider_versym[2];
    fixture_version_def_t provider_scope_verdef;
    fixture_version_def_t alias_provider_verdef;
    fixture_scope_elem_t source_scope_elem;
    uintptr_t source_scope_array[2];
    uintptr_t source_scope_maps[2];
    uintptr_t slot;
    uintptr_t dlerror_slot;
    fixture_lazy_source_t source;
    kzt_guest_object_observation_t source_observation;
    kzt_guest_dynamic_view_t dynamic_view;
    kzt_guest_dynamic_view_t provider_dynamic_view;
    kzt_guest_dynamic_view_t alias_provider_dynamic_view;
} fixture_t;

typedef enum hook_mode {
    HOOK_NONE = 0,
    HOOK_RECYCLE_BEFORE_ACQUIRE,
    HOOK_VIEW_CHANGE_BEFORE_DECISION_ACQUIRE,
    HOOK_SLOT_CONFLICT_BEFORE_FINAL_LOAD,
} hook_mode_t;

static fixture_t *hook_fixture;
static hook_mode_t hook_mode;
static int before_acquire_calls;
static int source_memory_access_calls;
static int owner_memory_access_calls;
static int owner_memory_all_lifetimes_held;
static int slot_load_calls;
static int after_cas_calls;
static int shadow_run_calls;
static unsigned long recycled_generation;
static int permission_begin_calls;
static int permission_end_calls;
static int fail_permission_begin;
static int fail_permission_end;
static int fail_permission_end_once;
static int decision_lease_active;
static int decision_lease_acquires;
static int decision_lease_releases;
static int decision_lease_held_at_validate;
static int decision_lease_held_at_permission_begin;
static int decision_lease_held_at_permission_end;
static int decision_lease_held_at_cas;
static int generation_validate_calls;
static int runtime_full_lifetime_validation_calls;
static pthread_mutex_t mapping_transaction_lock = PTHREAD_MUTEX_INITIALIZER;
static int mapping_lock_active;

int kzt_jump_slot_production_test_read_guest_memory(
    uintptr_t address, void *dst, size_t size);

static int fixture_guest_range_read(
    uintptr_t address, uintptr_t guest_base, const void *host_base,
    size_t host_size, void *dst, size_t size)
{
    uintptr_t offset;

    if (address < guest_base) {
        return -1;
    }
    offset = address - guest_base;
    if (offset > host_size || size > host_size - offset) {
        return -1;
    }
    memcpy(dst, (const unsigned char *)host_base + offset, size);
    return 0;
}

static int fixture_scope_read_guest_memory(
    uintptr_t address, void *dst, size_t size, void *opaque)
{
    (void)opaque;
    return kzt_jump_slot_production_test_read_guest_memory(
        address, dst, size);
}

int kzt_jump_slot_production_test_read_guest_memory(
    uintptr_t address, void *dst, size_t size)
{
    if (!hook_fixture || !address || !dst || !size) {
        return -1;
    }
    if (fixture_guest_range_read(
            address, SOURCE_LINK_MAP, &hook_fixture->source_map,
            sizeof(hook_fixture->source_map), dst, size) == 0 ||
        fixture_guest_range_read(
            address, PROVIDER_LINK_MAP, &hook_fixture->provider_map,
            sizeof(hook_fixture->provider_map), dst, size) == 0) {
        return 0;
    }
    if (address < 0x10000) {
        return -1;
    }
    memcpy(dst, (const void *)address, size);
    return 0;
}

uintptr_t CheckBridged(bridge_t *bridge, void *fnc);
uintptr_t AddCheckBridge(bridge_t *bridge, wrapper_t wrapper, void *fnc,
                         int stack_bytes, const char *name);
int BridgeForkProtectionAvailable(void);
const char *SymName(elfheader_t *head, Elf64_Sym *sym);
void kzt_jump_slot_production_test_before_source_lease_acquire(void);
void kzt_jump_slot_production_test_before_source_memory_access(void);
void kzt_jump_slot_production_test_before_owner_memory_access(
    int source_lease_active, int decision_lease_active,
    int quiescence_active, int retained_provider_active,
    int owner_lease_active);
void kzt_jump_slot_production_test_before_slot_load(void);
void kzt_jump_slot_production_test_after_slot_load(uintptr_t *value);
void kzt_jump_slot_production_test_after_slot_cas(int exchanged);
void kzt_jump_slot_production_test_shadow_run(void);
void kzt_jump_slot_production_test_before_generation_validate(void);
void kzt_jump_slot_production_test_before_patch_decision_lease_acquire(void);
void kzt_jump_slot_production_test_after_patch_decision_lease_acquire(void);
void kzt_jump_slot_production_test_before_patch_decision_lease_release(void);
void kzt_jump_slot_production_test_full_enrich(void);
void kzt_jump_slot_production_test_wrapper_only_enrich(void);
int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease);
int kzt_jump_slot_production_test_end_slot_write(
    kzt_patch_spike_permission_lease_t *lease);
void kzt_jump_slot_production_test_mapping_lock(void);
void kzt_jump_slot_production_test_mapping_unlock(void);
void kzt_rela_runtime_bridge_test_full_lifetime_validation(void);

int kzt_guest_dl_api_publish_dlerror_entry(
    dlprivate_t *dl, const char *symbol, uintptr_t guest_entry,
    int custom_wrapper)
{
    (void)dl;
    (void)symbol;
    (void)guest_entry;
    (void)custom_wrapper;
    return 0;
}

void kzt_rela_runtime_bridge_test_full_lifetime_validation(void)
{
    ++runtime_full_lifetime_validation_calls;
}

int BridgeForkProtectionAvailable(void)
{
    return 1;
}

static void fixture_iFp(uintptr_t fnc)
{
    (void)fnc;
}

uintptr_t CheckBridged(bridge_t *bridge, void *fnc)
{
    fixture_bridge_map_t *map = (fixture_bridge_map_t *)bridge;

    if (!map) {
        return 0;
    }
    ++map->check_calls;
    return fnc == map->native_symbol ? map->target : 0;
}

uintptr_t AddCheckBridge(bridge_t *bridge, wrapper_t wrapper, void *fnc,
                         int stack_bytes, const char *name)
{
    fixture_bridge_map_t *map = (fixture_bridge_map_t *)bridge;
    uintptr_t target;

    (void)stack_bytes;
    (void)name;
    target = CheckBridged(bridge, fnc);
    if (target || !map || !map->entry || !wrapper || !fnc) {
        return target;
    }
    ++map->add_calls;
    map->entry->CC = 0xCC;
    map->entry->S = 'S';
    map->entry->C = 'C';
    map->entry->w = map->force_inexact_add ? NULL : wrapper;
    map->entry->f = (uintptr_t)fnc;
    map->entry->C3 = 0xC3;
    map->native_symbol = fnc;
    map->target = (uintptr_t)&map->entry->CC;
    return map->target;
}

void *GetNativeSymbolUnversionned(void *lib, const char *name)
{
    return lib && name ? dlsym(lib, name) : NULL;
}

kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    return context ? context->kzt_guest_registry_context.registry : NULL;
}

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(
    box64context_t *context)
{
    return context ? context->kzt_guest_library_access.bindings : NULL;
}

kzt_lazy_prebind_scope_t *KztLazyPrebindScopeForContext(
    box64context_t *context)
{
    return context ? context->kzt_lazy_prebind_scope : NULL;
}

int KztGuestLibraryLookupForContext(
    box64context_t *context, const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    return context ? kzt_guest_library_access_lookup(
                         &context->kzt_guest_library_access, key, handle) :
                     -1;
}

kzt_patch_spike_guard_t *KztPatchSpikeGuardForContext(
    box64context_t *context)
{
    return context ? &context->kzt_patch_spike_guard : NULL;
}

const char *SymName(elfheader_t *head, Elf64_Sym *sym)
{
    (void)head;
    (void)sym;
    return fixture_symbol_name;
}

const char *GetSymbolVersion(elfheader_t *head, int version)
{
    (void)head;
    return version == 2 ? FIXTURE_VERSION : NULL;
}

static kzt_guest_object_observation_t observation(
    uintptr_t link_map, uintptr_t start, uintptr_t end, const char *name)
{
    return (kzt_guest_object_observation_t) {
        .link_map_addr = link_map,
        .load_bias = { start, KZT_GUEST_FIELD_OK },
        .dynamic_addr = { start + 0x1000, KZT_GUEST_FIELD_OK },
        .map_start = { start, KZT_GUEST_FIELD_OK },
        .map_end = { end, KZT_GUEST_FIELD_OK },
        .namespace_id = { 0, KZT_GUEST_FIELD_OK },
        .path = { name, KZT_GUEST_FIELD_OK },
        .soname = { name, KZT_GUEST_FIELD_OK },
        .dynamic_view_status = KZT_GUEST_FIELD_NOT_PARSED,
    };
}

static kzt_guest_dynamic_field_t runtime_field(uintptr_t value)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS,
    };
}

static kzt_guest_dynamic_field_t scalar_field(uint64_t value)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = KZT_GUEST_DYNAMIC_SCALAR,
    };
}

static unsigned long observe_object(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *object)
{
    kzt_guest_object_snapshot_t *snapshot = NULL;
    unsigned long generation = 0;

    CHECK("observe.add", kzt_guest_registry_observe(registry, object) ==
                         KZT_GUEST_REGISTRY_ADDED);
    CHECK("observe.find", kzt_guest_registry_find_by_link_map(
                              registry, object->link_map_addr,
                              &snapshot) == 0 && snapshot != NULL);
    if (snapshot) {
        generation = snapshot->generation;
    }
    kzt_guest_object_snapshot_free(snapshot);
    return generation;
}

static unsigned long fixture_publish_source(fixture_t *fixture)
{
    unsigned long generation = observe_object(
        fixture->context.kzt_guest_registry_context.registry,
        &fixture->source_observation);

    CHECK("source.dynamic", kzt_guest_registry_commit_dynamic_view(
              fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP,
              generation, &fixture->dynamic_view) ==
              KZT_GUEST_REGISTRY_UPDATED);
    return generation;
}

static void fixture_publish_resolver_for_head(fixture_t *fixture,
                                              elfheader_t *head,
                                              int registry_owned_head)
{
    kzt_guest_lazy_resolver_t resolver = {
        .link_map_slot = SOURCE_START + 0x2000,
        .resolver_slot = SOURCE_START + 0x2008,
        .guest_link_map = SOURCE_LINK_MAP,
        .guest_resolver = SOURCE_START + 0x3000,
        .object_head = (uintptr_t)head,
        .registry_owned_head = registry_owned_head,
    };

    fixture->source.guest_resolver = resolver.guest_resolver;
    CHECK("source.resolver", kzt_guest_registry_publish_lazy_resolver(
              fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP,
              fixture->source.generation, 0, &resolver) == 0);
}

static void fixture_publish_resolver(fixture_t *fixture)
{
    fixture_publish_resolver_for_head(fixture, &fixture->head, 0);
}



static void reset_guard(fixture_t *fixture, int enabled)
{
    kzt_patch_spike_config_t config = { enabled, 1, 1 };
    kzt_patch_spike_guard_init(&fixture->context.kzt_patch_spike_guard,
                               &config);
}

static void reset_guard_budget(box64context_t *context,
                               unsigned long budget)
{
    kzt_patch_spike_config_t config = { 1, 1, budget };

    kzt_patch_spike_guard_init(&context->kzt_patch_spike_guard, &config);
}

static void fixture_init_guest_scope(fixture_t *fixture)
{
    static const char provider_strings[] =
        "\0" FIXTURE_SYMBOL "\0" FIXTURE_VERSION "\0";

    fixture->source_map.l_ld = (uintptr_t)fixture->source_scope_dynamic;
    fixture->source_map.l_next = PROVIDER_LINK_MAP;
    fixture->source_map.l_real = SOURCE_LINK_MAP;
    fixture->source_map.l_scope_max = 2;
    fixture->source_map.l_scope =
        (uintptr_t)fixture->source_scope_array;
    fixture->source_map.l_local_scope[0] =
        (uintptr_t)&fixture->source_scope_elem;
    fixture->provider_map.l_ld =
        (uintptr_t)fixture->provider_scope_dynamic;
    fixture->provider_map.l_prev = SOURCE_LINK_MAP;
    fixture->provider_map.l_real = PROVIDER_LINK_MAP;

    fixture->source_scope_elem.r_list =
        (uintptr_t)fixture->source_scope_maps;
    fixture->source_scope_elem.r_nlist = 2;
    fixture->source_scope_array[0] =
        (uintptr_t)&fixture->source_scope_elem;
    fixture->source_scope_maps[0] = SOURCE_LINK_MAP;
    fixture->source_scope_maps[1] = PROVIDER_LINK_MAP;

    fixture->source_scope_dynamic[0].d_tag = DT_SYMTAB;
    fixture->source_scope_dynamic[0].d_un.d_ptr =
        (uintptr_t)fixture->source_scope_symbols;
    fixture->source_scope_dynamic[1].d_tag = DT_STRTAB;
    fixture->source_scope_dynamic[1].d_un.d_ptr =
        (uintptr_t)fixture->source_scope_strings;
    fixture->source_scope_dynamic[2].d_tag = DT_SYMENT;
    fixture->source_scope_dynamic[2].d_un.d_val = sizeof(Elf64_Sym);
    fixture->source_scope_dynamic[3].d_tag = DT_STRSZ;
    fixture->source_scope_dynamic[3].d_un.d_val =
        sizeof(fixture->source_scope_strings);
    fixture->source_scope_dynamic[4].d_tag = DT_HASH;
    fixture->source_scope_dynamic[4].d_un.d_ptr =
        (uintptr_t)&fixture->source_scope_hash;
    fixture->source_scope_dynamic[5].d_tag = DT_NULL;
    fixture->source_scope_hash.nbucket = 1;
    fixture->source_scope_hash.nchain = 1;

    memcpy(fixture->provider_scope_strings, provider_strings,
           sizeof(provider_strings));
    fixture->provider_scope_symbols[1].st_name = 1;
    fixture->provider_scope_symbols[1].st_info =
        ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    fixture->provider_scope_symbols[1].st_other = STV_DEFAULT;
    fixture->provider_scope_symbols[1].st_shndx = SHN_ABS;
    fixture->provider_scope_symbols[1].st_value = GUEST_TARGET;
    fixture->provider_scope_hash.nbucket = 1;
    fixture->provider_scope_hash.nchain = 2;
    fixture->provider_scope_hash.buckets[0] = 1;
    fixture->provider_scope_versym[1] = 2;
    fixture->provider_scope_verdef.definition.vd_version = 1;
    fixture->provider_scope_verdef.definition.vd_ndx = 2;
    fixture->provider_scope_verdef.definition.vd_cnt = 1;
    fixture->provider_scope_verdef.definition.vd_aux = sizeof(Elf64_Verdef);
    fixture->provider_scope_verdef.auxiliary.vda_name =
        sizeof("\0" FIXTURE_SYMBOL);

    fixture->provider_scope_dynamic[0].d_tag = DT_SYMTAB;
    fixture->provider_scope_dynamic[0].d_un.d_ptr =
        (uintptr_t)fixture->provider_scope_symbols;
    fixture->provider_scope_dynamic[1].d_tag = DT_STRTAB;
    fixture->provider_scope_dynamic[1].d_un.d_ptr =
        (uintptr_t)fixture->provider_scope_strings;
    fixture->provider_scope_dynamic[2].d_tag = DT_SYMENT;
    fixture->provider_scope_dynamic[2].d_un.d_val = sizeof(Elf64_Sym);
    fixture->provider_scope_dynamic[3].d_tag = DT_STRSZ;
    fixture->provider_scope_dynamic[3].d_un.d_val =
        sizeof(provider_strings);
    fixture->provider_scope_dynamic[4].d_tag = DT_HASH;
    fixture->provider_scope_dynamic[4].d_un.d_ptr =
        (uintptr_t)&fixture->provider_scope_hash;
    fixture->provider_scope_dynamic[5].d_tag = DT_VERSYM;
    fixture->provider_scope_dynamic[5].d_un.d_ptr =
        (uintptr_t)fixture->provider_scope_versym;
    fixture->provider_scope_dynamic[6].d_tag = DT_VERDEF;
    fixture->provider_scope_dynamic[6].d_un.d_ptr =
        (uintptr_t)&fixture->provider_scope_verdef;
    fixture->provider_scope_dynamic[7].d_tag = DT_VERDEFNUM;
    fixture->provider_scope_dynamic[7].d_un.d_val = 1;
    fixture->provider_scope_dynamic[8].d_tag = DT_NULL;

    fixture->alias_provider_dynamic[0].d_tag = DT_SYMTAB;
    fixture->alias_provider_dynamic[0].d_un.d_ptr =
        (uintptr_t)fixture->alias_provider_symbols;
    fixture->alias_provider_dynamic[1].d_tag = DT_STRTAB;
    fixture->alias_provider_dynamic[1].d_un.d_ptr =
        (uintptr_t)fixture->alias_provider_strings;
    fixture->alias_provider_dynamic[2].d_tag = DT_SYMENT;
    fixture->alias_provider_dynamic[2].d_un.d_val = sizeof(Elf64_Sym);
    fixture->alias_provider_dynamic[3].d_tag = DT_STRSZ;
    fixture->alias_provider_dynamic[3].d_un.d_val =
        sizeof(fixture->alias_provider_strings);
    fixture->alias_provider_dynamic[4].d_tag = DT_HASH;
    fixture->alias_provider_dynamic[4].d_un.d_ptr =
        (uintptr_t)&fixture->alias_provider_hash;
    fixture->alias_provider_dynamic[5].d_tag = DT_NULL;
    fixture->alias_provider_hash.nbucket = 1;
    fixture->alias_provider_hash.nchain = 1;
}

static int fixture_init_with_options(fixture_t *fixture,
                                     int provider_range_available,
                                     int wrapper_alias)
{
    static char source_name[] = "librequester.so";
    static char provider_name[] = "libc.so.6";
    static char alias_owner_name[] = "libdl.so.2";
    size_t string_offset;
    size_t version_offset;
    size_t libdl_offset;
    kzt_guest_object_observation_t binding_observation;
    kzt_guest_object_observation_t provider_observation;
    kzt_guest_library_binding_key_t provider_key;
    unsigned long provider_generation;
    khint_t map_key;
    int inserted;
    int initial_failures = failures;

    memset(fixture, 0, sizeof(*fixture));
    fixture_symbol_name = FIXTURE_SYMBOL;
    string_offset = 1;
    memcpy(fixture->dynamic_strings + string_offset,
           FIXTURE_SYMBOL, sizeof(FIXTURE_SYMBOL));
    string_offset += sizeof(FIXTURE_SYMBOL);
    version_offset = string_offset;
    memcpy(fixture->dynamic_strings + string_offset,
           FIXTURE_VERSION, sizeof(FIXTURE_VERSION));
    string_offset += sizeof(FIXTURE_VERSION);
    memcpy(fixture->dynamic_strings + string_offset,
           "KZT_BAD_VERSION", sizeof("KZT_BAD_VERSION"));
    string_offset += sizeof("KZT_BAD_VERSION");
    libdl_offset = string_offset;
    memcpy(fixture->dynamic_strings + string_offset,
           "libdl.so.2", sizeof("libdl.so.2"));
    string_offset += sizeof("libdl.so.2");
    memcpy(fixture->dynamic_strings + string_offset,
           "libm.so.6", sizeof("libm.so.6"));
    string_offset += sizeof("libm.so.6");
    fixture_init_guest_scope(fixture);
    fixture->versym = 2;
    fixture->slot = GUEST_TARGET;
    fixture->context.kzt_guest_registry_context.registry =
        kzt_guest_registry_init();
    CHECK("registry.init",
          fixture->context.kzt_guest_registry_context.registry != NULL);
    CHECK("binding.init", kzt_guest_library_access_init(
                              &fixture->context.kzt_guest_library_access) == 0);
    fixture->context.kzt_lazy_prebind_scope = kzt_lazy_prebind_scope_init();
    fixture->context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF;
    fixture->context.kzt_guest_registry_context.main_namespace_head =
        SOURCE_LINK_MAP;
    CHECK("prebind.init", fixture->context.kzt_lazy_prebind_scope != NULL);
    if (!fixture->context.kzt_guest_registry_context.registry ||
        !fixture->context.kzt_guest_library_access.initialized ||
        !fixture->context.kzt_lazy_prebind_scope) {
        return -1;
    }
    reset_guard(fixture, 1);

    fixture->scope_libraries[0] = &fixture->provider;
    fixture->scope.libraries = fixture->scope_libraries;
    fixture->scope.libsz = 1;
    fixture->scope.context = &fixture->context;
    fixture->context.maplib = &fixture->scope;
    fixture->provider.name = provider_name;
    fixture->provider.path = provider_name;
    fixture->provider.type = LIB_WRAPPED;
    fixture->provider.active = 1;
    fixture->provider.context = &fixture->context;
    fixture->context.libclib = &fixture->provider;
    fixture->provider.priv.w.lib = dlopen(
        "libc.so.6", RTLD_LAZY | RTLD_LOCAL);
    CHECK("provider.dlopen", fixture->provider.priv.w.lib != NULL);
    if (!fixture->provider.priv.w.lib) {
        return -1;
    }
    dlerror();
    fixture_native_symbol = (uintptr_t)dlsym(
        fixture->provider.priv.w.lib, FIXTURE_SYMBOL);
    CHECK("provider.native", fixture_native_symbol != 0 && dlerror() == NULL);

    fixture->provider.symbolmap = kh_init(symbolmap);
    CHECK("provider.map", fixture->provider.symbolmap != NULL);
    if (!fixture->provider.symbolmap) {
        return -1;
    }
    map_key = kh_put(symbolmap, fixture->provider.symbolmap,
                     FIXTURE_SYMBOL, &inserted);
    CHECK("provider.map-entry", inserted != -1 &&
                                map_key != kh_end(fixture->provider.symbolmap));
    kh_value(fixture->provider.symbolmap, map_key) = fixture_iFp;
    fixture->bridge_entry.CC = 0xCC;
    fixture->bridge_entry.S = 'S';
    fixture->bridge_entry.C = 'C';
    fixture->bridge_entry.w = fixture_iFp;
    fixture->bridge_entry.f = fixture_native_symbol;
    fixture->bridge_entry.C3 = 0xC3;
    fixture_native_bridge = (uintptr_t)&fixture->bridge_entry.CC;
    fixture->bridge_map.native_symbol = (void *)fixture_native_symbol;
    fixture->bridge_map.target = fixture_native_bridge;
    fixture->bridge_map.entry = &fixture->bridge_entry;
    fixture->provider.priv.w.bridge = (bridge_t *)&fixture->bridge_map;

    fixture->source_observation = observation(
        SOURCE_LINK_MAP, SOURCE_START, SOURCE_START + 0x10000, source_name);
    provider_observation = observation(
        PROVIDER_LINK_MAP, 0x71000000, 0x71010000,
        wrapper_alias ? alias_owner_name : provider_name);
    if (!provider_range_available) {
        provider_observation.map_start = (kzt_guest_scalar_field_t) {
            0, KZT_GUEST_FIELD_UNKNOWN,
        };
        provider_observation.map_end = (kzt_guest_scalar_field_t) {
            0, KZT_GUEST_FIELD_UNKNOWN,
        };
    }
    fixture->dynamic_view = (kzt_guest_dynamic_view_t) {
        .dynamic_addr = SOURCE_START + 0x1000,
        .load_bias = 0,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 1,
        .has_null = 1,
    };
    fixture->dynamic_view.jmprel = runtime_field(
        (uintptr_t)&fixture->rela);
    fixture->dynamic_view.pltrelsz = scalar_field(sizeof(fixture->rela));
    fixture->dynamic_view.pltrel = scalar_field(DT_RELA);
    fixture->dynamic_view.symtab = runtime_field((uintptr_t)&fixture->sym);
    fixture->dynamic_view.pltgot = runtime_field((uintptr_t)&fixture->slot);
    fixture->dynamic_view.syment = scalar_field(sizeof(fixture->sym));
    fixture->dynamic_view.strtab = runtime_field(
        (uintptr_t)fixture->dynamic_strings);
    fixture->dynamic_view.strsz = scalar_field(string_offset);
    fixture->dynamic_view.needed_count = 1;
    fixture->dynamic_view.needed_offsets[0] = libdl_offset;
    fixture->dynamic_view.needed_address_semantics =
        KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET;
    fixture->dynamic_view.versym = runtime_field((uintptr_t)&fixture->versym);
    fixture->dynamic_view.verneed = runtime_field(
        (uintptr_t)&fixture->version_need);
    fixture->dynamic_view.verneednum = scalar_field(1);
    fixture->provider_dynamic_view = (kzt_guest_dynamic_view_t) {
        .dynamic_addr = (uintptr_t)fixture->provider_scope_dynamic,
        .load_bias = 0,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 9,
        .has_null = 1,
    };
    fixture->provider_dynamic_view.symtab = runtime_field(
        (uintptr_t)fixture->provider_scope_symbols);
    fixture->provider_dynamic_view.strtab = runtime_field(
        (uintptr_t)fixture->provider_scope_strings);
    fixture->provider_dynamic_view.syment = scalar_field(sizeof(Elf64_Sym));
    fixture->provider_dynamic_view.strsz = scalar_field(
        sizeof(fixture->provider_scope_strings));
    fixture->provider_dynamic_view.hash = runtime_field(
        (uintptr_t)&fixture->provider_scope_hash);
    fixture->provider_dynamic_view.versym = runtime_field(
        (uintptr_t)fixture->provider_scope_versym);
    fixture->provider_dynamic_view.verdef = runtime_field(
        (uintptr_t)&fixture->provider_scope_verdef);
    fixture->provider_dynamic_view.verdefnum = scalar_field(1);
    fixture->alias_provider_dynamic_view = (kzt_guest_dynamic_view_t) {
        .dynamic_addr = 0x72001000,
        .load_bias = 0,
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .entry_count = 6,
        .has_null = 1,
    };
    fixture->alias_provider_dynamic_view.symtab = runtime_field(
        (uintptr_t)fixture->alias_provider_symbols);
    fixture->alias_provider_dynamic_view.strtab = runtime_field(
        (uintptr_t)fixture->alias_provider_strings);
    fixture->alias_provider_dynamic_view.syment = scalar_field(
        sizeof(Elf64_Sym));
    fixture->alias_provider_dynamic_view.strsz = scalar_field(
        sizeof(fixture->alias_provider_strings));
    fixture->alias_provider_dynamic_view.hash = runtime_field(
        (uintptr_t)&fixture->alias_provider_hash);
    fixture->alias_provider_dynamic_view.versym = runtime_field(
        (uintptr_t)fixture->alias_provider_versym);
    fixture->alias_provider_dynamic_view.verdef = runtime_field(
        (uintptr_t)&fixture->alias_provider_verdef);
    fixture->alias_provider_dynamic_view.verdefnum = scalar_field(1);
    fixture->sym.st_name = 1;
    fixture->sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    fixture->sym.st_other = STV_DEFAULT;
    fixture->version_need.need.vn_version = 1;
    fixture->version_need.need.vn_cnt = 1;
    fixture->version_need.need.vn_aux = sizeof(Elf64_Verneed);
    fixture->version_need.aux.vna_other = 2;
    fixture->version_need.aux.vna_name = version_offset;
    fixture->source.generation = fixture_publish_source(fixture);
    fixture_publish_resolver(fixture);
    provider_generation = observe_object(
        fixture->context.kzt_guest_registry_context.registry,
        &provider_observation);
    binding_observation = wrapper_alias
        ? observation(ALIAS_PROVIDER_LINK_MAP, 0x72000000, 0x72010000,
                      provider_name)
        : provider_observation;
    provider_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = wrapper_alias ? ALIAS_PROVIDER_LINK_MAP
                                       : PROVIDER_LINK_MAP,
        .generation = wrapper_alias
                          ? observe_object(
                                fixture->context
                                    .kzt_guest_registry_context.registry,
                                &binding_observation)
                          : provider_generation,
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    CHECK("provider.dynamic", kzt_guest_registry_commit_dynamic_view(
              fixture->context.kzt_guest_registry_context.registry,
              PROVIDER_LINK_MAP, provider_generation,
              &fixture->provider_dynamic_view) == KZT_GUEST_REGISTRY_UPDATED);
    if (wrapper_alias) {
        CHECK("alias-provider.dynamic",
              kzt_guest_registry_commit_dynamic_view(
                  fixture->context.kzt_guest_registry_context.registry,
                  ALIAS_PROVIDER_LINK_MAP, provider_key.generation,
                  &fixture->alias_provider_dynamic_view) ==
                  KZT_GUEST_REGISTRY_UPDATED);
    }
    CHECK("provider.track", kzt_guest_library_track(
              fixture->context.kzt_guest_library_access.bindings,
              &fixture->provider) == 0);
    CHECK("provider.pair", kzt_guest_library_note_exact_pair(
              fixture->context.kzt_guest_library_access.bindings,
              provider_key.link_map_addr, &fixture->provider,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("provider.publish", kzt_guest_library_note_observation(
              fixture->context.kzt_guest_library_access.bindings,
              &provider_key) == KZT_GUEST_LIBRARY_BINDING_ADDED);

    fixture->rela.r_info = R_X86_64_JUMP_SLOT;
    fixture->rela.r_offset = (uintptr_t)&fixture->slot;
    fixture->head.name = source_name;
    fixture->head.path = source_name;
    fixture->head.latx_type = LATX_ELF_TYPE_EMUED;
    fixture->head.memory = (char *)SOURCE_START;
    fixture->head.memsz = 0x10000;
    fixture->head.Dynamic = (Elf64_Dyn *)(SOURCE_START + 0x1000);
    fixture->head.jmprel = (uintptr_t)&fixture->rela;
    fixture->head.pltsz = sizeof(fixture->rela);
    fixture->head.pltent = sizeof(fixture->rela);
    fixture->head.DynSym = &fixture->sym;
    fixture->head.numDynSym = 1;
    fixture->head.VerSym = &fixture->versym;
    fixture->head.self_link_map = SOURCE_LINK_MAP;
    fixture->head.kzt_guest_resolver = fixture->source.guest_resolver;
    fixture->elfs[0] = &fixture->head;
    fixture->context.elfs = fixture->elfs;
    fixture->context.elfsize = 1;

    fixture->source.unresolved_stub = GUEST_TARGET - 0x10;
    fixture->source.symbol = FIXTURE_SYMBOL;
    fixture->source.version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    fixture->source.version = FIXTURE_VERSION;
    return failures == initial_failures ? 0 : -1;
}

static int fixture_init(fixture_t *fixture)
{
    return fixture_init_with_options(fixture, 1, 0);
}

static void fixture_use_alias_symbol(fixture_t *fixture,
                                     const char *alias_symbol)
{
    char *source_strings =
        (char *)(uintptr_t)fixture->dynamic_view.strtab.value;
    size_t symbol_size = strlen(alias_symbol) + 1;
    size_t version_offset = 1 + symbol_size;
    size_t string_offset = version_offset;
    size_t libdl_offset;
    khint_t map_key;
    int inserted;

    memset(source_strings, 0, sizeof(fixture->dynamic_strings));
    memcpy(source_strings + 1, alias_symbol, symbol_size);
    memcpy(source_strings + string_offset,
           FIXTURE_VERSION, sizeof(FIXTURE_VERSION));
    string_offset += sizeof(FIXTURE_VERSION);
    memcpy(source_strings + string_offset,
           "KZT_BAD_VERSION", sizeof("KZT_BAD_VERSION"));
    string_offset += sizeof("KZT_BAD_VERSION");
    libdl_offset = string_offset;
    memcpy(source_strings + string_offset,
           "libdl.so.2", sizeof("libdl.so.2"));
    string_offset += sizeof("libdl.so.2");
    memcpy(source_strings + string_offset,
           "libm.so.6", sizeof("libm.so.6"));
    string_offset += sizeof("libm.so.6");
    fixture->dynamic_view.strsz = scalar_field(string_offset);
    fixture->dynamic_view.needed_offsets[0] = libdl_offset;
    fixture->version_need.aux.vna_name = version_offset;

    memset(fixture->provider_scope_strings, 0,
           sizeof(fixture->provider_scope_strings));
    memcpy(fixture->provider_scope_strings + 1,
           alias_symbol, symbol_size);
    memcpy(fixture->provider_scope_strings + version_offset,
           FIXTURE_VERSION, sizeof(FIXTURE_VERSION));
    fixture->provider_scope_verdef.auxiliary.vda_name = version_offset;
    fixture->source.symbol = alias_symbol;
    fixture_symbol_name = alias_symbol;
    map_key = kh_put(symbolmap, fixture->provider.symbolmap,
                     alias_symbol, &inserted);
    CHECK("alias-symbol.map-entry",
          inserted != -1 && map_key != kh_end(fixture->provider.symbolmap));
    kh_value(fixture->provider.symbolmap, map_key) = fixture_iFp;
    dlerror();
    fixture_native_symbol = (uintptr_t)dlsym(
        fixture->provider.priv.w.lib, alias_symbol);
    CHECK("alias-symbol.native",
          fixture_native_symbol != 0 && dlerror() == NULL);
    fixture->bridge_entry.f = fixture_native_symbol;
    fixture->bridge_map.native_symbol = (void *)fixture_native_symbol;
}

static void fixture_use_dlsym_alias_symbol(fixture_t *fixture)
{
    static char custom_prefix[] = "";
    khint_t key;
    int inserted;

    fixture_use_alias_symbol(fixture, "dlsym");
    fixture->context.kzt_guest_registry_context.main_namespace_head =
        SOURCE_LINK_MAP + 0x100;
    key = kh_get(symbolmap, fixture->provider.symbolmap, "dlsym");
    CHECK("dlsym-custom.normal-map-entry",
          key != kh_end(fixture->provider.symbolmap));
    if (key != kh_end(fixture->provider.symbolmap)) {
        kh_del(symbolmap, fixture->provider.symbolmap, key);
    }
    fixture->provider.mysymbolmap = kh_init(symbolmap);
    CHECK("dlsym-custom.map", fixture->provider.mysymbolmap != NULL);
    if (!fixture->provider.mysymbolmap) {
        return;
    }
    key = kh_put(symbolmap, fixture->provider.mysymbolmap,
                 "dlsym", &inserted);
    CHECK("dlsym-custom.map-entry",
          inserted != -1 && key != kh_end(fixture->provider.mysymbolmap));
    if (key != kh_end(fixture->provider.mysymbolmap)) {
        kh_value(fixture->provider.mysymbolmap, key) = fixture_iFp;
    }
    fixture->provider.altmy = custom_prefix;
    fixture->provider.priv.w.box64lib = fixture->provider.priv.w.lib;
}

static int fixture_publish_native_dlerror(fixture_t *fixture)
{
    kzt_guest_registry_address_match_t provider = { 0 };
    kzt_lazy_prebind_record_t record = { 0 };
    kzt_lazy_prebind_lease_t publish = { 0 };

    if (kzt_guest_registry_find_live_object(
            fixture->context.kzt_guest_registry_context.registry,
            ALIAS_PROVIDER_LINK_MAP, &provider) != 0) {
        return -1;
    }
    record.source = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = SOURCE_LINK_MAP,
        .generation = fixture->source.generation,
        .namespace_id = 0,
    };
    record.provider = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = ALIAS_PROVIDER_LINK_MAP,
        .generation = provider.generation,
        .namespace_id = 0,
    };
    fixture->dlerror_slot = GUEST_TARGET - 0x20;
    record.slot_addr = (uintptr_t)&fixture->dlerror_slot;
    record.expected_slot = fixture->dlerror_slot;
    record.relocation_index = 1;
    record.bridge_target = fixture_native_bridge;
    record.bridge_generation = provider.generation;
    record.bridge_custom_wrapper = 1;
    record.version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    strcpy(record.symbol, "dlerror");
    strcpy(record.version, FIXTURE_VERSION);
    record.scope_proof = (kzt_guest_symbol_scope_result_t) {
        .status = KZT_GUEST_SYMBOL_SCOPE_SAFE,
        .reason = KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER,
        .scope_complete = 1,
        .lookup_order_known = 1,
        .selected_provider_link_map = record.provider.link_map_addr,
        .selected_provider_address = fixture_native_symbol,
        .selected_provider_binding = STB_GLOBAL,
        .selected_provider_type = STT_FUNC,
        .selected_provider_visibility = STV_DEFAULT,
        .scope_identity = {
            .source = {
                .link_map_addr = record.source.link_map_addr,
                .generation = record.source.generation,
                .namespace_id = record.source.namespace_id,
                .namespace_head = SOURCE_LINK_MAP + 0x100,
                .layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF,
            },
        },
    };
    if (kzt_lazy_prebind_scope_claim(
            fixture->context.kzt_lazy_prebind_scope, &record) !=
            KZT_LAZY_PREBIND_CLAIM_CREATED ||
        kzt_lazy_prebind_scope_publish_acquire(
            fixture->context.kzt_lazy_prebind_scope, &record, &publish) != 0) {
        return -1;
    }
    kzt_lazy_prebind_scope_publish_finish(&publish, 1);
    fixture->dlerror_slot = record.bridge_target;
    return 0;
}

static void fixture_destroy(fixture_t *fixture)
{
    if (fixture->provider.symbolmap) {
        kh_destroy(symbolmap, fixture->provider.symbolmap);
    }
    if (fixture->provider.mysymbolmap) {
        kh_destroy(symbolmap, fixture->provider.mysymbolmap);
    }
    if (fixture->provider.priv.w.lib) {
        dlclose(fixture->provider.priv.w.lib);
    }
    kzt_guest_library_access_destroy(&fixture->context.kzt_guest_library_access);
    kzt_lazy_prebind_scope_destroy(&fixture->context.kzt_lazy_prebind_scope);
    kzt_guest_registry_destroy(
        &fixture->context.kzt_guest_registry_context.registry);
}


static int fixture_lazy_direct_route(
    fixture_t *fixture, kzt_lazy_direct_route_result_t *result)
{
    return kzt_production_lazy_direct_route(
        &fixture->context, &fixture->head, 0, &fixture->rela,
        (uint64_t *)&fixture->slot, fixture->slot, 0,
        fixture->source.symbol,
        fixture->source.version_evidence, fixture->source.version, result);
}

static void fixture_set_unresolved_slot(fixture_t *fixture)
{
    fixture->slot = fixture->source.unresolved_stub;
    fixture->head.plt = fixture->slot - 8;
    fixture->head.plt_end = fixture->slot + 8;
}

static int fixture_claim_prebind_record(fixture_t *fixture)
{
    kzt_guest_registry_address_match_t provider_match;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = fixture_scope_read_guest_memory,
    };
    kzt_guest_symbol_scope_request_t request = {
        .source = {
            .link_map_addr = SOURCE_LINK_MAP,
            .generation = fixture->source.generation,
            .namespace_id = 0,
            .namespace_head = SOURCE_LINK_MAP,
            .layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF,
        },
        .symbol = FIXTURE_SYMBOL,
        .version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .version = FIXTURE_VERSION,
        .reference_binding = STB_GLOBAL,
        .reference_type = STT_FUNC,
        .reference_visibility = STV_DEFAULT,
    };
    kzt_lazy_prebind_record_t record = { 0 };

    if (kzt_guest_registry_find_live_object(
            fixture->context.kzt_guest_registry_context.registry,
            PROVIDER_LINK_MAP, &provider_match) != 0 ||
        kzt_guest_symbol_scope_discover(
            &request, &reader_ops, &record.scope_proof) !=
            KZT_GUEST_SYMBOL_SCOPE_SAFE) {
        return -1;
    }
    record.source = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = SOURCE_LINK_MAP,
        .generation = fixture->source.generation,
        .namespace_id = 0,
    };
    record.provider = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = PROVIDER_LINK_MAP,
        .generation = provider_match.generation,
        .namespace_id = 0,
    };
    record.slot_addr = (uintptr_t)&fixture->slot;
    record.expected_slot = fixture->slot;
    record.relocation_index = 0;
    record.bridge_target = fixture_native_bridge;
    record.bridge_generation = provider_match.generation;
    record.version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    strcpy(record.symbol, FIXTURE_SYMBOL);
    strcpy(record.version, FIXTURE_VERSION);
    return kzt_lazy_prebind_scope_claim(
               fixture->context.kzt_lazy_prebind_scope, &record) ==
               KZT_LAZY_PREBIND_CLAIM_CREATED ? 0 : -1;
}

static int fixture_eager_route(fixture_t *fixture,
                               uintptr_t expected_guest_target,
                               const char *version,
                               kzt_jump_slot_route_result_t *result)
{
    return kzt_production_jump_slot_route(
        &fixture->context, &fixture->provider, fixture_native_bridge,
        &fixture->head, 1, 0, &fixture->rela, (uint64_t *)&fixture->slot,
        fixture->slot, 0, 0, FIXTURE_SYMBOL, version, 1,
        expected_guest_target, fixture_native_bridge, result);
}

static int fixture_eager_route_with_evidence(
    fixture_t *fixture, uintptr_t expected_guest_target,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_jump_slot_route_result_t *result)
{
    return kzt_production_jump_slot_route_with_version_evidence(
        &fixture->context, &fixture->provider, fixture_native_bridge,
        &fixture->head, 1, 0, &fixture->rela, (uint64_t *)&fixture->slot,
        fixture->slot, 0, 0, FIXTURE_SYMBOL, version_evidence, version, 1,
        expected_guest_target, fixture_native_bridge, result);
}

static int fixture_eager_registry_route(
    fixture_t *fixture, uintptr_t expected_guest_target,
    kzt_jump_slot_route_result_t *result)
{
    return kzt_production_jump_slot_route_with_version_evidence(
        &fixture->context, NULL, expected_guest_target,
        &fixture->head, 1, 0, &fixture->rela,
        (uint64_t *)&fixture->slot, fixture->slot, 0, 0,
        FIXTURE_SYMBOL, KZT_SYMBOL_VERSION_VERSIONED, FIXTURE_VERSION, 1,
        expected_guest_target, 0, result);
}

static void hooks_reset(fixture_t *fixture, hook_mode_t mode)
{
    hook_fixture = fixture;
    hook_mode = mode;
    before_acquire_calls = 0;
    source_memory_access_calls = 0;
    owner_memory_access_calls = 0;
    owner_memory_all_lifetimes_held = 1;
    slot_load_calls = 0;
    after_cas_calls = 0;
    shadow_run_calls = 0;
    recycled_generation = 0;
    permission_begin_calls = 0;
    permission_end_calls = 0;
    fail_permission_begin = 0;
    fail_permission_end = 0;
    fail_permission_end_once = 0;
    decision_lease_active = 0;
    decision_lease_acquires = 0;
    decision_lease_releases = 0;
    decision_lease_held_at_validate = 0;
    decision_lease_held_at_permission_begin = 0;
    decision_lease_held_at_permission_end = 0;
    decision_lease_held_at_cas = 0;
    generation_validate_calls = 0;
    runtime_full_lifetime_validation_calls = 0;
    mapping_lock_active = 0;
}

void kzt_jump_slot_production_test_mapping_lock(void)
{
    CHECK("mapping-lock.acquire",
          pthread_mutex_lock(&mapping_transaction_lock) == 0);
    mapping_lock_active = 1;
}

void kzt_jump_slot_production_test_mapping_unlock(void)
{
    CHECK("mapping-lock.active", mapping_lock_active == 1);
    mapping_lock_active = 0;
    CHECK("mapping-lock.release",
          pthread_mutex_unlock(&mapping_transaction_lock) == 0);
}

int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease)
{
    if (!lease || !slot_addr) {
        return -1;
    }
    ++permission_begin_calls;
    decision_lease_held_at_permission_begin |= decision_lease_active;
    lease->checked = 1;
    lease->guest_page = slot_addr & ~(uintptr_t)0xfff;
    lease->guest_page_length = 0x1000;
    lease->original_permissions = 5;
    if (fail_permission_begin) {
        return -1;
    }
    lease->write_enabled = 1;
    return 0;
}

int kzt_jump_slot_production_test_end_slot_write(
    kzt_patch_spike_permission_lease_t *lease)
{
    if (!lease) {
        return -1;
    }
    ++permission_end_calls;
    decision_lease_held_at_permission_end |= decision_lease_active;
    if (fail_permission_end_once) {
        fail_permission_end_once = 0;
        return -1;
    }
    return fail_permission_end ? -1 : 0;
}

void kzt_jump_slot_production_test_before_source_lease_acquire(void)
{
    ++before_acquire_calls;
    if (hook_mode != HOOK_RECYCLE_BEFORE_ACQUIRE || !hook_fixture) {
        return;
    }
    CHECK("before.retire", kzt_guest_registry_retire(
              hook_fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP,
              hook_fixture->source.generation) == 0);
    recycled_generation = fixture_publish_source(hook_fixture);
    hook_mode = HOOK_NONE;
}

void kzt_jump_slot_production_test_before_source_memory_access(void)
{
    ++source_memory_access_calls;
}

void kzt_jump_slot_production_test_before_owner_memory_access(
    int source_lease_active, int decision_lease_active,
    int quiescence_active, int retained_provider_active,
    int owner_lease_active)
{
    ++owner_memory_access_calls;
    owner_memory_all_lifetimes_held &=
        source_lease_active && decision_lease_active && quiescence_active &&
        retained_provider_active && owner_lease_active;
}

void kzt_jump_slot_production_test_before_slot_load(void)
{
    if (hook_mode == HOOK_SLOT_CONFLICT_BEFORE_FINAL_LOAD &&
        decision_lease_active && hook_fixture) {
        hook_fixture->slot ^= 0x80;
        hook_mode = HOOK_NONE;
    }
    ++slot_load_calls;
}

void kzt_jump_slot_production_test_after_slot_load(uintptr_t *value)
{
    (void)value;
}

void kzt_jump_slot_production_test_after_slot_cas(int exchanged)
{
    (void)exchanged;
    ++after_cas_calls;
    decision_lease_held_at_cas |= decision_lease_active;
}

void kzt_jump_slot_production_test_shadow_run(void)
{
    ++shadow_run_calls;
}

void kzt_jump_slot_production_test_full_enrich(void)
{
}

void kzt_jump_slot_production_test_wrapper_only_enrich(void)
{
}

void kzt_jump_slot_production_test_before_generation_validate(void)
{
    if (!hook_fixture) {
        return;
    }
    ++generation_validate_calls;
    decision_lease_held_at_validate |= decision_lease_active;
}

void kzt_jump_slot_production_test_before_patch_decision_lease_acquire(void)
{
    kzt_guest_registry_t *registry;

    if (!hook_fixture) {
        return;
    }
    registry = hook_fixture->context.kzt_guest_registry_context.registry;
    if (hook_mode == HOOK_VIEW_CHANGE_BEFORE_DECISION_ACQUIRE) {
        kzt_guest_dynamic_view_t changed_view = hook_fixture->dynamic_view;

        changed_view.dynamic_addr += 0x2000;
        CHECK("pre-acquire.view-change", kzt_guest_registry_commit_dynamic_view(
              registry, SOURCE_LINK_MAP, hook_fixture->source.generation,
              &changed_view) == KZT_GUEST_REGISTRY_UPDATED);
        hook_mode = HOOK_NONE;
    }
}

void kzt_jump_slot_production_test_after_patch_decision_lease_acquire(void)
{
    decision_lease_active = 1;
    ++decision_lease_acquires;
}

void kzt_jump_slot_production_test_before_patch_decision_lease_release(void)
{
    CHECK("decision-lease.release-after-permission-end",
          permission_end_calls == 0 || decision_lease_held_at_permission_end == 1);
    CHECK("decision-lease.release-after-cas",
          after_cas_calls == 0 || decision_lease_held_at_cas == 1);
    decision_lease_active = 0;
    ++decision_lease_releases;
}


static void test_active_loader_scope_forces_guest_fallback(void)
{
    fixture_t fixture;
    kzt_guest_library_loader_scope_t loader_scope = { 0 };
    kzt_lazy_direct_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    fixture_set_unresolved_slot(&fixture);
    CHECK("loader-active.begin",
          kzt_guest_library_loader_scope_begin(
              fixture.context.kzt_guest_library_access.bindings,
              &loader_scope) == 0);
    CHECK("loader-active.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("loader-active.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
          fixture.slot == fixture.source.unresolved_stub);
    CHECK("loader-active.no-writer", after_cas_calls == 0);
    kzt_guest_library_loader_scope_end(&loader_scope);
    fixture_destroy(&fixture);
}

static void test_active_loader_scope_rejects_cached_scope_proof(void)
{
    fixture_t fixture;
    kzt_guest_library_loader_scope_t loader_scope = { 0 };
    kzt_lazy_direct_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    fixture_set_unresolved_slot(&fixture);
    CHECK("loader-active-cache.claim",
          fixture_claim_prebind_record(&fixture) == 0);
    CHECK("loader-active-cache.begin",
          kzt_guest_library_loader_scope_begin(
              fixture.context.kzt_guest_library_access.bindings,
              &loader_scope) == 0);
    CHECK("loader-active-cache.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("loader-active-cache.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
          fixture.slot == fixture.source.unresolved_stub);
    CHECK("loader-active-cache.no-writer", after_cas_calls == 0);
    kzt_guest_library_loader_scope_end(&loader_scope);
    fixture_destroy(&fixture);
}



static void test_retained_exact_handle_avoids_discovery_owner_walk(void)
{
    fixture_t fixture;
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t handle = {0};
    kzt_wrapper_bridge_provider_t provider;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("retained-discovery.lookup",
          kzt_guest_library_access_lookup_by_library(
              &fixture.context.kzt_guest_library_access, &fixture.provider,
              &key, &handle) == 0);
    CHECK("retained-discovery.prepare",
          kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
              &fixture.context, &handle, FIXTURE_SYMBOL,
              KZT_SYMBOL_VERSION_VERSIONED, FIXTURE_VERSION, &provider) == 1);
    CHECK("retained-discovery.handle",
          provider.match.retained_provider_handle == &handle);
    CHECK("retained-discovery.no-native-owner-walk",
          provider.match.native_owner == NULL &&
          runtime_full_lifetime_validation_calls == 0);
    CHECK("retained-discovery.check",
          provider.bridge_ops.check_bridge(provider.entry.native_symbol,
                                           provider.bridge_ops.opaque) ==
              fixture_native_bridge);
    CHECK("retained-discovery.no-late-full-validation",
          runtime_full_lifetime_validation_calls == 0);
    kzt_guest_library_handle_release(&handle);
    fixture_destroy(&fixture);
}

static void test_unretained_provider_revalidates_lifetime(void)
{
    fixture_t fixture;
    kzt_wrapper_bridge_provider_t provider;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unretained-handle.prepare",
          kzt_rela_runtime_wrapper_provider_discover(
              &fixture.context, &fixture.provider, FIXTURE_SYMBOL,
              FIXTURE_VERSION, &provider) == 1);
    CHECK("unretained-handle.not-retained",
          provider.match.retained_provider_handle == NULL);
    CHECK("unretained-handle.check",
          provider.bridge_ops.check_bridge(provider.entry.native_symbol,
                                           provider.bridge_ops.opaque) ==
              fixture_native_bridge);
    CHECK("unretained-handle.full-lifetime-validation",
          runtime_full_lifetime_validation_calls > 0);
    fixture_destroy(&fixture);
}

static void test_eager_decision_lease_lifetime(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager-decision.route", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager-decision.applied",
          result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED);
    CHECK("eager-decision.lifetime",
          decision_lease_acquires == 1 && decision_lease_releases == 1 &&
          decision_lease_active == 0 && decision_lease_held_at_validate == 1 &&
          decision_lease_held_at_permission_begin == 1 &&
          decision_lease_held_at_permission_end == 1 &&
          decision_lease_held_at_cas == 1);
    CHECK("eager-decision.single-under-lease-evidence-validation",
          generation_validate_calls == 1);
    fixture_destroy(&fixture);
}

static void test_guest_version_is_not_used_for_host_lookup(void)
{
    fixture_t fixture;
    kzt_wrapper_bridge_provider_t provider;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    CHECK("version-different.prepare",
          kzt_rela_runtime_wrapper_provider_discover(
              &fixture.context, &fixture.provider, FIXTURE_SYMBOL,
              FIXTURE_VERSION, &provider) == 1);
    CHECK("version-different.guest-version-kept",
          provider.manifest.entry_count == 1 &&
          !strcmp(provider.entry.symbol_version, FIXTURE_VERSION));
    CHECK("version-different.native-provider-symbol",
          provider.entry.native_symbol == fixture_native_symbol);
    fixture_destroy(&fixture);
}

static void test_native_symbol_missing_fails_open(void)
{
    fixture_t fixture;
    kzt_wrapper_bridge_provider_t provider;
    khint_t key;
    int inserted;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    key = kh_put(symbolmap, fixture.provider.symbolmap,
                 "kzt_native_symbol_missing", &inserted);
    CHECK("native-missing.map", inserted != -1 &&
          key != kh_end(fixture.provider.symbolmap));
    if (key != kh_end(fixture.provider.symbolmap)) {
        kh_value(fixture.provider.symbolmap, key) = fixture_iFp;
    }
    CHECK("native-missing.prepare",
          kzt_rela_runtime_wrapper_provider_discover(
              &fixture.context, &fixture.provider,
              "kzt_native_symbol_missing", FIXTURE_VERSION,
              &provider) == 0);
    CHECK("native-missing.no-manifest", provider.manifest.available == 0);
    CHECK("native-missing.no-add", fixture.bridge_map.add_calls == 0);
    fixture_destroy(&fixture);
}

static void test_dependency_symbol_owner_mismatch_fails_open(void)
{
    fixture_t fixture;
    kzt_wrapper_bridge_provider_t provider;
    void *libc_handle;
    void *libm_handle;
    void *dependency_symbol;
    struct link_map *handle_map = NULL;
    struct link_map *symbol_map = NULL;
    Dl_info symbol_info;
    khint_t key;
    int inserted;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    libm_handle = dlopen("libm.so.6", RTLD_LAZY | RTLD_LOCAL);
    CHECK("owner-mismatch.libm", libm_handle != NULL);
    if (!libm_handle) {
        fixture_destroy(&fixture);
        return;
    }
    dependency_symbol = dlsym(libm_handle, "malloc");
    CHECK("owner-mismatch.dependency-symbol", dependency_symbol != NULL);
    CHECK("owner-mismatch.precondition",
          dependency_symbol &&
          dlinfo(libm_handle, RTLD_DI_LINKMAP, &handle_map) == 0 &&
          dladdr1(dependency_symbol, &symbol_info, (void **)&symbol_map,
                  RTLD_DL_LINKMAP) != 0 &&
          handle_map && symbol_map && handle_map != symbol_map);
    key = kh_put(symbolmap, fixture.provider.symbolmap, "malloc", &inserted);
    CHECK("owner-mismatch.map", inserted != -1 &&
          key != kh_end(fixture.provider.symbolmap));
    if (key != kh_end(fixture.provider.symbolmap)) {
        kh_value(fixture.provider.symbolmap, key) = fixture_iFp;
    }
    libc_handle = fixture.provider.priv.w.lib;
    fixture.provider.priv.w.lib = libm_handle;
    CHECK("owner-mismatch.prepare",
          kzt_rela_runtime_wrapper_provider_discover(
              &fixture.context, &fixture.provider, "malloc",
              FIXTURE_VERSION, &provider) == 0);
    CHECK("owner-mismatch.no-manifest", provider.manifest.available == 0);
    CHECK("owner-mismatch.no-add", fixture.bridge_map.add_calls == 0);
    fixture.provider.priv.w.lib = libc_handle;
    dlclose(libm_handle);
    fixture_destroy(&fixture);
}


static void test_eager_registry_binding_selects_exact_provider(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.bridge_map.target = 0;
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("registry-eager.route",
          fixture_eager_registry_route(
              &fixture, GUEST_TARGET, &result) == 0);
    CHECK("registry-eager.applied",
          result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED);
    CHECK("registry-eager.exact",
          result.exact_provider_acquired && result.exact_provider_matched);
    CHECK("registry-eager.slot",
          fixture.slot == fixture_native_bridge);
    CHECK("registry-eager.add-once", fixture.bridge_map.add_calls == 1);
    fixture_destroy(&fixture);
}

static void test_exact_owner_bridge_survives_unsupported_scope_layout(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unsupported-scope.route",
          fixture_eager_registry_route(
              &fixture, GUEST_TARGET, &result) == 0);
    CHECK("unsupported-scope.status",
          result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED);
    CHECK("unsupported-scope.exact-provider",
          result.exact_provider_acquired && result.exact_provider_matched);
    CHECK("unsupported-scope.writer", result.native_writer_called);
    CHECK("unsupported-scope.slot", fixture.slot == fixture_native_bridge);
    fixture_destroy(&fixture);
}






static void test_lazy_direct_no_scope_uses_global_guard(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t result;

    if (fixture_init_with_options(&fixture, 0, 0) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 0);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("direct-no-scope-disabled.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("direct-no-scope-disabled.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
          fixture.slot == fixture.source.unresolved_stub);
    CHECK("direct-no-scope-disabled.no-cas", after_cas_calls == 0);
    CHECK("direct-no-scope-disabled.no-budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 0);
    fixture_destroy(&fixture);

    if (fixture_init_with_options(&fixture, 0, 1) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_use_dlsym_alias_symbol(&fixture);
    CHECK("direct-no-scope-enabled.dlerror",
          fixture_publish_native_dlerror(&fixture) == 0);
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("direct-no-scope-enabled.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("direct-no-scope-enabled.native",
          result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          result.selected_target == fixture_native_bridge &&
          fixture.slot == fixture_native_bridge);
    CHECK("direct-no-scope-enabled.cas", after_cas_calls == 1);
    CHECK("direct-no-scope-enabled.budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 1);
    CHECK("direct-no-scope-enabled.owner-reread",
          owner_memory_access_calls > 0 && owner_memory_all_lifetimes_held);
    fixture_destroy(&fixture);

    if (fixture_init_with_options(&fixture, 0, 0) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    kzt_patch_spike_guard_trip(&fixture.context.kzt_patch_spike_guard);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("direct-no-scope-circuit.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("direct-no-scope-circuit.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
              fixture.slot == fixture.source.unresolved_stub);
    CHECK("direct-no-scope-circuit.no-cas", after_cas_calls == 0);
    CHECK("direct-no-scope-circuit.no-budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 0);
    fixture_destroy(&fixture);
}

static void test_lazy_direct_no_scope_borrows_libdl_alias(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t result;

    if (fixture_init_with_options(&fixture, 0, 1) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_use_dlsym_alias_symbol(&fixture);
    CHECK("direct-libdl-alias.dlerror",
          fixture_publish_native_dlerror(&fixture) == 0);
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("direct-libdl-alias.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("direct-libdl-alias.native",
          result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          result.selected_target == fixture_native_bridge &&
          fixture.slot == fixture_native_bridge);
    CHECK("direct-libdl-alias.cas", after_cas_calls == 1);
    CHECK("direct-libdl-alias.budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 1);
    CHECK("direct-libdl-alias.owner-reread",
          owner_memory_access_calls > 0 && owner_memory_all_lifetimes_held);
    fixture_destroy(&fixture);
}






static void test_dlsym_requires_non_main_source_boundary(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t result;

    if (fixture_init_with_options(&fixture, 0, 1) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_use_dlsym_alias_symbol(&fixture);
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("dlsym-dso-no-dlerror.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("dlsym-dso-no-dlerror.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
          fixture.slot == fixture.source.unresolved_stub);
    CHECK("dlsym-dso-no-dlerror.no-cas", after_cas_calls == 0);
    fixture_destroy(&fixture);

    if (fixture_init_with_options(&fixture, 0, 1) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_use_dlsym_alias_symbol(&fixture);
    CHECK("dlsym-dso.dlerror",
          fixture_publish_native_dlerror(&fixture) == 0);
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("dlsym-dso.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("dlsym-dso.applied",
          result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          fixture.slot == fixture_native_bridge);
    CHECK("dlsym-dso.budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 1);
    fixture_destroy(&fixture);

    if (fixture_init_with_options(&fixture, 0, 1) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_use_dlsym_alias_symbol(&fixture);
    CHECK("dlsym-main.dlerror",
          fixture_publish_native_dlerror(&fixture) == 0);
    fixture.head.latx_type = LATX_ELF_TYPE_MAIN;
    fixture.context.kzt_guest_registry_context.main_namespace_head =
        SOURCE_LINK_MAP;
    fixture.context.kzt_guest_scope_layout =
        KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    fixture_set_unresolved_slot(&fixture);
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("dlsym-main.route",
          fixture_lazy_direct_route(&fixture, &result) == 0);
    CHECK("dlsym-main.guest",
          result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED &&
          fixture.slot == fixture.source.unresolved_stub);
    CHECK("dlsym-main.no-writer-budget",
          fixture.context.kzt_patch_spike_guard.write_attempts == 0 &&
          fixture.context.kzt_patch_spike_guard.write_successes == 0);
    CHECK("dlsym-main.no-cas", after_cas_calls == 0);
    fixture_destroy(&fixture);
}


static void test_created_inexact_bridge_fails_open(void)
{
    fixture_t fixture;
    kzt_wrapper_bridge_provider_t provider;
    kzt_wrapper_probe_request_t request = {
        .symbol_name = FIXTURE_SYMBOL,
        .symbol_version = FIXTURE_VERSION,
    };
    kzt_wrapper_probe_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.bridge_map.target = 0;
    fixture.bridge_map.force_inexact_add = 1;
    CHECK("inexact-add.prepare",
          kzt_rela_runtime_wrapper_provider_discover(
              &fixture.context, &fixture.provider, FIXTURE_SYMBOL,
              FIXTURE_VERSION, &provider) == 1);
    CHECK("inexact-add.probe",
          kzt_wrapper_probe_minimal_manifest(
              &provider.manifest, &request, &provider.bridge_ops,
              &result) == 0);
    CHECK("inexact-add.no-bridge", result.bridge_target == 0);
    CHECK("inexact-add.add-once", fixture.bridge_map.add_calls == 1);
    fixture_destroy(&fixture);
}

static void test_eager_production_request_evidence(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }

    hooks_reset(&fixture, HOOK_NONE);
    kzt_registry_diagnostics = 0;
    CHECK("eager.owner-match.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.owner-match.native",
          result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED &&
          fixture.slot == fixture_native_bridge &&
          result.legacy_fallback_attempted == 0);
    CHECK("eager.diagnostics-off-fast", shadow_run_calls == 0);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    kzt_registry_diagnostics = 1;
    CHECK("eager.shadow.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.shadow.real-route",
          result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED &&
          shadow_run_calls == 1);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager.owner-mismatch.call", fixture_eager_route(
          &fixture, SOURCE_START + 0x20, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.owner-mismatch.declined",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 &&
          fixture.slot == GUEST_TARGET);

    fixture.slot = 0xdeadbeef;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager.owner-unknown.call", fixture_eager_route(
          &fixture, 0xdeadbeef, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.owner-unknown.declined",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 &&
          fixture.slot == 0xdeadbeef);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager.wrapper-version.call", fixture_eager_route(
          &fixture, GUEST_TARGET, "KZT_UNSUPPORTED_VERSION", &result) == 0);
    CHECK("eager.wrapper-version.declined",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 &&
          fixture.slot == GUEST_TARGET);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    fixture.version_need.aux.vna_name = 20;
    CHECK("eager.runtime-version.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.runtime-version.declined-without-write",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 && after_cas_calls == 0 &&
          fixture.slot == GUEST_TARGET);
    fixture.version_need.aux.vna_name = 7;

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_RECYCLE_BEFORE_ACQUIRE);
    CHECK("eager.generation-race.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.generation-race.declined-without-write",
          recycled_generation > fixture.source.generation &&
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 && after_cas_calls == 0 &&
          fixture.slot == GUEST_TARGET);
    kzt_registry_diagnostics = 0;
    fixture_destroy(&fixture);
}

static void fixture_set_confirmed_unversioned(fixture_t *fixture)
{
    fixture->dynamic_view.versym.present = 0;
    fixture->dynamic_view.verneed.present = 0;
    fixture->dynamic_view.verneednum.present = 0;
    fixture->head.VerSym = NULL;
    fixture->source.version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    fixture->source.version = NULL;
    CHECK("unversioned.dynamic-view", kzt_guest_registry_commit_dynamic_view(
              fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP, fixture->source.generation,
              &fixture->dynamic_view) != KZT_GUEST_REGISTRY_ERROR);
}

static void test_confirmed_unversioned_production_paths_apply(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t lazy_result;
    kzt_jump_slot_route_result_t eager_result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_set_confirmed_unversioned(&fixture);
    fixture_set_unresolved_slot(&fixture);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unversioned-lazy.route",
          fixture_lazy_direct_route(&fixture, &lazy_result) == 0);
    CHECK("unversioned-lazy.applied",
          lazy_result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          fixture.slot == fixture_native_bridge);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unversioned-eager.route",
          fixture_eager_route_with_evidence(
              &fixture, GUEST_TARGET,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
              &eager_result) == 0);
    CHECK("unversioned-eager.applied",
          eager_result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED &&
          eager_result.legacy_fallback_attempted == 0 &&
          fixture.slot == fixture_native_bridge);
    fixture_destroy(&fixture);
}

static void test_unknown_version_evidence_preserves_guest_path(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_set_confirmed_unversioned(&fixture);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unknown-eager.route",
          fixture_eager_route_with_evidence(
              &fixture, GUEST_TARGET, KZT_SYMBOL_VERSION_UNKNOWN, NULL,
              &result) == 0);
    CHECK("unknown-eager.declined",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 &&
          fixture.slot == GUEST_TARGET);
    fixture_destroy(&fixture);
}



static void test_eager_transaction_rolls_back_to_zero(void)
{
    fixture_t fixture;
    uintptr_t final_value = GUEST_TARGET;
    kzt_production_slot_transaction_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.slot = 0;
    hooks_reset(&fixture, HOOK_NONE);
    fail_permission_end_once = 1;
    result = kzt_production_guest_relocation_write(
        &fixture.context, SOURCE_LINK_MAP,
        KZT_PATCH_RELOCATION_GLOB_DAT, (uintptr_t)&fixture.slot, 0,
        GUEST_TARGET, FIXTURE_SYMBOL,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &final_value);
    CHECK("eager-zero.result",
          result == KZT_PRODUCTION_SLOT_TRANSACTION_ROLLED_BACK);
    CHECK("eager-zero.slot-restored", fixture.slot == 0 && final_value == 0);
    CHECK("eager-zero.two-cas", after_cas_calls == 2);
    CHECK("eager-zero.permission-restored", permission_end_calls == 2);
    CHECK("eager-zero.circuit-closed",
          kzt_patch_spike_guard_circuit_open(
              &fixture.context.kzt_patch_spike_guard) == 0);
    fixture_destroy(&fixture);
}

static void test_guest_relocation_ignores_optional_patch_gate(void)
{
    fixture_t fixture;
    uintptr_t final_value;
    kzt_production_slot_transaction_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    reset_guard(&fixture, 0);
    fixture.slot = 0;
    final_value = 0;
    result = kzt_production_guest_relocation_write(
        &fixture.context, SOURCE_LINK_MAP,
        KZT_PATCH_RELOCATION_GLOB_DAT, (uintptr_t)&fixture.slot, 0,
        GUEST_TARGET, FIXTURE_SYMBOL,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &final_value);
    CHECK("guest-mandatory.disabled.applied",
          result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED &&
          fixture.slot == GUEST_TARGET && final_value == GUEST_TARGET);
    CHECK("guest-mandatory.disabled.no-budget-use",
          fixture.context.kzt_patch_spike_guard.write_attempts == 0);

    hooks_reset(&fixture, HOOK_NONE);
    reset_guard_budget(&fixture.context, 0);
    fixture.slot = 0;
    final_value = 0;
    result = kzt_production_guest_relocation_write(
        &fixture.context, SOURCE_LINK_MAP,
        KZT_PATCH_RELOCATION_JUMP_SLOT, (uintptr_t)&fixture.slot, 0,
        GUEST_TARGET, FIXTURE_SYMBOL,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL, &final_value);
    CHECK("guest-mandatory.budget-exhausted.applied",
          result == KZT_PRODUCTION_SLOT_TRANSACTION_APPLIED &&
          fixture.slot == GUEST_TARGET && final_value == GUEST_TARGET);
    CHECK("guest-mandatory.budget-exhausted.no-budget-use",
          fixture.context.kzt_patch_spike_guard.write_attempts == 0);
    fixture_destroy(&fixture);
}





static void test_eager_pre_acquire_evidence_change_fails_open(void)
{
    fixture_t fixture;
    kzt_jump_slot_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_VIEW_CHANGE_BEFORE_DECISION_ACQUIRE);
    CHECK("eager-pre-acquire.route", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager-pre-acquire.declined",
          result.status == KZT_JUMP_SLOT_ROUTE_BYPASS &&
          result.legacy_fallback_attempted == 0 &&
          fixture.slot == GUEST_TARGET);
    CHECK("eager-pre-acquire.no-add", fixture.bridge_map.add_calls == 0);
    CHECK("eager-pre-acquire.decision-release",
          decision_lease_acquires == 1 && decision_lease_releases == 1 &&
          decision_lease_active == 0);
    fixture_destroy(&fixture);
}

static void test_final_slot_stale_before_bridge_creation_fails_open(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t lazy_result;
    kzt_jump_slot_route_result_t eager_result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.bridge_map.target = 0;
    fixture_set_unresolved_slot(&fixture);
    hooks_reset(&fixture, HOOK_SLOT_CONFLICT_BEFORE_FINAL_LOAD);
    CHECK("lazy-final-stale.route",
          fixture_lazy_direct_route(&fixture, &lazy_result) == 0);
    CHECK("lazy-final-stale.status",
          lazy_result.status == KZT_LAZY_DIRECT_ROUTE_GUEST_REQUIRED);
    CHECK("lazy-final-stale.slot", fixture.slot != fixture_native_bridge);
    CHECK("lazy-final-stale.no-write",
          permission_begin_calls == 0 && after_cas_calls == 0);
    CHECK("lazy-final-stale.decision-release",
          decision_lease_acquires == 1 && decision_lease_releases == 1 &&
          decision_lease_active == 0);

    fixture.slot = GUEST_TARGET;
    fixture.bridge_map.target = 0;
    fixture.bridge_map.add_calls = 0;
    fixture.bridge_map.check_calls = 0;
    hooks_reset(&fixture, HOOK_SLOT_CONFLICT_BEFORE_FINAL_LOAD);
    CHECK("eager-final-stale.route", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &eager_result) == 0);
    CHECK("eager-final-stale.preserved",
          eager_result.status == KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED &&
          fixture.bridge_map.add_calls == 0 && permission_begin_calls == 0 &&
          fixture.bridge_map.check_calls == 0 && after_cas_calls == 0 &&
          eager_result.native_writer_called == 0 &&
          decision_lease_acquires == 1 && decision_lease_releases == 1 &&
          decision_lease_active == 0);
    fixture_destroy(&fixture);
}

static void test_bridge_first_bindings(void)
{
    fixture_t fixture;
    kzt_lazy_direct_route_result_t lazy_result;
    kzt_jump_slot_route_result_t eager_result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.bridge_map.target = 0;
    fixture_set_unresolved_slot(&fixture);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("bridge.lazy-route",
          fixture_lazy_direct_route(&fixture, &lazy_result) == 0);
    CHECK("bridge.lazy-first-create",
          lazy_result.status == KZT_LAZY_DIRECT_ROUTE_NATIVE_APPLIED &&
          fixture.bridge_map.add_calls == 1);

    fixture.slot = GUEST_TARGET;
    fixture.bridge_map.target = 0;
    fixture.bridge_map.add_calls = 0;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("bridge.eager-route", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &eager_result) == 0);
    CHECK("bridge.eager-first-create",
          eager_result.status == KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED &&
          fixture.bridge_map.add_calls == 1);
    fixture_destroy(&fixture);
}














static int finish_test_run(const char *pass_message)
{
    if (failures) {
        fprintf(stderr, "%d lazy production lease checks failed\n", failures);
        return 1;
    }
    puts(pass_message);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "this test does not accept selectors\n");
        return 2;
    }
    test_active_loader_scope_forces_guest_fallback();
    test_active_loader_scope_rejects_cached_scope_proof();
    test_retained_exact_handle_avoids_discovery_owner_walk();
    test_unretained_provider_revalidates_lifetime();
    test_eager_decision_lease_lifetime();
    test_guest_version_is_not_used_for_host_lookup();
    test_native_symbol_missing_fails_open();
    test_dependency_symbol_owner_mismatch_fails_open();
    test_eager_registry_binding_selects_exact_provider();
    test_exact_owner_bridge_survives_unsupported_scope_layout();
    test_lazy_direct_no_scope_uses_global_guard();
    test_lazy_direct_no_scope_borrows_libdl_alias();
    test_dlsym_requires_non_main_source_boundary();
    test_created_inexact_bridge_fails_open();
    test_eager_production_request_evidence();
    test_confirmed_unversioned_production_paths_apply();
    test_unknown_version_evidence_preserves_guest_path();
    test_eager_transaction_rolls_back_to_zero();
    test_guest_relocation_ignores_optional_patch_gate();
    test_eager_pre_acquire_evidence_change_fails_open();
    test_final_slot_stale_before_bridge_creation_fails_open();
    test_bridge_first_bindings();

    return finish_test_run(
        "KZT lazy direct and eager production routes: PASS");
}
