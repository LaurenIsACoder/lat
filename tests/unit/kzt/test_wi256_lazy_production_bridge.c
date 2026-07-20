#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "elf.h"
#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge_private.h"
#include "target/i386/latx/include/elfloader_private.h"
#include "target/i386/latx/include/khash.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/kzt_jump_slot_production.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"
#include "target/i386/latx/include/librarian_private.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

#define FIXTURE_SYMBOL "uname"
#define FIXTURE_VERSION "GLIBC_2.2.5"
#define SOURCE_LINK_MAP 0x1000
#define PROVIDER_LINK_MAP 0x2000
#define SOURCE_START 0x70000000
#define GUEST_TARGET 0x71000020
#define STRESS_ITERATIONS 1000

static int failures;
static uintptr_t fixture_native_symbol;
static uintptr_t fixture_native_bridge;
int relocation_log;
int kzt_registry_diagnostics;

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
    uintptr_t slot;
    kzt_lazy_binding_pending_t pending;
    kzt_guest_object_observation_t source_observation;
    kzt_guest_dynamic_view_t dynamic_view;
} fixture_t;

typedef enum hook_mode {
    HOOK_NONE = 0,
    HOOK_RECYCLE_BEFORE_ACQUIRE,
    HOOK_RETIRE_AFTER_CAS,
    HOOK_RETIRE_AFTER_CAS_ROLLBACK,
} hook_mode_t;

typedef struct retire_sync {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    fixture_t *fixture;
    unsigned long generation;
    int go;
    int retire_called;
    int retire_done;
    int retire_result;
    int unloading_observed;
    int completed_inside_hook;
} retire_sync_t;

static fixture_t *hook_fixture;
static retire_sync_t *hook_retire;
static hook_mode_t hook_mode;
static int before_acquire_calls;
static int source_memory_access_calls;
static int slot_load_calls;
static int after_cas_calls;
static int lease_seen_at_first_slot_load;
static int force_verify_mismatch;
static int shadow_run_calls;
static unsigned long recycled_generation;
static int permission_begin_calls;
static int permission_end_calls;
static int fail_permission_begin;
static int fail_permission_end;

uintptr_t CheckBridged(bridge_t *bridge, void *fnc);
uintptr_t AddCheckBridge(bridge_t *bridge, wrapper_t wrapper, void *fnc,
                         int stack_bytes, const char *name);
const char *SymName(elfheader_t *head, Elf64_Sym *sym);
void kzt_jump_slot_production_test_before_source_lease_acquire(void);
void kzt_jump_slot_production_test_before_source_memory_access(void);
void kzt_jump_slot_production_test_before_slot_load(void);
void kzt_jump_slot_production_test_after_slot_load(uintptr_t *value);
void kzt_jump_slot_production_test_after_slot_cas(int exchanged);
void kzt_jump_slot_production_test_shadow_run(void);
int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease);
int kzt_jump_slot_production_test_end_slot_write(
    kzt_patch_spike_permission_lease_t *lease);

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
    return FIXTURE_SYMBOL;
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

static void fixture_publish_resolver(fixture_t *fixture)
{
    kzt_guest_lazy_resolver_t resolver = {
        .link_map_slot = SOURCE_START + 0x2000,
        .resolver_slot = SOURCE_START + 0x2008,
        .guest_link_map = SOURCE_LINK_MAP,
        .guest_resolver = SOURCE_START + 0x3000,
    };

    fixture->pending.guest_resolver = resolver.guest_resolver;
    CHECK("source.resolver", kzt_guest_registry_publish_lazy_resolver(
              fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP,
              fixture->pending.source_generation, 0, &resolver) == 0);
}

static void reset_guard(fixture_t *fixture, int enabled)
{
    kzt_patch_spike_config_t config = { enabled, 1, 1 };
    kzt_patch_spike_guard_init(&fixture->context.kzt_patch_spike_guard,
                               &config);
}

static int fixture_init(fixture_t *fixture)
{
    static char source_name[] = "librequester.so";
    static char provider_name[] = "libc.so.6";
    static char dynstr[] = "\0uname\0" FIXTURE_VERSION "\0KZT_BAD_VERSION\0";
    kzt_guest_object_observation_t provider_observation;
    kzt_guest_library_binding_key_t provider_key;
    khint_t map_key;
    int inserted;
    int initial_failures = failures;

    memset(fixture, 0, sizeof(*fixture));
    fixture->versym = 2;
    fixture->slot = GUEST_TARGET;
    fixture->context.kzt_guest_registry_context.registry =
        kzt_guest_registry_init();
    CHECK("registry.init",
          fixture->context.kzt_guest_registry_context.registry != NULL);
    CHECK("binding.init", kzt_guest_library_access_init(
                              &fixture->context.kzt_guest_library_access) == 0);
    if (!fixture->context.kzt_guest_registry_context.registry ||
        !fixture->context.kzt_guest_library_access.initialized) {
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
        PROVIDER_LINK_MAP, 0x71000000, 0x71010000, provider_name);
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
    fixture->dynamic_view.syment = scalar_field(sizeof(fixture->sym));
    fixture->dynamic_view.strtab = runtime_field((uintptr_t)dynstr);
    fixture->dynamic_view.strsz = scalar_field(sizeof(dynstr));
    fixture->dynamic_view.versym = runtime_field((uintptr_t)&fixture->versym);
    fixture->dynamic_view.verneed = runtime_field(
        (uintptr_t)&fixture->version_need);
    fixture->dynamic_view.verneednum = scalar_field(1);
    fixture->sym.st_name = 1;
    fixture->version_need.need.vn_version = 1;
    fixture->version_need.need.vn_cnt = 1;
    fixture->version_need.need.vn_aux = sizeof(Elf64_Verneed);
    fixture->version_need.aux.vna_other = 2;
    fixture->version_need.aux.vna_name = 7;
    fixture->pending.source_generation = fixture_publish_source(fixture);
    fixture_publish_resolver(fixture);
    provider_key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = PROVIDER_LINK_MAP,
        .generation = observe_object(
            fixture->context.kzt_guest_registry_context.registry,
            &provider_observation),
        .namespace_id = 0,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    CHECK("provider.track", kzt_guest_library_track(
              fixture->context.kzt_guest_library_access.bindings,
              &fixture->provider) == 0);
    CHECK("provider.pair", kzt_guest_library_note_exact_pair(
              fixture->context.kzt_guest_library_access.bindings,
              PROVIDER_LINK_MAP, &fixture->provider,
              KZT_GUEST_LIBRARY_OBJECT_WRAPPED) ==
              KZT_GUEST_LIBRARY_BINDING_PENDING);
    CHECK("provider.publish", kzt_guest_library_note_observation(
              fixture->context.kzt_guest_library_access.bindings,
              &provider_key) == KZT_GUEST_LIBRARY_BINDING_ADDED);

    fixture->rela.r_info = R_X86_64_JUMP_SLOT;
    fixture->rela.r_offset = (uintptr_t)&fixture->slot;
    fixture->head.name = source_name;
    fixture->head.path = source_name;
    fixture->head.memory = (char *)SOURCE_START;
    fixture->head.memsz = 0x10000;
    fixture->head.Dynamic = (Elf64_Dyn *)(SOURCE_START + 0x1000);
    fixture->head.jmprel = (uintptr_t)&fixture->rela;
    fixture->head.pltsz = sizeof(fixture->rela);
    fixture->head.pltent = sizeof(fixture->rela);
    fixture->head.DynSym = &fixture->sym;
    fixture->head.VerSym = &fixture->versym;
    fixture->head.self_link_map = SOURCE_LINK_MAP;
    fixture->elfs[0] = &fixture->head;
    fixture->context.elfs = fixture->elfs;
    fixture->context.elfsize = 1;

    fixture->pending.armed = 1;
    fixture->pending.context_id = (uintptr_t)&fixture->context;
    fixture->pending.source_link_map = SOURCE_LINK_MAP;
    fixture->pending.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN;
    fixture->pending.namespace_id = 0;
    fixture->pending.slot_addr = (uintptr_t)&fixture->slot;
    fixture->pending.unresolved_stub = GUEST_TARGET - 0x10;
    fixture->pending.symbol = FIXTURE_SYMBOL;
    fixture->pending.version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    fixture->pending.version = FIXTURE_VERSION;
    return failures == initial_failures ? 0 : -1;
}

static void fixture_destroy(fixture_t *fixture)
{
    if (fixture->provider.symbolmap) {
        kh_destroy(symbolmap, fixture->provider.symbolmap);
    }
    if (fixture->provider.priv.w.lib) {
        dlclose(fixture->provider.priv.w.lib);
    }
    kzt_guest_library_access_destroy(&fixture->context.kzt_guest_library_access);
    kzt_guest_registry_destroy(
        &fixture->context.kzt_guest_registry_context.registry);
}

static int fixture_route(fixture_t *fixture,
                         kzt_lazy_binding_route_result_t *result)
{
    return kzt_production_lazy_route_guest_target(
        &fixture->context, &fixture->pending, GUEST_TARGET, result);
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

static void hooks_reset(fixture_t *fixture, hook_mode_t mode)
{
    hook_fixture = fixture;
    hook_retire = NULL;
    hook_mode = mode;
    before_acquire_calls = 0;
    source_memory_access_calls = 0;
    slot_load_calls = 0;
    after_cas_calls = 0;
    lease_seen_at_first_slot_load = 0;
    force_verify_mismatch = mode == HOOK_RETIRE_AFTER_CAS_ROLLBACK;
    shadow_run_calls = 0;
    recycled_generation = 0;
    permission_begin_calls = 0;
    permission_end_calls = 0;
    fail_permission_begin = 0;
    fail_permission_end = 0;
}

int kzt_jump_slot_production_test_begin_slot_write(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease)
{
    if (!lease || !slot_addr) {
        return -1;
    }
    ++permission_begin_calls;
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
              hook_fixture->pending.source_generation) == 0);
    recycled_generation = fixture_publish_source(hook_fixture);
    hook_mode = HOOK_NONE;
}

void kzt_jump_slot_production_test_before_source_memory_access(void)
{
    ++source_memory_access_calls;
}

void kzt_jump_slot_production_test_before_slot_load(void)
{
    if (slot_load_calls == 0 && hook_fixture) {
        kzt_guest_object_snapshot_t *snapshot = NULL;

        if (kzt_guest_registry_find_by_link_map(
                hook_fixture->context.kzt_guest_registry_context.registry,
                SOURCE_LINK_MAP,
                &snapshot) == 0 && snapshot &&
            snapshot->active_source_leases == 1) {
            lease_seen_at_first_slot_load = 1;
        }
        kzt_guest_object_snapshot_free(snapshot);
    }
    ++slot_load_calls;
}

void kzt_jump_slot_production_test_after_slot_load(uintptr_t *value)
{
    if (force_verify_mismatch && slot_load_calls == 3 && value) {
        *value ^= 0x10;
        force_verify_mismatch = 0;
    }
}

static void *retire_worker(void *opaque)
{
    retire_sync_t *sync = opaque;
    int result;

    pthread_mutex_lock(&sync->lock);
    while (!sync->go) {
        pthread_cond_wait(&sync->cond, &sync->lock);
    }
    sync->retire_called = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);

    result = kzt_guest_registry_retire(
        sync->fixture->context.kzt_guest_registry_context.registry,
        SOURCE_LINK_MAP,
        sync->generation);
    pthread_mutex_lock(&sync->lock);
    sync->retire_result = result;
    sync->retire_done = 1;
    pthread_cond_broadcast(&sync->cond);
    pthread_mutex_unlock(&sync->lock);
    return NULL;
}

void kzt_jump_slot_production_test_after_slot_cas(int exchanged)
{
    struct timespec start;
    retire_sync_t *sync = hook_retire;

    ++after_cas_calls;
    if (!exchanged ||
        (hook_mode != HOOK_RETIRE_AFTER_CAS &&
         hook_mode != HOOK_RETIRE_AFTER_CAS_ROLLBACK) || !sync) {
        return;
    }
    hook_mode = HOOK_NONE;
    pthread_mutex_lock(&sync->lock);
    sync->go = 1;
    pthread_cond_broadcast(&sync->cond);
    while (!sync->retire_called) {
        pthread_cond_wait(&sync->cond, &sync->lock);
    }
    pthread_mutex_unlock(&sync->lock);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        kzt_guest_object_snapshot_t *snapshot = NULL;
        struct timespec now;
        int done;

        if (kzt_guest_registry_find_by_link_map(
                sync->fixture->context.kzt_guest_registry_context.registry,
                SOURCE_LINK_MAP,
                &snapshot) != 0) {
            pthread_mutex_lock(&sync->lock);
            done = sync->retire_done;
            sync->unloading_observed = !done;
            sync->completed_inside_hook = done;
            pthread_mutex_unlock(&sync->lock);
            kzt_guest_object_snapshot_free(snapshot);
            break;
        }
        kzt_guest_object_snapshot_free(snapshot);
        pthread_mutex_lock(&sync->lock);
        done = sync->retire_done;
        pthread_mutex_unlock(&sync->lock);
        if (done) {
            pthread_mutex_lock(&sync->lock);
            sync->completed_inside_hook = 1;
            pthread_mutex_unlock(&sync->lock);
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 2) {
            break;
        }
        sched_yield();
    }
}

void kzt_jump_slot_production_test_shadow_run(void)
{
    ++shadow_run_calls;
}

static int retire_sync_init(retire_sync_t *sync, fixture_t *fixture)
{
    memset(sync, 0, sizeof(*sync));
    sync->fixture = fixture;
    sync->generation = fixture->pending.source_generation;
    if (pthread_mutex_init(&sync->lock, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&sync->cond, NULL) != 0) {
        pthread_mutex_destroy(&sync->lock);
        return -1;
    }
    return 0;
}

static void retire_sync_destroy(retire_sync_t *sync)
{
    pthread_cond_destroy(&sync->cond);
    pthread_mutex_destroy(&sync->lock);
}

static void test_successful_production_route(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("success.route", fixture_route(&fixture, &result) == 0);
    CHECK("success.applied",
          result.status == KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED);
    CHECK("success.slot", fixture.slot == fixture_native_bridge);
    CHECK("success.lease", before_acquire_calls == 1);
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

static void test_missing_bridge_is_created_from_exact_provider(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.bridge_map.target = 0;
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("create-bridge.route", fixture_route(&fixture, &result) == 0);
    CHECK("create-bridge.applied",
          result.status == KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED);
    CHECK("create-bridge.add-once", fixture.bridge_map.add_calls == 1);
    CHECK("create-bridge.slot", fixture.slot == fixture_native_bridge);
    CHECK("create-bridge.exact",
          CheckBridged(fixture.provider.priv.w.bridge,
                       (void *)fixture_native_symbol) ==
              fixture_native_bridge);
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
    CHECK("eager.owner-mismatch.legacy",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 &&
          fixture.slot == fixture_native_bridge);

    fixture.slot = 0xdeadbeef;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager.owner-unknown.call", fixture_eager_route(
          &fixture, 0xdeadbeef, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.owner-unknown.legacy",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 &&
          fixture.slot == fixture_native_bridge);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("eager.wrapper-version.call", fixture_eager_route(
          &fixture, GUEST_TARGET, "KZT_UNSUPPORTED_VERSION", &result) == 0);
    CHECK("eager.wrapper-version.legacy",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 &&
          fixture.slot == fixture_native_bridge);

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    fixture.version_need.aux.vna_name = 20;
    CHECK("eager.runtime-version.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.runtime-version.legacy-once",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 && after_cas_calls == 1 &&
          fixture.slot == fixture_native_bridge);
    fixture.version_need.aux.vna_name = 7;

    fixture.slot = GUEST_TARGET;
    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_RECYCLE_BEFORE_ACQUIRE);
    CHECK("eager.generation-race.call", fixture_eager_route(
          &fixture, GUEST_TARGET, FIXTURE_VERSION, &result) == 0);
    CHECK("eager.generation-race.legacy-once",
          recycled_generation > fixture.pending.source_generation &&
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 && after_cas_calls == 1 &&
          fixture.slot == fixture_native_bridge);
    kzt_registry_diagnostics = 0;
    fixture_destroy(&fixture);
}

static void fixture_set_confirmed_unversioned(fixture_t *fixture)
{
    fixture->dynamic_view.versym.present = 0;
    fixture->dynamic_view.verneed.present = 0;
    fixture->dynamic_view.verneednum.present = 0;
    fixture->head.VerSym = NULL;
    fixture->pending.version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    fixture->pending.version = NULL;
    CHECK("unversioned.dynamic-view", kzt_guest_registry_commit_dynamic_view(
              fixture->context.kzt_guest_registry_context.registry,
              SOURCE_LINK_MAP, fixture->pending.source_generation,
              &fixture->dynamic_view) != KZT_GUEST_REGISTRY_ERROR);
}

static void test_confirmed_unversioned_production_paths_apply(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t lazy_result;
    kzt_jump_slot_route_result_t eager_result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture_set_confirmed_unversioned(&fixture);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("unversioned-lazy.route",
          fixture_route(&fixture, &lazy_result) == 0);
    CHECK("unversioned-lazy.applied",
          lazy_result.status == KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED &&
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
    CHECK("unknown-eager.legacy",
          result.status == KZT_JUMP_SLOT_ROUTE_LEGACY_APPLIED &&
          result.legacy_fallback_attempted == 1 &&
          fixture.slot == fixture_native_bridge);
    fixture_destroy(&fixture);
}

static void test_production_permission_transaction_preserves_on_restore_error(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_NONE);
    fail_permission_end = 1;
    CHECK("permission.route", fixture_route(&fixture, &result) == 0);
    CHECK("permission.begin", permission_begin_calls == 1);
    CHECK("permission.end", permission_end_calls == 1);
    CHECK("permission.no-legacy-mask",
          result.status == KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED);
    CHECK("permission.no-second-write", after_cas_calls == 1);
    CHECK("permission.circuit",
          kzt_patch_spike_guard_circuit_open(
              &fixture.context.kzt_patch_spike_guard) == 1);
    fixture_destroy(&fixture);
}

static void test_recycle_before_acquire_preserves_guest(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t result;
    unsigned long old_generation;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    old_generation = fixture.pending.source_generation;
    hooks_reset(&fixture, HOOK_RECYCLE_BEFORE_ACQUIRE);
    CHECK("before.route", fixture_route(&fixture, &result) == 0);
    CHECK("before.recycled", recycled_generation > old_generation);
    CHECK("before.preserved",
          result.status == KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED);
    CHECK("before.slot", fixture.slot == GUEST_TARGET);
    CHECK("before.no-source-memory", source_memory_access_calls == 0);
    CHECK("before.no-slot-read", slot_load_calls == 0);
    fixture_destroy(&fixture);
}

static void test_retire_before_first_slot_read_skips_guest_memory(void)
{
    fixture_t fixture;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    uintptr_t value = 0;
    unsigned long old_generation;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    old_generation = fixture.pending.source_generation;
    hooks_reset(&fixture, HOOK_RECYCLE_BEFORE_ACQUIRE);
    CHECK("first-read.load-rejected",
          kzt_production_lazy_load_slot_with_lease(
              &fixture.context, &fixture.pending,
              (uintptr_t)&fixture.slot, &value, &source_lease) != 0);
    CHECK("first-read.recycled", recycled_generation > old_generation);
    CHECK("first-read.no-lease", source_lease.active == 0);
    CHECK("first-read.no-slot-access", slot_load_calls == 0);
    CHECK("first-read.slot-untouched", fixture.slot == GUEST_TARGET);
    fixture_destroy(&fixture);
}

static void test_namespace_mismatch_precedes_any_source_read(void)
{
    fixture_t fixture;
    kzt_lazy_binding_result_t result;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    fixture.pending.namespace_id = 1;
    fixture.pending.namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_EXPLICIT;
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("namespace.complete", kzt_production_lazy_complete(
          &fixture.context, &fixture.pending, &result) == 0);
    CHECK("namespace.preserved",
          result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK("namespace.reason",
          result.reason == KZT_LAZY_BINDING_REASON_SLOT_READ_ERROR);
    CHECK("namespace.real-result-empty", result.slot_before == 0 &&
          result.slot_after == 0 && result.selected_target == 0);
    CHECK("namespace.pending-consumed", fixture.pending.armed == 0 &&
          result.pending_cleared == 1);
    CHECK("namespace.no-lease-hook", before_acquire_calls == 0);
    CHECK("namespace.no-source-memory", source_memory_access_calls == 0);
    CHECK("namespace.no-slot-read", slot_load_calls == 0);
    CHECK("namespace.no-memory-change", fixture.slot == GUEST_TARGET);
    fixture_destroy(&fixture);
}

typedef enum guard_fail_open_mode {
    GUARD_FAIL_OPEN_DISABLED = 0,
    GUARD_FAIL_OPEN_CIRCUIT,
    GUARD_FAIL_OPEN_BUDGET_ZERO,
} guard_fail_open_mode_t;

static void run_completion_guard_fail_open(guard_fail_open_mode_t mode,
                                           const char *prefix)
{
    fixture_t fixture;
    kzt_lazy_binding_result_t result;
    kzt_patch_spike_config_t config = { 0 };

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    switch (mode) {
    case GUARD_FAIL_OPEN_DISABLED:
        /* Matches the real verifier default-options all-zero guard. */
        break;
    case GUARD_FAIL_OPEN_CIRCUIT:
        config = (kzt_patch_spike_config_t) { 1, 1, 1 };
        break;
    case GUARD_FAIL_OPEN_BUDGET_ZERO:
        config = (kzt_patch_spike_config_t) { 1, 1, 0 };
        break;
    }
    kzt_patch_spike_guard_init(&fixture.context.kzt_patch_spike_guard,
                               &config);
    if (mode == GUARD_FAIL_OPEN_CIRCUIT) {
        fixture.context.kzt_patch_spike_guard.circuit_open = 1;
    }
    hooks_reset(&fixture, HOOK_NONE);

    CHECK(prefix, kzt_production_lazy_complete(
          &fixture.context, &fixture.pending, &result) == 0);
    CHECK(prefix, result.status == KZT_LAZY_BINDING_GUEST_PRESERVED);
    CHECK(prefix, result.reason == KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE);
    CHECK(prefix, result.slot_before == GUEST_TARGET);
    CHECK(prefix, result.slot_after == GUEST_TARGET);
    CHECK(prefix, result.selected_target == GUEST_TARGET);
    CHECK(prefix, fixture.slot == GUEST_TARGET);
    CHECK(prefix, fixture.context.kzt_patch_spike_guard.write_attempts == 0 &&
          fixture.context.kzt_patch_spike_guard.write_successes == 0);
    CHECK(prefix, before_acquire_calls == 1);
    CHECK(prefix, lease_seen_at_first_slot_load == 1);
    CHECK(prefix, slot_load_calls > 0 && source_memory_access_calls > 0);
    CHECK(prefix, fixture.pending.armed == 0 && result.pending_cleared == 1);
    fixture_destroy(&fixture);
}

static void test_guard_fail_open_keeps_real_completion_evidence(void)
{
    run_completion_guard_fail_open(GUARD_FAIL_OPEN_DISABLED,
                                   "guard-disabled-completion");
    run_completion_guard_fail_open(GUARD_FAIL_OPEN_CIRCUIT,
                                   "guard-circuit-completion");
    run_completion_guard_fail_open(GUARD_FAIL_OPEN_BUDGET_ZERO,
                                   "guard-budget-completion");
}

static void run_after_cas_retire(fixture_t *fixture, const char *prefix)
{
    retire_sync_t sync;
    pthread_t thread;
    kzt_lazy_binding_route_result_t result;
    int created;

    if (retire_sync_init(&sync, fixture) != 0) {
        CHECK(prefix, 0);
        return;
    }
    hooks_reset(fixture, HOOK_RETIRE_AFTER_CAS);
    hook_retire = &sync;
    created = pthread_create(&thread, NULL, retire_worker, &sync);
    CHECK(prefix, created == 0);
    if (created != 0) {
        retire_sync_destroy(&sync);
        return;
    }
    CHECK(prefix, fixture_route(fixture, &result) == 0);
    CHECK(prefix, pthread_join(thread, NULL) == 0);
    CHECK(prefix, sync.unloading_observed == 1);
    CHECK(prefix, sync.completed_inside_hook == 0);
    CHECK(prefix, sync.retire_done == 1 && sync.retire_result == 0);
    CHECK(prefix, result.status == KZT_LAZY_BINDING_ROUTE_NATIVE_APPLIED);
    CHECK(prefix, fixture->slot == fixture_native_bridge);
    retire_sync_destroy(&sync);
}

static void test_retire_waits_for_writer_transaction(void)
{
    fixture_t fixture;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    run_after_cas_retire(&fixture, "after-cas");
    fixture_destroy(&fixture);
}

static void test_completion_holds_one_lease_until_final_release(void)
{
    fixture_t fixture;
    retire_sync_t sync;
    pthread_t thread;
    kzt_lazy_binding_result_t result;
    int created;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    if (retire_sync_init(&sync, &fixture) != 0) {
        CHECK("completion.sync", 0);
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_RETIRE_AFTER_CAS);
    hook_retire = &sync;
    created = pthread_create(&thread, NULL, retire_worker, &sync);
    CHECK("completion.thread", created == 0);
    if (created != 0) {
        retire_sync_destroy(&sync);
        fixture_destroy(&fixture);
        return;
    }
    CHECK("completion.call", kzt_production_lazy_complete(
          &fixture.context, &fixture.pending, &result) == 0);
    CHECK("completion.join", pthread_join(thread, NULL) == 0);
    CHECK("completion.first-read-leased", lease_seen_at_first_slot_load == 1);
    CHECK("completion.single-acquire", before_acquire_calls == 1);
    CHECK("completion.retire-blocked", sync.unloading_observed == 1 &&
          sync.completed_inside_hook == 0);
    CHECK("completion.release-allows-retire", sync.retire_done == 1 &&
          sync.retire_result == 0);
    CHECK("completion.applied", result.status == KZT_LAZY_BINDING_NATIVE_APPLIED);
    CHECK("completion.pending-cleared", fixture.pending.armed == 0);
    retire_sync_destroy(&sync);
    fixture_destroy(&fixture);
}

static void test_retire_waits_through_verify_failure_and_rollback(void)
{
    fixture_t fixture;
    retire_sync_t sync;
    pthread_t thread;
    kzt_lazy_binding_route_result_t result;
    int created;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    if (retire_sync_init(&sync, &fixture) != 0) {
        CHECK("rollback.sync", 0);
        fixture_destroy(&fixture);
        return;
    }
    hooks_reset(&fixture, HOOK_RETIRE_AFTER_CAS_ROLLBACK);
    hook_retire = &sync;
    created = pthread_create(&thread, NULL, retire_worker, &sync);
    CHECK("rollback.thread", created == 0);
    if (created != 0) {
        retire_sync_destroy(&sync);
        fixture_destroy(&fixture);
        return;
    }
    CHECK("rollback.route", fixture_route(&fixture, &result) == 0);
    CHECK("rollback.join", pthread_join(thread, NULL) == 0);
    CHECK("rollback.retire-blocked", sync.unloading_observed == 1 &&
          sync.completed_inside_hook == 0);
    CHECK("rollback.two-cas", after_cas_calls == 2);
    CHECK("rollback.slot-restored", fixture.slot == GUEST_TARGET);
    CHECK("rollback.guest-preserved",
          result.status == KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED);
    CHECK("rollback.retire-after-release", sync.retire_done == 1 &&
          sync.retire_result == 0);
    retire_sync_destroy(&sync);
    fixture_destroy(&fixture);
}

static void test_fail_open_and_non_writer_paths(void)
{
    fixture_t fixture;
    kzt_lazy_binding_route_result_t result;
    kzt_lazy_binding_result_t completion_result;
    kzt_guest_registry_t *live_registry;
    kzt_guest_registry_t *disabled_registry;
    unsigned long live_generation;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    live_registry = fixture.context.kzt_guest_registry_context.registry;
    live_generation = fixture.pending.source_generation;

    hooks_reset(&fixture, HOOK_NONE);
    fixture.context.kzt_guest_registry_context.registry = NULL;
    CHECK("null.route", fixture_route(&fixture, &result) == 0);
    CHECK("null.preserved", result.status ==
                              KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED &&
                              fixture.slot == GUEST_TARGET);
    CHECK("null.no-lease", before_acquire_calls == 0);
    fixture.context.kzt_guest_registry_context.registry = live_registry;

    kzt_guest_registry_test_set_alloc_failure_after(1);
    disabled_registry = kzt_guest_registry_init();
    kzt_guest_registry_test_set_alloc_failure_after(-1);
    CHECK("disabled.registry", disabled_registry != NULL);
    hooks_reset(&fixture, HOOK_NONE);
    fixture.context.kzt_guest_registry_context.registry = disabled_registry;
    CHECK("disabled.route", fixture_route(&fixture, &result) == 0);
    CHECK("disabled.preserved", result.status ==
                                  KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED &&
                                  fixture.slot == GUEST_TARGET);
    CHECK("disabled.lease-attempt", before_acquire_calls == 1);
    CHECK("disabled.no-source-memory", source_memory_access_calls == 0);
    CHECK("disabled.no-slot-read", slot_load_calls == 0);
    fixture.context.kzt_guest_registry_context.registry = live_registry;
    kzt_guest_registry_destroy(&disabled_registry);

    hooks_reset(&fixture, HOOK_NONE);
    fixture.pending.source_generation = live_generation + 1;
    CHECK("stale.route", fixture_route(&fixture, &result) == 0);
    CHECK("stale.preserved", result.status ==
                               KZT_LAZY_BINDING_ROUTE_GUEST_PRESERVED &&
                               fixture.slot == GUEST_TARGET);
    CHECK("stale.lease-attempt", before_acquire_calls == 1);
    CHECK("stale.no-source-memory", source_memory_access_calls == 0);
    CHECK("stale.no-slot-read", slot_load_calls == 0);
    fixture.pending.source_generation = live_generation;

    hooks_reset(&fixture, HOOK_NONE);
    reset_guard(&fixture, 0);
    CHECK("disabled-guard.route", fixture_route(&fixture, &result) == 0);
    CHECK("disabled-guard.exact-lease", before_acquire_calls == 1);
    CHECK("disabled-guard.source-validated", source_memory_access_calls > 0);
    CHECK("disabled-guard.slot", fixture.slot == GUEST_TARGET);

    reset_guard(&fixture, 1);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("bound.first", fixture_route(&fixture, &result) == 0);
    CHECK("bound.first-applied", fixture.slot == fixture_native_bridge);
    hooks_reset(&fixture, HOOK_NONE);
    CHECK("bound.second", kzt_production_lazy_complete(
          &fixture.context, &fixture.pending, &completion_result) == 0);
    CHECK("bound.revalidation-lease", before_acquire_calls == 1);
    CHECK("bound.second-result",
          completion_result.status == KZT_LAZY_BINDING_GUEST_PRESERVED &&
          completion_result.reason ==
              KZT_LAZY_BINDING_REASON_NATIVE_UNAVAILABLE);
    CHECK("bound.second-values",
          completion_result.slot_before == fixture_native_bridge &&
          completion_result.slot_after == fixture_native_bridge &&
          completion_result.selected_target == fixture_native_bridge);
    CHECK("bound.second-pending",
          fixture.pending.armed == 0 && completion_result.pending_armed == 0 &&
          completion_result.pending_cleared == 1);
    CHECK("bound.slot-preserved", fixture.slot == fixture_native_bridge);
    fixture_destroy(&fixture);
}

static void test_retire_writer_stress_1000(void)
{
    fixture_t fixture;
    int baseline_failures;
    int i;

    if (fixture_init(&fixture) != 0) {
        fixture_destroy(&fixture);
        return;
    }
    baseline_failures = failures;
    for (i = 0; i < STRESS_ITERATIONS; ++i) {
        fixture.slot = GUEST_TARGET;
        reset_guard(&fixture, 1);
        run_after_cas_retire(&fixture, "stress");
        if (failures != baseline_failures) {
            fprintf(stderr, "stress failed at iteration %d\n", i);
            break;
        }
        if (i + 1 < STRESS_ITERATIONS) {
            fixture.pending.source_generation = fixture_publish_source(&fixture);
        }
    }
    CHECK("stress.iterations", i == STRESS_ITERATIONS);
    fixture_destroy(&fixture);
}

int main(void)
{
    test_successful_production_route();
    test_guest_version_is_not_used_for_host_lookup();
    test_native_symbol_missing_fails_open();
    test_dependency_symbol_owner_mismatch_fails_open();
    test_missing_bridge_is_created_from_exact_provider();
    test_created_inexact_bridge_fails_open();
    test_eager_production_request_evidence();
    test_confirmed_unversioned_production_paths_apply();
    test_unknown_version_evidence_preserves_guest_path();
    test_production_permission_transaction_preserves_on_restore_error();
    test_recycle_before_acquire_preserves_guest();
    test_retire_before_first_slot_read_skips_guest_memory();
    test_namespace_mismatch_precedes_any_source_read();
    test_guard_fail_open_keeps_real_completion_evidence();
    test_retire_waits_for_writer_transaction();
    test_completion_holds_one_lease_until_final_release();
    test_retire_waits_through_verify_failure_and_rollback();
    test_fail_open_and_non_writer_paths();
    test_retire_writer_stress_1000();

    if (failures) {
        fprintf(stderr, "%d lazy production lease checks failed\n", failures);
        return 1;
    }
    puts("KZT WI-256 lazy production source lease: PASS (1000 races)");
    return 0;
}
