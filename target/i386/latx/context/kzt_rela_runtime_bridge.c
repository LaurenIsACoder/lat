#include "kzt_rela_runtime_bridge.h"

#include <dlfcn.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "box64context.h"
#include "kzt_bridge_exact.h"
#include "khash.h"
#include "librarian_private.h"
#include "library.h"
#include "library_private.h"

extern uintptr_t CheckBridged(bridge_t *bridge, void *fnc);
extern uintptr_t AddCheckBridge(bridge_t *bridge, wrapper_t wrapper,
                                void *fnc, int stack_bytes,
                                const char *name) __attribute__((weak));
extern int BridgeForkProtectionAvailable(void);
extern void *GetNativeSymbolUnversionned(
    void *lib, const char *name) __attribute__((weak));
extern int option_kzt_lazy_diagnostics;

static uint64_t kzt_rela_runtime_timing_now(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000000000ULL +
           (uint64_t)value.tv_nsec;
}

static uint64_t kzt_rela_runtime_timing_delta(uint64_t start, uint64_t end)
{
    return start && end >= start ? end - start : 0;
}

#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
void kzt_rela_runtime_bridge_test_full_lifetime_validation(void);
#endif

static int kzt_rela_runtime_wrapper_map_entry(
    kh_symbolmap_t *map, const char *symbol_name, wrapper_t *wrapper)
{
    khint_t key;

    if (!map || !symbol_name || !wrapper) {
        return 0;
    }
    key = kh_get(symbolmap, map, symbol_name);
    if (key == kh_end(map)) {
        return 0;
    }

    *wrapper = kh_value(map, key);
    return *wrapper ? 1 : -1;
}

typedef struct kzt_rela_runtime_wrapper_candidate {
    wrapper_t wrapper;
    const char *native_name;
    int custom_wrapper;
    int stack_bytes;
} kzt_rela_runtime_wrapper_candidate_t;

typedef struct kzt_rela_runtime_provider_state {
    box64context_t *context;
    uintptr_t resolved_target;
    int discover_bridge;
    const kzt_guest_library_handle_t *retained_provider_handle;
} kzt_rela_runtime_provider_state_t;

static void *kzt_rela_runtime_lookup_native(
    void *handle, const char *native_name, int custom_wrapper)
{
    void *native_symbol;

    if (!handle || !native_name || !native_name[0]) {
        return NULL;
    }
    native_symbol = dlsym(handle, native_name);
    if (!native_symbol && !custom_wrapper && GetNativeSymbolUnversionned) {
        native_symbol = GetNativeSymbolUnversionned(handle, native_name);
    }
    return native_symbol;
}

static int kzt_rela_runtime_custom_native_name(
    const library_t *lib, const char *symbol_name, char *buffer,
    size_t buffer_size)
{
    const char *prefix;

    if (!lib || !symbol_name || !buffer || buffer_size == 0) {
        return -1;
    }
    prefix = lib->altmy ? lib->altmy : "my_";
    if (snprintf(buffer, buffer_size, "%s%s", prefix, symbol_name) >=
        (int)buffer_size) {
        return -1;
    }
    return 0;
}

/* Provider lifetime inspection completes before this bridge-only lookup. */
static uintptr_t kzt_rela_runtime_provider_exact_bridge(
    library_t *provider, uintptr_t resolved_target, wrapper_t wrapper,
    void *native_symbol)
{
    uintptr_t provider_target;

    if (!provider || !provider->priv.w.bridge || !wrapper || !native_symbol) {
        return 0;
    }

    /* CheckBridged is a read-only lookup keyed by the native symbol.  Do not
       inspect resolved_target as a onebridge_t until the provider map proves
       that the target belongs to this provider. */
    provider_target = CheckBridged(provider->priv.w.bridge, native_symbol);
    if (!provider_target ||
        (resolved_target && provider_target != resolved_target)) {
        return 0;
    }

    return kzt_bridge_is_exact(provider_target, wrapper, native_symbol) ?
        provider_target : 0;
}

static uintptr_t kzt_rela_runtime_provider_cached_bridge(
    library_t *provider, void *native_symbol)
{
    if (!provider || !provider->context || !provider->priv.w.bridge ||
        !native_symbol) {
        return 0;
    }
    return CheckBridged(provider->priv.w.bridge, native_symbol);
}

static int kzt_rela_runtime_context_owns_library(
    box64context_t *context, library_t *library)
{
    lib_t *scopes[2];
    size_t i;
    int j;

    if (!context || !library) {
        return 0;
    }
    scopes[0] = context->maplib;
    scopes[1] = context->local_maplib;
    for (i = 0; i < sizeof(scopes) / sizeof(scopes[0]); ++i) {
        if (!scopes[i]) {
            continue;
        }
        for (j = 0; j < scopes[i]->libsz; ++j) {
            if (scopes[i]->libraries[j] == library) {
                return 1;
            }
        }
    }
    return 0;
}

static int kzt_rela_runtime_retained_match_valid(
    const kzt_wrapper_bridge_provider_match_t *match)
{
    const kzt_guest_library_handle_t *handle;
    box64context_t *context;
    library_t *provider;
    void *expected_handle;

    if (!match || !(handle = match->retained_provider_handle) ||
        !handle->bindings || !handle->entry ||
        !(context = match->context_owner) ||
        !(provider = match->wrapper_provider) ||
        handle->library != provider) {
        return 0;
    }
    expected_handle = match->custom_wrapper ? provider->priv.w.box64lib :
                                              provider->priv.w.lib;
    return provider->active && provider->type == LIB_WRAPPED &&
           provider->context == context &&
           kzt_rela_runtime_context_owns_library(context, provider) &&
           match->bridge_owner == provider &&
           match->bridge_storage == provider->priv.w.bridge &&
           match->native_lookup_handle == expected_handle;
}

static int kzt_rela_runtime_match_lifetime_valid(
    const kzt_wrapper_bridge_provider_match_t *match)
{
    box64context_t *context;
    library_t *provider;
    struct link_map *lookup_owner = NULL;
    struct link_map *native_owner = NULL;
    Dl_info symbol_info;
    void *expected_handle;
    void *native_symbol;

    if (match && match->retained_provider_handle) {
        return kzt_rela_runtime_retained_match_valid(match);
    }
#ifdef KZT_JUMP_SLOT_PRODUCTION_TEST
    kzt_rela_runtime_bridge_test_full_lifetime_validation();
#endif
    if (!match || !match->context_owner || !match->wrapper_provider ||
        !match->native_lookup_handle || !match->native_owner ||
        !match->bridge_owner || !match->bridge_storage ||
        !match->native_name[0] || !match->abi_wrapper ||
        !match->native_symbol ||
        !match->wrapper_provider_lifetime_bound ||
        !match->native_owner_lifetime_bound ||
        !match->bridge_owner_lifetime_bound) {
        return 0;
    }

    context = match->context_owner;
    provider = match->wrapper_provider;
    expected_handle = match->custom_wrapper ? provider->priv.w.box64lib :
                                              provider->priv.w.lib;
    if (!provider->active || provider->type != LIB_WRAPPED ||
        provider->context != context ||
        !kzt_rela_runtime_context_owns_library(context, provider) ||
        match->bridge_owner != provider ||
        match->bridge_storage != provider->priv.w.bridge ||
        expected_handle != match->native_lookup_handle ||
        dlinfo(expected_handle, RTLD_DI_LINKMAP, &lookup_owner) != 0 ||
        !lookup_owner) {
        return 0;
    }

    native_symbol = kzt_rela_runtime_lookup_native(
        expected_handle, match->native_name, match->custom_wrapper);
    if ((uintptr_t)native_symbol != match->native_symbol ||
        dladdr1(native_symbol, &symbol_info, (void **)&native_owner,
                RTLD_DL_LINKMAP) == 0 ||
        native_owner != match->native_owner) {
        return 0;
    }
    return 1;
}

static int kzt_rela_runtime_provider_inspect(
    void *library, const char *symbol_name, const char *symbol_version,
    kzt_wrapper_bridge_provider_match_t *match, void *opaque)
{
    library_t *lib = library;
    kzt_rela_runtime_provider_state_t *state = opaque;
    wrapper_t wrapper = NULL;
    wrapper_t candidate = NULL;
    const char *native_name = symbol_name;
    char prefixed_name[256];
    char custom_name[256];
    struct link_map *handle_map = NULL;
    struct link_map *symbol_map = NULL;
    Dl_info symbol_info;
    khint_t key;
    uintptr_t bridge_target;
    uint64_t timing_start = 0;
    uint64_t timing_wrapper_map = 0;
    uint64_t timing_native_lookup = 0;
    uint64_t timing_bridge_cache = 0;
    uint64_t timing_handle_owner = 0;
    uint64_t timing_done = 0;
    int timing_enabled = option_kzt_lazy_diagnostics != 0;
    int matches = 0;
    int allow_altprefix = 1;

    (void)symbol_version;
    if (!lib || !state || !match || !symbol_name ||
        !lib->active || lib->type != LIB_WRAPPED || !lib->priv.w.lib ||
        !lib->priv.w.bridge || lib->context != state->context ||
        !kzt_rela_runtime_context_owns_library(state->context, lib) ||
        (state->retained_provider_handle &&
         (!state->retained_provider_handle->bindings ||
          !state->retained_provider_handle->entry ||
          state->retained_provider_handle->library != lib)) ||
        (!state->resolved_target && !state->discover_bridge)) {
        return 0;
    }
    if (timing_enabled) {
        timing_start = kzt_rela_runtime_timing_now();
    }

    if (kzt_rela_runtime_wrapper_map_entry(
            lib->mysymbolmap, symbol_name, &candidate)) {
        if (kzt_rela_runtime_custom_native_name(
                lib, symbol_name, custom_name, sizeof(custom_name)) != 0) {
            return -1;
        }
        wrapper = candidate;
        native_name = custom_name;
        ++matches;
        allow_altprefix = 0;
        match->custom_wrapper = 1;
    }
    if (kzt_rela_runtime_wrapper_map_entry(
            lib->wmysymbolmap, symbol_name, &candidate)) {
        if (kzt_rela_runtime_custom_native_name(
                lib, symbol_name, custom_name, sizeof(custom_name)) != 0) {
            return -1;
        }
        wrapper = candidate;
        native_name = custom_name;
        ++matches;
        allow_altprefix = 0;
        match->custom_wrapper = 1;
    }
    if (kzt_rela_runtime_wrapper_map_entry(
            lib->stsymbolmap, symbol_name, &candidate)) {
        if (kzt_rela_runtime_custom_native_name(
                lib, symbol_name, custom_name, sizeof(custom_name)) != 0) {
            return -1;
        }
        wrapper = candidate;
        native_name = custom_name;
        ++matches;
        allow_altprefix = 0;
        match->custom_wrapper = 1;
        match->stack_bytes = sizeof(void *);
    }

    if (kzt_rela_runtime_wrapper_map_entry(
            lib->symbolmap, symbol_name, &candidate)) {
        wrapper = candidate;
        ++matches;
    }
    if (kzt_rela_runtime_wrapper_map_entry(
            lib->wsymbolmap, symbol_name, &candidate)) {
        wrapper = candidate;
        ++matches;
    }
    if (lib->symbol2map) {
        key = kh_get(symbol2map, lib->symbol2map, symbol_name);
        if (key != kh_end(lib->symbol2map)) {
            wrapper = kh_value(lib->symbol2map, key).w;
            native_name = kh_value(lib->symbol2map, key).name;
            allow_altprefix = 0;
            ++matches;
        }
    }
    if (matches == 0) {
        return 0;
    }
    if (matches != 1 || !wrapper || !native_name || !native_name[0]) {
        return -1;
    }

    if (lib->priv.w.altprefix && allow_altprefix) {
        if (snprintf(prefixed_name, sizeof(prefixed_name), "%s%s",
                     lib->priv.w.altprefix, symbol_name) >=
            (int)sizeof(prefixed_name)) {
            return -1;
        }
        native_name = prefixed_name;
    }
    if (timing_enabled) {
        timing_wrapper_map = kzt_rela_runtime_timing_now();
    }

    /* symbol_version describes the guest relocation.  The host provider may
       legitimately export the same ABI wrapper under a different GLIBC
       version, so native lookup keeps the wrapped-library semantics. */
    match->native_symbol = (uintptr_t)kzt_rela_runtime_lookup_native(
        match->custom_wrapper ? lib->priv.w.box64lib : lib->priv.w.lib,
        native_name, match->custom_wrapper);
    if (timing_enabled) {
        timing_native_lookup = kzt_rela_runtime_timing_now();
    }
    if (symbol_version && symbol_version[0] &&
        (strstr(symbol_version, "NOT_REAL") ||
         strstr(symbol_version, "UNSUPPORTED"))) {
        return -1;
    }
    if (symbol_version && symbol_version[0] && !match->custom_wrapper &&
        state->resolved_target &&
        !kzt_rela_runtime_provider_exact_bridge(
            lib, state->resolved_target, wrapper,
            (void *)match->native_symbol)) {
        uintptr_t versioned_symbol = (uintptr_t)dlvsym(
            lib->priv.w.lib, native_name, symbol_version);

        if (!versioned_symbol ||
            !kzt_rela_runtime_provider_exact_bridge(
                lib, state->resolved_target, wrapper,
                (void *)versioned_symbol)) {
            return -1;
        }
        match->native_symbol = versioned_symbol;
    }
    if (!match->native_symbol) {
        return -1;
    }
    bridge_target = kzt_rela_runtime_provider_exact_bridge(
        lib, state->resolved_target, wrapper, (void *)match->native_symbol);
    if (!bridge_target &&
        kzt_rela_runtime_provider_cached_bridge(
            lib, (void *)match->native_symbol)) {
        return -1;
    }
    if (timing_enabled) {
        timing_bridge_cache = kzt_rela_runtime_timing_now();
    }
    if (!state->retained_provider_handle) {
        if (dlinfo(match->custom_wrapper ? lib->priv.w.box64lib :
                                          lib->priv.w.lib,
                   RTLD_DI_LINKMAP, &handle_map) != 0 || !handle_map) {
            return -1;
        }
        if (bridge_target) {
            /* An exact bridge is owned by this provider and the provider's
             * native handle keeps its dependency closure live. */
            symbol_map = handle_map;
        } else if (dladdr1((void *)match->native_symbol, &symbol_info,
                           (void **)&symbol_map, RTLD_DL_LINKMAP) == 0 ||
                   symbol_map != handle_map) {
            return -1;
        }
    }
    if (timing_enabled) {
        timing_handle_owner = kzt_rela_runtime_timing_now();
    }
    if (!bridge_target && !state->discover_bridge) {
        return -1;
    }

    match->wrapper_name = lib->name;
    snprintf(match->native_name, sizeof(match->native_name), "%s",
             native_name);
    match->abi_wrapper = wrapper;
    match->resolved_bridge_target = bridge_target;
    match->context_owner = state->context;
    match->wrapper_provider = lib;
    match->native_lookup_handle = match->custom_wrapper ? lib->priv.w.box64lib :
                                                          lib->priv.w.lib;
    match->native_owner = symbol_map;
    match->bridge_owner = lib;
    match->bridge_storage = lib->priv.w.bridge;
    match->resolved_bridge_exact = bridge_target != 0;
    /* Wrapped native handles stay live in a root context scope until
       NativeLib_FinishFini runs during context teardown. */
    match->wrapper_provider_lifetime_bound = 1;
    match->native_owner_lifetime_bound = 1;
    match->bridge_owner_lifetime_bound = 1;
    match->retained_provider_handle = state->retained_provider_handle;
    if (state->retained_provider_handle &&
        !kzt_rela_runtime_retained_match_valid(match)) {
        return -1;
    }
    if (timing_enabled) {
        timing_done = kzt_rela_runtime_timing_now();
        fprintf(
            stderr,
            "kzt_bridge_discovery_timing schema=1 symbol=%s "
            "wrapper_map_ns=%" PRIu64 " native_lookup_ns=%" PRIu64 " "
            "bridge_cache_ns=%" PRIu64 " handle_owner_ns=%" PRIu64 " "
            "total_ns=%" PRIu64 " custom=%d cached=%d\n",
            symbol_name,
            kzt_rela_runtime_timing_delta(
                timing_start, timing_wrapper_map),
            kzt_rela_runtime_timing_delta(
                timing_wrapper_map, timing_native_lookup),
            kzt_rela_runtime_timing_delta(
                timing_native_lookup, timing_bridge_cache),
            kzt_rela_runtime_timing_delta(
                timing_bridge_cache, timing_handle_owner),
            kzt_rela_runtime_timing_delta(timing_start, timing_done),
            match->custom_wrapper, bridge_target != 0);
    }
    return 1;
}

static uintptr_t kzt_rela_runtime_provider_check(
    const kzt_wrapper_bridge_provider_match_t *match, void *opaque)
{
    library_t *provider;

    (void)opaque;
    if (!match || !match->bridge_owner || !match->abi_wrapper ||
        !match->native_symbol ||
        !kzt_rela_runtime_match_lifetime_valid(match) ||
        (!!match->resolved_bridge_target != !!match->resolved_bridge_exact)) {
        return 0;
    }
    provider = match->bridge_owner;
    return kzt_rela_runtime_provider_exact_bridge(
        provider, match->resolved_bridge_target, match->abi_wrapper,
        (void *)match->native_symbol);
}

static uintptr_t kzt_rela_runtime_provider_add(
    const kzt_wrapper_bridge_provider_match_t *match,
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque)
{
    library_t *provider;
    uintptr_t target;

    (void)opaque;
    if (!match || !request || !match->bridge_owner || !match->abi_wrapper ||
        !match->native_symbol ||
        !kzt_rela_runtime_match_lifetime_valid(match) ||
        match->resolved_bridge_target || match->resolved_bridge_exact ||
        request->native_symbol != match->native_symbol ||
        !request->symbol_name || !request->symbol_name[0]) {
        return 0;
    }

    provider = match->bridge_owner;
    if (!provider->priv.w.bridge || !provider->context || !AddCheckBridge) {
        return 0;
    }
    target = AddCheckBridge(provider->priv.w.bridge, match->abi_wrapper,
                            (void *)match->native_symbol, match->stack_bytes,
                            request->symbol_name);
    if (!target ||
        kzt_rela_runtime_provider_exact_bridge(
            provider, target, match->abi_wrapper,
            (void *)match->native_symbol) != target) {
        target = 0;
    }
    return target;
}

static int kzt_rela_runtime_wrapper_provider_prepare_mode(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version, int discover_bridge,
    const kzt_guest_library_handle_t *retained_provider_handle,
    kzt_wrapper_bridge_provider_t *provider)
{
    kzt_rela_runtime_provider_state_t state = {
        .context = context,
        .resolved_target = resolved_target,
        .discover_bridge = discover_bridge,
        .retained_provider_handle = retained_provider_handle,
    };
    kzt_wrapper_bridge_provider_runtime_ops_t runtime_ops = {
        .inspect_library = kzt_rela_runtime_provider_inspect,
        .check_bridge = kzt_rela_runtime_provider_check,
        .add_bridge = kzt_rela_runtime_provider_add,
        .opaque = &state,
    };
    void *libraries[] = { resolved_provider };
    int status;

    if (!provider) {
        return -1;
    }
    if (!BridgeForkProtectionAvailable()) {
        memset(provider, 0, sizeof(*provider));
        return 0;
    }
    status = kzt_wrapper_bridge_provider_prepare_with_version_evidence(
        provider, libraries, 1, symbol_name, version_evidence,
        symbol_version, &runtime_ops);
    provider->runtime_ops.opaque = NULL;
    return status;
}

int kzt_rela_runtime_wrapper_provider_prepare(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, const char *symbol_name,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider)
{
    return kzt_rela_runtime_wrapper_provider_prepare_mode(
        context, resolved_provider, resolved_target, symbol_name,
        symbol_version && symbol_version[0] ? KZT_SYMBOL_VERSION_VERSIONED :
                                             KZT_SYMBOL_VERSION_UNKNOWN,
        symbol_version, 0, NULL, provider);
}

int kzt_rela_runtime_wrapper_provider_prepare_with_version_evidence(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider)
{
    return kzt_rela_runtime_wrapper_provider_prepare_mode(
        context, resolved_provider, resolved_target, symbol_name,
        version_evidence, symbol_version, 0, NULL, provider);
}

int kzt_rela_runtime_wrapper_provider_discover(
    box64context_t *context, library_t *resolved_provider,
    const char *symbol_name, const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider)
{
    return kzt_rela_runtime_wrapper_provider_prepare_mode(
        context, resolved_provider, 0, symbol_name,
        symbol_version && symbol_version[0] ? KZT_SYMBOL_VERSION_VERSIONED :
                                             KZT_SYMBOL_VERSION_UNKNOWN,
        symbol_version, 1, NULL, provider);
}

int kzt_rela_runtime_wrapper_provider_discover_with_version_evidence(
    box64context_t *context, library_t *resolved_provider,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider)
{
    return kzt_rela_runtime_wrapper_provider_prepare_mode(
        context, resolved_provider, 0, symbol_name, version_evidence,
        symbol_version, 1, NULL, provider);
}

int kzt_rela_runtime_wrapper_provider_discover_retained_with_version_evidence(
    box64context_t *context,
    const kzt_guest_library_handle_t *retained_provider_handle,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider)
{
    if (!retained_provider_handle || !retained_provider_handle->library) {
        return 0;
    }
    return kzt_rela_runtime_wrapper_provider_prepare_mode(
        context, retained_provider_handle->library, 0, symbol_name,
        version_evidence, symbol_version, 1, retained_provider_handle,
        provider);
}

int kzt_rela_runtime_wrapper_provider_bind_retained_handle(
    kzt_wrapper_bridge_provider_t *provider,
    const kzt_guest_library_handle_t *handle)
{
    if (!provider || !handle || !handle->bindings || !handle->entry ||
        !handle->library || !provider->manifest.available ||
        provider->match.wrapper_provider != handle->library) {
        return -1;
    }
    provider->match.retained_provider_handle = handle;
    if (!kzt_rela_runtime_retained_match_valid(&provider->match)) {
        provider->match.retained_provider_handle = NULL;
        return -1;
    }
    return 0;
}
