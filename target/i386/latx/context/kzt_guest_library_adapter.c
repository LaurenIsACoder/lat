#include "kzt_guest_library_adapter.h"

#include <string.h>

#include "box64context.h"
#include "callback.h"
#include "debug.h"
#include "kzt_guest_dynsym_lookup.h"
#include "kzt_guest_library_binding.h"
#include "kzt_guest_registry.h"
#include "library.h"
#include "library_private.h"
#ifndef KZT_GUEST_LIBRARY_ADAPTER_TEST
#include "qemu.h"
#endif

#define KZT_GUEST_WRAPPER_DIAGNOSTIC_LIMIT 16

#ifdef CONFIG_LATX_KZT
#ifdef KZT_GUEST_LIBRARY_ADAPTER_TEST
extern int option_kzt;
#endif
extern int wine_option_kzt;
#endif

static unsigned long kzt_guest_wrapper_diagnostic_count;

static void kzt_guest_library_note_wrapper_diagnostic(
    const char *phase, const char *reason, uintptr_t link_map_addr,
    unsigned long generation, const char *symbol, unsigned char symbol_type)
{
    unsigned long ticket;

    if (!kzt_registry_diagnostics_enabled()) {
        return;
    }
    ticket = __atomic_fetch_add(
        &kzt_guest_wrapper_diagnostic_count, 1, __ATOMIC_RELAXED);
    if (ticket >= KZT_GUEST_WRAPPER_DIAGNOSTIC_LIMIT) {
        return;
    }
    printf_kzt_registry_diagnostics(
        "kzt_wrapper_gate schema=1 phase=%s reason=%s link_map=0x%lx "
        "generation=%lu symbol=%s symbol_type=%u\n",
        phase ? phase : "unknown", reason ? reason : "unknown",
        (unsigned long)link_map_addr, generation,
        symbol && symbol[0] ? symbol : "<none>", (unsigned int)symbol_type);
}

static int kzt_guest_library_read_memory(uintptr_t guest_addr, void *dst,
                                         size_t size, void *opaque)
{
    (void)opaque;
#ifdef KZT_GUEST_LIBRARY_ADAPTER_TEST
    (void)guest_addr;
    (void)dst;
    (void)size;
    return -1;
#else
    void *host_ptr;

    if ((!guest_addr || !dst) && size) {
        return -1;
    }
    if (!size) {
        return 0;
    }
    host_ptr = lock_user(VERIFY_READ, (abi_ulong)guest_addr, size, true);
    if (!host_ptr) {
        return -1;
    }
    memcpy(dst, host_ptr, size);
    unlock_user(host_ptr, (abi_ulong)guest_addr, 0);
    return 0;
#endif
}

static const char *kzt_guest_library_basename(const char *path)
{
    const char *name;

    if (!path || !path[0]) {
        return NULL;
    }
    name = strrchr(path, '/');
    return name ? name + 1 : path;
}

static int kzt_guest_library_path_is_canonical(const char *path)
{
    const char *component;

    if (!path || path[0] != '/' || !path[1]) {
        return 0;
    }
    component = path + 1;
    while (*component) {
        const char *end = strchr(component, '/');
        size_t length = end ? (size_t)(end - component) : strlen(component);

        if (!length || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.')) {
            return 0;
        }
        if (!end) {
            return 1;
        }
        component = end + 1;
    }
    return 0;
}

static int kzt_guest_library_path_matches_manifest(const char *path,
                                                   const char *wrapper_name)
{
    static const char *const directories[] = {
        "/lib",
        "/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/x86_64-linux-gnu/lib",
    };
    const char *name;
    size_t directory_length;
    size_t i;

    if (!kzt_guest_library_path_is_canonical(path) ||
        !wrapper_name || !wrapper_name[0] ||
        !(name = strrchr(path, '/')) || !name[1] ||
        strcmp(name + 1, wrapper_name) != 0) {
        return 0;
    }
    directory_length = (size_t)(name - path);
    for (i = 0; i < sizeof(directories) / sizeof(directories[0]); ++i) {
        if (strlen(directories[i]) == directory_length &&
            strncmp(path, directories[i], directory_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int kzt_guest_library_source_match_valid(
    const kzt_guest_registry_address_match_t *match,
    const char *requested_path, const char *wrapper_name)
{
    const char *observed_name;

    if (!match || match->match_count != 1 ||
        match->namespace_id_status != KZT_GUEST_FIELD_OK ||
        match->namespace_id != 0 || !match->generation ||
        match->path_status != KZT_GUEST_FIELD_OK ||
        !requested_path || !requested_path[0] ||
        !kzt_guest_library_path_matches_manifest(
            match->path, wrapper_name)) {
        return 0;
    }
    observed_name = kzt_guest_library_basename(match->path);
    if (!observed_name || strcmp(observed_name, wrapper_name) != 0 ||
        (strchr(requested_path, '/') &&
         strcmp(requested_path, match->path) != 0) ||
        (!strchr(requested_path, '/') &&
         strcmp(requested_path, wrapper_name) != 0) ||
        (match->soname_status == KZT_GUEST_FIELD_OK && match->soname[0] &&
         strcmp(match->soname, wrapper_name) != 0)) {
        return 0;
    }
    return 1;
}

int kzt_guest_library_wrapper_source_acquire(
    box64context_t *context, uintptr_t link_map_addr,
    const char *requested_path, const char *wrapper_name,
    kzt_guest_wrapper_source_proof_t *proof)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_registry_t *registry;
    kzt_guest_registry_address_match_t before = { 0 };
    kzt_guest_registry_address_match_t after = { 0 };

    if (!proof) {
        return -1;
    }
    memset(proof, 0, sizeof(*proof));
    if (!context || !link_map_addr ||
        !(registry = KztGuestRegistryForContext(context)) ||
        kzt_guest_registry_find_live_object(
            registry, link_map_addr, &before) != 0 ||
        !kzt_guest_library_source_match_valid(
            &before, requested_path, wrapper_name) ||
        kzt_guest_registry_source_lease_acquire(
            registry, before.link_map_addr, before.generation,
            before.namespace_id, &proof->lease) != 0 ||
        kzt_guest_registry_find_live_object(
            registry, link_map_addr, &after) != 0 ||
        after.link_map_addr != before.link_map_addr ||
        after.generation != before.generation ||
        after.namespace_id != before.namespace_id ||
        after.namespace_id_status != before.namespace_id_status ||
        after.path_status != before.path_status ||
        strcmp(after.path, before.path) != 0 ||
        after.soname_status != before.soname_status ||
        strcmp(after.soname, before.soname) != 0) {
        kzt_guest_registry_source_lease_release(&proof->lease);
        kzt_guest_library_note_wrapper_diagnostic(
            "source", "identity_or_path_unproven", link_map_addr,
            before.generation, wrapper_name, 0);
        return -1;
    }
    proof->key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = before.link_map_addr,
        .generation = before.generation,
        .namespace_id = before.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    return 0;
#else
    (void)context;
    (void)link_map_addr;
    (void)requested_path;
    (void)wrapper_name;
    if (proof) {
        memset(proof, 0, sizeof(*proof));
    }
    return -1;
#endif
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

uint64_t kzt_guest_library_run_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *thread_scope,
    uintptr_t function, void *filename, int flag,
    kzt_guest_library_loader_scope_t *call_scope)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_loader_scope_t previous = { 0 };
    kzt_guest_library_bindings_t *bindings =
        KztGuestLibraryBindingsForContext(context);
    int scoped = 0;
    uint64_t result;

    if (call_scope) {
        *call_scope = (kzt_guest_library_loader_scope_t){ 0 };
    }
    if (thread_scope && call_scope && bindings &&
        kzt_guest_library_loader_scope_begin(bindings, call_scope) == 0) {
        previous = *thread_scope;
        *thread_scope = *call_scope;
        scoped = 1;
    }
    result = RunFunctionWithState(function, 2, filename, flag);
    if (scoped) {
        call_scope->prebind_refresh_pending =
            thread_scope->prebind_refresh_pending;
        if (previous.bindings && previous.identity && previous.cookie &&
            call_scope->prebind_refresh_pending) {
            previous.prebind_refresh_pending = 1;
            call_scope->prebind_refresh_pending = 0;
        }
        *thread_scope = previous;
    }
    return result;
#else
    (void)context;
    (void)thread_scope;
    (void)call_scope;
    return RunFunctionWithState(function, 2, filename, flag);
#endif
}

void kzt_guest_library_finish_dlopen_scoped(
    box64context_t *context,
    kzt_guest_library_loader_scope_t *call_scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof, int publish)
{
#ifdef CONFIG_LATX_KZT
    if (!call_scope || !call_scope->bindings ||
        !call_scope->identity || !call_scope->cookie) {
        return;
    }
    if (publish && link_map_addr) {
        if (library) {
            kzt_guest_library_publish_loader_pair_scoped(
                context, call_scope, link_map_addr, library, proof);
        } else {
            kzt_guest_library_publish_loader_observed_scoped(
                context, call_scope, link_map_addr);
        }
    }
    kzt_guest_library_loader_scope_end(call_scope);
#else
    (void)context;
    (void)call_scope;
    (void)link_map_addr;
    (void)library;
    (void)proof;
    (void)publish;
#endif
}

uint64_t kzt_guest_library_run_dlsym(
    uintptr_t function, void *handle, void *symbol)
{
    return RunFunctionWithState(function, 2, handle, symbol);
}

uint64_t kzt_guest_library_run_dlvsym(
    uintptr_t function, void *handle, void *symbol, const char *version)
{
    return RunFunctionWithState(function, 3, handle, symbol, version);
}

uint64_t kzt_guest_library_run_dlerror(uintptr_t function)
{
    return RunFunctionWithState(function, 0);
}

int kzt_guest_library_run_dlclose(uintptr_t function, void *handle)
{
    return (int)RunFunctionWithState(function, 1, handle);
}

uint64_t kzt_guest_library_run_dlmopen(
    uintptr_t function, void *lmid, void *filename, int flag)
{
    return RunFunctionWithState(function, 3, lmid, filename, flag);
}

int kzt_guest_library_run_dlinfo(
    uintptr_t function, void *handle, int request, void *info)
{
    return RunFunctionWithState(function, 3, handle, request, info);
}

uintptr_t kzt_guest_library_select_symbol_result(
    box64context_t *context, uintptr_t guest_handle,
    uintptr_t guest_result, const char *symbol, const char *version)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_loader_identity_t lookup_identity = { 0 };
    kzt_guest_registry_t *registry;
    kzt_guest_registry_source_lease_t source_lease = { 0 };
    kzt_guest_library_binding_key_t key;
    kzt_guest_library_handle_t handle = { 0 };
    kzt_guest_dynamic_view_t dynamic_view;
    kzt_guest_dynsym_lookup_result_t dynsym_result = { 0 };
    kzt_guest_field_status_t dynamic_status;
    unsigned long dynamic_revision = 0;
    kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = kzt_guest_library_read_memory,
    };
    uintptr_t proven_runtime_address = 0;
    unsigned char proven_symbol_type = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t selected = guest_result;
    const char *diagnostic_reason = "source_generation_stale";

    if ((!option_kzt && !wine_option_kzt) ||
        !context || !guest_result || !symbol || !symbol[0] ||
        (version && version[0]) ||
        !(registry = KztGuestRegistryForContext(context)) ||
        kzt_guest_registry_loader_symbol_source_acquire(
            registry, guest_handle, &lookup_identity, &dynamic_view,
            &dynamic_status, &dynamic_revision, &source_lease) != 0) {
        return guest_result;
    }
    if (!lookup_identity.link_map_addr || !lookup_identity.generation ||
        lookup_identity.namespace_id != 0 ||
        dynamic_status != KZT_GUEST_FIELD_OK || !dynamic_revision) {
        kzt_guest_registry_source_lease_release(&source_lease);
        return guest_result;
    }
    key = (kzt_guest_library_binding_key_t) {
        .link_map_addr = lookup_identity.link_map_addr,
        .generation = lookup_identity.generation,
        .namespace_id = lookup_identity.namespace_id,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
    };
    if (kzt_guest_library_access_lookup(
            &context->kzt_guest_library_access, &key, &handle) != 0) {
        kzt_guest_registry_source_lease_release(&source_lease);
        return guest_result;
    }
    if (handle.object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
        handle.library) {
        diagnostic_reason = "dynsym_unproven";
        if (kzt_guest_library_symbol_evidence_lookup(
                &handle, symbol, dynamic_revision, &proven_runtime_address,
                &proven_symbol_type) != 0) {
            kzt_guest_dynsym_lookup_status_t dynsym_status =
                kzt_guest_dynsym_lookup(
                    &dynamic_view, &reader_ops, symbol,
                    KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL,
                    &dynsym_result);

            if (dynsym_status == KZT_GUEST_DYNSYM_LOOKUP_FOUND) {
                proven_runtime_address = dynsym_result.runtime_address;
                proven_symbol_type = dynsym_result.type;
                kzt_guest_library_symbol_evidence_store(
                    &handle, symbol, dynamic_revision,
                    proven_runtime_address,
                    proven_symbol_type);
            }
        }
        diagnostic_reason =
            proven_runtime_address != guest_result
                ? "dynsym_address_mismatch"
                : proven_symbol_type != STT_FUNC
                      ? "unsupported_symbol_type"
                      : "bridge_missing";
        if (proven_runtime_address == guest_result &&
            proven_symbol_type == STT_FUNC &&
            GetLibFunctionSymbolStartEnd(
                handle.library, symbol, 0, &start, &end)) {
            selected = start;
            diagnostic_reason = NULL;
        }
        if (diagnostic_reason) {
            kzt_guest_library_note_wrapper_diagnostic(
                "symbol", diagnostic_reason, key.link_map_addr,
                key.generation, symbol, proven_symbol_type);
        }
    }
    kzt_guest_registry_source_lease_release(&source_lease);
    kzt_guest_library_handle_release(&handle);
    return selected;
#else
    (void)context;
    (void)guest_handle;
    (void)symbol;
    (void)version;
    return guest_result;
#endif
}

static kzt_guest_library_object_type_t loader_object_type(library_t *library)
{
    return library && library->type == LIB_WRAPPED
               ? KZT_GUEST_LIBRARY_OBJECT_WRAPPED
               : library && library->type == LIB_EMULATED
                     ? KZT_GUEST_LIBRARY_OBJECT_EMULATED
                     : KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED;
}

static int kzt_guest_library_wrapper_proof_matches(
    const kzt_guest_wrapper_source_proof_t *proof, uintptr_t link_map_addr)
{
    return proof && proof->lease.active && proof->lease.registry &&
           proof->key.link_map_addr == link_map_addr &&
           proof->key.link_map_addr == proof->lease.link_map_addr &&
           proof->key.generation == proof->lease.generation &&
           proof->key.namespace_id == proof->lease.namespace_id &&
           proof->key.namespace_id == 0 &&
           proof->key.namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN;
}

kzt_guest_library_binding_result_t kzt_guest_library_note_loader_pair(
    box64context_t *context, uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_object_type_t type;
    if (!context || !link_map_addr || !library)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    type = loader_object_type(library);
    if (type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED) {
        if (!kzt_guest_library_wrapper_proof_matches(proof, link_map_addr))
            return KZT_GUEST_LIBRARY_BINDING_ERROR;
        return kzt_guest_library_bind(
            KztGuestLibraryBindingsForContext(context), &proof->key,
            library, type);
    }
    return kzt_guest_library_publish_loader_pair(
        KztGuestLibraryBindingsForContext(context), link_map_addr,
        library, type);
#else
    (void)context;
    (void)link_map_addr;
    (void)library;
    (void)proof;
    return KZT_GUEST_LIBRARY_BINDING_DISABLED;
#endif
}

kzt_guest_library_binding_result_t
kzt_guest_library_note_loader_pair_pending(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_object_type_t type = loader_object_type(library);

    if (!context || !scope || !link_map_addr || !library ||
        (type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
         !kzt_guest_library_wrapper_proof_matches(proof, link_map_addr)))
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    return kzt_guest_library_loader_scope_note_pair(
        scope, link_map_addr, library, type);
#else
    (void)context; (void)scope; (void)link_map_addr; (void)library; (void)proof;
    return KZT_GUEST_LIBRARY_BINDING_DISABLED;
#endif
}

kzt_guest_library_binding_result_t
kzt_guest_library_publish_loader_pair_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    const kzt_guest_wrapper_source_proof_t *proof)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_object_type_t type = loader_object_type(library);

    if (!context || !scope || !link_map_addr || !library ||
        (type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED &&
         !kzt_guest_library_wrapper_proof_matches(proof, link_map_addr)))
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    return kzt_guest_library_loader_scope_publish_pair(
        scope, link_map_addr, library, type);
#else
    (void)context; (void)scope; (void)link_map_addr; (void)library; (void)proof;
    return KZT_GUEST_LIBRARY_BINDING_DISABLED;
#endif
}

void kzt_guest_library_publish_loader_observed_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr)
{
#ifdef CONFIG_LATX_KZT
    if (!context || !scope || !link_map_addr) return;
    (void)kzt_guest_library_loader_scope_publish_observed(
        scope, link_map_addr);
#else
    (void)context; (void)scope; (void)link_map_addr;
#endif
}
