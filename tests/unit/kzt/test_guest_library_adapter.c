#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_library_adapter.h"
#include "target/i386/latx/include/kzt_guest_library_binding.h"
#include "target/i386/latx/include/kzt_guest_dynsym_lookup.h"
#include "target/i386/latx/include/kzt_guest_registry.h"
#include "target/i386/latx/include/callback.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

struct kzt_guest_library_bindings {
    int unused;
};

int relocation_log;
int kzt_registry_diagnostics;
int option_kzt = 1;
int wine_option_kzt;

static struct kzt_guest_library_bindings bindings;
static kzt_guest_library_loader_scope_t *thread_scope;
static uintptr_t expected_function;
static uintptr_t expected_filename;
static int expected_flag;
static uint64_t guest_result;
static int begin_result;
static int expect_scoped;
static int guest_sets_refresh_pending;
static int call_count;
static int publish_pair_count;
static int raw_publish_pair_count;
static int publish_observed_count;
static int end_count;
static int sequence;
static int publish_sequence;
static int end_sequence;

typedef enum guest_call_kind {
    GUEST_CALL_DLOPEN = 0,
    GUEST_CALL_DLSYM,
    GUEST_CALL_DLVSYM,
    GUEST_CALL_DLERROR,
    GUEST_CALL_DLMOPEN,
    GUEST_CALL_DLINFO,
} guest_call_kind_t;

static guest_call_kind_t expected_call_kind;
static uintptr_t expected_handle;
static uintptr_t expected_symbol;
static uintptr_t expected_version;
static uintptr_t expected_lmid;
static uintptr_t expected_info;
static int expected_request;
static uintptr_t resolved_guest_address;
static kzt_guest_registry_address_match_t resolved_match;
static int resolve_result;
static int lookup_result;
static library_t *lookup_library;
static kzt_guest_library_object_type_t lookup_object_type;
static int wrapper_lookup_result;
static int wrapper_function_lookup_result;
static uintptr_t wrapper_result;
static int resolve_count;
static int lookup_count;
static int release_count;
static unsigned char dynsym_type;
static kzt_guest_dynsym_lookup_status_t dynsym_status;
static uintptr_t dynsym_runtime_address;
static kzt_guest_field_status_t dynamic_view_status;
static unsigned long dynamic_view_generation;
static int find_live_result;
static int source_lease_result;
static uintptr_t lookup_guest_handle;
static kzt_guest_loader_identity_t lookup_loader_identity;
static int lookup_loader_identity_result;
static int symbol_source_result;
static int symbol_source_acquire_count;
static int dynamic_view_count;
static int dynsym_lookup_count;
static int evidence_lookup_count;
static int evidence_store_count;
static int evidence_valid;
static unsigned long evidence_dynamic_revision;
static uintptr_t evidence_runtime_address;
static unsigned char evidence_symbol_type;

#define CHECK(label, condition)                                              \
    do {                                                                     \
        if (!(condition)) {                                                  \
            fprintf(stderr, "%s: FAIL\n", label);                            \
            exit(EXIT_FAILURE);                                              \
        }                                                                    \
    } while (0)

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(
    box64context_t *context)
{
    return context ? &bindings : NULL;
}

kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    return context ? (kzt_guest_registry_t *)(uintptr_t)0x1110 : NULL;
}

int kzt_guest_registry_resolve_address_pair(
    kzt_guest_registry_t *registry,
    uintptr_t current_address,
    uintptr_t expected_address,
    kzt_guest_registry_address_pair_t *pair)
{
    CHECK("resolve registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("resolve current", current_address == resolved_guest_address);
    CHECK("resolve expected", expected_address == resolved_guest_address);
    ++resolve_count;
    if (resolve_result != 0)
        return resolve_result;
    memset(pair, 0, sizeof(*pair));
    pair->current = resolved_match;
    pair->expected = resolved_match;
    return 0;
}

int kzt_guest_registry_find_loader_identity(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity)
{
    CHECK("loader identity registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("loader identity handle", handle == lookup_guest_handle);
    if (lookup_loader_identity_result != 0) {
        memset(identity, 0, sizeof(*identity));
        return lookup_loader_identity_result;
    }
    *identity = lookup_loader_identity;
    return 0;
}

int kzt_guest_registry_loader_symbol_source_acquire(
    kzt_guest_registry_t *registry, uintptr_t handle,
    kzt_guest_loader_identity_t *identity,
    kzt_guest_dynamic_view_t *dynamic_view,
    kzt_guest_field_status_t *dynamic_status,
    unsigned long *dynamic_revision,
    kzt_guest_registry_source_lease_t *lease)
{
    CHECK("symbol source registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("symbol source handle", handle == lookup_guest_handle);
    ++symbol_source_acquire_count;
    if (symbol_source_result != 0) {
        memset(identity, 0, sizeof(*identity));
        memset(dynamic_view, 0, sizeof(*dynamic_view));
        *dynamic_status = KZT_GUEST_FIELD_UNKNOWN;
        *dynamic_revision = 0;
        memset(lease, 0, sizeof(*lease));
        return symbol_source_result;
    }
    *identity = lookup_loader_identity;
    memset(dynamic_view, 0, sizeof(*dynamic_view));
    dynamic_view->status = KZT_GUEST_DYNAMIC_COMPLETE;
    *dynamic_status = dynamic_view_status;
    *dynamic_revision = 5;
    *lease = (kzt_guest_registry_source_lease_t) {
        .registry = registry,
        .link_map_addr = identity->link_map_addr,
        .generation = identity->generation,
        .namespace_id = identity->namespace_id,
        .active = 1,
    };
    return 0;
}

int kzt_guest_library_access_lookup(
    kzt_guest_library_access_t *access,
    const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    CHECK("lookup access", access != NULL);
    CHECK("lookup link map", key->link_map_addr == resolved_match.link_map_addr);
    CHECK("lookup generation", key->generation == resolved_match.generation);
    CHECK("lookup namespace", key->namespace_id == resolved_match.namespace_id);
    ++lookup_count;
    memset(handle, 0, sizeof(*handle));
    if (lookup_result != 0)
        return lookup_result;
    handle->bindings = &bindings;
    handle->entry = (void *)(uintptr_t)0x1120;
    handle->library = lookup_library;
    handle->object_type = lookup_object_type;
    return 0;
}

void kzt_guest_library_handle_release(kzt_guest_library_handle_t *handle)
{
    CHECK("release handle", handle != NULL);
    ++release_count;
    memset(handle, 0, sizeof(*handle));
}

int kzt_guest_registry_source_lease_acquire(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    unsigned long generation, uintptr_t namespace_id,
    kzt_guest_registry_source_lease_t *lease)
{
    CHECK("lease registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("lease link map", link_map_addr == resolved_match.link_map_addr);
    CHECK("lease generation", generation == resolved_match.generation);
    CHECK("lease namespace", namespace_id == resolved_match.namespace_id);
    if (source_lease_result != 0) {
        memset(lease, 0, sizeof(*lease));
        return source_lease_result;
    }
    *lease = (kzt_guest_registry_source_lease_t) {
        .registry = registry,
        .link_map_addr = link_map_addr,
        .generation = generation,
        .namespace_id = namespace_id,
        .active = 1,
    };
    return 0;
}

int kzt_guest_registry_find_live_object(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    kzt_guest_registry_address_match_t *match)
{
    CHECK("live registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("live link map", link_map_addr == resolved_match.link_map_addr);
    if (find_live_result != 0) {
        memset(match, 0, sizeof(*match));
        return find_live_result;
    }
    *match = resolved_match;
    return 0;
}

void kzt_guest_registry_source_lease_release(
    kzt_guest_registry_source_lease_t *lease)
{
    memset(lease, 0, sizeof(*lease));
}

int kzt_guest_registry_find_dynamic_view(
    kzt_guest_registry_t *registry, uintptr_t link_map_addr,
    kzt_guest_dynamic_view_t *view, kzt_guest_field_status_t *status,
    unsigned long *generation)
{
    ++dynamic_view_count;
    CHECK("dynamic view registry",
          registry == (kzt_guest_registry_t *)(uintptr_t)0x1110);
    CHECK("dynamic view link map",
          link_map_addr == resolved_match.link_map_addr);
    memset(view, 0, sizeof(*view));
    view->status = KZT_GUEST_DYNAMIC_COMPLETE;
    *status = dynamic_view_status;
    *generation = dynamic_view_generation;
    return 0;
}

kzt_guest_dynsym_lookup_status_t kzt_guest_dynsym_lookup(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_link_map_reader_ops_t *reader_ops, const char *symbol,
    kzt_symbol_version_evidence_t version_evidence, const char *version,
    kzt_guest_dynsym_lookup_result_t *result)
{
    ++dynsym_lookup_count;
    CHECK("dynsym complete view", view->status == KZT_GUEST_DYNAMIC_COMPLETE);
    CHECK("dynsym reader", reader_ops && reader_ops->read_memory);
    CHECK("dynsym symbol", strcmp(symbol, "wi963_symbol") == 0);
    CHECK("dynsym unversioned",
          version_evidence == KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED &&
          version == NULL);
    memset(result, 0, sizeof(*result));
    result->status = dynsym_status;
    result->binding = STB_GLOBAL;
    result->type = dynsym_type;
    result->visibility = STV_DEFAULT;
    result->runtime_address = dynsym_runtime_address;
    return result->status;
}

int kzt_guest_library_symbol_evidence_lookup(
    const kzt_guest_library_handle_t *handle, const char *symbol,
    unsigned long dynamic_revision, uintptr_t *runtime_address,
    unsigned char *symbol_type)
{
    CHECK("evidence lookup handle", handle && handle->entry);
    CHECK("evidence lookup symbol", strcmp(symbol, "wi963_symbol") == 0);
    ++evidence_lookup_count;
    if (!evidence_valid || evidence_dynamic_revision != dynamic_revision)
        return -1;
    *runtime_address = evidence_runtime_address;
    *symbol_type = evidence_symbol_type;
    return 0;
}

void kzt_guest_library_symbol_evidence_store(
    const kzt_guest_library_handle_t *handle, const char *symbol,
    unsigned long dynamic_revision, uintptr_t runtime_address,
    unsigned char symbol_type)
{
    CHECK("evidence store handle", handle && handle->entry);
    CHECK("evidence store symbol", strcmp(symbol, "wi963_symbol") == 0);
    ++evidence_store_count;
    evidence_valid = 1;
    evidence_dynamic_revision = dynamic_revision;
    evidence_runtime_address = runtime_address;
    evidence_symbol_type = symbol_type;
}

int GetLibSymbolStartEnd(
    library_t *library, const char *name, khint_t pre_k,
    uintptr_t *start, uintptr_t *end, int version,
    const char *vername, int local)
{
    CHECK("wrapper lookup library", library == lookup_library);
    CHECK("wrapper lookup symbol", strcmp(name, "wi963_symbol") == 0);
    CHECK("wrapper lookup hash", pre_k == 0);
    CHECK("wrapper lookup version", version == -1 && vername == NULL);
    CHECK("wrapper lookup local", local == 1);
    if (!wrapper_lookup_result)
        return 0;
    *start = wrapper_result;
    *end = wrapper_result + sizeof(void *);
    return 1;
}

int GetLibFunctionSymbolStartEnd(
    library_t *library, const char *name, khint_t pre_k,
    uintptr_t *start, uintptr_t *end)
{
    CHECK("function lookup library", library == lookup_library);
    CHECK("function lookup symbol", strcmp(name, "wi963_symbol") == 0);
    CHECK("function lookup hash", pre_k == 0);
    if (!wrapper_function_lookup_result)
        return 0;
    *start = wrapper_result;
    *end = wrapper_result + sizeof(void *);
    return 1;
}

int kzt_guest_library_loader_scope_begin(
    kzt_guest_library_bindings_t *actual_bindings,
    kzt_guest_library_loader_scope_t *scope)
{
    if (begin_result != 0)
        return begin_result;
    CHECK("begin bindings", actual_bindings == &bindings);
    scope->bindings = actual_bindings;
    scope->identity = 17;
    scope->cookie = 23;
    return 0;
}

void kzt_guest_library_loader_scope_end(
    kzt_guest_library_loader_scope_t *scope)
{
    CHECK("end valid scope",
          scope && scope->bindings == &bindings &&
          scope->identity == 17 && scope->cookie == 23);
    ++end_count;
    end_sequence = ++sequence;
    memset(scope, 0, sizeof(*scope));
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_note_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    (void)scope;
    (void)link_map_addr;
    (void)library;
    (void)object_type;
    return KZT_GUEST_LIBRARY_BINDING_PENDING;
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    CHECK("publish pair scope", scope && scope->identity == 17);
    CHECK("publish pair address", link_map_addr == guest_result);
    CHECK("publish pair library", library != NULL);
    CHECK("publish pair type",
          object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED);
    ++publish_pair_count;
    publish_sequence = ++sequence;
    return KZT_GUEST_LIBRARY_BINDING_ADDED;
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_observed(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr)
{
    CHECK("publish observed scope", scope && scope->identity == 17);
    CHECK("publish observed address", link_map_addr == guest_result);
    ++publish_observed_count;
    publish_sequence = ++sequence;
    return KZT_GUEST_LIBRARY_BINDING_PENDING;
}

kzt_guest_library_binding_result_t kzt_guest_library_publish_loader_pair(
    kzt_guest_library_bindings_t *actual_bindings,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    (void)actual_bindings;
    (void)link_map_addr;
    (void)library;
    (void)object_type;
    ++raw_publish_pair_count;
    return KZT_GUEST_LIBRARY_BINDING_ADDED;
}

kzt_guest_library_binding_result_t kzt_guest_library_bind(
    kzt_guest_library_bindings_t *actual_bindings,
    const kzt_guest_library_binding_key_t *key, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    CHECK("direct bind bindings", actual_bindings == &bindings);
    CHECK("direct bind key", key && key->link_map_addr != 0 &&
          key->generation != 0 && key->namespace_id == 0);
    CHECK("direct bind library", library != NULL);
    CHECK("direct bind wrapped",
          object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED);
    ++raw_publish_pair_count;
    return KZT_GUEST_LIBRARY_BINDING_ADDED;
}

uint64_t RunFunctionWithState(uintptr_t function, int nargs, ...)
{
    va_list args;

    ++call_count;
    CHECK("guest function", function == expected_function);
    va_start(args, nargs);
    switch (expected_call_kind) {
    case GUEST_CALL_DLOPEN: {
        uintptr_t filename;
        int flag;

        CHECK("guest nargs", nargs == 2);
        if (expect_scoped) {
            CHECK("scope installed during guest call",
                  thread_scope && thread_scope->identity == 17 &&
                  thread_scope->cookie == 23);
            if (guest_sets_refresh_pending) {
                thread_scope->prebind_refresh_pending = 1;
            }
        } else {
            CHECK("scope failure preserves guest call scope",
                  thread_scope && thread_scope->identity == 31 &&
                  thread_scope->cookie == 37);
        }
        filename = va_arg(args, uintptr_t);
        flag = va_arg(args, int);
        CHECK("guest filename", filename == expected_filename);
        CHECK("guest flag", flag == expected_flag);
        break;
    }
    case GUEST_CALL_DLSYM:
        CHECK("dlsym nargs", nargs == 2);
        CHECK("dlsym handle",
              va_arg(args, uintptr_t) == expected_handle);
        CHECK("dlsym symbol",
              va_arg(args, uintptr_t) == expected_symbol);
        break;
    case GUEST_CALL_DLVSYM:
        CHECK("dlvsym nargs", nargs == 3);
        CHECK("dlvsym handle",
              va_arg(args, uintptr_t) == expected_handle);
        CHECK("dlvsym symbol",
              va_arg(args, uintptr_t) == expected_symbol);
        CHECK("dlvsym version",
              va_arg(args, uintptr_t) == expected_version);
        break;
    case GUEST_CALL_DLERROR:
        CHECK("dlerror nargs", nargs == 0);
        break;
    case GUEST_CALL_DLMOPEN:
        CHECK("dlmopen nargs", nargs == 3);
        CHECK("dlmopen lmid",
              va_arg(args, uintptr_t) == expected_lmid);
        CHECK("dlmopen filename",
              va_arg(args, uintptr_t) == expected_filename);
        CHECK("dlmopen flag", va_arg(args, int) == expected_flag);
        break;
    case GUEST_CALL_DLINFO:
        CHECK("dlinfo nargs", nargs == 3);
        CHECK("dlinfo handle",
              va_arg(args, uintptr_t) == expected_handle);
        CHECK("dlinfo request", va_arg(args, int) == expected_request);
        CHECK("dlinfo info",
              va_arg(args, uintptr_t) == expected_info);
        break;
    }
    va_end(args);
    return guest_result;
}

static void reset_counters(void)
{
    call_count = 0;
    publish_pair_count = 0;
    raw_publish_pair_count = 0;
    publish_observed_count = 0;
    end_count = 0;
    sequence = 0;
    publish_sequence = 0;
    end_sequence = 0;
    resolve_count = 0;
    lookup_count = 0;
    release_count = 0;
    guest_sets_refresh_pending = 0;
}

static void test_pair_publish_restores_scope(void)
{
    box64context_t context = { 0 };
    library_t library = { .type = LIB_WRAPPED };
    kzt_guest_library_loader_scope_t original = {
        .bindings = (void *)0x1000,
        .identity = 3,
        .cookie = 5,
    };
    kzt_guest_library_loader_scope_t call_scope = { 0 };
    kzt_guest_wrapper_source_proof_t proof = {
        .lease = {
            .registry = (kzt_guest_registry_t *)(uintptr_t)0x1110,
            .link_map_addr = 0x4000,
            .generation = 7,
            .namespace_id = 0,
            .active = 1,
        },
        .key = {
            .link_map_addr = 0x4000,
            .generation = 7,
            .namespace_id = 0,
            .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        },
    };
    uint64_t result;

    reset_counters();
    begin_result = 0;
    expect_scoped = 1;
    expected_call_kind = GUEST_CALL_DLOPEN;
    expected_function = 0x2000;
    expected_filename = 0x3000;
    expected_flag = 0x102;
    guest_result = 0x4000;
    thread_scope = &original;
    guest_sets_refresh_pending = 1;

    result = kzt_guest_library_run_dlopen_scoped(
        &context, thread_scope, expected_function,
        (void *)expected_filename, expected_flag, &call_scope);
    CHECK("pair guest result", result == guest_result);
    CHECK("pair called once", call_count == 1);
    CHECK("pair original scope restored",
          original.bindings == (void *)0x1000 &&
          original.identity == 3 && original.cookie == 5 &&
          original.prebind_refresh_pending == 1);
    CHECK("nested refresh deferred to parent",
          call_scope.prebind_refresh_pending == 0);

    kzt_guest_library_finish_dlopen_scoped(
        &context, &call_scope, result, &library, &proof, 1);
    CHECK("pair published once", publish_pair_count == 1);
    CHECK("pair not observed", publish_observed_count == 0);
    CHECK("pair scope ended", end_count == 1);
    CHECK("pair published before end",
          publish_sequence && publish_sequence < end_sequence);
}

static void test_wrapped_publication_requires_source_proof(void)
{
    box64context_t context = { 0 };
    library_t library = { .type = LIB_WRAPPED };

    reset_counters();
    kzt_guest_library_note_loader_pair(
        &context, 0x4100, &library, NULL);
    CHECK("proofless wrapped publication rejected",
          raw_publish_pair_count == 0);
}

static void test_observed_and_failed_calls(void)
{
    box64context_t context = { 0 };
    kzt_guest_library_loader_scope_t current = { 0 };
    kzt_guest_library_loader_scope_t call_scope = { 0 };
    uint64_t result;

    reset_counters();
    begin_result = 0;
    expect_scoped = 1;
    expected_call_kind = GUEST_CALL_DLOPEN;
    expected_function = 0x5000;
    expected_filename = 0x6000;
    expected_flag = 2;
    guest_result = 0x7000;
    thread_scope = &current;
    guest_sets_refresh_pending = 1;
    result = kzt_guest_library_run_dlopen_scoped(
        &context, thread_scope, expected_function,
        (void *)expected_filename, expected_flag, &call_scope);
    CHECK("outer refresh retained for completion",
          call_scope.prebind_refresh_pending == 1);
    kzt_guest_library_finish_dlopen_scoped(
        &context, &call_scope, result, NULL, NULL, 1);
    CHECK("observed published", publish_observed_count == 1);
    CHECK("observed scope ended", end_count == 1);

    reset_counters();
    memset(&call_scope, 0, sizeof(call_scope));
    guest_result = 0;
    result = kzt_guest_library_run_dlopen_scoped(
        &context, thread_scope, expected_function,
        (void *)expected_filename, expected_flag, &call_scope);
    kzt_guest_library_finish_dlopen_scoped(
        &context, &call_scope, result, NULL, NULL, 0);
    CHECK("failed call still ran", call_count == 1);
    CHECK("failed call not published",
          publish_pair_count == 0 && publish_observed_count == 0);
    CHECK("failed scope ended", end_count == 1);
}

static void test_scope_failure_is_fail_open(void)
{
    box64context_t context = { 0 };
    kzt_guest_library_loader_scope_t original = {
        .bindings = (void *)0x8000,
        .identity = 31,
        .cookie = 37,
    };
    kzt_guest_library_loader_scope_t call_scope = { 0 };
    uint64_t result;

    reset_counters();
    begin_result = -1;
    expect_scoped = 0;
    expected_call_kind = GUEST_CALL_DLOPEN;
    expected_function = 0x9000;
    expected_filename = 0xa000;
    expected_flag = 1;
    guest_result = 0xb000;
    thread_scope = &original;

    result = kzt_guest_library_run_dlopen_scoped(
        &context, thread_scope, expected_function,
        (void *)expected_filename, expected_flag, &call_scope);
    CHECK("scope failure guest result", result == guest_result);
    CHECK("scope failure still called", call_count == 1);
    CHECK("scope failure preserves original",
          original.bindings == (void *)0x8000 &&
          original.identity == 31 && original.cookie == 37);
    kzt_guest_library_finish_dlopen_scoped(
        &context, &call_scope, result, NULL, NULL, 1);
    CHECK("scope failure not published",
          publish_pair_count == 0 && publish_observed_count == 0);
    CHECK("scope failure not ended", end_count == 0);
}

static void test_guest_symbol_queries_preserve_arguments(void)
{
    reset_counters();
    expected_call_kind = GUEST_CALL_DLSYM;
    expected_function = 0xc000;
    expected_handle = 0xc100;
    expected_symbol = 0xc200;
    guest_result = 0xc300;
    CHECK("dlsym result",
          kzt_guest_library_run_dlsym(
              expected_function, (void *)expected_handle,
              (void *)expected_symbol) == guest_result);
    CHECK("dlsym called once", call_count == 1);

    reset_counters();
    expected_call_kind = GUEST_CALL_DLVSYM;
    expected_function = 0xd000;
    expected_handle = 0xd100;
    expected_symbol = 0xd200;
    expected_version = 0xd300;
    guest_result = 0xd400;
    CHECK("dlvsym result",
          kzt_guest_library_run_dlvsym(
              expected_function, (void *)expected_handle,
              (void *)expected_symbol,
              (const char *)expected_version) == guest_result);
    CHECK("dlvsym called once", call_count == 1);

    reset_counters();
    expected_call_kind = GUEST_CALL_DLERROR;
    expected_function = 0xe000;
    guest_result = 0xe100;
    CHECK("dlerror result",
          kzt_guest_library_run_dlerror(expected_function) == guest_result);
    CHECK("dlerror called once", call_count == 1);
}

static void test_guest_namespace_calls_preserve_arguments(void)
{
    reset_counters();
    expected_call_kind = GUEST_CALL_DLMOPEN;
    expected_function = 0xe200;
    expected_lmid = ~(uintptr_t)0;
    expected_filename = 0xe300;
    expected_flag = 0x2;
    guest_result = 0xe400;
    CHECK("dlmopen result",
          kzt_guest_library_run_dlmopen(
              expected_function, (void *)expected_lmid,
              (void *)expected_filename, expected_flag) == guest_result);
    CHECK("dlmopen called once", call_count == 1);

    reset_counters();
    expected_call_kind = GUEST_CALL_DLINFO;
    expected_function = 0xe500;
    expected_handle = 0xe600;
    expected_request = 1;
    expected_info = 0xe700;
    guest_result = 0;
    CHECK("dlinfo result",
          kzt_guest_library_run_dlinfo(
              expected_function, (void *)expected_handle,
              expected_request, (void *)expected_info) == 0);
    CHECK("dlinfo called once", call_count == 1);
}

static void prepare_symbol_selection(library_t *library)
{
    resolved_guest_address = 0xf100;
    resolved_match = (kzt_guest_registry_address_match_t) {
        .link_map_addr = 0xf200,
        .map_start = 0xf000,
        .map_end = 0x10000,
        .namespace_id = 0,
        .generation = 7,
        .namespace_id_status = KZT_GUEST_FIELD_OK,
        .match_count = 1,
    };
    resolve_result = 0;
    lookup_result = 0;
    lookup_library = library;
    lookup_object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED;
    wrapper_lookup_result = 1;
    wrapper_function_lookup_result = 1;
    wrapper_result = 0xf300;
    dynsym_type = STT_FUNC;
    dynsym_status = KZT_GUEST_DYNSYM_LOOKUP_FOUND;
    dynsym_runtime_address = resolved_guest_address;
    dynamic_view_status = KZT_GUEST_FIELD_OK;
    dynamic_view_generation = resolved_match.generation;
    find_live_result = 0;
    source_lease_result = 0;
    lookup_guest_handle = 0xf400;
    lookup_loader_identity = (kzt_guest_loader_identity_t) {
        .handle = lookup_guest_handle,
        .link_map_addr = resolved_match.link_map_addr,
        .generation = resolved_match.generation,
        .namespace_id = resolved_match.namespace_id,
        .handle_generation = 3,
    };
    lookup_loader_identity_result = 0;
    symbol_source_result = 0;
    symbol_source_acquire_count = 0;
    dynamic_view_count = 0;
    dynsym_lookup_count = 0;
    evidence_lookup_count = 0;
    evidence_store_count = 0;
    evidence_valid = 0;
    evidence_dynamic_revision = 0;
}

static void prepare_trusted_source(library_t *library)
{
    prepare_symbol_selection(library);
    resolved_match.path_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.path,
           "/lib/x86_64-linux-gnu/libwi963.so");
    resolved_match.soname_status = KZT_GUEST_FIELD_NOT_PARSED;
    resolved_match.soname[0] = '\0';
}

static void test_wrapper_source_accepts_only_exact_trusted_identity(void)
{
    box64context_t context = { 0 };
    kzt_guest_wrapper_source_proof_t proof = { 0 };

    reset_counters();
    prepare_trusted_source(NULL);
    CHECK("trusted basename source accepted",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) == 0);
    CHECK("trusted source exact key",
          proof.lease.active &&
          proof.key.link_map_addr == resolved_match.link_map_addr &&
          proof.key.generation == resolved_match.generation &&
          proof.key.namespace_id == 0 &&
          proof.key.namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN);
    kzt_guest_library_wrapper_source_release(&proof);
    CHECK("trusted source release", !proof.lease.active);

    prepare_trusted_source(NULL);
    CHECK("trusted explicit source accepted",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr,
              "/lib/x86_64-linux-gnu/libwi963.so", "libwi963.so",
              &proof) == 0);
    kzt_guest_library_wrapper_source_release(&proof);

    prepare_trusted_source(NULL);
    CHECK("different explicit path rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr,
              "/usr/lib/x86_64-linux-gnu/libwi963.so", "libwi963.so",
              &proof) != 0);

    prepare_trusted_source(NULL);
    resolved_match.soname_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.soname, "libspoofed.so");
    CHECK("conflicting soname rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);

    prepare_trusted_source(NULL);
    resolved_match.namespace_id = 9;
    CHECK("non-main source rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);

    prepare_trusted_source(NULL);
    source_lease_result = -1;
    CHECK("stale generation source rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);

    prepare_trusted_source(NULL);
    find_live_result = -1;
    CHECK("missing identity source rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);
}

static void test_wrapper_source_rejects_untrusted_same_basename(void)
{
    box64context_t context = { 0 };
    kzt_guest_wrapper_source_proof_t proof = { 0 };

    reset_counters();
    prepare_symbol_selection(NULL);
    resolved_match.path_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.path, "/tmp/libwi963.so");
    resolved_match.soname_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.soname, "libwi963.so");
    CHECK("untrusted same basename rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);
    CHECK("rejected proof remains inactive", !proof.lease.active);

    prepare_symbol_selection(NULL);
    resolved_match.path_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.path, "/usr/lib/custom/libwi963.so");
    resolved_match.soname_status = KZT_GUEST_FIELD_OK;
    strcpy(resolved_match.soname, "libwi963.so");
    CHECK("trusted-prefix custom soname rejected",
          kzt_guest_library_wrapper_source_acquire(
              &context, resolved_match.link_map_addr, "libwi963.so",
              "libwi963.so", &proof) != 0);
    CHECK("trusted-prefix proof remains inactive", !proof.lease.active);
}

static void test_symbol_selection_requires_exact_wrapped_owner(void)
{
    box64context_t context = { 0 };
    library_t library = { .type = LIB_WRAPPED };
    uintptr_t selected;

    reset_counters();
    prepare_symbol_selection(&library);
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("exact wrapped bridge selected", selected == wrapper_result);
    CHECK("exact wrapped uses handle source without address scan",
          resolve_count == 0 && symbol_source_acquire_count == 1);
    CHECK("exact wrapped lookup", lookup_count == 1);
    CHECK("exact wrapped released", release_count == 1);

    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("cached exact wrapped bridge selected", selected == wrapper_result);
    CHECK("cached selector avoids guest dynsym reread",
          dynsym_lookup_count == 1 && evidence_lookup_count == 2 &&
              evidence_store_count == 1);
    {
        size_t i;

        for (i = 0; i < 1000; ++i) {
            selected = kzt_guest_library_select_symbol_result(
                &context, lookup_guest_handle, resolved_guest_address,
                "wi963_symbol", NULL);
            CHECK("steady cached selector bridge", selected == wrapper_result);
        }
    }
    CHECK("steady cached selector reads dynsym once",
          dynsym_lookup_count == 1 && evidence_lookup_count == 1002 &&
              evidence_store_count == 1 && resolve_count == 0);

    reset_counters();
    prepare_symbol_selection(&library);
    wrapper_function_lookup_result = 0;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("wrapper data manifest keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    lookup_result = -1;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("lookup provider without exact binding keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    option_kzt = 0;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    option_kzt = 1;
    CHECK("disabled KZT keeps guest", selected == resolved_guest_address);
    CHECK("disabled KZT skips Registry", resolve_count == 0);

    reset_counters();
    prepare_symbol_selection(&library);
    dynsym_type = STT_OBJECT;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("object symbol keeps guest", selected == resolved_guest_address);

    {
        static const unsigned char unsupported_types[] = {
            STT_TLS,
            STT_NOTYPE,
            0xfe,
#ifdef STT_GNU_IFUNC
            STT_GNU_IFUNC,
#endif
        };
        size_t i;

        for (i = 0; i < sizeof(unsupported_types) /
                            sizeof(unsupported_types[0]); ++i) {
            reset_counters();
            prepare_symbol_selection(&library);
            dynsym_type = unsupported_types[i];
            selected = kzt_guest_library_select_symbol_result(
                &context, lookup_guest_handle, resolved_guest_address,
                "wi963_symbol", NULL);
            CHECK("unsupported symbol type keeps guest",
                  selected == resolved_guest_address);
        }
    }

    reset_counters();
    prepare_symbol_selection(&library);
    dynsym_runtime_address = resolved_guest_address + 8;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("dynsym address mismatch keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    dynsym_status = KZT_GUEST_DYNSYM_LOOKUP_UNKNOWN;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("unknown dynsym evidence keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    dynamic_view_status = KZT_GUEST_FIELD_UNKNOWN;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("stale dynamic generation keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    symbol_source_result = -1;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("stale source generation keeps guest",
          selected == resolved_guest_address);

    reset_counters();
    prepare_symbol_selection(&library);
    symbol_source_result = -1;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("missing exact handle source keeps guest",
          selected == resolved_guest_address);
    CHECK("missing exact handle source skips lookup", lookup_count == 0);

    reset_counters();
    prepare_symbol_selection(&library);
    lookup_object_type = KZT_GUEST_LIBRARY_OBJECT_EMULATED;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("emulated owner keeps guest",
          selected == resolved_guest_address);
    CHECK("emulated owner released", release_count == 1);

    reset_counters();
    prepare_symbol_selection(&library);
    wrapper_lookup_result = 0;
    wrapper_function_lookup_result = 0;
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", NULL);
    CHECK("missing wrapper keeps guest",
          selected == resolved_guest_address);
    CHECK("missing wrapper released", release_count == 1);

    reset_counters();
    prepare_symbol_selection(&library);
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, 0, "wi963_symbol", NULL);
    CHECK("missing guest result stays missing", selected == 0);
    CHECK("missing guest skips registry", resolve_count == 0);

    reset_counters();
    prepare_symbol_selection(&library);
    selected = kzt_guest_library_select_symbol_result(
        &context, lookup_guest_handle, resolved_guest_address,
        "wi963_symbol", "WI982_1.0");
    CHECK("versioned lookup keeps guest",
          selected == resolved_guest_address);
    CHECK("versioned lookup skips unversioned owner selection",
          resolve_count == 0 && lookup_count == 0 && release_count == 0);
}

int main(void)
{
    test_pair_publish_restores_scope();
    test_wrapped_publication_requires_source_proof();
    test_observed_and_failed_calls();
    test_scope_failure_is_fail_open();
    test_guest_symbol_queries_preserve_arguments();
    test_guest_namespace_calls_preserve_arguments();
    test_symbol_selection_requires_exact_wrapped_owner();
    test_wrapper_source_rejects_untrusted_same_basename();
    test_wrapper_source_accepts_only_exact_trusted_identity();
    puts("kzt-guest-library-adapter: PASS");
    return EXIT_SUCCESS;
}
