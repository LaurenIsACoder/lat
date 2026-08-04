#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/box64context.h"
#include "target/i386/latx/include/bridge.h"
#include "target/i386/latx/include/elfloader.h"
#include "target/i386/latx/include/khash.h"
#include "target/i386/latx/include/kzt_bridge_exact.h"
#include "target/i386/latx/include/kzt_rela_runtime_bridge.h"
#include "target/i386/latx/include/librarian_private.h"
#include "target/i386/latx/include/library.h"
#include "target/i386/latx/include/library_private.h"

#define FIXTURE_SYMBOL "uname"

box64context_t *my_context;
int relocation_log;
int kzt_registry_diagnostics;

KHASH_MAP_IMPL_STR(symbolmap, wrapper_t)
KHASH_MAP_IMPL_STR(symbol2map, symbol2_t)

elfheader_t *FindElfAddress(box64context_t *context, uintptr_t address)
{
    (void)context;
    (void)address;
    return NULL;
}

static void wrapper(uintptr_t fnc)
{
    (void)fnc;
}

int main(void)
{
    static char libc_name[] = "libc.so.6";
    box64context_t context = { 0 };
    lib_t scope = { 0 };
    library_t provider = { 0 };
    library_t *libraries[] = { &provider };
    kzt_guest_library_handle_t handle = {
        .bindings = (kzt_guest_library_bindings_t *)(uintptr_t)1,
        .entry = (void *)(uintptr_t)1,
        .library = &provider,
        .object_type = KZT_GUEST_LIBRARY_OBJECT_WRAPPED,
    };
    bridge_t *bridge = NULL;
    void *native_symbol = NULL;
    uintptr_t first = 0;
    uintptr_t second = 0;
    khint_t key;
    int inserted;
    int failed = 0;

    bridge = NewBridge();
    provider.priv.w.lib = dlopen(libc_name, RTLD_LAZY | RTLD_LOCAL);
    provider.symbolmap = kh_init(symbolmap);
    if (!bridge || !provider.priv.w.lib || !provider.symbolmap) {
        fprintf(stderr, "cannot initialize real bridge fixture\n");
        failed = 1;
        goto out;
    }
    key = kh_put(symbolmap, provider.symbolmap, FIXTURE_SYMBOL, &inserted);
    if (inserted == -1 || key == kh_end(provider.symbolmap)) {
        fprintf(stderr, "cannot add wrapper manifest entry\n");
        failed = 1;
        goto out;
    }
    kh_value(provider.symbolmap, key) = wrapper;
    scope.libraries = libraries;
    scope.libsz = 1;
    scope.context = &context;
    context.maplib = &scope;
    provider.name = libc_name;
    provider.path = libc_name;
    provider.type = LIB_WRAPPED;
    provider.active = 1;
    provider.context = &context;
    provider.priv.w.bridge = bridge;

    native_symbol = dlsym(provider.priv.w.lib, FIXTURE_SYMBOL);
    if (!native_symbol || CheckBridged(bridge, native_symbol)) {
        fprintf(stderr, "native fixture is unavailable or already bridged\n");
        failed = 1;
        goto out;
    }
    first = kzt_rela_runtime_select_exact_wrapper_bridge_retained(
        &context, &handle, FIXTURE_SYMBOL,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL);
    second = kzt_rela_runtime_select_exact_wrapper_bridge_retained(
        &context, &handle, FIXTURE_SYMBOL,
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED, NULL);
    if (!first || second != first ||
        CheckBridged(bridge, native_symbol) != first ||
        !kzt_bridge_is_exact(first, wrapper, native_symbol)) {
        fprintf(stderr,
                "real selector did not create and reuse one exact bridge\n");
        failed = 1;
    }

out:
    if (provider.symbolmap) kh_destroy(symbolmap, provider.symbolmap);
    if (provider.priv.w.lib) dlclose(provider.priv.w.lib);
    if (bridge) FreeBridge(&bridge);
    return failed;
}
