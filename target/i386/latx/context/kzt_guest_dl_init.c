#include "qemu/osdep.h"

#include "kzt_guest_dl_init.h"

#include "elfloader.h"
#include "kzt_guest_dl_api.h"
#include "kzt_guest_runtime_entry_state.h"
#include "pathcoll.h"

extern const char *interp_prefix;
elfheader_t *tryLoadElfFromFileForContext(
    box64context_t *context, const char *name);
void freeElfFromFile(elfheader_t **header);

typedef struct kzt_guest_dl_init_scope_s {
    box64context_t *context;
    uintptr_t runtime_entries[KZT_GUEST_RUNTIME_ENTRY_COUNT];
} kzt_guest_dl_init_scope_t;

static int kzt_guest_dl_resolve_entries(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    static const char *symbols[] = {
        "dlopen", "dlmopen", "dlsym", "dlclose", "dladdr", "dladdr1",
        "dlinfo", "dlvsym", "dlerror",
        "free", "realloc", "pthread_setcanceltype",
    };
    kzt_guest_dl_init_scope_t *scope = opaque;
    box64context_t *context = scope->context;
    elfheader_t *header;
    void *resolved[ARRAY_SIZE(symbols)] = { 0 };
    int resolved_count = 0;

#ifdef CONFIG_LOONGARCH_NEW_WORLD
    char path[PATH_MAX] = { 0 };

    snprintf(path, sizeof(path), "%s%s", interp_prefix,
             "/usr/lib/glibc-hwcaps/x86-64-v2/");
    if (!FindInCollection(path, &context->box64_ld_lib)) {
        PrependList(&context->box64_ld_lib, path, 1);
    }
#endif
    header = tryLoadElfFromFileForContext(context, "libc.so.6");
    if (header) {
        ResetSpecialCaseElf(
            header, symbols, ARRAY_SIZE(symbols), resolved,
            &resolved_count);
        freeElfFromFile(&header);
    }
    if (resolved_count != ARRAY_SIZE(symbols)) {
        header = tryLoadElfFromFileForContext(context, "libdl.so.2");
        if (header) {
            ResetSpecialCaseElf(
                header, symbols, ARRAY_SIZE(symbols), resolved,
                &resolved_count);
            freeElfFromFile(&header);
        }
    }
    *entries = (kzt_guest_dl_entries_t) {
        .dlopen = (uintptr_t)resolved[0],
        .dlmopen = (uintptr_t)resolved[1],
        .dlsym = (uintptr_t)resolved[2],
        .dlclose = (uintptr_t)resolved[3],
        .dladdr = (uintptr_t)resolved[4],
        .dladdr1 = (uintptr_t)resolved[5],
        .dlinfo = (uintptr_t)resolved[6],
        .dlvsym = (uintptr_t)resolved[7],
        .dlerror = (uintptr_t)resolved[8],
    };
    scope->runtime_entries[KZT_GUEST_RUNTIME_FREE] =
        (uintptr_t)resolved[9];
    scope->runtime_entries[KZT_GUEST_RUNTIME_REALLOC] =
        (uintptr_t)resolved[10];
    scope->runtime_entries[KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE] =
        (uintptr_t)resolved[11];
    return resolved_count == ARRAY_SIZE(symbols) ? 0 : -1;
}

static int kzt_guest_dl_prepare_entries(
    const kzt_guest_dl_entries_t *entries, void *opaque)
{
    kzt_guest_dl_init_scope_t *scope = opaque;

    (void)entries;
    return kzt_guest_runtime_entry_state_publish(
        &scope->context->dlprivate->guest_dl_entries,
        scope->runtime_entries);
}

const kzt_guest_dl_entries_t *kzt_guest_dl_init_entries(
    box64context_t *context, kzt_guest_dl_entries_t *fallback)
{
    kzt_guest_dl_init_scope_t scope = { .context = context };

    if (!context || !context->dlprivate || !fallback) {
        return NULL;
    }
    return kzt_guest_dl_api_ensure_entries_prepared(
        context->dlprivate, kzt_guest_dl_resolve_entries,
        kzt_guest_dl_prepare_entries, &scope, fallback, NULL);
}
