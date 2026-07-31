#include "qemu/osdep.h"

#include "kzt_guest_dl_init.h"

#include "elfloader.h"
#include "kzt_guest_dl_api.h"
#include "pathcoll.h"

extern const char *interp_prefix;
elfheader_t *tryLoadElfFromFile(const char *name);
void freeElfFromFile(elfheader_t **header);
void kzt_wine_init_x86(box64context_t *context, uintptr_t guest_dlsym);

static int kzt_guest_dl_resolve_entries(
    kzt_guest_dl_entries_t *entries, void *opaque)
{
    static const char *symbols[] = {
        "dlopen", "dlmopen", "dlsym", "dlclose", "dladdr", "dladdr1",
        "dlinfo", "dlvsym", "dlerror",
    };
    box64context_t *context = opaque;
    elfheader_t *header;
    void *resolved[9] = { 0 };
    int resolved_count = 0;

#ifdef CONFIG_LOONGARCH_NEW_WORLD
    char path[PATH_MAX] = { 0 };

    snprintf(path, sizeof(path), "%s%s", interp_prefix,
             "/usr/lib/glibc-hwcaps/x86-64-v2/");
    if (!FindInCollection(path, &context->box64_ld_lib)) {
        PrependList(&context->box64_ld_lib, path, 1);
    }
#else
    (void)context;
#endif
    header = tryLoadElfFromFile("libc.so.6");
    if (header) {
        ResetSpecialCaseElf(
            header, symbols, ARRAY_SIZE(symbols), resolved,
            &resolved_count);
        freeElfFromFile(&header);
    }
    if (resolved_count != ARRAY_SIZE(symbols)) {
        header = tryLoadElfFromFile("libdl.so.2");
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
    return resolved_count == ARRAY_SIZE(symbols) ? 0 : -1;
}

static void kzt_guest_dl_prepare_entries(
    const kzt_guest_dl_entries_t *entries, void *opaque)
{
    kzt_wine_init_x86(opaque, entries->dlsym);
}

const kzt_guest_dl_entries_t *kzt_guest_dl_init_entries(
    box64context_t *context, kzt_guest_dl_entries_t *fallback)
{
    if (!context || !context->dlprivate || !fallback) {
        return NULL;
    }
    return kzt_guest_dl_api_ensure_entries_prepared(
        context->dlprivate, kzt_guest_dl_resolve_entries,
        kzt_guest_dl_prepare_entries, context, fallback, NULL);
}
