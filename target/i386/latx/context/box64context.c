/*
 * This file is derived from Box64.
 *
 * SPDX-FileCopyrightText: 2020 ptitSeb
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <time.h>

#include "box64context.h"
#include "debug.h"
#include "elfloader.h"
#include "bridge.h"
#include "librarian.h"
#include "library.h"
#include "wrapper.h"
#include "kzt_guest_dl_api.h"
#ifdef CONFIG_LATX_KZT
#include "kzt_guest_registry.h"
#include "kzt_guest_registry_context.h"
#include "kzt_guest_library_binding.h"
#include "kzt_lazy_prebind_scope.h"
#endif
#include <pthread.h>

static void kzt_xcb_shadow_destroy(void *guest, void *opaque)
{
    (void)opaque;
    free(guest);
}

#ifdef CONFIG_LATX_KZT
static uint64_t kzt_context_init_timing_now(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000000000ULL +
           (uint64_t)value.tv_nsec;
}

static uint64_t kzt_context_init_timing_delta(uint64_t start, uint64_t end)
{
    return start && end >= start ? end - start : 0;
}
#endif

dlprivate_t *NewDLPrivate(void)
{
    dlprivate_t *dl = box_calloc(1, sizeof(*dl));

    if (dl) {
        dl->legacy_error.dlerror_slow_required = 1;
    }
    if (dl && kzt_guest_dl_api_entry_state_init(dl) != 0) {
        box_free(dl);
        return NULL;
    }
    return dl;
}

void FreeDLPrivate(dlprivate_t **dl)
{
    if (!dl || !*dl) {
        return;
    }
    kzt_guest_dl_api_entry_state_destroy(*dl);
    kzt_guest_dl_api_free_errors(&(*dl)->legacy_error);
    box_free(*dl);
    *dl = NULL;
}

box64context_t *NewBox64Context(int argc)
{
#ifdef CONFIG_LATX_KZT
    kzt_patch_spike_config_t patch_spike_config;
    uint64_t timing_start = 0;
    uint64_t timing_base = 0;
    uint64_t timing_access = 0;
    uint64_t timing_guard = 0;
    int timing_enabled = kzt_registry_diagnostics_enabled();

    if (timing_enabled) {
        timing_start = kzt_context_init_timing_now();
    }
#endif
    // init and put default values
    box64context_t *context = (box64context_t*)box_calloc(1, sizeof(box64context_t));

    context->deferedInit = 1;
    context->sel_serial = 1;

    context->maplib = NewLibrarian(context, 1);
    context->local_maplib = NewLibrarian(context, 1);
    context->versym = NewDictionnary();
    context->system = NewBridge();
    context->dlprivate = NewDLPrivate();
    context->box64lib = dlopen(NULL, RTLD_NOW|RTLD_GLOBAL);
    context->kzt_xcb_connection_map =
        kzt_xcb_connection_map_init(kzt_xcb_shadow_destroy, NULL);
    context->argc = argc;
    context->argv = (char**)box_calloc(context->argc+1, sizeof(char*));
    pthread_mutex_init(&context->mutex_lock, NULL);
#ifdef CONFIG_LATX_KZT
    if (timing_enabled) {
        timing_base = kzt_context_init_timing_now();
    }
    /* Optional acceleration metadata is created on first KZT use so a
     * context that never observes a guest link-map keeps the old footprint. */
    (void)kzt_guest_library_access_init(&context->kzt_guest_library_access);
    kzt_loader_event_hook_context_init(&context->kzt_loader_event_hook);
    context->kzt_lazy_prebind_scope = kzt_lazy_prebind_scope_init();
    if (timing_enabled) {
        timing_access = kzt_context_init_timing_now();
    }
    kzt_patch_spike_config_from_options(&patch_spike_config);
    kzt_patch_spike_guard_init(&context->kzt_patch_spike_guard,
                               &patch_spike_config);
    if (timing_enabled) {
        timing_guard = kzt_context_init_timing_now();
        fprintf(
            stderr,
            "kzt_context_init_timing schema=1 base_ns=%" PRIu64 " "
            "library_access_ns=%" PRIu64 " patch_guard_ns=%" PRIu64 " "
            "total_ns=%" PRIu64 "\n",
            kzt_context_init_timing_delta(timing_start, timing_base),
            kzt_context_init_timing_delta(timing_base, timing_access),
            kzt_context_init_timing_delta(timing_access, timing_guard),
            kzt_context_init_timing_delta(timing_start, timing_guard));
    }
#endif

    return context;
}

#ifdef CONFIG_LATX_KZT
kzt_guest_registry_t *KztGuestRegistryForContext(box64context_t *context)
{
    if (!context) {
        return NULL;
    }
    return kzt_guest_registry_context_get(
        &context->kzt_guest_registry_context, &context->mutex_lock);
}

kzt_guest_library_bindings_t *KztGuestLibraryBindingsForContext(box64context_t *context)
{
    return context ? context->kzt_guest_library_access.bindings : NULL;
}

int KztGuestLibraryLookupForContext(
    box64context_t *context,
    const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    return context
               ? kzt_guest_library_access_lookup(
                     &context->kzt_guest_library_access, key, handle)
               : -1;
}

kzt_lazy_prebind_scope_t *KztLazyPrebindScopeForContext(
    box64context_t *context)
{
    return context ? context->kzt_lazy_prebind_scope : NULL;
}
#endif

kzt_patch_spike_guard_t *KztPatchSpikeGuardForContext(box64context_t *context)
{
#ifdef CONFIG_LATX_KZT
    return context ? &context->kzt_patch_spike_guard : NULL;
#else
    (void)context;
    return NULL;
#endif
}

EXPORTDYN
void FreeBox64Context(box64context_t** context)
{
    if(!context)
        return;
    
    if(--(*context)->forked >= 0)
        return;

    box64context_t* ctx = *context;   // local copy to do the cleanning

    kzt_guest_dl_api_entry_state_begin_teardown(ctx->dlprivate);
    free(ctx->kzt_loader_bridge_info);
    ctx->kzt_loader_bridge_info = NULL;

#ifdef CONFIG_LATX_KZT
    /* FreeBox64Context is entered only after guest execution and loader
     * callbacks have stopped. Close the context-owned lookup gate first and
     * drain acquired handles, while keeping registry/binding storage alive
     * for the librarian destruction pass below. */
    kzt_guest_library_access_begin_teardown(
        &ctx->kzt_guest_library_access);
#endif

    kzt_xcb_connection_map_destroy(&ctx->kzt_xcb_connection_map);
    if(ctx->local_maplib)
        FreeLibrarian(&ctx->local_maplib);
    if(ctx->maplib)
        FreeLibrarian(&ctx->maplib);
#ifdef CONFIG_LATX_KZT
    kzt_loader_event_hook_context_destroy(&ctx->kzt_loader_event_hook);
    kzt_guest_library_access_destroy(&ctx->kzt_guest_library_access);
    kzt_lazy_prebind_scope_destroy(&ctx->kzt_lazy_prebind_scope);
    kzt_guest_registry_context_destroy(&ctx->kzt_guest_registry_context,
                                       &ctx->mutex_lock);
#endif
    FreeDictionnary(&ctx->versym);

    for(int i=0; i<ctx->elfsize; ++i) {
        FreeElfHeader(&ctx->elfs[i]);
    }
    box_free(ctx->elfs);

    FreeCollection(&ctx->box64_path);
    FreeCollection(&ctx->box64_ld_lib);
    FreeCollection(&ctx->box64_emulated_libs);

    if(ctx->deferedInitList)
        box_free(ctx->deferedInitList);

    /*box_free(ctx->argv);*/
    
    /*for (int i=0; i<ctx->envc; ++i)
        box_free(ctx->envv[i]);
    box_free(ctx->envv);*/

    if(ctx->atfork_sz) {
        box_free(ctx->atforks);
        ctx->atforks = NULL;
        ctx->atfork_sz = ctx->atfork_cap = 0;
    }

    for(int i=0; i<MAX_SIGNAL; ++i)
        if(ctx->signals[i]!=0 && ctx->signals[i]!=1) {
            signal(i, SIG_DFL);
        }

    *context = NULL;                // bye bye my_context

    box_free(ctx->fullpath);
    box_free(ctx->box64path);

    FreeBridge(&ctx->system);
    if(ctx->stack_clone)
        box_free(ctx->stack_clone);

    free_neededlib(&ctx->neededlibs);

    FreeDLPrivate(&ctx->dlprivate);

    box_free(ctx);
}
#if defined(CONFIG_LATX_KZT) && defined(CONFIG_LATX_DEBUG)
int AddKztDebugInfo(box64context_t* ctx, struct latx_kzt_debug* debuginfo)
{
    int idx = ctx->latx_kzt_debugsize;
    if(idx==ctx->latx_kzt_debugcap) {
        // resize...
        ctx->latx_kzt_debugcap += 16;
        ctx->latx_kzt_debugs = (struct latx_kzt_debug**)box_realloc(ctx->latx_kzt_debugs, sizeof(struct latx_kzt_debug *) * ctx->latx_kzt_debugcap);
    }
    ctx->latx_kzt_debugs[idx] = debuginfo;
    ctx->latx_kzt_debugsize++;
    printf_log(LOG_NONE, "Adding \"%p\" as #%d in latx_kzt_debug collection\n", ctx->latx_kzt_debugs[idx], idx);
    return idx;
}
#endif

int AddElfHeader(box64context_t* ctx, elfheader_t* head) {
    int idx = ctx->elfsize;
    if(idx==ctx->elfcap) {
        // resize...
        ctx->elfcap += 16;
        ctx->elfs = (elfheader_t**)box_realloc(ctx->elfs, sizeof(elfheader_t*) * ctx->elfcap);
    }
    ctx->elfs[idx] = head;
    ctx->elfsize++;
    printf_log(LOG_INFO, "Adding \"%s\" as #%d in elf collection\n", ElfName(head), idx);
    return idx;
}


void add_neededlib(needed_libs_t* needed, library_t* lib)
{
    if(!needed)
        return;
    for(int i=0; i<needed->size; ++i)
        if(needed->libs[i] == lib)
            return;
    if(needed->size == needed->cap) {
        needed->cap += 8;
        needed->libs = (library_t**)box_realloc(needed->libs, needed->cap*sizeof(library_t*));
    }
    needed->libs[needed->size++] = lib;
}

void free_neededlib(needed_libs_t* needed)
{
    if(!needed)
        return;
    needed->cap = 0;
    needed->size = 0;
    if(needed->libs)
        box_free(needed->libs);
    needed->libs = NULL;
}

void add_dependedlib(needed_libs_t* depended, library_t* lib)
{
    if(!depended)
        return;
    for(int i=0; i<depended->size; ++i)
        if(depended->libs[i] == lib)
            return;
    if(depended->size == depended->cap) {
        depended->cap += 8;
        depended->libs = (library_t**)box_realloc(depended->libs, depended->cap*sizeof(library_t*));
    }
    depended->libs[depended->size++] = lib;
}

void free_dependedlib(needed_libs_t* depended)
{
    if(!depended)
        return;
    depended->cap = 0;
    depended->size = 0;
    if(depended->libs)
        box_free(depended->libs);
    depended->libs = NULL;
}
