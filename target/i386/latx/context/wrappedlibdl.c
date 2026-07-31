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
#include <dlfcn.h>
#include "elf.h"
#include <link.h>

#include "wrappedlibs.h"

#include "debug.h"
#include "wrapper.h"
#include "bridge.h"
#include "library_private.h"
#include "library.h"
#include "librarian.h"
#include "box64context.h"
#include "elfloader.h"
#include "elfloader_private.h"
#include "callback.h"
#include "myalign.h"
#include "fileutils.h"
#include "kzt_guest_library_adapter.h"
#include "kzt_guest_dl_api.h"
#include "kzt_guest_dl_init.h"
#ifdef CONFIG_LATX_KZT
#include "kzt_guest_library_binding.h"
#endif
#include "kzt_loader_callback_scope.h"

#define FORWORDBACK 0

void* my_dlopen(void *filename, int flag) EXPORT;
void* my_dlmopen(void* mlid, void *filename, int flag) EXPORT;
char* my_dlerror(void) EXPORT;
void* my_dlsym(void *handle, void *symbol) EXPORT;
int my_dlclose(void *handle) EXPORT;
int my_dladdr(void *addr, void *info) EXPORT;
int my_dladdr1(void *addr, void *info, void** extra_info, int flags) EXPORT;
void* my_dlvsym(void *handle, void *symbol, const char *vername) EXPORT;
int my_dlinfo(void* handle, int request, void* info) EXPORT;

#define LIBNAME libdl
const char* libdlName = "libdl.so.2";

#if defined(CONFIG_LATX_KZT) && defined(TARGET_X86_64)
#define DLERROR_STATE(cpu, dl) ((void)(dl), &(cpu)->kzt_guest_dlerror_state)
#define DLERROR_FAST_RESULT() kzt_guest_dl_api_current_fast_result()
#else
#define DLERROR_STATE(cpu, dl) (&(dl)->legacy_error)
#define DLERROR_FAST_RESULT() \
    (my_context->dlprivate->legacy_error.dlerror_fast_result)
#endif
#define CLEARERR guest_error_was_clean = kzt_guest_dl_api_begin_call(error_state);
//#define R_RSP cpu->regs[R_ESP]
static void Push64(CPUX86State *cpu, uint64_t v)
{
    cpu->regs[R_ESP] -= 8;
    *((uint64_t*)cpu->regs[R_ESP]) = v;
}

void* my_dlopen(void *filename, int flag){
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    uint64_t result;
    int guest_error_was_clean;

    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlopen) {
        return NULL;
    }
    printf_dlsym(LOG_DEBUG, "Call to dlopen(\"%s\"/%p, %X)\n",
                 filename ? (char *)filename : "<null>", filename, flag);
    result = kzt_guest_dl_api_dlopen(
        my_context, &cpu->kzt_guest_library_loader_scope,
        entries, error_state, filename, flag);
    if (result) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return (void *)(uintptr_t)result;
}

void* my_dlmopen(void* lmid, void *filename, int flag)
{
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    uint64_t result;
    int guest_error_was_clean;

    if (!lmid) {
        return my_dlopen(filename, flag);
    }
    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlmopen) {
        return NULL;
    }
    result = kzt_guest_dl_api_dlmopen(
        my_context, entries, lmid, filename, flag);
    if (result) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return (void *)(uintptr_t)result;
}

void* my_dlsym(void *handle, void *symbol)
{
    dlprivate_t *dl = my_context->dlprivate;
    kzt_guest_dl_symbol_result_t result;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int guest_error_was_clean;

    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlsym) {
        return NULL;
    }
    printf_dlsym(LOG_DEBUG, "Call to dlsym(%p, \"%s\")\n",
                 handle, symbol ? (char *)symbol : "<null>");
    result = kzt_guest_dl_api_dlsym(
        my_context, entries, handle, symbol);
    if (result.forward_to_guest_caller) {
        Push64(cpu, entries->dlsym);
        return NULL;
    }
    if (result.value) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return (void *)result.value;
}

int my_dlclose(void *handle)
{
    printf_dlsym(LOG_DEBUG, "Call to dlclose(%p)\n", handle);
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int result;
    int guest_error_was_clean;
    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlclose) {
        return -1;
    }
    result = kzt_guest_dl_api_dlclose(
        my_context, &cpu->kzt_guest_library_loader_scope, entries, handle);
    if (result == 0) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return result;
}

static uintptr_t kzt_guest_dlerror_entry_slow(
    box64context_t *context) __attribute__((noinline));

static uintptr_t kzt_guest_dlerror_entry_slow(box64context_t *context)
{
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries =
        kzt_guest_dl_entries_for_call(context, &fallback);

    return entries ? entries->dlerror : 0;
}

static char *kzt_guest_dlerror_slow_path(
    box64context_t *context, CPUX86State *cpu,
    kzt_guest_dlerror_state_t *error_state,
    uintptr_t guest_dlerror) __attribute__((noinline, cold));

static char *kzt_guest_dlerror_slow_path(
    box64context_t *context, CPUX86State *cpu,
    kzt_guest_dlerror_state_t *error_state, uintptr_t guest_dlerror)
{
    kzt_guest_dlerror_result_t result;

    if (kzt_guest_dl_api_dlerror_needs_slow_path(error_state)) {
        result = kzt_guest_dl_api_dlerror(error_state, guest_dlerror);
        if (!result.forward_to_guest_caller) {
            return result.value;
        }
    }
    if (!guest_dlerror) {
        guest_dlerror = kzt_guest_dl_api_load_dlerror_hint(
            context->dlprivate);
        if (!guest_dlerror) {
            guest_dlerror = kzt_guest_dlerror_entry_slow(context);
        }
        if (!guest_dlerror) {
            return NULL;
        }
        error_state->guest_dlerror_entry = guest_dlerror;
    }
    Push64(cpu, guest_dlerror);
    return NULL;
}

char* my_dlerror(void)
{
#if defined(__loongarch__)
    register char *fast_result __asm__("r4") =
#else
    char *fast_result =
#endif
        (char *)DLERROR_FAST_RESULT();

    /* Keep the clean sentinel in the return register across the cold test. */
    __asm__ volatile("" : "+r"(fast_result));
    if (fast_result) {
        dlprivate_t *dl = my_context->dlprivate;
        __MY_CPU;
        kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
        uintptr_t guest_dlerror = error_state->guest_dlerror_entry;

        return kzt_guest_dlerror_slow_path(
            my_context, cpu, error_state, guest_dlerror);
    }
    return fast_result;
}

int my_dladdr1(void *addr, void *i, void** extra_info, int flags)
{
    //int dladdr(void *addr, Dl_info *info);
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int guest_error_was_clean;
    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    Dl_info *info = (Dl_info*)i;
    printf_dlsym(LOG_DEBUG, "Warning: partially unimplement call to dladdr/dladdr1(%p, %p, %p, %d)\n", addr, info, extra_info, flags);
    uint64_t ret = 0;
    if (entries && extra_info == NULL && flags == 0 && entries->dladdr) {
        ret = RunFunctionWithState(entries->dladdr, 2, cpu->regs[R_EDI], cpu->regs[R_ESI]);
    } else if (entries && entries->dladdr1) {
        ret = RunFunctionWithState(entries->dladdr1, 4, cpu->regs[R_EDI], cpu->regs[R_ESI], cpu->regs[R_EDX], cpu->regs[R_ECX]);
    }
    printf_dlsym(LOG_DEBUG, "     call to x86dladdr1 return saddr=%p, fname=\"%s\", sname=\"%s\" ret=%ld\n", info->dli_saddr, info->dli_sname?info->dli_sname:"", info->dli_fname?info->dli_fname:"", ret);
    if (ret == 1) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
        return ret;
    }
    //emu->quit = 1;
    library_t* lib = NULL;
    info->dli_saddr = NULL;
    info->dli_fname = NULL;
    info->dli_sname = FindSymbolName(my_context->maplib, addr, &info->dli_saddr, NULL, &info->dli_fname, &info->dli_fbase, &lib);
    printf_dlsym(LOG_DEBUG, "     dladdr return saddr=%p, fname=\"%s\", sname=\"%s\"\n", info->dli_saddr, info->dli_sname?info->dli_sname:"", info->dli_fname?info->dli_fname:"");
    if(flags==RTLD_DL_SYMENT) {
        printf_dlsym(LOG_INFO, "Warning, unimplement call to dladdr1 with RTLD_DL_SYMENT flags\n");
    } else if (flags==RTLD_DL_LINKMAP) {
        printf_dlsym(LOG_INFO, "Warning, partially unimplemented call to dladdr1 with RTLD_DL_LINKMAP flags\n");
        *(linkmap_t**)extra_info = getLinkMapLib(lib);
    }
    return (info->dli_sname)?1:0;   // success is non-null here...
}
int my_dladdr(void *addr, void *i)
{
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int guest_error_was_clean;
    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
#ifdef CONFIG_LATX_DEBUG
    Dl_info *info = (Dl_info*)i;
#endif
    printf_dlsym(LOG_DEBUG, "Warning: partially unimplement call to dladdr(%p, %p)\n", addr, info);
    uint64_t ret = entries && entries->dladdr
                       ? RunFunctionWithState(entries->dladdr, 2,
                                              cpu->regs[R_EDI],
                                              cpu->regs[R_ESI])
                       : 0;
    printf_dlsym(LOG_DEBUG, "     call to x86dladdr return saddr=%p, fname=\"%s\", sname=\"%s\" ret=%ld\n", info->dli_saddr, info->dli_sname?info->dli_sname:"", info->dli_fname?info->dli_fname:"", ret);
    if (ret == 1) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
        return ret;
    }
    return my_dladdr1(addr, i, NULL, 0);
}
void* my_dlvsym(void *handle, void *symbol, const char *vername)
{
    dlprivate_t *dl = my_context->dlprivate;
    kzt_guest_dl_symbol_result_t result;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int guest_error_was_clean;

    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlvsym) {
        return NULL;
    }
    printf_dlsym(LOG_DEBUG, "Call to dlvsym(%p, \"%s\", %s)\n",
                 handle, symbol ? (char *)symbol : "<null>",
                 vername ? vername : "(nil)");
    result = kzt_guest_dl_api_dlvsym(
        my_context, entries, handle, symbol, vername);
    if (result.forward_to_guest_caller) {
        Push64(cpu, entries->dlvsym);
        return NULL;
    }
    if (result.value) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return (void *)result.value;
}

int my_dlinfo(void* handle, int request, void* info)
{
    printf_dlsym(LOG_DEBUG, "Call to dlinfo(%p, %d, %p)\n", handle, request, info);
    dlprivate_t *dl = my_context->dlprivate;
    __MY_CPU;
    kzt_guest_dlerror_state_t *error_state = DLERROR_STATE(cpu, dl);
    kzt_guest_dl_entries_t fallback;
    const kzt_guest_dl_entries_t *entries;
    int result;
    int guest_error_was_clean;

    CLEARERR
    entries = kzt_guest_dl_entries_for_call(my_context, &fallback);
    if (!entries || !entries->dlinfo) {
        return -1;
    }
    result = kzt_guest_dl_api_dlinfo(entries, handle, request, info);
    if (result == 0) {
        kzt_guest_dl_api_finish_success(error_state, guest_error_was_clean);
    }
    return result;
}

#include "wrappedlib_init.h"
