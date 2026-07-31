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
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>

#include <wrappedlibs.h>
#include "bridge.h"
#include "bridge_private.h"
#include "khash.h"
#include "qemu/atomic.h"
#include "debug.h"
#include "box64context.h"
#include "elfloader.h"

KHASH_MAP_INIT_INT64(bridgemap, uintptr_t)

//onebridge is 32 bytes
#define NBRICK  4096/sizeof(onebridge_t)
typedef struct brick_s brick_t;
typedef struct brick_s {
    onebridge_t *b;
    int         sz;
    brick_t     *next;
} brick_t;

typedef struct bridge_s {
    pthread_mutex_t   lock;
    brick_t         *head;
    brick_t         *last;      // to speed up
    kh_bridgemap_t  *bridgemap;
    struct bridge_s *fork_next;
} bridge_t;

static pthread_mutex_t bridge_fork_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t alternate_writer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t bridge_atfork_once = PTHREAD_ONCE_INIT;
static bridge_t *fork_bridges;
enum bridge_fork_protection_state {
    BRIDGE_FORK_PROTECTION_UNKNOWN = 0,
    BRIDGE_FORK_PROTECTION_AVAILABLE,
    BRIDGE_FORK_PROTECTION_UNAVAILABLE,
};
static int bridge_fork_protection_state;

static int alternate_add_if_absent(void *addr, void *alt);

static void bridge_fork_unlock(void)
{
    bridge_t *bridge;

    for (bridge = fork_bridges; bridge; bridge = bridge->fork_next) {
        pthread_mutex_unlock(&bridge->lock);
    }
    pthread_mutex_unlock(&alternate_writer_lock);
    pthread_mutex_unlock(&bridge_fork_lock);
}

static void bridge_fork_prepare(void)
{
    bridge_t *bridge;

    pthread_mutex_lock(&bridge_fork_lock);
    pthread_mutex_lock(&alternate_writer_lock);
    for (bridge = fork_bridges; bridge; bridge = bridge->fork_next) {
        pthread_mutex_lock(&bridge->lock);
    }
}

static void bridge_fork_parent(void)
{
    bridge_fork_unlock();
}

static void bridge_fork_child(void)
{
    bridge_fork_unlock();
}

static int bridge_call_atfork(void (*prepare)(void), void (*parent)(void),
                              void (*child)(void))
{
#ifdef BRIDGE_TEST_ATFORK_FAIL
    (void)prepare;
    (void)parent;
    (void)child;
    return ENOMEM;
#else
    return pthread_atfork(prepare, parent, child);
#endif
}

static void bridge_register_atfork(void)
{
    int status = bridge_call_atfork(bridge_fork_prepare,
                                    bridge_fork_parent,
                                    bridge_fork_child);

    qatomic_store_release(
        &bridge_fork_protection_state,
        status == 0 ? BRIDGE_FORK_PROTECTION_AVAILABLE :
                      BRIDGE_FORK_PROTECTION_UNAVAILABLE);
    if (status != 0) {
        printf_kzt_registry_diagnostics(
            "kzt_bridge_fallback schema=1 "
            "reason=atfork_registration_failed status=%d error=%s\n",
            status, strerror(status));
    }
}

int BridgeForkProtectionAvailable(void)
{
    int state = qatomic_load_acquire(&bridge_fork_protection_state);
    int status;

    if (state == BRIDGE_FORK_PROTECTION_AVAILABLE) {
        return 1;
    }
    if (state == BRIDGE_FORK_PROTECTION_UNAVAILABLE) {
        return 0;
    }

    status = pthread_once(&bridge_atfork_once, bridge_register_atfork);
    if (status != 0) {
        if (qatomic_cmpxchg(
                &bridge_fork_protection_state,
                BRIDGE_FORK_PROTECTION_UNKNOWN,
                BRIDGE_FORK_PROTECTION_UNAVAILABLE) ==
            BRIDGE_FORK_PROTECTION_UNKNOWN) {
            printf_kzt_registry_diagnostics(
                "kzt_bridge_fallback schema=1 "
                "reason=atfork_once_failed status=%d error=%s\n",
                status, strerror(status));
        }
        return 0;
    }

    state = qatomic_load_acquire(&bridge_fork_protection_state);
    if (state == BRIDGE_FORK_PROTECTION_UNKNOWN) {
        if (qatomic_cmpxchg(
                &bridge_fork_protection_state,
                BRIDGE_FORK_PROTECTION_UNKNOWN,
                BRIDGE_FORK_PROTECTION_UNAVAILABLE) ==
            BRIDGE_FORK_PROTECTION_UNKNOWN) {
            printf_kzt_registry_diagnostics(
                "kzt_bridge_fallback schema=1 "
                "reason=atfork_state_unpublished\n");
        }
        return 0;
    }
    return state == BRIDGE_FORK_PROTECTION_AVAILABLE;
}

#ifdef BRIDGE_TEST
static bridge_test_hook_fn test_after_check_hook;
static void *test_after_check_hook_opaque;
static bridge_test_hook_fn test_before_free_hook;
static void *test_before_free_hook_opaque;

void bridge_test_set_after_check_hook(bridge_test_hook_fn hook, void *opaque)
{
    test_after_check_hook = hook;
    test_after_check_hook_opaque = opaque;
}

void bridge_test_set_before_free_hook(bridge_test_hook_fn hook, void *opaque)
{
    test_before_free_hook = hook;
    test_before_free_hook_opaque = opaque;
}

int bridge_test_lock_is_held(bridge_t *bridge)
{
    int status = pthread_mutex_trylock(&bridge->lock);

    if (status == 0) {
        pthread_mutex_unlock(&bridge->lock);
        return 0;
    }
    return status == EBUSY;
}
#endif

//from wrapped/wrappedlibc.c
//void* my_mmap(x64emu_t* emu, void* addr, unsigned long length, int prot, int flags, int fd, int64_t offset);
//int my_munmap(x64emu_t* emu, void* addr, unsigned long length);

brick_t* NewBrick(void)
{
    brick_t* ret = (brick_t*)box_calloc(1, sizeof(brick_t));
    // ptr needed to be fixed
    void* ptr = mmap64(NULL, NBRICK * sizeof(onebridge_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x40 | MAP_ANONYMOUS, -1, 0); // 0x40 is MAP_32BIT
    if(ptr == MAP_FAILED) {
        printf("Warning, cannot allocate 0x%lx aligned bytes for bridge, will probably crash later\n", NBRICK*sizeof(onebridge_t));
    }
    ret->b = ptr;
    return ret;
}

bridge_t *NewBridge(void)
{
    bridge_t *b;

    (void)BridgeForkProtectionAvailable();
    b = (bridge_t*)box_calloc(1, sizeof(bridge_t));
    if (!b || pthread_mutex_init(&b->lock, NULL) != 0) {
        box_free(b);
        return NULL;
    }
    b->head = NewBrick();
    b->last = b->head;
    b->bridgemap = kh_init(bridgemap);
    pthread_mutex_lock(&bridge_fork_lock);
    b->fork_next = fork_bridges;
    fork_bridges = b;
    pthread_mutex_unlock(&bridge_fork_lock);

    return b;
}
void FreeBridge(bridge_t** bridge)
{
    bridge_t *current;
    bridge_t **entry;

    if(!bridge || !*bridge)
        return;
    current = *bridge;
    pthread_mutex_lock(&bridge_fork_lock);
    pthread_mutex_lock(&current->lock);
#ifdef BRIDGE_TEST
    if (test_before_free_hook) {
        test_before_free_hook(test_before_free_hook_opaque);
    }
#endif
    for (entry = &fork_bridges; *entry; entry = &(*entry)->fork_next) {
        if (*entry == current) {
            *entry = current->fork_next;
            break;
        }
    }
    brick_t *b = current->head;
    while(b) {
        brick_t *n = b->next;
        munmap(b->b, NBRICK*sizeof(onebridge_t));
        box_free(b);
        b = n;
    }
    kh_destroy(bridgemap, current->bridgemap);
    *bridge = NULL;
    pthread_mutex_unlock(&current->lock);
    pthread_mutex_destroy(&current->lock);
    box_free(current);
    pthread_mutex_unlock(&bridge_fork_lock);
}

static uintptr_t bridge_add_locked(bridge_t* bridge, wrapper_t w, void* fnc,
                                   int N, const char* name)
{
    brick_t *b = NULL;
    int sz = -1;
    b = bridge->last;
    if(b->sz == NBRICK) {
        b->next = NewBrick();
        b = b->next;
        bridge->last = b;
    }
    sz = b->sz;
    b->sz++;
    b->b[sz].CC = 0xCC;
    b->b[sz].S = 'S'; b->b[sz].C='C';
    b->b[sz].w = w;
    b->b[sz].f = (uintptr_t)fnc;
    b->b[sz].C3 = N?0xC2:0xC3;
    b->b[sz].N = N;
    // add bridge to map, for fast recovery
    int ret;
    khint_t k = kh_put(bridgemap, bridge->bridgemap, (uintptr_t)fnc, &ret);
    kh_value(bridge->bridgemap, k) = (uintptr_t)&b->b[sz].CC;

    return (uintptr_t)&b->b[sz].CC;
}

static uintptr_t bridge_check_locked(bridge_t* bridge, void* fnc)
{
    // check if function alread have a bridge (the function wrapper will not be tested)
    khint_t k = kh_get(bridgemap, bridge->bridgemap, (uintptr_t)fnc);
    if(k==kh_end(bridge->bridgemap))
        return 0;
    return kh_value(bridge->bridgemap, k);
}

uintptr_t AddBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N, const char* name)
{
    uintptr_t ret;

    if (!bridge) {
        return 0;
    }
    pthread_mutex_lock(&bridge->lock);
    ret = bridge_add_locked(bridge, w, fnc, N, name);
    pthread_mutex_unlock(&bridge->lock);
    return ret;
}

uintptr_t CheckBridged(bridge_t* bridge, void* fnc)
{
    uintptr_t ret;

    if (!bridge) {
        return 0;
    }
    pthread_mutex_lock(&bridge->lock);
    ret = bridge_check_locked(bridge, fnc);
    pthread_mutex_unlock(&bridge->lock);
    return ret;
}

uintptr_t AddCheckBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N, const char* name)
{
    uintptr_t ret;

    if(!fnc && w)
        return 0;
    if (!bridge) {
        return 0;
    }
    pthread_mutex_lock(&bridge->lock);
    ret = bridge_check_locked(bridge, fnc);
#ifdef BRIDGE_TEST
    if (test_after_check_hook) {
        test_after_check_hook(test_after_check_hook_opaque);
    }
#endif
    if(!ret)
        ret = bridge_add_locked(bridge, w, fnc, N, name);
    pthread_mutex_unlock(&bridge->lock);
    return ret;
}

uintptr_t AddAutomaticBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N)
{
    uintptr_t ret;

    if(!fnc)
        return 0;
    if (!bridge) {
        return 0;
    }
    pthread_mutex_lock(&bridge->lock);
    ret = bridge_check_locked(bridge, fnc);
#ifdef BRIDGE_TEST
    if (test_after_check_hook) {
        test_after_check_hook(test_after_check_hook_opaque);
    }
#endif
    if(!ret)
        ret = bridge_add_locked(bridge, w, fnc, N, NULL);
    pthread_mutex_unlock(&bridge->lock);
    if(alternate_add_if_absent(fnc, (void*)ret)) {
        printf_log(LOG_DEBUG, "Adding AutomaticBridge for %p to %p\n", fnc, (void*)ret);
    }
    return ret;
}

void* GetNativeFnc(uintptr_t fnc)
{
    if(!fnc) return NULL;
    // check if function exist in some loaded lib
    if(!FindElfAddress(my_context, fnc)) {
        Dl_info info;
        if(dladdr((void*)fnc, &info))
            return (void*)fnc;
    }
    // check if it's an indirect jump
    #define PK(a)       *(uint8_t*)(fnc+a)
    #define PK32(a)     *(uint32_t*)(fnc+a)
    if(PK(0)==0xff && PK(1)==0x25) {    // "absolute" jump, maybe the GOT (it's a RIP+relative in fact)
        uintptr_t a1 = fnc+6+(PK32(2)); // need to add a check to see if the address is from the GOT !
        a1 = *(uintptr_t*)a1;
        if(a1 && a1>0x10000) {
            a1 = (uintptr_t)GetNativeFnc(a1);
            if(a1)
                return (void*)a1;
        }
    }
    #undef PK
    #undef PK32
    // check if bridge exist
    onebridge_t *b = (onebridge_t*)fnc;
    if(b->CC != 0xCC || b->S!='S' || b->C!='C' || (b->C3!=0xC3 && b->C3!=0xC2))
        return NULL;    // not a bridge?!
    return (void*)b->f;
}

void* GetNativeFncOrFnc(uintptr_t fnc)
{
    onebridge_t *b = (onebridge_t*)fnc;
    if(b->CC != 0xCC || b->S!='S' || b->C!='C' || (b->C3!=0xC3 && b->C3!=0xC2))
        return (void*)fnc;    // not a bridge?!
    return (void*)b->f;
}


// Alternate address handling. Buckets are fixed; entries grow through
// immutable collision chains and are only inserted.
#define ALTERNATE_BUCKET_COUNT 4096

typedef struct alternate_entry_s {
    uintptr_t native_addr;
    uintptr_t alternate_addr;
    struct alternate_entry_s *next;
} alternate_entry_t;

static alternate_entry_t *alternate_buckets[ALTERNATE_BUCKET_COUNT];
static int alternate_nonempty;

static unsigned int alternate_bucket_index(uintptr_t address)
{
    uint64_t key = address >> 4;

    return (unsigned int)((key * UINT64_C(0x9e3779b97f4a7c15)) >>
                          (64 - 12));
}

static int alternate_add_if_absent(void *addr, void *alt)
{
    alternate_entry_t *entry;
    alternate_entry_t *head;
    unsigned int bucket;

    entry = box_calloc(1, sizeof(*entry));
    if (!entry) {
        return 0;
    }
    entry->native_addr = (uintptr_t)addr;
    entry->alternate_addr = (uintptr_t)alt;
    bucket = alternate_bucket_index(entry->native_addr);
    pthread_mutex_lock(&alternate_writer_lock);
    head = qatomic_read(&alternate_buckets[bucket]);
    for (; head; head = head->next) {
        if (head->native_addr == entry->native_addr) {
            pthread_mutex_unlock(&alternate_writer_lock);
            box_free(entry);
            return 0;
        }
    }
    entry->next = qatomic_read(&alternate_buckets[bucket]);
    qatomic_store_release(&alternate_buckets[bucket], entry);
    /* Bucket release publication linearizes normal inserts. The first entry
     * becomes visible to empty-table readers at nonempty publication below. */
    qatomic_store_release(&alternate_nonempty, 1);
    pthread_mutex_unlock(&alternate_writer_lock);
    return 1;
}

int hasAlternate(void* addr) {
    alternate_entry_t *entry;

    if (!qatomic_load_acquire(&alternate_nonempty)) {
        return 0;
    }
    entry = qatomic_load_acquire(
        &alternate_buckets[alternate_bucket_index((uintptr_t)addr)]);
    for (; entry; entry = entry->next) {
        if (entry->native_addr == (uintptr_t)addr) {
            return 1;
        }
    }
    return 0;
}

void* getAlternate(void* addr) {
    alternate_entry_t *entry;

    if (!qatomic_load_acquire(&alternate_nonempty)) {
        return addr;
    }
    entry = qatomic_load_acquire(
        &alternate_buckets[alternate_bucket_index((uintptr_t)addr)]);
    for (; entry; entry = entry->next) {
        if (entry->native_addr == (uintptr_t)addr) {
            return (void *)entry->alternate_addr;
        }
    }
    return addr;
}

void addAlternate(void* addr, void* alt) {
    (void)alternate_add_if_absent(addr, alt);
}

void cleanAlternate(void) {
    /* This is only valid at process teardown or in tests after all alternate
     * readers and writers have stopped. */
    pthread_mutex_lock(&alternate_writer_lock);
    qatomic_store_release(&alternate_nonempty, 0);
    for (unsigned int i = 0; i < ALTERNATE_BUCKET_COUNT; ++i) {
        alternate_entry_t *entry = qatomic_read(&alternate_buckets[i]);

        qatomic_store_release(&alternate_buckets[i], NULL);
        while (entry) {
            alternate_entry_t *next = entry->next;

            box_free(entry);
            entry = next;
        }
    }
    pthread_mutex_unlock(&alternate_writer_lock);
}

void init_bridge_helper(void)
{
}

void fini_bridge_helper(void)
{
    cleanAlternate();
}
