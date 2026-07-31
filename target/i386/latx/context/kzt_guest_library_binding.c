#include "kzt_guest_library_binding.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kzt_guest_registry.h"
#include "kzt_lifecycle_diagnostics.h"

#define KZT_GUEST_LIBRARY_SYMBOL_CACHE_SLOTS 16
#define KZT_GUEST_LIBRARY_SYMBOL_NAME_LIMIT 128

typedef struct kzt_guest_library_symbol_evidence {
    char symbol[KZT_GUEST_LIBRARY_SYMBOL_NAME_LIMIT];
    uintptr_t runtime_address;
    unsigned long age;
    unsigned long dynamic_revision;
    unsigned char symbol_type;
    int valid;
} kzt_guest_library_symbol_evidence_t;

typedef struct kzt_guest_library_binding_entry {
    kzt_guest_library_binding_key_t key;
    library_t *library;
    kzt_guest_library_object_type_t object_type;
    kzt_guest_library_binding_state_t state;
    unsigned int references;
    int retire_started;
    unsigned long symbol_cache_age;
    kzt_guest_library_symbol_evidence_t symbol_cache[
        KZT_GUEST_LIBRARY_SYMBOL_CACHE_SLOTS];
} kzt_guest_library_binding_entry_t;

typedef struct kzt_guest_library_lifecycle {
    library_t *library;
    kzt_guest_library_binding_state_t state;
    int destroy_started;
    uintptr_t fallback_closed_addr;
    unsigned long fallback_closed_epoch;
} kzt_guest_library_lifecycle_t;

typedef struct kzt_guest_library_callback_gate {
    struct kzt_guest_library_callback_gate *next;
    uintptr_t link_map_addr;
    library_t *closed_by;
    unsigned long state;
} kzt_guest_library_callback_gate_t;

#define KZT_CALLBACK_GATE_CLOSED \
    (1UL << (sizeof(unsigned long) * 8 - 1))
#define KZT_CALLBACK_GATE_READERS (KZT_CALLBACK_GATE_CLOSED - 1)

typedef struct kzt_guest_library_pending {
    uintptr_t link_map_addr;
    library_t *library;
    kzt_guest_library_object_type_t object_type;
    int active;
} kzt_guest_library_pending_t;

typedef struct kzt_guest_library_observed {
    kzt_guest_library_binding_key_t key;
    int claimed;
    library_t *retire_owner;
    int retire_started;
} kzt_guest_library_observed_t;

#define KZT_LOADER_ATTEMPT_SLOTS 16
#define KZT_LOADER_ATTEMPT_OBJECTS 16

typedef enum kzt_guest_library_loader_pair_state {
    KZT_LOADER_PAIR_EMPTY = 0,
    KZT_LOADER_PAIR_PREPARED,
    KZT_LOADER_PAIR_PUBLISHED,
} kzt_guest_library_loader_pair_state_t;

typedef struct kzt_guest_library_loader_object {
    uintptr_t link_map_addr;
    library_t *library;
    kzt_guest_library_object_type_t object_type;
    kzt_guest_library_loader_pair_state_t pair_state;
    kzt_guest_library_callback_gate_t *transition_gate;
    kzt_guest_library_lifecycle_t *transition_fallback;
    library_t *next_closed_by;
    int transition_pending;
    int reopen;
} kzt_guest_library_loader_object_t;

typedef struct kzt_guest_library_loader_attempt {
    unsigned long identity;
    unsigned long cookie;
    pthread_t owner;
    size_t object_count;
    int active;
    kzt_guest_library_loader_object_t objects[KZT_LOADER_ATTEMPT_OBJECTS];
} kzt_guest_library_loader_attempt_t;

typedef struct kzt_guest_library_loader_state {
    unsigned long epoch;
    kzt_guest_library_loader_attempt_t attempts[KZT_LOADER_ATTEMPT_SLOTS];
} kzt_guest_library_loader_state_t;

struct kzt_guest_library_bindings {
    pthread_mutex_t lock;
    pthread_cond_t idle;
    int shutting_down;
    kzt_guest_library_binding_entry_t *entries;
    size_t count;
    size_t capacity;
    kzt_guest_library_lifecycle_t *lifecycles;
    size_t lifecycle_count;
    size_t lifecycle_capacity;
    kzt_guest_library_pending_t *pending;
    size_t pending_count;
    size_t pending_capacity;
    kzt_guest_library_observed_t *observed;
    size_t observed_count;
    size_t observed_capacity;
    kzt_guest_library_callback_gate_t *callback_gates;
    unsigned int fallback_callback_readers;
    kzt_guest_library_loader_state_t *loader_state;
    unsigned long loader_quiescence_epoch;
    kzt_guest_library_loader_quiescence_lease_t *loader_quiescence_leases;
    kzt_guest_library_loader_quiescence_writer_t *loader_quiescence_writers;
    unsigned int loader_quiescence_readers;
    unsigned int loader_quiescence_waiters;
    struct {
        unsigned long registry_missing;
        unsigned long retire_unprovable;
    } diagnostics;
};

#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
static long fail_after = -1;
static kzt_guest_library_binding_test_retire_fn test_before_registry_retire;
static void *test_before_registry_retire_opaque;
static kzt_guest_library_binding_test_lifecycle_wait_fn
    test_before_lifecycle_wait;
static void *test_before_lifecycle_wait_opaque;

void kzt_guest_library_binding_test_set_alloc_failure_after(long allocations)
{
    fail_after = allocations;
}
void kzt_guest_library_binding_test_set_before_registry_retire(
    kzt_guest_library_binding_test_retire_fn hook, void *opaque)
{
    test_before_registry_retire = hook;
    test_before_registry_retire_opaque = opaque;
}
void kzt_guest_library_binding_test_set_before_lifecycle_wait(
    kzt_guest_library_binding_test_lifecycle_wait_fn hook, void *opaque)
{
    test_before_lifecycle_wait = hook;
    test_before_lifecycle_wait_opaque = opaque;
}
static int should_fail_alloc(void)
{
    if (fail_after < 0) return 0;
    if (fail_after == 0) return 1;
    --fail_after;
    return 0;
}
#else
static int should_fail_alloc(void) { return 0; }
#endif

static void *binding_calloc(size_t count, size_t size)
{
    return should_fail_alloc() ? NULL : calloc(count, size);
}

static kzt_guest_library_loader_object_t *find_gate_transition_locked(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_callback_gate_t *gate);

static int grow_array(void **array, size_t *capacity, size_t element_size)
{
    size_t next = *capacity ? *capacity * 2 : 8;
    void *grown;
    if (next < *capacity || next > SIZE_MAX / element_size ||
        should_fail_alloc())
        return -1;
    grown = realloc(*array, next * element_size);
    if (!grown) return -1;
    *array = grown;
    *capacity = next;
    return 0;
}

static int same_key(const kzt_guest_library_binding_key_t *a,
                    const kzt_guest_library_binding_key_t *b)
{
    return a->link_map_addr == b->link_map_addr &&
           a->generation == b->generation &&
           a->namespace_id == b->namespace_id &&
           a->namespace_kind == b->namespace_kind;
}

static int supported_key(const kzt_guest_library_binding_key_t *key)
{
    return key && key->link_map_addr && key->generation &&
           key->namespace_kind == KZT_GUEST_LIBRARY_NAMESPACE_MAIN &&
           key->namespace_id == 0;
}

static kzt_guest_library_lifecycle_t *find_lifecycle_locked(
    kzt_guest_library_bindings_t *bindings, library_t *library)
{
    for (size_t i = 0; i < bindings->lifecycle_count; ++i)
        if (bindings->lifecycles[i].library == library)
            return &bindings->lifecycles[i];
    return NULL;
}

static kzt_guest_library_observed_t *find_observed_locked(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr)
{
    for (size_t i = 0; i < bindings->observed_count; ++i)
        if (bindings->observed[i].key.link_map_addr == link_map_addr)
            return &bindings->observed[i];
    return NULL;
}

static kzt_guest_library_observed_t *find_observed_key_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key)
{
    for (size_t i = 0; i < bindings->observed_count; ++i)
        if (same_key(&bindings->observed[i].key, key))
            return &bindings->observed[i];
    return NULL;
}

static kzt_guest_library_callback_gate_t *find_callback_gate_locked(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr)
{
    for (kzt_guest_library_callback_gate_t *gate = bindings->callback_gates;
         gate; gate = gate->next)
        if (gate->link_map_addr == link_map_addr)
            return gate;
    return NULL;
}

static kzt_guest_library_callback_gate_t *find_callback_gate(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr)
{
    kzt_guest_library_callback_gate_t *gate =
        __atomic_load_n(&bindings->callback_gates, __ATOMIC_ACQUIRE);
    for (; gate; gate = gate->next)
        if (gate->link_map_addr == link_map_addr)
            return gate;
    return NULL;
}

static kzt_guest_library_callback_gate_t *add_callback_gate_locked(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr)
{
    kzt_guest_library_callback_gate_t *gate =
        binding_calloc(1, sizeof(*gate));
    if (!gate) return NULL;
    gate->link_map_addr = link_map_addr;
    gate->next = bindings->callback_gates;
    __atomic_store_n(&bindings->callback_gates, gate, __ATOMIC_RELEASE);
    return gate;
}

static void close_callback_addr_locked(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_lifecycle_t *lifecycle, library_t *library,
    uintptr_t link_map_addr)
{
    kzt_guest_library_callback_gate_t *gate;
    if (!link_map_addr) return;
    lifecycle->fallback_closed_epoch =
        bindings->loader_state ? bindings->loader_state->epoch : 0;
    gate = find_callback_gate_locked(bindings, link_map_addr);
    if (!gate)
        gate = add_callback_gate_locked(bindings, link_map_addr);
    if (!gate) {
        /* A lifecycle normally has one current link_map.  Keep its closed
         * address inline so allocation failure cannot admit a late callback
         * or block unrelated libraries. */
        lifecycle->fallback_closed_addr = link_map_addr;
        return;
    }
    unsigned long state = __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
    if ((state & KZT_CALLBACK_GATE_CLOSED) &&
        (state & KZT_CALLBACK_GATE_READERS) && gate->closed_by &&
        gate->closed_by != library) {
        kzt_guest_library_loader_object_t *transition =
            find_gate_transition_locked(bindings, gate);
        if (transition) {
            transition->next_closed_by = library;
            transition->reopen = 0;
        } else {
            lifecycle->fallback_closed_addr = link_map_addr;
        }
    } else {
        gate->closed_by = library;
    }
    __atomic_fetch_or(&gate->state, KZT_CALLBACK_GATE_CLOSED,
                      __ATOMIC_ACQ_REL);
}

static int shutting_down(kzt_guest_library_bindings_t *bindings)
{
    return __atomic_load_n(&bindings->shutting_down, __ATOMIC_ACQUIRE);
}

static kzt_guest_library_loader_attempt_t *find_loader_attempt_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_loader_scope_t *scope)
{
    if (!scope || scope->bindings != bindings || !scope->identity ||
        !bindings->loader_state ||
        !scope->cookie)
        return NULL;
    for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
        kzt_guest_library_loader_attempt_t *attempt =
            &bindings->loader_state->attempts[i];
        if (attempt->active && attempt->identity == scope->identity &&
            attempt->cookie == scope->cookie)
            return attempt;
    }
    return NULL;
}

static int loader_scope_active_locked(
    const kzt_guest_library_bindings_t *bindings)
{
    if (!bindings->loader_state) return 0;
    for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i)
        if (bindings->loader_state->attempts[i].active)
            return 1;
    return 0;
}

static kzt_guest_library_loader_attempt_t *loader_scope_valid_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_loader_scope_t *scope)
{
    kzt_guest_library_loader_attempt_t *attempt =
        find_loader_attempt_locked(bindings, scope);
    unsigned long newest = 0;

    if (!attempt || !pthread_equal(attempt->owner, pthread_self()))
        return NULL;
    for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
        kzt_guest_library_loader_attempt_t *candidate =
            &bindings->loader_state->attempts[i];
        if (candidate->active &&
            pthread_equal(candidate->owner, attempt->owner) &&
            candidate->identity > newest)
            newest = candidate->identity;
    }
    return newest == attempt->identity ? attempt : NULL;
}

static kzt_guest_library_loader_object_t *find_loader_object_locked(
    kzt_guest_library_loader_attempt_t *attempt, uintptr_t link_map_addr)
{
    for (size_t i = 0; i < attempt->object_count; ++i)
        if (attempt->objects[i].link_map_addr == link_map_addr)
            return &attempt->objects[i];
    return NULL;
}

static kzt_guest_library_loader_object_t *find_gate_transition_locked(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_callback_gate_t *gate)
{
    if (!bindings->loader_state) return NULL;
    for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
        kzt_guest_library_loader_attempt_t *attempt =
            &bindings->loader_state->attempts[i];
        for (size_t j = 0; j < attempt->object_count; ++j) {
            kzt_guest_library_loader_object_t *object = &attempt->objects[j];
            if (object->transition_pending &&
                object->transition_gate == gate)
                return object;
        }
    }
    return NULL;
}

static void clear_loader_transition_locked(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_object_t *object)
{
    kzt_guest_library_loader_attempt_t *attempt = NULL;
    if (!bindings->loader_state || !object) return;
    for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
        kzt_guest_library_loader_attempt_t *candidate =
            &bindings->loader_state->attempts[i];
        if (object >= candidate->objects &&
            object < candidate->objects + KZT_LOADER_ATTEMPT_OBJECTS) {
            attempt = candidate;
            break;
        }
    }
    object->transition_gate = NULL;
    object->transition_fallback = NULL;
    object->next_closed_by = NULL;
    object->transition_pending = 0;
    object->reopen = 0;
    if (attempt && !attempt->active) {
        int pending = 0;
        for (size_t i = 0; i < attempt->object_count; ++i)
            pending |= attempt->objects[i].transition_pending;
        if (!pending) memset(attempt, 0, sizeof(*attempt));
    }
}

static int observe_loader_object_locked(
    kzt_guest_library_loader_attempt_t *attempt, uintptr_t link_map_addr)
{
    if (find_loader_object_locked(attempt, link_map_addr))
        return 0;
    if (attempt->object_count == KZT_LOADER_ATTEMPT_OBJECTS)
        return -1;
    attempt->objects[attempt->object_count++].link_map_addr = link_map_addr;
    return 0;
}

static void reopen_callback_addr_locked(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    library_t *library, kzt_guest_library_loader_attempt_t *attempt)
{
    kzt_guest_library_callback_gate_t *gate =
        find_callback_gate_locked(bindings, link_map_addr);
    (void)library;

    if (gate && (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
                 KZT_CALLBACK_GATE_CLOSED)) {
        unsigned long state = __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
        if (state & KZT_CALLBACK_GATE_READERS) {
            kzt_guest_library_loader_object_t *object =
                attempt ? find_loader_object_locked(attempt, link_map_addr)
                        : NULL;
            if (object) {
                object->transition_gate = gate;
                object->transition_pending = 1;
                object->reopen = 1;
            }
        } else {
            kzt_guest_library_lifecycle_t *owner =
                find_lifecycle_locked(bindings, gate->closed_by);
            if (owner) owner->fallback_closed_epoch = 0;
            gate->closed_by = NULL;
            __atomic_fetch_and(&gate->state, ~KZT_CALLBACK_GATE_CLOSED,
                               __ATOMIC_ACQ_REL);
        }
    }
    for (size_t i = 0; i < bindings->lifecycle_count; ++i) {
        if (bindings->lifecycles[i].fallback_closed_addr == link_map_addr) {
            if (bindings->fallback_callback_readers) {
                kzt_guest_library_loader_object_t *object =
                    attempt ? find_loader_object_locked(
                                  attempt, link_map_addr) : NULL;
                if (object) {
                    object->transition_fallback = &bindings->lifecycles[i];
                    object->transition_pending = 1;
                    object->reopen = 1;
                }
            } else {
                bindings->lifecycles[i].fallback_closed_addr = 0;
                bindings->lifecycles[i].fallback_closed_epoch = 0;
            }
        }
    }
}

static int callback_access_busy_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_lifecycle_t *lifecycle, library_t *library)
{
    if (bindings->fallback_callback_readers)
        return 1;
    for (kzt_guest_library_callback_gate_t *gate = bindings->callback_gates;
         gate; gate = gate->next) {
        if (gate->closed_by == library &&
            (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
             KZT_CALLBACK_GATE_READERS))
            return 1;
    }
    return 0;
}

static kzt_guest_library_binding_result_t bind_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_lifecycle_t *lifecycle;
    if (shutting_down(bindings) || !supported_key(key) || !library ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_MAIN ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (!lifecycle || lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    for (size_t i = 0; i < bindings->count; ++i) {
        kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];
        if (!same_key(&entry->key, key) ||
            entry->state == KZT_GUEST_LIBRARY_BINDING_DEAD)
            continue;
        return entry->state == KZT_GUEST_LIBRARY_BINDING_LIVE &&
                       entry->library == library &&
                       entry->object_type == object_type
                   ? KZT_GUEST_LIBRARY_BINDING_UNCHANGED
                   : KZT_GUEST_LIBRARY_BINDING_CONFLICT;
    }
    if (object_type == KZT_GUEST_LIBRARY_OBJECT_WRAPPED) {
        for (size_t i = 0; i < bindings->count; ++i) {
            kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];

            if (entry->state == KZT_GUEST_LIBRARY_BINDING_LIVE &&
                entry->library == library && !same_key(&entry->key, key)) {
                return KZT_GUEST_LIBRARY_BINDING_CONFLICT;
            }
        }
    }
    if (bindings->count == bindings->capacity &&
        grow_array((void **)&bindings->entries, &bindings->capacity,
                   sizeof(*bindings->entries)) != 0)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    bindings->entries[bindings->count++] =
        (kzt_guest_library_binding_entry_t){
            .key = *key,
            .library = library,
            .object_type = object_type,
            .state = KZT_GUEST_LIBRARY_BINDING_LIVE,
        };
    return KZT_GUEST_LIBRARY_BINDING_ADDED;
}

kzt_guest_library_bindings_t *kzt_guest_library_bindings_init(void)
{
    kzt_guest_library_bindings_t *bindings =
        binding_calloc(1, sizeof(*bindings));
    if (!bindings) return NULL;
    if (pthread_mutex_init(&bindings->lock, NULL) != 0) {
        free(bindings);
        return NULL;
    }
    if (pthread_cond_init(&bindings->idle, NULL) != 0) {
        pthread_mutex_destroy(&bindings->lock);
        free(bindings);
        return NULL;
    }
    return bindings;
}

void kzt_guest_library_bindings_begin_teardown(
    kzt_guest_library_bindings_t *bindings)
{
    if (!bindings) return;
    pthread_mutex_lock(&bindings->lock);
    __atomic_store_n(&bindings->shutting_down, 1, __ATOMIC_RELEASE);
    pthread_cond_broadcast(&bindings->idle);
    for (size_t i = 0; i < bindings->pending_count; ++i)
        bindings->pending[i].active = 0;
    for (size_t i = 0; i < bindings->count; ++i)
        bindings->entries[i].state = KZT_GUEST_LIBRARY_BINDING_UNLOADING;
    for (;;) {
        int busy = 0;
        for (size_t i = 0; i < bindings->count; ++i)
            busy |= bindings->entries[i].references != 0;
        for (size_t i = 0; i < bindings->lifecycle_count; ++i)
            busy |= bindings->lifecycles[i].state ==
                    KZT_GUEST_LIBRARY_BINDING_UNLOADING;
        busy |= bindings->fallback_callback_readers != 0;
        for (kzt_guest_library_callback_gate_t *gate =
                 bindings->callback_gates;
             gate; gate = gate->next)
            busy |= (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
                     KZT_CALLBACK_GATE_READERS) != 0;
        busy |= bindings->loader_quiescence_readers != 0;
        busy |= bindings->loader_quiescence_waiters != 0;
        busy |= loader_scope_active_locked(bindings);
        if (!busy) break;
        pthread_cond_wait(&bindings->idle, &bindings->lock);
    }
    pthread_mutex_unlock(&bindings->lock);
}

void kzt_guest_library_bindings_destroy(kzt_guest_library_bindings_t **slot)
{
    kzt_guest_library_bindings_t *bindings;
    if (!slot || !(bindings = *slot)) return;
    kzt_guest_library_bindings_begin_teardown(bindings);
    pthread_cond_destroy(&bindings->idle);
    pthread_mutex_destroy(&bindings->lock);
    while (bindings->callback_gates) {
        kzt_guest_library_callback_gate_t *next =
            bindings->callback_gates->next;
        free(bindings->callback_gates);
        bindings->callback_gates = next;
    }
    free(bindings->observed);
    free(bindings->pending);
    if (bindings->loader_state) free(bindings->loader_state);
    free(bindings->lifecycles);
    free(bindings->entries);
    free(bindings);
    *slot = NULL;
}

int kzt_guest_library_access_init(kzt_guest_library_access_t *access)
{
    if (!access) return -1;
    memset(access, 0, sizeof(*access));
    if (pthread_mutex_init(&access->lock, NULL) != 0)
        return -1;
    access->initialized = 1;
    access->bindings = kzt_guest_library_bindings_init();
    access->accepting = 1;
    return 0;
}

void kzt_guest_library_access_begin_teardown(
    kzt_guest_library_access_t *access)
{
    if (!access || !access->initialized) return;
    pthread_mutex_lock(&access->lock);
    access->accepting = 0;
    /* Closing the context-owned gate under its lock drains any lookup already
     * inside the gate and prevents new acquisitions.  Drop the gate before
     * waiting for binding handles or unload owners so a source-lease holder
     * can fast-fail provider lookup and release its lease. */
    pthread_mutex_unlock(&access->lock);
    kzt_guest_library_bindings_begin_teardown(access->bindings);
}

void kzt_guest_library_access_destroy(kzt_guest_library_access_t *access)
{
    if (!access || !access->initialized) return;
    kzt_guest_library_access_begin_teardown(access);
    kzt_guest_library_bindings_destroy(&access->bindings);
    pthread_mutex_destroy(&access->lock);
    memset(access, 0, sizeof(*access));
}

int kzt_guest_library_track(kzt_guest_library_bindings_t *bindings,
                            library_t *library)
{
    kzt_guest_library_lifecycle_t *lifecycle;
    int result = -1;
    if (!bindings || !library) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings)) {
        goto out;
    }
    lifecycle = find_lifecycle_locked(bindings, library);
    if (lifecycle) {
        result = lifecycle->state == KZT_GUEST_LIBRARY_BINDING_LIVE ? 0 : -1;
        goto out;
    }
    if (bindings->lifecycle_count == bindings->lifecycle_capacity &&
        grow_array((void **)&bindings->lifecycles,
                   &bindings->lifecycle_capacity,
                   sizeof(*bindings->lifecycles)) != 0) {
        goto out;
    }
    bindings->lifecycles[bindings->lifecycle_count++] =
        (kzt_guest_library_lifecycle_t){
            .library = library,
            .state = KZT_GUEST_LIBRARY_BINDING_LIVE,
        };
    result = 0;
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

int kzt_guest_library_reactivate(kzt_guest_library_bindings_t *bindings,
                                 library_t *library)
{
    kzt_guest_library_lifecycle_t *lifecycle;
    int result = -1;
    if (!bindings || !library) return -1;
    pthread_mutex_lock(&bindings->lock);
    lifecycle = find_lifecycle_locked(bindings, library);
    if (shutting_down(bindings) || !lifecycle || lifecycle->destroy_started) {
        goto out;
    }
    if (lifecycle->state == KZT_GUEST_LIBRARY_BINDING_LIVE) {
        result = 0;
        goto out;
    }
    if (lifecycle->state != KZT_GUEST_LIBRARY_BINDING_DEAD)
        goto out;
    lifecycle->state = KZT_GUEST_LIBRARY_BINDING_LIVE;
    result = 0;
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

int kzt_guest_library_loader_scope_begin(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_scope_t *scope)
{
    int result = -1;
    pthread_t owner = pthread_self();

    if (scope) memset(scope, 0, sizeof(*scope));
    if (!bindings || !scope) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (!shutting_down(bindings) &&
        bindings->loader_quiescence_readers) {
        ++bindings->loader_quiescence_waiters;
        while (!shutting_down(bindings) &&
               bindings->loader_quiescence_readers)
            pthread_cond_wait(&bindings->idle, &bindings->lock);
        --bindings->loader_quiescence_waiters;
        pthread_cond_broadcast(&bindings->idle);
    }
    if (!shutting_down(bindings) &&
        (!bindings->loader_state || bindings->loader_state->epoch != ULONG_MAX)) {
        kzt_guest_library_loader_attempt_t *slot = NULL;
        if (!bindings->loader_state)
            bindings->loader_state = binding_calloc(
                1, sizeof(*bindings->loader_state));
        if (!bindings->loader_state)
            goto out;
        for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
            kzt_guest_library_loader_attempt_t *attempt =
                &bindings->loader_state->attempts[i];
            if (!attempt->active && !attempt->identity && !slot)
                slot = attempt;
        }
        if (slot) {
            unsigned long identity = ++bindings->loader_state->epoch;
            unsigned long cookie = identity ^ (unsigned long)(uintptr_t)bindings ^
                                   (unsigned long)(uintptr_t)slot;
            if (!cookie) cookie = ~identity;
            memset(slot, 0, sizeof(*slot));
            slot->identity = identity;
            slot->cookie = cookie;
            slot->owner = owner;
            slot->active = 1;
            scope->bindings = bindings;
            scope->identity = identity;
            scope->cookie = cookie;
            result = 0;
        }
    }
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

void kzt_guest_library_loader_scope_end(
    kzt_guest_library_loader_scope_t *scope)
{
    kzt_guest_library_bindings_t *bindings;
    if (!scope || !(bindings = scope->bindings)) return;
    pthread_mutex_lock(&bindings->lock);
    kzt_guest_library_loader_attempt_t *attempt =
        find_loader_attempt_locked(bindings, scope);
    if (attempt && pthread_equal(attempt->owner, pthread_self())) {
        int pending = 0;
        for (size_t i = 0; i < attempt->object_count; ++i)
            pending |= attempt->objects[i].transition_pending;
        if (pending)
            attempt->active = 0;
        else
            memset(attempt, 0, sizeof(*attempt));
        pthread_cond_broadcast(&bindings->idle);
    }
    pthread_mutex_unlock(&bindings->lock);
    memset(scope, 0, sizeof(*scope));
}

int kzt_guest_library_loader_quiescence_try_acquire(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_quiescence_lease_t *lease)
{
    int result = -1;

    if (lease) memset(lease, 0, sizeof(*lease));
    if (!bindings || !lease) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (!shutting_down(bindings) &&
        !bindings->loader_quiescence_waiters &&
        !loader_scope_active_locked(bindings) &&
        bindings->loader_quiescence_epoch != ULONG_MAX &&
        bindings->loader_quiescence_readers != UINT_MAX) {
        unsigned long identity = ++bindings->loader_quiescence_epoch;
        unsigned long cookie =
            identity ^ (unsigned long)(uintptr_t)bindings;

        if (!cookie) cookie = ~identity;
        ++bindings->loader_quiescence_readers;
        lease->bindings = bindings;
        lease->cookie = cookie;
        lease->next = bindings->loader_quiescence_leases;
        bindings->loader_quiescence_leases = lease;
        result = 0;
    }
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

void kzt_guest_library_loader_quiescence_release(
    kzt_guest_library_loader_quiescence_lease_t *lease)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_loader_quiescence_lease_t **cursor;

    if (!lease || !(bindings = lease->bindings)) return;
    pthread_mutex_lock(&bindings->lock);
    cursor = &bindings->loader_quiescence_leases;
    while (*cursor && *cursor != lease)
        cursor = &(*cursor)->next;
    if (*cursor == lease && lease->cookie &&
        bindings->loader_quiescence_readers) {
        *cursor = lease->next;
        if (--bindings->loader_quiescence_readers == 0)
            pthread_cond_broadcast(&bindings->idle);
    }
    pthread_mutex_unlock(&bindings->lock);
    memset(lease, 0, sizeof(*lease));
}

int kzt_guest_library_loader_quiescence_writer_begin(
    kzt_guest_library_bindings_t *bindings,
    kzt_guest_library_loader_quiescence_writer_t *writer)
{
    kzt_guest_library_loader_quiescence_writer_t **cursor;
    unsigned long identity;
    unsigned long cookie;
    int result = -1;

    if (writer) memset(writer, 0, sizeof(*writer));
    if (!bindings || !writer) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings) ||
        bindings->loader_quiescence_epoch == ULONG_MAX ||
        bindings->loader_quiescence_waiters == UINT_MAX) {
        goto out;
    }
    identity = ++bindings->loader_quiescence_epoch;
    cookie =
        identity ^ (unsigned long)(uintptr_t)bindings ^
        (unsigned long)(uintptr_t)writer;

    if (!cookie) cookie = ~identity;
    if (!cookie) cookie = 1;
    writer->bindings = bindings;
    writer->cookie = cookie;
    writer->next = bindings->loader_quiescence_writers;
    bindings->loader_quiescence_writers = writer;
    ++bindings->loader_quiescence_waiters;
    while (!shutting_down(bindings) &&
           bindings->loader_quiescence_readers) {
        pthread_cond_wait(&bindings->idle, &bindings->lock);
    }
    if (!shutting_down(bindings)) {
        result = 0;
    } else {
        cursor = &bindings->loader_quiescence_writers;
        while (*cursor && *cursor != writer)
            cursor = &(*cursor)->next;
        if (*cursor == writer && bindings->loader_quiescence_waiters) {
            *cursor = writer->next;
            --bindings->loader_quiescence_waiters;
            pthread_cond_broadcast(&bindings->idle);
        }
        memset(writer, 0, sizeof(*writer));
    }
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

void kzt_guest_library_loader_quiescence_writer_end(
    kzt_guest_library_loader_quiescence_writer_t *writer)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_loader_quiescence_writer_t **cursor;

    if (!writer || !(bindings = writer->bindings)) return;
    pthread_mutex_lock(&bindings->lock);
    cursor = &bindings->loader_quiescence_writers;
    while (*cursor && *cursor != writer)
        cursor = &(*cursor)->next;
    if (*cursor == writer && writer->cookie &&
        bindings->loader_quiescence_waiters) {
        *cursor = writer->next;
        --bindings->loader_quiescence_waiters;
        pthread_cond_broadcast(&bindings->idle);
    }
    pthread_mutex_unlock(&bindings->lock);
    memset(writer, 0, sizeof(*writer));
}

static int callback_access_begin(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    const kzt_guest_library_loader_scope_t *scope,
    kzt_guest_library_callback_access_t *access)
{
    kzt_guest_library_callback_gate_t *gate;
    kzt_guest_library_loader_attempt_t *attempt;
    kzt_guest_library_lifecycle_t *fallback_owner = NULL;
    int closed_seen = 0;

    if (access) memset(access, 0, sizeof(*access));
    if (!bindings || !link_map_addr || !access) return -1;
    if (shutting_down(bindings)) return -1;
    gate = find_callback_gate(bindings, link_map_addr);
    if (gate) {
        unsigned long state =
            __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
        if (state & KZT_CALLBACK_GATE_CLOSED)
            goto slow;
        do {
            if ((state & KZT_CALLBACK_GATE_READERS) ==
                KZT_CALLBACK_GATE_READERS)
                return -1;
        } while (!__atomic_compare_exchange_n(
            &gate->state, &state, state + 1, 1,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
        if (scope && scope->bindings) {
            int valid;
            pthread_mutex_lock(&bindings->lock);
            kzt_guest_library_loader_attempt_t *fast_attempt =
                loader_scope_valid_locked(bindings, scope);
            valid = fast_attempt &&
                    observe_loader_object_locked(
                        fast_attempt, link_map_addr) == 0;
            pthread_mutex_unlock(&bindings->lock);
            if (!valid) {
                __atomic_fetch_sub(&gate->state, 1, __ATOMIC_ACQ_REL);
                return -1;
            }
        }
        if (shutting_down(bindings)) {
            unsigned long previous = __atomic_fetch_sub(
                &gate->state, 1, __ATOMIC_ACQ_REL);
            if ((previous & KZT_CALLBACK_GATE_READERS) == 1) {
                pthread_mutex_lock(&bindings->lock);
                pthread_cond_broadcast(&bindings->idle);
                pthread_mutex_unlock(&bindings->lock);
            }
            return -1;
        }
        access->bindings = bindings;
        access->link_map_addr = link_map_addr;
        access->gate = gate;
        return 0;
    }

slow:
    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings)) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    if (!scope || !scope->bindings) {
        for (size_t i = 0; i < bindings->lifecycle_count; ++i) {
            if (bindings->lifecycles[i].fallback_closed_addr ==
                link_map_addr) {
                pthread_mutex_unlock(&bindings->lock);
                return -1;
            }
        }
        gate = find_callback_gate_locked(bindings, link_map_addr);
        if (gate && (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
                     KZT_CALLBACK_GATE_CLOSED)) {
            pthread_mutex_unlock(&bindings->lock);
            return -1;
        }
        if (!gate)
            gate = add_callback_gate_locked(bindings, link_map_addr);
        goto acquire_locked;
    }
    attempt = loader_scope_valid_locked(bindings, scope);
    if (!attempt) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    for (size_t i = 0; i < bindings->lifecycle_count; ++i) {
        kzt_guest_library_lifecycle_t *lifecycle = &bindings->lifecycles[i];
        if (lifecycle->fallback_closed_addr != link_map_addr)
            continue;
        closed_seen = 1;
        fallback_owner = lifecycle;
        if (!attempt || attempt->identity <= lifecycle->fallback_closed_epoch) {
            pthread_mutex_unlock(&bindings->lock);
            return -1;
        }
    }
    gate = find_callback_gate_locked(bindings, link_map_addr);
    if (gate && (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
                 KZT_CALLBACK_GATE_CLOSED)) {
        kzt_guest_library_lifecycle_t *owner =
            find_lifecycle_locked(bindings, gate->closed_by);
        unsigned long closed_epoch = owner ? owner->fallback_closed_epoch : 0;

        closed_seen = 1;
        if (!attempt || attempt->identity <= closed_epoch) {
            pthread_mutex_unlock(&bindings->lock);
            return -1;
        }
    }
    if (attempt && observe_loader_object_locked(attempt, link_map_addr) != 0) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    if (!gate)
        gate = add_callback_gate_locked(bindings, link_map_addr);
    if (gate && closed_seen && fallback_owner &&
        !(__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
          KZT_CALLBACK_GATE_CLOSED)) {
        gate->closed_by = fallback_owner->library;
        __atomic_fetch_or(&gate->state, KZT_CALLBACK_GATE_CLOSED,
                          __ATOMIC_ACQ_REL);
    }
acquire_locked:
    access->bindings = bindings;
    access->link_map_addr = link_map_addr;
    if (gate) {
        unsigned long state = __atomic_load_n(&gate->state, __ATOMIC_ACQUIRE);
        if ((state & KZT_CALLBACK_GATE_READERS) == KZT_CALLBACK_GATE_READERS) {
            pthread_mutex_unlock(&bindings->lock);
            memset(access, 0, sizeof(*access));
            return -1;
        }
        __atomic_add_fetch(&gate->state, 1, __ATOMIC_ACQ_REL);
        access->gate = gate;
    } else {
        ++bindings->fallback_callback_readers;
        access->fallback = 1;
    }
    pthread_mutex_unlock(&bindings->lock);
    return 0;
}

int kzt_guest_library_callback_access_begin(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    kzt_guest_library_callback_access_t *access)
{
    return callback_access_begin(bindings, link_map_addr, NULL, access);
}

int kzt_guest_library_callback_access_begin_scoped(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    const kzt_guest_library_loader_scope_t *scope,
    kzt_guest_library_callback_access_t *access)
{
    return callback_access_begin(bindings, link_map_addr, scope, access);
}

void kzt_guest_library_callback_access_end(
    kzt_guest_library_callback_access_t *access)
{
    kzt_guest_library_bindings_t *bindings;
    if (!access || !(bindings = access->bindings)) return;
    if (access->gate) {
        kzt_guest_library_callback_gate_t *gate = access->gate;
        unsigned long previous = __atomic_fetch_sub(
            &gate->state, 1, __ATOMIC_ACQ_REL);
        int last = (previous & KZT_CALLBACK_GATE_READERS) == 1;
        if (last && ((previous & KZT_CALLBACK_GATE_CLOSED) ||
                     shutting_down(bindings))) {
            pthread_mutex_lock(&bindings->lock);
            if (!shutting_down(bindings) &&
                (__atomic_load_n(&gate->state, __ATOMIC_ACQUIRE) &
                 KZT_CALLBACK_GATE_READERS) == 0) {
                kzt_guest_library_loader_object_t *transition =
                    find_gate_transition_locked(bindings, gate);
                if (transition && transition->next_closed_by) {
                    gate->closed_by = transition->next_closed_by;
                    clear_loader_transition_locked(bindings, transition);
                } else if (transition && transition->reopen) {
                    kzt_guest_library_lifecycle_t *owner =
                        find_lifecycle_locked(bindings, gate->closed_by);
                    if (owner) owner->fallback_closed_epoch = 0;
                    gate->closed_by = NULL;
                    __atomic_fetch_and(&gate->state,
                                       ~KZT_CALLBACK_GATE_CLOSED,
                                       __ATOMIC_ACQ_REL);
                    clear_loader_transition_locked(bindings, transition);
                }
            }
            pthread_cond_broadcast(&bindings->idle);
            pthread_mutex_unlock(&bindings->lock);
        }
        memset(access, 0, sizeof(*access));
        return;
    }
    pthread_mutex_lock(&bindings->lock);
    if (access->fallback) {
        if (bindings->fallback_callback_readers)
            --bindings->fallback_callback_readers;
        if (!bindings->fallback_callback_readers &&
            !shutting_down(bindings)) {
            if (bindings->loader_state) {
                for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i) {
                    kzt_guest_library_loader_attempt_t *attempt =
                        &bindings->loader_state->attempts[i];
                    for (size_t j = 0; j < attempt->object_count; ++j) {
                        kzt_guest_library_loader_object_t *object =
                            &attempt->objects[j];
                        if (object->transition_pending && object->reopen &&
                            object->transition_fallback) {
                            object->transition_fallback->fallback_closed_addr = 0;
                            object->transition_fallback->fallback_closed_epoch = 0;
                            clear_loader_transition_locked(bindings, object);
                        }
                    }
                }
            }
        }
    }
    pthread_cond_broadcast(&bindings->idle);
    pthread_mutex_unlock(&bindings->lock);
    memset(access, 0, sizeof(*access));
}

kzt_guest_library_binding_result_t kzt_guest_library_bind(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_binding_result_t result;
    if (!bindings) return KZT_GUEST_LIBRARY_BINDING_DISABLED;
    pthread_mutex_lock(&bindings->lock);
    result = bind_locked(bindings, key, library, object_type);
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

static kzt_guest_library_binding_result_t note_exact_pair_locked(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    library_t *library, kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_observed_t *observed;
    kzt_guest_library_lifecycle_t *lifecycle;
    kzt_guest_library_binding_result_t result;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (shutting_down(bindings) || !lifecycle ||
        lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE) {
        result = KZT_GUEST_LIBRARY_BINDING_ERROR;
        return result;
    }
    observed = find_observed_locked(bindings, link_map_addr);
    if (observed) {
        if (observed->retire_owner) {
            return KZT_GUEST_LIBRARY_BINDING_CANCELLED;
        }
        result = bind_locked(bindings, &observed->key, library, object_type);
        if (result == KZT_GUEST_LIBRARY_BINDING_ADDED ||
            result == KZT_GUEST_LIBRARY_BINDING_UNCHANGED)
            observed->claimed = 1;
        return result;
    }
    for (size_t i = 0; i < bindings->pending_count; ++i) {
        kzt_guest_library_pending_t *pending = &bindings->pending[i];
        if (!pending->active || pending->link_map_addr != link_map_addr)
            continue;
        result = pending->library == library &&
                         pending->object_type == object_type
                     ? KZT_GUEST_LIBRARY_BINDING_PENDING
                     : KZT_GUEST_LIBRARY_BINDING_CONFLICT;
        return result;
    }
    if (bindings->pending_count == bindings->pending_capacity &&
        grow_array((void **)&bindings->pending, &bindings->pending_capacity,
                   sizeof(*bindings->pending)) != 0) {
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    }
    bindings->pending[bindings->pending_count++] =
        (kzt_guest_library_pending_t){
            .link_map_addr = link_map_addr,
            .library = library,
            .object_type = object_type,
            .active = 1,
        };
    return KZT_GUEST_LIBRARY_BINDING_PENDING;
}

kzt_guest_library_binding_result_t kzt_guest_library_note_exact_pair(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    library_t *library, kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_binding_result_t result;
    if (!link_map_addr || !library ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_MAIN ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    if (!bindings) return KZT_GUEST_LIBRARY_BINDING_DISABLED;
    pthread_mutex_lock(&bindings->lock);
    result = note_exact_pair_locked(bindings, link_map_addr, library,
                                    object_type);
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_note_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_loader_attempt_t *attempt;
    kzt_guest_library_loader_object_t *object;
    kzt_guest_library_lifecycle_t *lifecycle;

    if (!scope || !(bindings = scope->bindings) || !link_map_addr || !library ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_MAIN ||
        object_type == KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    pthread_mutex_lock(&bindings->lock);
    attempt = loader_scope_valid_locked(bindings, scope);
    object = attempt ? find_loader_object_locked(attempt, link_map_addr) : NULL;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (shutting_down(bindings) || !object || !lifecycle ||
        lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE ||
        lifecycle->destroy_started ||
        (object->pair_state != KZT_LOADER_PAIR_EMPTY &&
         (object->library != library ||
          object->object_type != object_type))) {
        pthread_mutex_unlock(&bindings->lock);
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    }
    object->library = library;
    object->object_type = object_type;
    if (object->pair_state == KZT_LOADER_PAIR_EMPTY)
        object->pair_state = KZT_LOADER_PAIR_PREPARED;
    pthread_mutex_unlock(&bindings->lock);
    return KZT_GUEST_LIBRARY_BINDING_PENDING;
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_pair(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library,
    kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_binding_result_t result;
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_loader_attempt_t *attempt;
    kzt_guest_library_loader_object_t *object;
    kzt_guest_library_lifecycle_t *lifecycle;

    if (!scope || !(bindings = scope->bindings) || !link_map_addr || !library)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    pthread_mutex_lock(&bindings->lock);
    attempt = loader_scope_valid_locked(bindings, scope);
    object = attempt ? find_loader_object_locked(attempt, link_map_addr) : NULL;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (shutting_down(bindings) || !object ||
        object->pair_state != KZT_LOADER_PAIR_PREPARED ||
        object->library != library ||
        object->object_type != object_type || !lifecycle ||
        lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE ||
        lifecycle->destroy_started) {
        pthread_mutex_unlock(&bindings->lock);
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    }
    result = note_exact_pair_locked(bindings, link_map_addr, library,
                                    object_type);
    if (result != KZT_GUEST_LIBRARY_BINDING_ADDED &&
        result != KZT_GUEST_LIBRARY_BINDING_UNCHANGED &&
        result != KZT_GUEST_LIBRARY_BINDING_PENDING) {
        pthread_mutex_unlock(&bindings->lock);
        return result;
    }
    object->pair_state = KZT_LOADER_PAIR_PUBLISHED;
    reopen_callback_addr_locked(bindings, link_map_addr, library, attempt);
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

kzt_guest_library_binding_result_t
kzt_guest_library_loader_scope_publish_observed(
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr)
{
    kzt_guest_library_bindings_t *bindings;
    library_t *library = NULL;
    kzt_guest_library_object_type_t object_type =
        KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED;

    if (!scope || !(bindings = scope->bindings))
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    pthread_mutex_lock(&bindings->lock);
    kzt_guest_library_loader_attempt_t *attempt =
        loader_scope_valid_locked(bindings, scope);
    kzt_guest_library_loader_object_t *object =
        attempt ? find_loader_object_locked(attempt, link_map_addr) : NULL;
    if (object) {
        library = object->library;
        object_type = object->object_type;
    }
    pthread_mutex_unlock(&bindings->lock);
    if (!library)
        return KZT_GUEST_LIBRARY_BINDING_ERROR;
    return kzt_guest_library_loader_scope_publish_pair(
        scope, link_map_addr, library, object_type);
}

kzt_guest_library_binding_result_t kzt_guest_library_publish_loader_pair(
    kzt_guest_library_bindings_t *bindings, uintptr_t link_map_addr,
    library_t *library, kzt_guest_library_object_type_t object_type)
{
    kzt_guest_library_binding_result_t result =
        kzt_guest_library_note_exact_pair(bindings, link_map_addr, library,
                                          object_type);

    if (!bindings || (result != KZT_GUEST_LIBRARY_BINDING_ADDED &&
                      result != KZT_GUEST_LIBRARY_BINDING_UNCHANGED &&
                      result != KZT_GUEST_LIBRARY_BINDING_PENDING))
        return result;
    pthread_mutex_lock(&bindings->lock);
    kzt_guest_library_lifecycle_t *lifecycle =
        find_lifecycle_locked(bindings, library);
    if (!shutting_down(bindings) && lifecycle &&
        lifecycle->state == KZT_GUEST_LIBRARY_BINDING_LIVE &&
        !lifecycle->destroy_started) {
        kzt_guest_library_callback_gate_t *gate =
            find_callback_gate_locked(bindings, link_map_addr);
        int same_reactivated_library =
            gate && gate->closed_by == library;
        for (size_t i = 0; i < bindings->lifecycle_count; ++i)
            if (bindings->lifecycles[i].library == library &&
                bindings->lifecycles[i].fallback_closed_addr == link_map_addr)
                same_reactivated_library = 1;
        if (same_reactivated_library)
            reopen_callback_addr_locked(bindings, link_map_addr, library,
                                        NULL);
    }
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

kzt_guest_library_binding_result_t kzt_guest_library_note_observation(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_binding_key_t *key)
{
    kzt_guest_library_observed_t *observed;
    kzt_guest_library_binding_result_t result =
        KZT_GUEST_LIBRARY_BINDING_UNCHANGED;
    if (!supported_key(key)) return KZT_GUEST_LIBRARY_BINDING_ERROR;
    if (!bindings) return KZT_GUEST_LIBRARY_BINDING_DISABLED;
    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings)) {
        result = KZT_GUEST_LIBRARY_BINDING_DISABLED;
        goto out;
    }
    for (size_t i = 0; i < bindings->count; ++i) {
        kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];
        if (entry->state == KZT_GUEST_LIBRARY_BINDING_UNLOADING &&
            same_key(&entry->key, key)) {
            /* Phase 1 has assigned this exact generation to the binding
             * lifecycle owner.  This check deliberately precedes the
             * address-only pending cancellation path. */
            result = KZT_GUEST_LIBRARY_BINDING_RETIRE_OWNED;
            goto out;
        }
    }
    observed = find_observed_key_locked(bindings, key);
    if (observed && observed->retire_owner) {
        result = KZT_GUEST_LIBRARY_BINDING_RETIRE_OWNED;
        goto out;
    }
    {
        int active_pending = 0;
        int cancelled_pending = 0;
        for (size_t i = 0; i < bindings->pending_count; ++i) {
            kzt_guest_library_pending_t *pending = &bindings->pending[i];
            if (pending->link_map_addr != key->link_map_addr)
                continue;
            if (pending->active)
                active_pending = 1;
            else {
                kzt_guest_library_lifecycle_t *lifecycle =
                    find_lifecycle_locked(bindings, pending->library);
                if (lifecycle &&
                    lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
                    cancelled_pending = 1;
            }
        }
        if (cancelled_pending && !active_pending) {
            for (size_t i = 0; i < bindings->pending_count; ++i) {
                kzt_guest_library_pending_t *pending = &bindings->pending[i];
                kzt_guest_library_lifecycle_t *lifecycle;
                if (pending->active ||
                    pending->link_map_addr != key->link_map_addr)
                    continue;
                lifecycle = find_lifecycle_locked(bindings,
                                                  pending->library);
                if (lifecycle &&
                    lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
                    pending->link_map_addr = 0;
            }
            result = KZT_GUEST_LIBRARY_BINDING_CANCELLED;
            goto out;
        }
    }
    observed = find_observed_key_locked(bindings, key);
    if (!observed) {
        kzt_guest_library_observed_t *same_addr =
            find_observed_locked(bindings, key->link_map_addr);
        if (same_addr && !same_addr->retire_owner)
            observed = same_addr;
    }
    if (observed) {
        observed->key = *key;
        observed->claimed = 0;
    } else {
        if (bindings->observed_count == bindings->observed_capacity &&
            grow_array((void **)&bindings->observed,
                       &bindings->observed_capacity,
                       sizeof(*bindings->observed)) != 0) {
            result = KZT_GUEST_LIBRARY_BINDING_ERROR;
            goto out;
        }
        bindings->observed[bindings->observed_count++] =
            (kzt_guest_library_observed_t){ .key = *key };
        observed = &bindings->observed[bindings->observed_count - 1];
    }
    for (size_t i = 0; i < bindings->pending_count; ++i) {
        kzt_guest_library_pending_t *pending = &bindings->pending[i];
        kzt_guest_library_binding_result_t one;
        if (!pending->active || pending->link_map_addr != key->link_map_addr)
            continue;
        one = bind_locked(bindings, key, pending->library,
                          pending->object_type);
        if (one == KZT_GUEST_LIBRARY_BINDING_ADDED ||
            one == KZT_GUEST_LIBRARY_BINDING_UNCHANGED) {
            pending->active = 0;
            observed->claimed = 1;
            if (one == KZT_GUEST_LIBRARY_BINDING_ADDED)
                result = one;
        } else if (one == KZT_GUEST_LIBRARY_BINDING_CONFLICT) {
            result = one;
        }
    }
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

static int lookup_bindings(kzt_guest_library_bindings_t *bindings,
                           const kzt_guest_library_binding_key_t *key,
                           kzt_guest_library_handle_t *handle)
{
    if (handle) memset(handle, 0, sizeof(*handle));
    if (!bindings || !key || !handle) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings)) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    for (size_t i = 0; i < bindings->count; ++i) {
        kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];
        kzt_guest_library_lifecycle_t *lifecycle;
        if (entry->state != KZT_GUEST_LIBRARY_BINDING_LIVE ||
            !same_key(&entry->key, key))
            continue;
        lifecycle = find_lifecycle_locked(bindings, entry->library);
        if (!lifecycle || lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
            continue;
        ++entry->references;
        handle->bindings = bindings;
        /* A 1-based index remains stable when forced growth reallocates the
         * backing array while this handle protects library lifetime. */
        handle->entry = (void *)(uintptr_t)(i + 1);
        handle->library = entry->library;
        handle->object_type = entry->object_type;
        pthread_mutex_unlock(&bindings->lock);
        return 0;
    }
    pthread_mutex_unlock(&bindings->lock);
    return -1;
}

#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
int kzt_guest_library_lookup(kzt_guest_library_bindings_t *bindings,
                             const kzt_guest_library_binding_key_t *key,
                             kzt_guest_library_handle_t *handle)
{
    return lookup_bindings(bindings, key, handle);
}
#endif

int kzt_guest_library_access_lookup(
    kzt_guest_library_access_t *access,
    const kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    int result = -1;
    if (handle) memset(handle, 0, sizeof(*handle));
    if (!access || !access->initialized || !key || !handle) return -1;
    pthread_mutex_lock(&access->lock);
    if (access->accepting && access->bindings)
        result = lookup_bindings(access->bindings, key, handle);
    pthread_mutex_unlock(&access->lock);
    return result;
}

static int lookup_bindings_by_library(
    kzt_guest_library_bindings_t *bindings, library_t *library,
    kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    kzt_guest_library_binding_entry_t *match = NULL;
    size_t match_index = 0;
    int result = -1;

    if (key) memset(key, 0, sizeof(*key));
    if (handle) memset(handle, 0, sizeof(*handle));
    if (!bindings || !library || !key || !handle) return -1;

    pthread_mutex_lock(&bindings->lock);
    if (shutting_down(bindings)) goto out;

    kzt_guest_library_lifecycle_t *lifecycle =
        find_lifecycle_locked(bindings, library);
    if (!lifecycle || lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
        goto out;

    for (size_t i = 0; i < bindings->count; ++i) {
        kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];
        if (entry->library != library ||
            entry->state != KZT_GUEST_LIBRARY_BINDING_LIVE)
            continue;
        if (!supported_key(&entry->key) || match)
            goto out;
        match = entry;
        match_index = i;
    }
    if (!match) goto out;

    ++match->references;
    *key = match->key;
    handle->bindings = bindings;
    handle->entry = (void *)(uintptr_t)(match_index + 1);
    handle->library = match->library;
    handle->object_type = match->object_type;
    result = 0;
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

int kzt_guest_library_access_lookup_by_library(
    kzt_guest_library_access_t *access, library_t *library,
    kzt_guest_library_binding_key_t *key,
    kzt_guest_library_handle_t *handle)
{
    int result = -1;
    if (key) memset(key, 0, sizeof(*key));
    if (handle) memset(handle, 0, sizeof(*handle));
    if (!access || !access->initialized || !library || !key || !handle)
        return -1;
    pthread_mutex_lock(&access->lock);
    if (access->accepting && access->bindings)
        result = lookup_bindings_by_library(
            access->bindings, library, key, handle);
    pthread_mutex_unlock(&access->lock);
    return result;
}

static kzt_guest_library_binding_entry_t *
kzt_guest_library_handle_entry_locked(
    kzt_guest_library_bindings_t *bindings,
    const kzt_guest_library_handle_t *handle)
{
    size_t index;
    kzt_guest_library_binding_entry_t *entry;

    if (!bindings || !handle || handle->bindings != bindings ||
        !handle->entry || !handle->library) {
        return NULL;
    }
    index = (size_t)(uintptr_t)handle->entry - 1;
    if (index >= bindings->count) return NULL;
    entry = &bindings->entries[index];
    if (!entry->references || entry->library != handle->library ||
        entry->object_type != handle->object_type ||
        entry->state != KZT_GUEST_LIBRARY_BINDING_LIVE) {
        return NULL;
    }
    return entry;
}

int kzt_guest_library_symbol_evidence_lookup(
    const kzt_guest_library_handle_t *handle, const char *symbol,
    unsigned long dynamic_revision, uintptr_t *runtime_address,
    unsigned char *symbol_type)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_binding_entry_t *entry;
    size_t i;
    int result = -1;

    if (runtime_address) *runtime_address = 0;
    if (symbol_type) *symbol_type = 0;
    if (!handle || !(bindings = handle->bindings) || !symbol || !symbol[0] ||
        !dynamic_revision || !runtime_address || !symbol_type) {
        return -1;
    }
    pthread_mutex_lock(&bindings->lock);
    entry = kzt_guest_library_handle_entry_locked(bindings, handle);
    if (!entry || shutting_down(bindings)) goto out;
    for (i = 0; i < KZT_GUEST_LIBRARY_SYMBOL_CACHE_SLOTS; ++i) {
        kzt_guest_library_symbol_evidence_t *cached =
            &entry->symbol_cache[i];

        if (cached->valid &&
            cached->dynamic_revision == dynamic_revision &&
            strcmp(cached->symbol, symbol) == 0) {
            cached->age = ++entry->symbol_cache_age;
            *runtime_address = cached->runtime_address;
            *symbol_type = cached->symbol_type;
            result = 0;
            break;
        }
    }
out:
    pthread_mutex_unlock(&bindings->lock);
    return result;
}

void kzt_guest_library_symbol_evidence_store(
    const kzt_guest_library_handle_t *handle, const char *symbol,
    unsigned long dynamic_revision, uintptr_t runtime_address,
    unsigned char symbol_type)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_binding_entry_t *entry;
    kzt_guest_library_symbol_evidence_t *selected = NULL;
    size_t symbol_length;
    size_t i;

    if (!handle || !(bindings = handle->bindings) || !symbol ||
        !(symbol_length = strlen(symbol)) ||
        symbol_length >= KZT_GUEST_LIBRARY_SYMBOL_NAME_LIMIT ||
        !dynamic_revision ||
        !runtime_address) {
        return;
    }
    pthread_mutex_lock(&bindings->lock);
    entry = kzt_guest_library_handle_entry_locked(bindings, handle);
    if (!entry || shutting_down(bindings)) goto out;
    for (i = 0; i < KZT_GUEST_LIBRARY_SYMBOL_CACHE_SLOTS; ++i) {
        kzt_guest_library_symbol_evidence_t *cached =
            &entry->symbol_cache[i];

        if (cached->valid && strcmp(cached->symbol, symbol) == 0) {
            selected = cached;
            break;
        }
        if (!selected || !cached->valid || cached->age < selected->age) {
            selected = cached;
        }
    }
    if (selected) {
        memcpy(selected->symbol, symbol, symbol_length + 1);
        selected->runtime_address = runtime_address;
        selected->symbol_type = symbol_type;
        selected->dynamic_revision = dynamic_revision;
        selected->age = ++entry->symbol_cache_age;
        selected->valid = 1;
    }
out:
    pthread_mutex_unlock(&bindings->lock);
}

void kzt_guest_library_handle_release(kzt_guest_library_handle_t *handle)
{
    kzt_guest_library_bindings_t *bindings;
    if (!handle || !(bindings = handle->bindings) || !handle->entry) return;
    pthread_mutex_lock(&bindings->lock);
    size_t index = (size_t)(uintptr_t)handle->entry - 1;
    if (index < bindings->count) {
        kzt_guest_library_binding_entry_t *entry =
            &bindings->entries[index];
        if (entry->references && --entry->references == 0)
            pthread_cond_broadcast(&bindings->idle);
    }
    pthread_mutex_unlock(&bindings->lock);
    memset(handle, 0, sizeof(*handle));
}

int kzt_guest_library_cleanup_exact_handle(
    kzt_guest_library_handle_t *handle,
    kzt_guest_library_exact_cleanup_fn cleanup,
    void *opaque)
{
    kzt_guest_library_bindings_t *bindings;
    kzt_guest_library_binding_entry_t *entry;
    kzt_guest_library_lifecycle_t *lifecycle;
    library_t *library;
    size_t index;
    size_t i;

    if (!handle || !(bindings = handle->bindings) || !handle->entry ||
        !handle->library) {
        return -1;
    }
    pthread_mutex_lock(&bindings->lock);
    index = (size_t)(uintptr_t)handle->entry - 1;
    if (index >= bindings->count) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    entry = &bindings->entries[index];
    library = handle->library;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (entry->library != library || !entry->references ||
        entry->state != KZT_GUEST_LIBRARY_BINDING_LIVE || !lifecycle ||
        lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE) {
        pthread_mutex_unlock(&bindings->lock);
        return -1;
    }
    for (i = 0; i < bindings->count; ++i) {
        if (i != index && bindings->entries[i].library == library &&
            bindings->entries[i].state == KZT_GUEST_LIBRARY_BINDING_LIVE &&
            !same_key(&bindings->entries[i].key, &entry->key)) {
            pthread_mutex_unlock(&bindings->lock);
            return -1;
        }
    }

    lifecycle->state = KZT_GUEST_LIBRARY_BINDING_UNLOADING;
    entry->state = KZT_GUEST_LIBRARY_BINDING_UNLOADING;
    close_callback_addr_locked(bindings, lifecycle, library,
                               entry->key.link_map_addr);
    for (i = 0; i < bindings->pending_count; ++i) {
        if (bindings->pending[i].library == library &&
            bindings->pending[i].link_map_addr ==
                entry->key.link_map_addr) {
            bindings->pending[i].active = 0;
        }
    }
    for (i = 0; i < bindings->observed_count; ++i) {
        if (same_key(&bindings->observed[i].key, &entry->key)) {
            memset(&bindings->observed[i], 0,
                   sizeof(bindings->observed[i]));
        }
    }

    --entry->references;
    memset(handle, 0, sizeof(*handle));
    while (entry->references) {
        pthread_cond_wait(&bindings->idle, &bindings->lock);
    }
    if (cleanup) {
        cleanup(library, opaque);
    }
    entry->state = KZT_GUEST_LIBRARY_BINDING_DEAD;
    lifecycle->state = KZT_GUEST_LIBRARY_BINDING_DEAD;
    pthread_cond_broadcast(&bindings->idle);
    pthread_mutex_unlock(&bindings->lock);
    return 0;
}

static void unload_library(kzt_guest_library_bindings_t *bindings,
                           kzt_guest_registry_t *registry,
                           library_t *library,
                           uintptr_t guest_link_map_hint, int permanent)
{
    kzt_guest_library_lifecycle_t *lifecycle;
    int owns_lifecycle = 0;
    int waits_for_lifecycle = 0;
    uint64_t timing_start = 0;
    uint64_t retire_ns = 0;
    if (!bindings || !library) return;
    if (kzt_lifecycle_diagnostics_enabled()) {
        timing_start = kzt_lifecycle_diagnostics_now();
    }
    pthread_mutex_lock(&bindings->lock);

    /* Phase 1 closes every binding-side path without allocation.  Only the
     * caller that changes this library from LIVE to UNLOADING may attach the
     * library as owner of an exact, unclaimed observation.  Registry
     * retirement is deliberately deferred: it may wait for a source lease,
     * and a lease holder may need bindings->lock for provider lookup. */
    lifecycle = find_lifecycle_locked(bindings, library);
    if (!lifecycle) {
        goto out;
    }
    if (permanent) lifecycle->destroy_started = 1;
    if (lifecycle->state != KZT_GUEST_LIBRARY_BINDING_LIVE) {
        waits_for_lifecycle =
            lifecycle->state == KZT_GUEST_LIBRARY_BINDING_UNLOADING;
        goto wait_or_out;
    }
    lifecycle->state = KZT_GUEST_LIBRARY_BINDING_UNLOADING;
    owns_lifecycle = 1;
    if (guest_link_map_hint) {
        for (size_t i = 0; i < bindings->observed_count; ++i) {
            kzt_guest_library_observed_t *observed =
                &bindings->observed[i];
            if (observed->key.link_map_addr == guest_link_map_hint &&
                !observed->claimed && !observed->retire_owner) {
                observed->retire_owner = library;
                break;
            }
        }
        close_callback_addr_locked(bindings, lifecycle, library,
                                   guest_link_map_hint);
    }
    for (size_t i = 0; i < bindings->pending_count; ++i)
        if (bindings->pending[i].library == library)
            bindings->pending[i].active = 0;
    for (size_t i = 0; i < bindings->count; ++i) {
        kzt_guest_library_binding_entry_t *entry = &bindings->entries[i];
        if (entry->library != library ||
            entry->state == KZT_GUEST_LIBRARY_BINDING_DEAD)
            continue;
        entry->state = KZT_GUEST_LIBRARY_BINDING_UNLOADING;
        entry->retire_started = 0;
        close_callback_addr_locked(bindings, lifecycle, library,
                                   entry->key.link_map_addr);
        for (size_t j = 0; j < bindings->observed_count; ++j)
            if (same_key(&bindings->observed[j].key, &entry->key)) {
                memset(&bindings->observed[j], 0,
                       sizeof(bindings->observed[j]));
            }
    }

    /* A callback that entered first may still need this lock for observation
     * publication and loader-pair binding, so wait with pthread_cond_wait.
     * New callbacks for the closed address are rejected before their first
     * guest-memory read. */
    while (callback_access_busy_locked(bindings, lifecycle, library))
        pthread_cond_wait(&bindings->idle, &bindings->lock);

    /* Phase 2 claims one exact key by value, drops bindings->lock, and only
     * then enters the registry.  Re-scanning after every lock acquisition is
     * safe across concurrent array growth/realloc and needs no allocation. */
    for (;;) {
        kzt_guest_library_binding_key_t retire_key = { 0 };
        int from_observation = 0;

        if (owns_lifecycle) {
            for (size_t i = 0; i < bindings->count; ++i) {
                kzt_guest_library_binding_entry_t *entry =
                    &bindings->entries[i];
                if (entry->library == library &&
                    entry->state == KZT_GUEST_LIBRARY_BINDING_UNLOADING &&
                    !entry->retire_started) {
                    retire_key = entry->key;
                    entry->retire_started = 1;
                    break;
                }
            }
        }
        if (!retire_key.link_map_addr) {
            for (size_t i = 0; i < bindings->observed_count; ++i) {
                kzt_guest_library_observed_t *observed =
                    &bindings->observed[i];
                if (observed->retire_owner == library &&
                    !observed->retire_started) {
                    retire_key = observed->key;
                    observed->retire_started = 1;
                    from_observation = 1;
                    break;
                }
            }
        }
        if (!retire_key.link_map_addr)
            break;

        pthread_mutex_unlock(&bindings->lock);
#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
        if (test_before_registry_retire)
            test_before_registry_retire(
                bindings, &retire_key, library, from_observation,
                test_before_registry_retire_opaque);
#endif
        if (!registry) {
            fprintf(stderr,
                    "KZT binding retire unavailable (registry missing): link_map=%p generation=%lu; continuing legacy flow\n",
                    (void *)retire_key.link_map_addr,
                    retire_key.generation);
            pthread_mutex_lock(&bindings->lock);
            ++bindings->diagnostics.registry_missing;
            pthread_mutex_unlock(&bindings->lock);
        } else {
            uint64_t retire_start = timing_start
                                        ? kzt_lifecycle_diagnostics_now()
                                        : 0;
            int retire_result = kzt_guest_registry_retire(
                registry, retire_key.link_map_addr, retire_key.generation);

            if (retire_start) {
                uint64_t duration =
                    kzt_lifecycle_diagnostics_now() - retire_start;
                retire_ns += duration;
                kzt_lifecycle_diagnostics_add(
                    KZT_LIFECYCLE_REGISTRY_RETIRE, duration);
            }
            if (retire_result != 0 &&
                kzt_guest_registry_wait_retired(
                    registry, retire_key.link_map_addr,
                    retire_key.generation) != 0) {
                /* An exact generation already in UNLOADING is waited to DEAD
                 * by wait_retired(). Disabled/missing/replaced/unprovable
                 * state is a new-KZT failure and keeps legacy flow alive. */
                fprintf(stderr,
                        "KZT binding retire state unprovable: link_map=%p generation=%lu; continuing legacy flow\n",
                        (void *)retire_key.link_map_addr,
                        retire_key.generation);
                pthread_mutex_lock(&bindings->lock);
                ++bindings->diagnostics.retire_unprovable;
                pthread_mutex_unlock(&bindings->lock);
            }
        }
        pthread_mutex_lock(&bindings->lock);

        if (from_observation) {
            for (size_t i = 0; i < bindings->observed_count; ++i) {
                kzt_guest_library_observed_t *observed =
                    &bindings->observed[i];
                if (observed->retire_owner == library &&
                    observed->retire_started &&
                    same_key(&observed->key, &retire_key)) {
                    memset(observed, 0, sizeof(*observed));
                    break;
                }
            }
        }
    }

wait_or_out:
    if (!owns_lifecycle) {
        while (waits_for_lifecycle) {
            lifecycle = find_lifecycle_locked(bindings, library);
            if (!lifecycle ||
                lifecycle->state != KZT_GUEST_LIBRARY_BINDING_UNLOADING)
                break;
#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
            if (test_before_lifecycle_wait)
                test_before_lifecycle_wait(
                    bindings, library, test_before_lifecycle_wait_opaque);
#endif
            pthread_cond_wait(&bindings->idle, &bindings->lock);
        }
        goto out;
    }

    /* Phase 3 waits only for binding handles.  Handle release takes
     * bindings->lock but no registry or access lock. */
    for (;;) {
        int busy = 0;
        for (size_t i = 0; i < bindings->count; ++i)
            if (bindings->entries[i].library == library &&
                bindings->entries[i].references)
                busy = 1;
        if (!busy) break;
        pthread_cond_wait(&bindings->idle, &bindings->lock);
    }
    for (size_t i = 0; i < bindings->count; ++i)
        if (bindings->entries[i].library == library)
            bindings->entries[i].state = KZT_GUEST_LIBRARY_BINDING_DEAD;
    lifecycle = find_lifecycle_locked(bindings, library);
    if (lifecycle)
        lifecycle->state = KZT_GUEST_LIBRARY_BINDING_DEAD;
    pthread_cond_broadcast(&bindings->idle);
out:
    pthread_mutex_unlock(&bindings->lock);
    if (timing_start) {
        uint64_t duration = kzt_lifecycle_diagnostics_now() - timing_start;

        kzt_lifecycle_diagnostics_add(
            KZT_LIFECYCLE_BINDING_CLEANUP,
            duration >= retire_ns ? duration - retire_ns : duration);
    }
}

#ifdef KZT_GUEST_LIBRARY_BINDING_TEST
int kzt_guest_library_binding_test_get_diagnostics(
    kzt_guest_library_bindings_t *bindings,
    unsigned long *registry_missing,
    unsigned long *retire_unprovable)
{
    if (registry_missing) *registry_missing = 0;
    if (retire_unprovable) *retire_unprovable = 0;
    if (!bindings) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (registry_missing)
        *registry_missing = bindings->diagnostics.registry_missing;
    if (retire_unprovable)
        *retire_unprovable = bindings->diagnostics.retire_unprovable;
    pthread_mutex_unlock(&bindings->lock);
    return 0;
}

int kzt_guest_library_binding_test_snapshot(
    kzt_guest_library_bindings_t *bindings, library_t *library,
    kzt_guest_library_binding_state_t *lifecycle_state,
    size_t *active_pending, size_t *live_entries)
{
    kzt_guest_library_lifecycle_t *lifecycle;
    if (lifecycle_state)
        *lifecycle_state = KZT_GUEST_LIBRARY_BINDING_DEAD;
    if (active_pending) *active_pending = 0;
    if (live_entries) *live_entries = 0;
    if (!bindings || !library) return -1;
    pthread_mutex_lock(&bindings->lock);
    lifecycle = find_lifecycle_locked(bindings, library);
    if (lifecycle_state && lifecycle)
        *lifecycle_state = lifecycle->state;
    for (size_t i = 0; i < bindings->pending_count; ++i)
        if (bindings->pending[i].library == library &&
            bindings->pending[i].active && active_pending)
            ++*active_pending;
    for (size_t i = 0; i < bindings->count; ++i)
        if (bindings->entries[i].library == library &&
            bindings->entries[i].state == KZT_GUEST_LIBRARY_BINDING_LIVE &&
            live_entries)
            ++*live_entries;
    pthread_mutex_unlock(&bindings->lock);
    return lifecycle ? 0 : -1;
}

int kzt_guest_library_binding_test_loader_state(
    kzt_guest_library_bindings_t *bindings,
    unsigned int *lease_readers, unsigned int *lease_waiters,
    unsigned int *active_scopes, int *is_shutting_down)
{
    if (lease_readers) *lease_readers = 0;
    if (lease_waiters) *lease_waiters = 0;
    if (active_scopes) *active_scopes = 0;
    if (is_shutting_down) *is_shutting_down = 0;
    if (!bindings) return -1;
    pthread_mutex_lock(&bindings->lock);
    if (lease_readers)
        *lease_readers = bindings->loader_quiescence_readers;
    if (lease_waiters)
        *lease_waiters = bindings->loader_quiescence_waiters;
    if (active_scopes && bindings->loader_state) {
        for (size_t i = 0; i < KZT_LOADER_ATTEMPT_SLOTS; ++i)
            if (bindings->loader_state->attempts[i].active)
                ++*active_scopes;
    }
    if (is_shutting_down)
        *is_shutting_down = shutting_down(bindings);
    pthread_mutex_unlock(&bindings->lock);
    return 0;
}
#endif

void kzt_guest_library_unbind(kzt_guest_library_bindings_t *bindings,
                              kzt_guest_registry_t *registry,
                              library_t *library,
                              uintptr_t guest_link_map_hint)
{
    unload_library(bindings, registry, library, guest_link_map_hint, 1);
}

void kzt_guest_library_inactivate(kzt_guest_library_bindings_t *bindings,
                                  kzt_guest_registry_t *registry,
                                  library_t *library,
                                  uintptr_t guest_link_map_hint)
{
    unload_library(bindings, registry, library, guest_link_map_hint, 0);
}
