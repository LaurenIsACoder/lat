#ifndef KZT_GUEST_DL_STATE_H
#define KZT_GUEST_DL_STATE_H

#include <pthread.h>
#include <stdint.h>

typedef struct kzt_guest_dlerror_state_s {
    char *last_error;
    char *last_error_returned;
    uintptr_t guest_dlerror_entry;
    union {
        struct {
            int last_error_guest_consumed;
            int dlerror_slow_required;
        };
        uintptr_t dlerror_fast_result;
    };
    uintptr_t *dlerror_fast_result_mirror;
} kzt_guest_dlerror_state_t;

typedef struct kzt_guest_dl_entries_s {
    uintptr_t dlopen;
    uintptr_t dlmopen;
    uintptr_t dlsym;
    uintptr_t dlclose;
    uintptr_t dladdr;
    uintptr_t dladdr1;
    uintptr_t dlinfo;
    uintptr_t dlvsym;
    uintptr_t dlerror;
} kzt_guest_dl_entries_t;

typedef int (*kzt_guest_dl_entries_resolver_fn)(
    kzt_guest_dl_entries_t *entries, void *opaque);
typedef int (*kzt_guest_dl_entries_prepare_fn)(
    const kzt_guest_dl_entries_t *entries, void *opaque);

typedef enum kzt_guest_runtime_entry_id_e {
    KZT_GUEST_RUNTIME_FREE = 0,
    KZT_GUEST_RUNTIME_REALLOC,
    KZT_GUEST_RUNTIME_PTHREAD_SETCANCELTYPE,
    KZT_GUEST_RUNTIME_ENTRY_COUNT,
} kzt_guest_runtime_entry_id_t;

#define KZT_GUEST_DL_LIFECYCLE_OPEN (1U << 31)
#define KZT_GUEST_DL_LIFECYCLE_CLOSING (1U << 30)
#define KZT_GUEST_DL_LIFECYCLE_USERS \
    ~(KZT_GUEST_DL_LIFECYCLE_OPEN | KZT_GUEST_DL_LIFECYCLE_CLOSING)

typedef struct kzt_guest_dl_entry_state_s {
    pthread_mutex_t mutex;
    pthread_cond_t ready;
    kzt_guest_dl_entries_t *published;
    uintptr_t observed_dlerror;
    pthread_t initializer;
    int initialized;
    int initializing;
    int initializer_valid;
    int teardown;
    unsigned int lifecycle;
    unsigned int slow_users;
    unsigned int runtime_users;
    uintptr_t runtime_entries[KZT_GUEST_RUNTIME_ENTRY_COUNT];
    pthread_t runtime_initializers[KZT_GUEST_RUNTIME_ENTRY_COUNT];
    unsigned int runtime_initializing;
} kzt_guest_dl_entry_state_t;

#endif
