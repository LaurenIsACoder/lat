#ifndef KZT_PER_OBJECT_GOT_PLT_H
#define KZT_PER_OBJECT_GOT_PLT_H

#include <stdint.h>

#include "kzt_guest_registry.h"

typedef int (*kzt_per_object_got_plt_write_fn)(
    uintptr_t link_map_addr,
    unsigned long generation,
    const kzt_guest_dynamic_view_t *view,
    void *opaque);

typedef enum kzt_per_object_got_plt_status {
    KZT_PER_OBJECT_GOT_PLT_FAIL_OPEN = 0,
    KZT_PER_OBJECT_GOT_PLT_APPLIED,
    KZT_PER_OBJECT_GOT_PLT_IN_PROGRESS,
    KZT_PER_OBJECT_GOT_PLT_ALREADY_APPLIED,
} kzt_per_object_got_plt_status_t;

typedef struct kzt_per_object_got_plt_request {
    kzt_guest_registry_t *registry;
    uintptr_t link_map_addr;
    kzt_per_object_got_plt_write_fn apply;
    void *opaque;
} kzt_per_object_got_plt_request_t;

typedef struct kzt_per_object_got_plt_result {
    kzt_per_object_got_plt_status_t status;
    unsigned long generation;
    int write_attempted;
} kzt_per_object_got_plt_result_t;

/* Runs one exact per-object GOT/PLT transaction.  All unsupported identity
 * or Dynamic View evidence is fail-open and does not call apply(). */
int kzt_per_object_got_plt_apply(
    const kzt_per_object_got_plt_request_t *request,
    kzt_per_object_got_plt_result_t *result);

#endif
