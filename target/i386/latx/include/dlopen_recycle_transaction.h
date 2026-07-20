#ifndef DLOPEN_RECYCLE_TRANSACTION_H
#define DLOPEN_RECYCLE_TRANSACTION_H

#include <stddef.h>

typedef int (*dlopen_recycle_step_fn)(void *opaque);
typedef void (*dlopen_recycle_prepare_fn)(void *opaque);
typedef void (*dlopen_recycle_rollback_fn)(void *opaque, int guest_opened);

void *dlopen_recycle_transaction(
    void *success_handle, size_t *count, int increment_count, void *opaque,
    dlopen_recycle_prepare_fn prepare, dlopen_recycle_step_fn guest_open,
    dlopen_recycle_step_fn reload,
    dlopen_recycle_rollback_fn rollback);

#endif
