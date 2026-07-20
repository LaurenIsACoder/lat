#include "dlopen_recycle_transaction.h"

void *dlopen_recycle_transaction(
    void *success_handle, size_t *count, int increment_count, void *opaque,
    dlopen_recycle_prepare_fn prepare, dlopen_recycle_step_fn guest_open,
    dlopen_recycle_step_fn reload,
    dlopen_recycle_rollback_fn rollback)
{
    int guest_opened = 0;

    if (!success_handle || !count || !prepare || !guest_open || !reload ||
        !rollback)
        return NULL;
    prepare(opaque);
    if (guest_open(opaque) != 0) {
        rollback(opaque, 0);
        return NULL;
    }
    guest_opened = 1;
    if (reload(opaque) != 0) {
        rollback(opaque, guest_opened);
        return NULL;
    }
    if (increment_count)
        ++*count;
    return success_handle;
}
