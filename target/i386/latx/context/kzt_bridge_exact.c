#include "kzt_bridge_exact.h"

#include "bridge_private.h"

int kzt_bridge_is_exact(uintptr_t target, kzt_bridge_wrapper_t wrapper,
                        void *native_symbol)
{
    onebridge_t *entry = (onebridge_t *)target;

    if (!entry || entry->CC != 0xCC || entry->S != 'S' ||
        entry->C != 'C' || (entry->C3 != 0xC3 && entry->C3 != 0xC2) ||
        entry->w != wrapper || entry->f != (uintptr_t)native_symbol) {
        return 0;
    }
    return 1;
}
