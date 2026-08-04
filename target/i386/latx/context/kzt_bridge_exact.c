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

int kzt_guarded_bridge_is_exact(
    uintptr_t target, kzt_bridge_wrapper_t wrapper, void *native_symbol,
    uintptr_t guest_fallback_target, kzt_bridge_guard_kind_t guard_kind)
{
    onebridge_t *entry = (onebridge_t *)target;

    return guest_fallback_target &&
           guard_kind == KZT_BRIDGE_GUARD_XCB_CONNECTION &&
           kzt_bridge_is_exact(target, wrapper, native_symbol) &&
           entry->guest_fallback_target == guest_fallback_target &&
           entry->guard_kind == guard_kind;
}
