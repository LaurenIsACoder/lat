#ifndef KZT_BRIDGE_EXACT_H
#define KZT_BRIDGE_EXACT_H

#include <stdint.h>

#include "bridge_private.h"

typedef void (*kzt_bridge_wrapper_t)(uintptr_t fnc);

int kzt_bridge_is_exact(uintptr_t target, kzt_bridge_wrapper_t wrapper,
                        void *native_symbol);
int kzt_guarded_bridge_is_exact(
    uintptr_t target, kzt_bridge_wrapper_t wrapper, void *native_symbol,
    uintptr_t guest_fallback_target, kzt_bridge_guard_kind_t guard_kind);

#endif
