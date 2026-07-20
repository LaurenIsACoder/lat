#ifndef KZT_BRIDGE_EXACT_H
#define KZT_BRIDGE_EXACT_H

#include <stdint.h>

typedef void (*kzt_bridge_wrapper_t)(uintptr_t fnc);

int kzt_bridge_is_exact(uintptr_t target, kzt_bridge_wrapper_t wrapper,
                        void *native_symbol);

#endif
