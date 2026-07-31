#ifndef __BRIDGE_H_
#define __BRIDGE_H_
#include <stdint.h>
#include "lsenv.h"

typedef struct bridge_s bridge_t;
typedef struct box64context_s box64context_t;
typedef void (*wrapper_t)( uintptr_t fnc);
typedef struct brick_s brick_t;
brick_t* NewBrick(void);
bridge_t *NewBridge(void);
/* Call only after all concurrent bridge users have stopped. */
void FreeBridge(bridge_t** bridge);

/* KZT callers must preserve the guest path when this process-wide proof is
 * unavailable.  Legacy bridge users remain available for compatibility. */
int BridgeForkProtectionAvailable(void);

uintptr_t AddBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N, const char* name);
uintptr_t CheckBridged(bridge_t* bridge, void* fnc);
uintptr_t AddCheckBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N, const char* name);
uintptr_t AddAutomaticBridge(bridge_t* bridge, wrapper_t w, void* fnc, int N);
void* GetNativeFnc(uintptr_t fnc);
void* GetNativeFncOrFnc(uintptr_t fnc);

int hasAlternate(void* addr);
void* getAlternate(void* addr);
void addAlternate(void* addr, void* alt);
void cleanAlternate(void);

#ifdef BRIDGE_TEST
typedef void (*bridge_test_hook_fn)(void *opaque);
void bridge_test_set_after_check_hook(bridge_test_hook_fn hook, void *opaque);
void bridge_test_set_before_free_hook(bridge_test_hook_fn hook, void *opaque);
int bridge_test_lock_is_held(bridge_t *bridge);
#endif

void init_bridge_helper(void);
void fini_bridge_helper(void);

#endif //__BRIDGE_H_
