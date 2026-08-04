#ifndef __BRIDGE_PRIVATE_H_
#define __BRIDGE_PRIVATE_H_
#include <stdint.h>

// the generic wrapper pointer functions
typedef void (*wrapper_t)(uintptr_t fnc);

#ifndef KZT_BRIDGE_GUARD_KIND_DEFINED
#define KZT_BRIDGE_GUARD_KIND_DEFINED
typedef enum kzt_bridge_guard_kind {
    KZT_BRIDGE_GUARD_NONE = 0,
    KZT_BRIDGE_GUARD_XCB_CONNECTION = 1,
} kzt_bridge_guard_kind_t;
#endif

#pragma pack(push, 1)
typedef union onebridge_s {
    struct {
    uint8_t CC;     // CC int 0x3
    uint8_t S, C;   // 'S' 'C', just a signature
    wrapper_t w;    // wrapper
    uintptr_t f;    // the function for the wrapper
    uint8_t C3;     // C2 or C3 ret
    uint16_t N;     // N in case of C2 ret
    uintptr_t guest_fallback_target;
    uint8_t guard_kind;
    };
    struct {
    uint8_t B8;     // B8 00 11 22 33 mov rax, num
    uint32_t num;
    uint8_t _0F; uint8_t _05;   // 0F 05 syscall
    uint8_t _C3;    // C3 ret
    };
    uint64_t dummy[4];
} onebridge_t;
#pragma pack(pop)

_Static_assert(sizeof(onebridge_t) == 32, "onebridge_t ABI must stay 32 bytes");

#endif //__BRIDGE_PRIVATE_H_
