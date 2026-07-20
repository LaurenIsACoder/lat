#ifndef KZT_RELA_STUB_DETECTOR_H
#define KZT_RELA_STUB_DETECTOR_H

#include <stdint.h>

typedef enum kzt_rela_stub_coordinate {
    KZT_RELA_STUB_COORDINATE_UNKNOWN = 0,
    KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW,
    KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
} kzt_rela_stub_coordinate_t;

int kzt_rela_slot_current_is_unresolved_stub(
    uintptr_t slot_current_value, kzt_rela_stub_coordinate_t coordinate,
    intptr_t load_bias,
    uintptr_t plt_start, uintptr_t plt_end,
    uintptr_t gotplt_start, uintptr_t gotplt_end);

#endif
