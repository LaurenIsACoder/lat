#ifndef KZT_GUEST_PROBE_H
#define KZT_GUEST_PROBE_H

#include <stdint.h>

#define KZT_GUEST_PROBE_CALL_COUNT 2

struct kzt_guest_probe_result {
    uintptr_t slot_addr;
    uintptr_t before;
    uintptr_t after_first;
    uintptr_t after_second;
    uint64_t first_call_ns;
    uint64_t second_call_ns;
};

int kzt_guest_probe(struct kzt_guest_probe_result *result);

#endif
