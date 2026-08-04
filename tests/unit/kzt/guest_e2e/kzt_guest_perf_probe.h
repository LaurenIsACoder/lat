#ifndef KZT_GUEST_PERF_PROBE_H
#define KZT_GUEST_PERF_PROBE_H

#include <stdint.h>

struct kzt_guest_perf_result {
    uintptr_t slot_addr;
    uintptr_t before;
    uintptr_t after_first;
    uintptr_t after_steady;
    uint64_t first_call_ns;
    uint64_t steady_total_ns;
    uint64_t steady_per_call_ns;
    uint64_t steady_calls;
    uint64_t checksum;
};

int kzt_guest_perf_first(struct kzt_guest_perf_result *result);
int kzt_guest_perf_steady(uint64_t steady_calls,
                          struct kzt_guest_perf_result *result);

#endif
