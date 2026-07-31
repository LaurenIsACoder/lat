#include "kzt_guest_perf_probe.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

extern char *dlerror(void);

struct guest_timespec {
    long seconds;
    long nanoseconds;
};

static uint64_t monotonic_raw_ns(void)
{
    struct guest_timespec value;
    long status;

    __asm__ volatile(
        "syscall"
        : "=a"(status)
        : "a"(228L), "D"(4L), "S"((long)&value)
        : "rcx", "r11", "memory");
    if (status != 0) {
        return 0;
    }
    return (uint64_t)value.seconds * 1000000000ULL +
           (uint64_t)value.nanoseconds;
}

static uintptr_t *dlerror_jump_slot(void)
{
    const unsigned char *plt;
    uint32_t raw_displacement;
    int32_t displacement;

    __asm__ volatile("lea dlerror@PLT(%%rip), %0" : "=r"(plt));
    if (plt[0] != 0xff || plt[1] != 0x25) {
        return 0;
    }
    raw_displacement = (uint32_t)plt[2] |
                       ((uint32_t)plt[3] << 8) |
                       ((uint32_t)plt[4] << 16) |
                       ((uint32_t)plt[5] << 24);
    displacement = (int32_t)raw_displacement;
    return (uintptr_t *)(plt + 6 + displacement);
}

static int dlerror_null_call(uint64_t *checksum)
{
    if (dlerror() != NULL) {
        return -1;
    }
    ++*checksum;
    return 0;
}

static int initialize_result(struct kzt_guest_perf_result *result,
                             uintptr_t **slot)
{
    if (!result || !slot || !(*slot = dlerror_jump_slot())) {
        return -1;
    }
    *result = (struct kzt_guest_perf_result) { 0 };
    result->slot_addr = (uintptr_t)*slot;
    result->before = *(volatile uintptr_t *)*slot;
    return result->before ? 0 : -1;
}

static int kzt_guest_perf_run_first(struct kzt_guest_perf_result *result)
{
    uintptr_t *slot;
    uint64_t before_call;
    uint64_t after_call;

    if (initialize_result(result, &slot) != 0) {
        return 2;
    }

    before_call = monotonic_raw_ns();
    if (!before_call) {
        return 1;
    }
    if (dlerror_null_call(&result->checksum) != 0) {
        return 1;
    }
    after_call = monotonic_raw_ns();
    if (!after_call || after_call < before_call) {
        return 1;
    }
    result->first_call_ns = after_call - before_call;
    result->after_first = *(volatile uintptr_t *)slot;
    result->after_steady = result->after_first;
    return result->after_first ? 0 : 1;
}

int kzt_guest_perf_first(struct kzt_guest_perf_result *result)
{
    return kzt_guest_perf_run_first(result);
}

int kzt_guest_perf_steady(uint64_t steady_calls,
                          struct kzt_guest_perf_result *result)
{
    uintptr_t *slot;
    uint64_t before_call;
    uint64_t after_call;
    uint64_t index;

    if (steady_calls < 100000 ||
        kzt_guest_perf_run_first(result) != 0 ||
        !(slot = (uintptr_t *)result->slot_addr)) {
        return 1;
    }

    before_call = monotonic_raw_ns();
    if (!before_call) {
        return 1;
    }
    for (index = 0; index < steady_calls; ++index) {
        if (dlerror_null_call(&result->checksum) != 0) {
            return 1;
        }
    }
    after_call = monotonic_raw_ns();
    if (!after_call || after_call <= before_call) {
        return 1;
    }
    result->steady_calls = steady_calls;
    result->steady_total_ns = after_call - before_call;
    result->steady_per_call_ns = result->steady_total_ns / steady_calls;
    result->after_steady = *(volatile uintptr_t *)slot;
    return result->steady_per_call_ns == 0 ||
           result->after_steady == 0 ||
           result->checksum != steady_calls + 1 ? 1 : 0;
}
