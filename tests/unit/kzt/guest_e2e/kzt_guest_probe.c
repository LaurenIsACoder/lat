#include "kzt_guest_probe.h"

struct guest_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

extern int uname(struct guest_utsname *result);

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

static uintptr_t *uname_jump_slot(void)
{
    const unsigned char *plt;
    uint32_t raw_displacement;
    int32_t displacement;

    __asm__ volatile("lea uname@PLT(%%rip), %0" : "=r"(plt));
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

int kzt_guest_probe(struct kzt_guest_probe_result *result)
{
    struct guest_utsname utsname;
    uintptr_t *slot;
    uint64_t before_call;
    uint64_t after_call;

    if (!result || !(slot = uname_jump_slot())) {
        return 2;
    }
    result->slot_addr = (uintptr_t)slot;
    result->before = *(volatile uintptr_t *)slot;

    before_call = monotonic_raw_ns();
    if (!before_call || uname(&utsname) != 0 ||
        utsname.machine[0] == '\0' ||
        !(after_call = monotonic_raw_ns()) || after_call < before_call) {
        return 1;
    }
    result->first_call_ns = after_call - before_call;
    result->after_first = *(volatile uintptr_t *)slot;

    before_call = monotonic_raw_ns();
    if (!before_call || uname(&utsname) != 0 ||
        utsname.machine[0] == '\0' ||
        !(after_call = monotonic_raw_ns()) || after_call < before_call) {
        return 1;
    }
    result->second_call_ns = after_call - before_call;
    result->after_second = *(volatile uintptr_t *)slot;
    return 0;
}
