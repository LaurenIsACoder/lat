#include <stddef.h>

#ifndef KZT_PREEMPTION_PROVIDER
#define KZT_PREEMPTION_PROVIDER 0
#endif

#if KZT_PREEMPTION_PROVIDER == 1
#define KZT_PREEMPTION_MARKER "KZT_PREEMPT_PROVIDER_A\n"
#elif KZT_PREEMPTION_PROVIDER == 2
#define KZT_PREEMPTION_MARKER "KZT_PREEMPT_PROVIDER_B\n"
#elif KZT_PREEMPTION_PROVIDER == 3
#define KZT_PREEMPTION_MARKER "KZT_LOCAL_PREEMPT_PROVIDER\n"
#else
#define KZT_PREEMPTION_MARKER "KZT_PREEMPT_PROVIDER_WEAK\n"
#endif

static long raw_write(int fd, const void *buffer, size_t size)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"((long)fd), "S"((long)buffer), "d"((long)size)
        : "rcx", "r11", "memory");
    return result;
}

#if KZT_PREEMPTION_PROVIDER == 0
__attribute__((weak))
#endif
char *dlerror(void)
{
    static const char marker[] = KZT_PREEMPTION_MARKER;

    (void)raw_write(2, marker, sizeof(marker) - 1);
    return 0;
}
