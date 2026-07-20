#include "kzt_guest_probe.h"

static long raw_syscall3(long number, long arg1, long arg2, long arg3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory");
    return result;
}

static void raw_exit(int status)
{
    __asm__ volatile(
        "syscall"
        :
        : "a"(60L), "D"((long)status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static char *append_text(char *cursor, const char *text)
{
    while (*text) {
        *cursor++ = *text++;
    }
    return cursor;
}

static char *append_hex(char *cursor, uintptr_t value)
{
    static const char digits[] = "0123456789abcdef";
    int shift;

    cursor = append_text(cursor, "0x");
    for (shift = (int)(sizeof(value) * 8) - 4; shift > 0; shift -= 4) {
        if ((value >> shift) != 0) {
            break;
        }
    }
    for (; shift >= 0; shift -= 4) {
        *cursor++ = digits[(value >> shift) & 0xf];
    }
    return cursor;
}

void _start(void)
{
    static const char failure[] = "KZT_GUEST_E2E_FAIL\n";
    struct kzt_guest_probe_result result;
    char success[256];
    char *cursor = success;

    if (kzt_guest_probe(&result) != 0) {
        (void)raw_syscall3(1, 2, (long)failure, sizeof(failure) - 1);
        raw_exit(1);
    }
    cursor = append_text(cursor, "KZT_GUEST_E2E_OK calls=2 slot=");
    cursor = append_hex(cursor, result.slot_addr);
    cursor = append_text(cursor, " before=");
    cursor = append_hex(cursor, result.before);
    cursor = append_text(cursor, " after_first=");
    cursor = append_hex(cursor, result.after_first);
    cursor = append_text(cursor, " after_second=");
    cursor = append_hex(cursor, result.after_second);
    cursor = append_text(cursor, " first_ns=");
    cursor = append_hex(cursor, result.first_call_ns);
    cursor = append_text(cursor, " second_ns=");
    cursor = append_hex(cursor, result.second_call_ns);
    *cursor++ = '\n';
    if (raw_syscall3(1, 1, (long)success, cursor - success) !=
        cursor - success) {
        raw_exit(2);
    }
    raw_exit(0);
}
