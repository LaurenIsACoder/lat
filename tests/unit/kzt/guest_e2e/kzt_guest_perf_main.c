#include "kzt_guest_perf_probe.h"

static long raw_write(int descriptor, const char *data, unsigned long length)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"((long)descriptor), "S"((long)data), "d"(length)
        : "rcx", "r11", "memory");
    return result;
}

static char *append_text(char *cursor, const char *text)
{
    while (*text) {
        *cursor++ = *text++;
    }
    return cursor;
}

static char *append_hex(char *cursor, uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    int shift;

    cursor = append_text(cursor, "0x");
    for (shift = 60; shift > 0; shift -= 4) {
        if ((value >> shift) != 0) {
            break;
        }
    }
    for (; shift >= 0; shift -= 4) {
        *cursor++ = digits[(value >> shift) & 0xf];
    }
    return cursor;
}

static int parse_count(const char *text, uint64_t *value)
{
    uint64_t parsed = 0;

    if (!text || !*text) {
        return -1;
    }
    while (*text) {
        unsigned int digit;

        if (*text < '0' || *text > '9') {
            return -1;
        }
        digit = (unsigned int)(*text++ - '0');
        if (parsed > (UINT64_MAX - digit) / 10) {
            return -1;
        }
        parsed = parsed * 10 + digit;
    }
    if (parsed < 100000) {
        return -1;
    }
    *value = parsed;
    return 0;
}

static int text_equals(const char *text, const char *expected)
{
    while (*text && *expected && *text == *expected) {
        ++text;
        ++expected;
    }
    return *text == '\0' && *expected == '\0';
}

int kzt_guest_perf_main(uintptr_t *initial_stack)
{
    static const char usage[] = "KZT_GUEST_PERF_FAIL invalid_mode\n";
    static const char failure[] = "KZT_GUEST_PERF_FAIL probe\n";
    struct kzt_guest_perf_result result = { 0 };
    char **argv = (char **)&initial_stack[1];
    const char *mode;
    char output[512];
    char *cursor = output;

    if (initial_stack[0] < 2 || initial_stack[0] > 3) {
        (void)raw_write(2, usage, sizeof(usage) - 1);
        return 2;
    }
    mode = argv[1];
    if (text_equals(mode, "startup") && initial_stack[0] == 2) {
        /* Loading the DSO is the mode's work; it must not call dlerror. */
    } else if (text_equals(mode, "first") && initial_stack[0] == 2) {
        if (kzt_guest_perf_first(&result) != 0) {
            (void)raw_write(2, failure, sizeof(failure) - 1);
            return 1;
        }
    } else if (text_equals(mode, "steady") && initial_stack[0] == 3 &&
               parse_count(argv[2], &result.steady_calls) == 0) {
        uint64_t steady_calls = result.steady_calls;

        if (kzt_guest_perf_steady(steady_calls, &result) != 0) {
            (void)raw_write(2, failure, sizeof(failure) - 1);
            return 1;
        }
    } else {
        (void)raw_write(2, usage, sizeof(usage) - 1);
        return 2;
    }

    cursor = append_text(cursor, "KZT_GUEST_PERF_OK mode=");
    cursor = append_text(cursor, mode);
    cursor = append_text(cursor, " steady_calls=");
    cursor = append_hex(cursor, result.steady_calls);
    cursor = append_text(cursor, " slot=");
    cursor = append_hex(cursor, result.slot_addr);
    cursor = append_text(cursor, " before=");
    cursor = append_hex(cursor, result.before);
    cursor = append_text(cursor, " after_first=");
    cursor = append_hex(cursor, result.after_first);
    cursor = append_text(cursor, " after_steady=");
    cursor = append_hex(cursor, result.after_steady);
    cursor = append_text(cursor, " first_ns=");
    cursor = append_hex(cursor, result.first_call_ns);
    cursor = append_text(cursor, " steady_total_ns=");
    cursor = append_hex(cursor, result.steady_total_ns);
    cursor = append_text(cursor, " steady_per_call_ns=");
    cursor = append_hex(cursor, result.steady_per_call_ns);
    cursor = append_text(cursor, " checksum=");
    cursor = append_hex(cursor, result.checksum);
    *cursor++ = '\n';
    if (raw_write(1, output, (unsigned long)(cursor - output)) !=
        cursor - output) {
        return 3;
    }
    return 0;
}
