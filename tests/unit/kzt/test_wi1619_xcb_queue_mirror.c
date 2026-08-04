#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kzt_xcb_queue_mirror.h"

#define CHECK(label, condition)                                             \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s: FAIL\n", label);                        \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

typedef struct guarded_queue {
    uint8_t before;
    char data[8];
    uint8_t after;
} guarded_queue_t;

static void test_live_bytes_are_copied(void)
{
    guarded_queue_t dest = { .before = 0x41, .after = 0x42 };
    char source[8] = "request";
    int length = -1;

    CHECK("queue live size", kzt_xcb_queue_copy(
          dest.data, sizeof(dest.data), &length,
          source, sizeof(source), 7) == 7);
    CHECK("queue live bytes",
          length == 7 && memcmp(dest.data, source, 7) == 0);
    CHECK("queue live bounds", dest.before == 0x41 && dest.after == 0x42);
}

static void test_invalid_lengths_are_clamped(void)
{
    guarded_queue_t dest = {
        .before = 0x51,
        .data = "unchange",
        .after = 0x52,
    };
    char source[16] = "0123456789abcde";
    int length = -1;

    CHECK("queue negative size", kzt_xcb_queue_copy(
          dest.data, sizeof(dest.data), &length,
          source, sizeof(source), -1) == 0 && length == 0);
    CHECK("queue negative unchanged",
          memcmp(dest.data, "unchange", sizeof(dest.data)) == 0);
    CHECK("queue oversized size", kzt_xcb_queue_copy(
          dest.data, sizeof(dest.data), &length,
          source, sizeof(source), 32) == sizeof(dest.data));
    CHECK("queue oversized bytes",
          length == (int)sizeof(dest.data) &&
          memcmp(dest.data, source, sizeof(dest.data)) == 0);
    CHECK("queue oversized bounds",
          dest.before == 0x51 && dest.after == 0x52);
}

static void test_unsupported_flush_state_falls_back(void)
{
    CHECK("flush state ordinary", kzt_xcb_flush_state_is_supported(
          64, 128, 2, 1, 0, 0, 0, 0));
    CHECK("flush state negative queue", !kzt_xcb_flush_state_is_supported(
          -1, 128, 0, 0, 0, 0, 0, 0));
    CHECK("flush state oversized queue", !kzt_xcb_flush_state_is_supported(
          129, 128, 0, 0, 0, 0, 0, 0));
    CHECK("flush state invalid fds", !kzt_xcb_flush_state_is_supported(
          0, 128, 17, 0, 0, 0, 0, 0));
    CHECK("flush state active writer", !kzt_xcb_flush_state_is_supported(
          0, 128, 0, 0, 1, 0, 0, 0));
    CHECK("flush state socket owner", !kzt_xcb_flush_state_is_supported(
          0, 128, 0, 0, 0, 1, 1, 1));
}

static __attribute__((noinline)) size_t benchmark_queue_copy(
    char *dest, int *length, const char *source)
{
    return kzt_xcb_queue_copy(
        dest, 64, length, source, 64, 64);
}

static void run_benchmark(void)
{
    const unsigned int iterations = 200000;
    char source[64] = { 0 };
    char dest[64] = { 0 };
    struct timespec start;
    struct timespec end;
    uint64_t elapsed_ns;
    double ns_per_copy;
    volatile unsigned int checksum = 0;
    int length = 0;
    unsigned int i;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < iterations; ++i) {
        source[i & 63] = (char)i;
        benchmark_queue_copy(dest, &length, source);
        checksum += (unsigned char)dest[i & 63];
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (uint64_t)(
        (end.tv_sec - start.tv_sec) * 1000000000LL +
        end.tv_nsec - start.tv_nsec);
    ns_per_copy = (double)elapsed_ns / iterations;
    printf("wi1619-xcb-queue-mirror-performance: %.2f ns/64-byte-copy\n",
           ns_per_copy);
    CHECK("queue benchmark result",
          length == 64 && dest[0] == source[0] && checksum != 0);
    CHECK("queue benchmark upper bound", ns_per_copy < 500.0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--benchmark") == 0) {
        run_benchmark();
        return EXIT_SUCCESS;
    }
    test_live_bytes_are_copied();
    test_invalid_lengths_are_clamped();
    test_unsupported_flush_state_falls_back();
    puts("wi1619-xcb-queue-mirror: PASS");
    return EXIT_SUCCESS;
}
