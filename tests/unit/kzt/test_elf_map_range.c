#include <stdint.h>
#include <stdio.h>

#include "elfmap.h"

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_address(const char *name, uintptr_t got,
                          uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static Elf64_Phdr load_segment(uint64_t virtual_address, uint64_t memory_size)
{
    return (Elf64_Phdr) {
        .p_type = PT_LOAD,
        .p_vaddr = virtual_address,
        .p_memsz = memory_size,
    };
}

static void expect_failure(const char *name, const Elf64_Phdr *headers,
                           size_t count, uintptr_t load_bias,
                           uintptr_t page_size)
{
    uintptr_t start = 0x11111111;
    uintptr_t end = 0x22222222;

    check_int(name, GetElfLoadRange(headers, count, load_bias, page_size,
                                    &start, &end), -1);
    check_address("failure-preserves-start", start, 0x11111111);
    check_address("failure-preserves-end", end, 0x22222222);
}

static void test_single_segment_is_page_aligned(void)
{
    Elf64_Phdr header = load_segment(0x1234, 0x2345);
    uintptr_t start = 0;
    uintptr_t end = 0;

    check_int("single.result",
              GetElfLoadRange(&header, 1, 0x400000, 0x1000,
                              &start, &end), 0);
    check_address("single.start", start, 0x401000);
    check_address("single.end", end, 0x404000);
}

static void test_page_aligned_end_is_not_extended(void)
{
    Elf64_Phdr header = load_segment(0x2000, 0x1000);
    uintptr_t start = 0;
    uintptr_t end = 0;

    check_int("aligned-end.result",
              GetElfLoadRange(&header, 1, 0x800000, 0x1000,
                              &start, &end), 0);
    check_address("aligned-end.start", start, 0x802000);
    check_address("aligned-end.end", end, 0x803000);
}

static void test_multiple_segments_use_outer_range(void)
{
    Elf64_Phdr headers[] = {
        load_segment(0x9000, 0x1100),
        load_segment(0x1234, 0x20),
        load_segment(0x5000, 0x2800),
    };
    uintptr_t start = 0;
    uintptr_t end = 0;

    check_int("multiple.result",
              GetElfLoadRange(headers, 3, 0x100000, 0x1000,
                              &start, &end), 0);
    check_address("multiple.start", start, 0x101000);
    check_address("multiple.end", end, 0x10b000);
}

static void test_non_load_and_empty_segments_are_ignored(void)
{
    Elf64_Phdr headers[] = {
        {
            .p_type = PT_DYNAMIC,
            .p_vaddr = UINT64_MAX - 1,
            .p_memsz = UINT64_MAX,
        },
        load_segment(UINT64_MAX, 0),
        load_segment(0x3001, 1),
    };
    uintptr_t start = 0;
    uintptr_t end = 0;

    check_int("ignored.result",
              GetElfLoadRange(headers, 3, 0, 0x1000, &start, &end), 0);
    check_address("ignored.start", start, 0x3000);
    check_address("ignored.end", end, 0x4000);
}

static void test_invalid_arguments(void)
{
    Elf64_Phdr header = load_segment(0x1000, 0x1000);
    uintptr_t start = 0x11111111;
    uintptr_t end = 0x22222222;

    check_int("null-headers",
              GetElfLoadRange(NULL, 1, 0, 0x1000, &start, &end), -1);
    check_int("zero-count",
              GetElfLoadRange(&header, 0, 0, 0x1000, &start, &end), -1);
    check_int("null-start",
              GetElfLoadRange(&header, 1, 0, 0x1000, NULL, &end), -1);
    check_int("null-end",
              GetElfLoadRange(&header, 1, 0, 0x1000, &start, NULL), -1);
    check_int("aliased-output",
              GetElfLoadRange(&header, 1, 0, 0x1000, &start, &start), -1);
    expect_failure("zero-page-size", &header, 1, 0, 0);
    expect_failure("non-power-of-two-page-size", &header, 1, 0, 0x1800);
}

static void test_missing_load_segment(void)
{
    Elf64_Phdr non_load = {
        .p_type = PT_DYNAMIC,
        .p_vaddr = 0x1000,
        .p_memsz = 0x1000,
    };
    Elf64_Phdr empty_load = load_segment(0x1000, 0);

    expect_failure("no-load", &non_load, 1, 0, 0x1000);
    expect_failure("empty-load", &empty_load, 1, 0, 0x1000);
}

static void test_segment_end_overflow(void)
{
    Elf64_Phdr header = load_segment(UINT64_MAX - 0xfff, 0x1000);

    expect_failure("segment-end-overflow", &header, 1, 0, 0x1000);
}

static void test_page_rounding_overflow(void)
{
    Elf64_Phdr header = load_segment(UINTPTR_MAX - 0x7ff, 0x400);

    expect_failure("page-rounding-overflow", &header, 1, 0, 0x1000);
}

static void test_load_bias_overflow(void)
{
    Elf64_Phdr header = load_segment(0x1000, 0x1000);

    expect_failure("load-bias-start-overflow", &header, 1,
                   UINTPTR_MAX, 0x1000);
    expect_failure("load-bias-end-overflow", &header, 1,
                   UINTPTR_MAX - 0x1000, 0x1000);
}

static void test_dynamic_runtime_address_ignores_empty_image_info_hint(void)
{
    Elf64_Phdr headers[] = {
        load_segment(0, 0x3000),
        {
            .p_type = PT_DYNAMIC,
            .p_vaddr = 0x2f00,
            .p_memsz = 0x100,
        },
    };
    uintptr_t image_info_pt_dynamic_addr = 0;
    uintptr_t dynamic_addr = image_info_pt_dynamic_addr;

    check_int("dynamic.normal-x86-image",
              GetElfDynamicAddress(headers, 2, 0x400000, &dynamic_addr), 0);
    check_address("dynamic.from-main-elf-phdr", dynamic_addr, 0x402f00);
}

static void test_dynamic_runtime_address_rejects_bad_evidence(void)
{
    Elf64_Phdr missing = load_segment(0, 0x1000);
    Elf64_Phdr duplicate[] = {
        { .p_type = PT_DYNAMIC, .p_vaddr = 0x1000 },
        { .p_type = PT_DYNAMIC, .p_vaddr = 0x2000 },
    };
    Elf64_Phdr overflow = {
        .p_type = PT_DYNAMIC,
        .p_vaddr = UINTPTR_MAX,
    };
    uintptr_t dynamic_addr = 0x11111111;

    check_int("dynamic.missing",
              GetElfDynamicAddress(&missing, 1, 0x400000,
                                   &dynamic_addr), -1);
    check_int("dynamic.duplicate",
              GetElfDynamicAddress(duplicate, 2, 0x400000,
                                   &dynamic_addr), -1);
    check_int("dynamic.overflow",
              GetElfDynamicAddress(&overflow, 1, 1, &dynamic_addr), -1);
    check_address("dynamic.failure-preserves-output", dynamic_addr,
                  0x11111111);
}

#if UINTPTR_MAX < UINT64_MAX
static void test_elf_address_too_wide_for_host(void)
{
    Elf64_Phdr start_too_wide = load_segment((uint64_t)UINTPTR_MAX + 1, 1);
    Elf64_Phdr end_too_wide = load_segment(UINTPTR_MAX - 0x100, 0x200);

    expect_failure("start-too-wide", &start_too_wide, 1, 0, 1);
    expect_failure("end-too-wide", &end_too_wide, 1, 0, 1);
}
#endif

int main(void)
{
    test_single_segment_is_page_aligned();
    test_page_aligned_end_is_not_extended();
    test_multiple_segments_use_outer_range();
    test_non_load_and_empty_segments_are_ignored();
    test_invalid_arguments();
    test_missing_load_segment();
    test_segment_end_overflow();
    test_page_rounding_overflow();
    test_load_bias_overflow();
    test_dynamic_runtime_address_ignores_empty_image_info_hint();
    test_dynamic_runtime_address_rejects_bad_evidence();
#if UINTPTR_MAX < UINT64_MAX
    test_elf_address_too_wide_for_host();
#endif

    if (failures) {
        fprintf(stderr, "kzt-elf-map-range: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-elf-map-range: all tests passed");
    return 0;
}
