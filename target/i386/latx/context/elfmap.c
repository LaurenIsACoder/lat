#include <stdint.h>

#include "elfmap.h"

static int AddToAddress(uintptr_t base, uint64_t offset, uintptr_t *result)
{
    if (offset > UINTPTR_MAX || base > UINTPTR_MAX - (uintptr_t)offset) {
        return -1;
    }
    *result = base + (uintptr_t)offset;
    return 0;
}

int GetElfLoadRange(
    const Elf64_Phdr *program_headers,
    size_t program_header_count,
    uintptr_t load_bias,
    uintptr_t page_size,
    uintptr_t *map_start,
    uintptr_t *map_end)
{
    if (!program_headers || !program_header_count || !map_start || !map_end
        || !page_size || (page_size & (page_size - 1))) {
        return -1;
    }

    uintptr_t first = UINTPTR_MAX;
    uintptr_t last = 0;
    uintptr_t page_mask = page_size - 1;
    int found_load_segment = 0;

    for (size_t i = 0; i < program_header_count; ++i) {
        const Elf64_Phdr *header = &program_headers[i];
        if (header->p_type != PT_LOAD || !header->p_memsz) {
            continue;
        }

        if (header->p_vaddr > UINT64_MAX - header->p_memsz) {
            return -1;
        }
        uint64_t segment_end = header->p_vaddr + header->p_memsz;
        if (header->p_vaddr > UINTPTR_MAX || segment_end > UINTPTR_MAX
            || segment_end > UINTPTR_MAX - page_mask) {
            return -1;
        }

        uintptr_t aligned_start = (uintptr_t)header->p_vaddr & ~page_mask;
        uintptr_t aligned_end =
            ((uintptr_t)segment_end + page_mask) & ~page_mask;
        uintptr_t runtime_start;
        uintptr_t runtime_end;
        if (AddToAddress(load_bias, aligned_start, &runtime_start)
            || AddToAddress(load_bias, aligned_end, &runtime_end)) {
            return -1;
        }

        if (runtime_start < first) {
            first = runtime_start;
        }
        if (runtime_end > last) {
            last = runtime_end;
        }
        found_load_segment = 1;
    }

    if (!found_load_segment || first >= last) {
        return -1;
    }

    *map_start = first;
    *map_end = last;
    return 0;
}
