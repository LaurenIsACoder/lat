#ifndef LATX_ELFMAP_H
#define LATX_ELFMAP_H

#include <stddef.h>
#include <stdint.h>

#include "elf.h"

int GetElfLoadRange(const Elf64_Phdr *program_headers,
                    size_t program_header_count,
                    uintptr_t load_bias,
                    uintptr_t page_size,
                    uintptr_t *map_start,
                    uintptr_t *map_end);

int GetElfDynamicAddress(const Elf64_Phdr *program_headers,
                         size_t program_header_count,
                         uintptr_t load_bias,
                         uintptr_t *dynamic_addr);

#endif
