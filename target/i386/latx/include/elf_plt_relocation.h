#ifndef ELF_PLT_RELOCATION_H
#define ELF_PLT_RELOCATION_H

typedef int (*elf_plt_relocation_apply_fn)(void *opaque,
                                           int *need_resolver);

int elf_plt_relocation_apply(elf_plt_relocation_apply_fn apply, void *opaque,
                             int *need_resolver);

#endif
