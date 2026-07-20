#include "elf_plt_relocation.h"

int elf_plt_relocation_apply(elf_plt_relocation_apply_fn apply, void *opaque,
                             int *need_resolver)
{
    if (!apply)
        return -1;
    return apply(opaque, need_resolver) ? -1 : 0;
}
