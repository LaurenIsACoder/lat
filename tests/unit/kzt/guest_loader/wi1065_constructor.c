#include "guest_loader_test.h"

__attribute__((constructor)) static void wi1065_constructor(void)
{
    wi600_write_text(1, "WI1065_CONSTRUCTOR\n");
}

int wi1065_constructor_value(void)
{
    return 1065;
}
