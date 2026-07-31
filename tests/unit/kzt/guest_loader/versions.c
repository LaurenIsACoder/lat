int wi600_versioned_value_v1(void)
{
    return 101;
}

int wi600_versioned_value_v2(void)
{
    return 202;
}

__asm__(".symver wi600_versioned_value_v1,wi600_versioned_value@WI600_1.0");
__asm__(".symver wi600_versioned_value_v2,wi600_versioned_value@@WI600_2.0");
