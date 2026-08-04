extern int wi600_helper_value(void);

int wi600_plugin_value(void)
{
    return wi600_helper_value() + 118;
}
