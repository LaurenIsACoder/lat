#include "guest_loader_test.h"

#define SCENARIO "dependency-reopen"
#define PLUGIN "libwi600_plugin.so"
#define SYMBOL "wi600_plugin_value"

void _start(void)
{
    wi600_value_function_t value;
    void *first;
    void *noload;
    void *nodelete;
    void *second;
    void *reopened;

    first = dlopen(PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(first != (void *)0, SCENARIO, 90,
                  "initial plugin dlopen failed");
    second = dlopen(PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(second != (void *)0, SCENARIO, 91,
                  "duplicate plugin dlopen failed");
    wi600_require(second == first, SCENARIO, 92,
                  "duplicate dlopen returned a different handle");

    wi600_clear_dlerror();
    value = wi600_value_symbol(second, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0, SCENARIO, 93,
                  "dlsym failed for dependency-backed symbol");
    wi600_require(dlerror() == (char *)0, SCENARIO, 94,
                  "successful dlsym left an error");
    wi600_require(value() == 123, SCENARIO, 95,
                  "dependency-backed call did not return 123");

    wi600_require(dlclose(second) == 0, SCENARIO, 96,
                  "first dlclose failed");
    wi600_require(value() == 123, SCENARIO, 97,
                  "remaining reference was not callable");
    wi600_require(dlclose(first) == 0, SCENARIO, 98,
                  "final dlclose failed");
    wi600_clear_dlerror();
    noload = dlopen(
        PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL | WI600_RTLD_NOLOAD);
    wi600_require(noload == (void *)0, SCENARIO, 99,
                  "fully closed object remained visible to NOLOAD");
    wi600_require(dlerror() != (char *)0, SCENARIO, 100,
                  "NOLOAD miss did not report an error");

    reopened = dlopen(PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(reopened != (void *)0, SCENARIO, 101,
                  "reopen after full close failed");
    wi600_clear_dlerror();
    value = wi600_value_symbol(reopened, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0, SCENARIO, 102,
                  "dlsym after reopen failed");
    wi600_require(dlerror() == (char *)0, SCENARIO, 103,
                  "reopened dlsym left an error");
    wi600_require(value() == 123, SCENARIO, 104,
                  "reopened plugin call did not return 123");
    wi600_require(dlclose(reopened) == 0, SCENARIO, 105,
                  "reopened plugin dlclose failed");

    nodelete = dlopen(
        PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL | WI600_RTLD_NODELETE);
    wi600_require(nodelete != (void *)0, SCENARIO, 106,
                  "NODELETE dlopen failed");
    wi600_require(dlclose(nodelete) == 0, SCENARIO, 107,
                  "NODELETE dlclose failed");
    wi600_clear_dlerror();
    noload = dlopen(
        PLUGIN, WI600_RTLD_NOW | WI600_RTLD_LOCAL | WI600_RTLD_NOLOAD);
    wi600_require(noload != (void *)0, SCENARIO, 108,
                  "NODELETE object disappeared after dlclose");
    wi600_clear_dlerror();
    value = wi600_value_symbol(noload, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0, SCENARIO, 109,
                  "NODELETE object symbol lookup failed");
    wi600_require(dlerror() == (char *)0, SCENARIO, 110,
                  "NODELETE symbol lookup left an error");
    wi600_require(value() == 123, SCENARIO, 111,
                  "NODELETE object symbol call failed");
    wi600_require(dlclose(noload) == 0, SCENARIO, 112,
                  "NODELETE NOLOAD handle close failed");
    wi600_pass(SCENARIO);
}
