#include "guest_loader_test.h"

#define SCENARIO "symbol-versions-errors"
#define LIBRARY "libwi600_versions.so"
#define MISSING_LIBRARY "libwi600-definitely-missing.so"
#define SYMBOL "wi600_versioned_value"

void _start(void)
{
    wi600_value_function_t value;
    void *handle;
    void *missing;

    handle = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(handle != (void *)0, SCENARIO, 90,
                  "versioned library dlopen failed");

    wi600_clear_dlerror();
    value = wi600_value_symbol(handle, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0 && value() == 202,
                  SCENARIO, 91,
                  "dlsym did not select the default version");
    wi600_require(dlerror() == (char *)0, SCENARIO, 92,
                  "default-version dlsym left an error");

    wi600_clear_dlerror();
    value = wi600_versioned_value_symbol(handle, SYMBOL, "WI600_1.0");
    wi600_require(value != (wi600_value_function_t)0 && value() == 101,
                  SCENARIO, 93, "dlvsym did not select WI600_1.0");
    wi600_require(dlerror() == (char *)0, SCENARIO, 94,
                  "WI600_1.0 dlvsym left an error");

    wi600_clear_dlerror();
    value = wi600_versioned_value_symbol(handle, SYMBOL, "WI600_2.0");
    wi600_require(value != (wi600_value_function_t)0 && value() == 202,
                  SCENARIO, 95, "dlvsym did not select WI600_2.0");
    wi600_require(dlerror() == (char *)0, SCENARIO, 96,
                  "WI600_2.0 dlvsym left an error");

    wi600_clear_dlerror();
    value = wi600_versioned_value_symbol(handle, SYMBOL, "WI600_9.9");
    wi600_require(value == (wi600_value_function_t)0, SCENARIO, 97,
                  "dlvsym accepted an unknown version");
    wi600_require(dlerror() != (char *)0, SCENARIO, 98,
                  "unknown version did not set dlerror");
    wi600_require(dlerror() == (char *)0, SCENARIO, 99,
                  "version error was not consumed exactly once");

    wi600_clear_dlerror();
    missing = dlopen(MISSING_LIBRARY, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(missing == (void *)0, SCENARIO, 100,
                  "missing library unexpectedly opened");
    wi600_require(dlerror() != (char *)0, SCENARIO, 101,
                  "missing library did not set dlerror");
    wi600_require(dlerror() == (char *)0, SCENARIO, 102,
                  "missing-library error was not consumed exactly once");

    wi600_require(dlclose(handle) == 0, SCENARIO, 103,
                  "versioned library dlclose failed");
    wi600_pass(SCENARIO);
}
