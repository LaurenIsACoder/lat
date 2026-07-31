#include "guest_loader_test.h"

#define SCENARIO "visibility-noload"
#define LIBRARY "libwi600_visibility.so"
#define SYMBOL "wi600_visibility_value"

void _start(void)
{
    wi600_value_function_t value;
    void *global;
    void *local;
    void *noload;

    noload = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_NOLOAD);
    wi600_require(noload == (void *)0, SCENARIO, 90,
                  "NOLOAD found an object before it was loaded");
    wi600_clear_dlerror();

    local = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(local != (void *)0, SCENARIO, 91,
                  "RTLD_LOCAL dlopen failed");
    wi600_clear_dlerror();
    value = wi600_value_symbol(WI600_RTLD_DEFAULT, SYMBOL);
    wi600_require(value == (wi600_value_function_t)0, SCENARIO, 92,
                  "RTLD_LOCAL symbol leaked into default scope");
    wi600_require(dlerror() != (char *)0, SCENARIO, 93,
                  "hidden local symbol did not set dlerror");

    noload = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_NOLOAD);
    wi600_require(noload == local, SCENARIO, 94,
                  "NOLOAD did not return the loaded handle");
    wi600_require(dlclose(noload) == 0, SCENARIO, 95,
                  "NOLOAD reference dlclose failed");
    value = wi600_value_symbol(local, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0 && value() == 77,
                  SCENARIO, 96,
                  "local reference was not callable after NOLOAD close");

    wi600_require(dlclose(local) == 0, SCENARIO, 106,
                  "first local reference dlclose failed");
    noload = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_NOLOAD);
    wi600_require(noload == (void *)0, SCENARIO, 107,
                  "NOLOAD retained an object after the first close cycle");
    wi600_clear_dlerror();

    local = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(local != (void *)0, SCENARIO, 108,
                  "second RTLD_LOCAL dlopen failed");
    global = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_GLOBAL);
    wi600_require(global == local, SCENARIO, 97,
                  "RTLD_GLOBAL reopen did not reuse the handle");
    wi600_clear_dlerror();
    value = wi600_value_symbol(WI600_RTLD_DEFAULT, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0 && value() == 77,
                  SCENARIO, 98,
                  "RTLD_GLOBAL symbol was not visible in default scope");
    wi600_require(dlerror() == (char *)0, SCENARIO, 99,
                  "global default-scope lookup left an error");

    wi600_require(dlclose(local) == 0, SCENARIO, 100,
                  "local reference dlclose failed");
    value = wi600_value_symbol(global, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0 && value() == 77,
                  SCENARIO, 101,
                  "global reference was not callable after local close");
    wi600_require(dlclose(global) == 0, SCENARIO, 102,
                  "global reference dlclose failed");

    /*
     * dlsym(RTLD_DEFAULT) may add a caller dependency and mark the provider
     * NODELETE.  The first close cycle above covers unload/refcount behavior;
     * this cycle covers LOCAL-to-GLOBAL visibility and successful closes.
     */
    wi600_pass(SCENARIO);
}
