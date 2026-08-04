#include "guest_loader_test.h"

#define SCENARIO "namespace-isolation"
#define LIBRARY "libwi600_namespace.so"
#define SYMBOL "wi600_namespace_value"

void _start(void)
{
    wi600_lmid_t namespace_id = WI600_LM_ID_BASE;
    wi600_value_function_t value;
    void *handle;
    void *main_noload;

    wi600_clear_dlerror();
    value = wi600_value_symbol(WI600_RTLD_DEFAULT, SYMBOL);
    wi600_require(value == (wi600_value_function_t)0, SCENARIO, 90,
                  "namespace symbol was present before dlmopen");
    wi600_require(dlerror() != (char *)0, SCENARIO, 91,
                  "missing pre-dlmopen symbol did not set dlerror");

    handle = dlmopen(WI600_LM_ID_NEWLM, LIBRARY,
                     WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(handle != (void *)0, SCENARIO, 92,
                  "dlmopen(LM_ID_NEWLM) failed");
    wi600_require(dlinfo(handle, WI600_RTLD_DI_LMID, &namespace_id) == 0,
                  SCENARIO, 93, "dlinfo(RTLD_DI_LMID) failed");
    wi600_require(namespace_id != WI600_LM_ID_BASE &&
                      namespace_id != WI600_LM_ID_NEWLM,
                  SCENARIO, 94,
                  "dlinfo did not return a non-main namespace id");

    wi600_clear_dlerror();
    value = wi600_value_symbol(handle, SYMBOL);
    wi600_require(value != (wi600_value_function_t)0 && value() == 211,
                  SCENARIO, 95,
                  "new-namespace symbol was not callable");
    wi600_require(dlerror() == (char *)0, SCENARIO, 96,
                  "new-namespace dlsym left an error");

    main_noload = dlopen(LIBRARY, WI600_RTLD_NOW | WI600_RTLD_NOLOAD);
    wi600_require(main_noload == (void *)0, SCENARIO, 97,
                  "new-namespace object polluted the main namespace");
    wi600_clear_dlerror();
    value = wi600_value_symbol(WI600_RTLD_DEFAULT, SYMBOL);
    wi600_require(value == (wi600_value_function_t)0, SCENARIO, 98,
                  "new-namespace symbol leaked into default scope");
    wi600_require(dlerror() != (char *)0, SCENARIO, 99,
                  "namespace-isolated lookup did not set dlerror");

    wi600_require(dlclose(handle) == 0, SCENARIO, 100,
                  "new-namespace dlclose failed");
    wi600_pass(SCENARIO);
}
