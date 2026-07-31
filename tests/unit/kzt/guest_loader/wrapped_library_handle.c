#include "guest_loader_test.h"

void _start(void)
{
    static const char scenario[] = "wrapped-library-handle";
    void *handle;
    void *duplicate;
    void *noload;
    void *link_map = 0;
    void *symbol;

    wi600_clear_dlerror();
    handle = dlopen("libdl.so.2", WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(handle != 0, scenario, 10, "libdl dlopen failed");
    wi600_require(dlinfo(handle, WI600_RTLD_DI_LINKMAP, &link_map) == 0,
                  scenario, 11, "libdl dlinfo failed");
    wi600_require(link_map == handle, scenario, 12,
                  "dlopen did not return the guest link_map handle");

    symbol = dlsym(handle, "dlopen");
    wi600_require(symbol != 0, scenario, 13, "libdl dlopen lookup failed");

    duplicate = dlopen("libdl.so.2",
                       WI600_RTLD_NOW | WI600_RTLD_LOCAL);
    wi600_require(duplicate == handle, scenario, 14,
                  "duplicate dlopen changed the guest handle");

    noload = dlopen("libdl.so.2",
                    WI600_RTLD_NOW | WI600_RTLD_NOLOAD);
    wi600_require(noload == handle, scenario, 15,
                  "RTLD_NOLOAD did not return the guest handle");
    wi600_require(dlclose(noload) == 0, scenario, 16,
                  "RTLD_NOLOAD handle close failed");
    wi600_require(dlclose(duplicate) == 0, scenario, 17,
                  "duplicate handle close failed");
    wi600_require(dlclose(handle) == 0, scenario, 18,
                  "original handle close failed");

    wi600_pass(scenario);
}
