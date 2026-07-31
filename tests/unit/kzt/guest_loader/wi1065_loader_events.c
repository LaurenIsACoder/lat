#include "guest_loader_test.h"

#define SCENARIO "wi1065-loader-events"
#define CONSTRUCTOR_LIBRARY "libwi1065_constructor.so"
#define PARTIAL_RELRO_LIBRARY "libwi1065_partial_relro.so"
#define FULL_RELRO_LIBRARY "libwi1065_full_relro.so"

typedef unsigned long wi1065_thread_t;
typedef void *(*wi1065_thread_start_t)(void *);

extern int pthread_create(wi1065_thread_t *thread, const void *attribute,
                          wi1065_thread_start_t start, void *argument);
extern int pthread_join(wi1065_thread_t thread, void **result);

static int wi1065_open_call_close(const char *library, int flags,
                                  const char *symbol)
{
    wi600_value_function_t value;
    void *handle = dlopen(library, flags | WI600_RTLD_LOCAL);

    if (!handle) {
        return 1;
    }
    wi600_clear_dlerror();
    value = wi600_value_symbol(handle, symbol);
    if (!value || dlerror() != (char *)0 || value() != 1065) {
        (void)dlclose(handle);
        return 2;
    }
    if (dlclose(handle) != 0) {
        return 3;
    }
    return 0;
}

static void *wi1065_loader_worker(void *argument)
{
    (void)argument;
    return wi1065_open_call_close(CONSTRUCTOR_LIBRARY, WI600_RTLD_NOW,
                                  "wi1065_constructor_value") == 0 ?
        (void *)0 : (void *)1;
}

void _start(void)
{
    wi1065_thread_t first;
    wi1065_thread_t second;
    void *first_result = (void *)1;
    void *second_result = (void *)1;

    wi600_write_text(1, "WI1065_STARTUP\n");
    wi600_require(wi1065_open_call_close(CONSTRUCTOR_LIBRARY, WI600_RTLD_NOW,
                                         "wi1065_constructor_value") == 0,
                  SCENARIO, 90, "constructor dlopen/dlclose failed");
    wi600_write_text(1, "WI1065_DLCLOSE constructor\n");

    wi600_require(wi1065_open_call_close(PARTIAL_RELRO_LIBRARY,
                                         WI600_RTLD_LAZY,
                                         "wi1065_relro_value") == 0,
                  SCENARIO, 91, "partial RELRO lazy dlopen failed");
    wi600_write_text(1, "WI1065_RELRO partial\n");
    wi600_write_text(1, "WI1065_DLCLOSE partial\n");

    wi600_require(wi1065_open_call_close(FULL_RELRO_LIBRARY, WI600_RTLD_NOW,
                                         "wi1065_relro_value") == 0,
                  SCENARIO, 92, "full RELRO bind-now dlopen failed");
    wi600_write_text(1, "WI1065_RELRO full\n");
    wi600_write_text(1, "WI1065_DLCLOSE full\n");

    wi600_require(pthread_create(&first, (void *)0, wi1065_loader_worker,
                                 (void *)0) == 0,
                  SCENARIO, 93, "first loader thread create failed");
    wi600_require(pthread_create(&second, (void *)0, wi1065_loader_worker,
                                 (void *)0) == 0,
                  SCENARIO, 94, "second loader thread create failed");
    wi600_require(pthread_join(first, &first_result) == 0 &&
                  pthread_join(second, &second_result) == 0 &&
                  first_result == (void *)0 && second_result == (void *)0,
                  SCENARIO, 95, "loader worker failed");
    wi600_write_text(1, "WI1065_THREADS_PASS\n");
    wi600_pass(SCENARIO);
}
