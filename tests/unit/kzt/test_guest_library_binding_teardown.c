#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "kzt_guest_library_binding.h"

typedef struct teardown_fixture {
    kzt_guest_library_bindings_t *bindings;
    int stop;
    unsigned long admitted;
} teardown_fixture_t;

static void *callback_worker(void *opaque)
{
    teardown_fixture_t *fixture = opaque;

    while (!__atomic_load_n(&fixture->stop, __ATOMIC_ACQUIRE)) {
        kzt_guest_library_callback_access_t access = { 0 };
        if (kzt_guest_library_callback_access_begin(
                fixture->bindings, 0xb10000, &access) == 0) {
            __atomic_add_fetch(&fixture->admitted, 1, __ATOMIC_RELAXED);
            kzt_guest_library_callback_access_end(&access);
        }
    }
    return NULL;
}

int main(void)
{
    teardown_fixture_t fixture = {
        .bindings = kzt_guest_library_bindings_init(),
    };
    pthread_t workers[4];

    if (!fixture.bindings) return EXIT_FAILURE;
    for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); ++i)
        if (pthread_create(&workers[i], NULL, callback_worker, &fixture) != 0)
            return EXIT_FAILURE;

    while (__atomic_load_n(&fixture.admitted, __ATOMIC_ACQUIRE) < 1000)
        sched_yield();
    kzt_guest_library_bindings_begin_teardown(fixture.bindings);
    __atomic_store_n(&fixture.stop, 1, __ATOMIC_RELEASE);
    for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); ++i)
        pthread_join(workers[i], NULL);
    kzt_guest_library_bindings_destroy(&fixture.bindings);
    puts("kzt-guest-library-binding-teardown: PASS");
    return EXIT_SUCCESS;
}
