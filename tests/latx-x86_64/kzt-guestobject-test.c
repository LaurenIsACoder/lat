#include "guestobject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__libc_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void *__libc_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void __libc_free(void *ptr)
{
    free(ptr);
}

char *box_strdup(const char *s)
{
    return strdup(s);
}

static int failures;

static void check_int(const char *name, unsigned long got,
                      unsigned long expected)
{
    if (got == expected)
        return;

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void check_string(const char *name, const char *got,
                         const char *expected)
{
    if (got && !strcmp(got, expected))
        return;

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n",
            name, got ? got : "(null)", expected);
    ++failures;
}

static void test_lookup_by_address(void)
{
    guest_object_registry_t *registry = NewGuestObjectRegistry();
    guest_object_lookup_t lookup;

    check_int("registry.new", registry != NULL, 1);
    if (!registry)
        return;

    check_int("lookup.empty",
              LookupGuestObjectByAddress(registry, 0x1000, &lookup), -1);
    check_int("observe.new",
              ObserveGuestObject(registry, 0x10, 0x1000, 0x1800,
                                 "/tmp/libfoo.so"),
              GUEST_OBJECT_OBSERVE_NEW);
    check_int("range.set",
              SetGuestObjectMapRange(registry, 0x10, 0x1000, 0x3000), 0);
    check_int("state.set",
              SetGuestObjectState(registry, 0x10, GUEST_OBJECT_WRAPPED), 0);

    memset(&lookup, 0, sizeof(lookup));
    check_int("lookup.start",
              LookupGuestObjectByAddress(registry, 0x1000, &lookup), 0);
    check_int("lookup.link-map", lookup.link_map_addr, 0x10);
    check_int("lookup.load-bias", lookup.load_bias, 0x1000);
    check_int("lookup.dynamic", lookup.dynamic_addr, 0x1800);
    check_int("lookup.map-start", lookup.map_start, 0x1000);
    check_int("lookup.map-end", lookup.map_end, 0x3000);
    check_int("lookup.state", lookup.state, GUEST_OBJECT_WRAPPED);
    check_string("lookup.name", lookup.name, "/tmp/libfoo.so");

    check_int("lookup.end-minus-one",
              LookupGuestObjectByAddress(registry, 0x2fff, &lookup), 0);
    check_int("lookup.end",
              LookupGuestObjectByAddress(registry, 0x3000, &lookup), -1);

    check_int("observe.changed",
              ObserveGuestObject(registry, 0x10, 0x4000, 0x4800,
                                 "/tmp/libbar.so"),
              GUEST_OBJECT_OBSERVE_CHANGED);
    check_int("lookup.cleared-range",
              LookupGuestObjectByAddress(registry, 0x1000, &lookup), -1);

    FreeGuestObjectRegistry(&registry);
    check_int("registry.free", registry == NULL, 1);
}

int main(void)
{
    test_lookup_by_address();

    if (failures)
        return 1;

    puts("KZT guestobject tests passed");
    return 0;
}
