#include <stdio.h>

#include "target/i386/latx/include/kzt_xcb_route_policy.h"

static int failures;

static void check_kind(const char *symbol_name,
                       kzt_xcb_route_kind_t expected)
{
    kzt_xcb_route_kind_t got = kzt_xcb_route_classify(symbol_name);

    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got route %d expected %d\n",
            symbol_name ? symbol_name : "(null)", got, expected);
    ++failures;
}

static void check_policy(const char *symbol_name, int expected_guarded,
                         int expected_guest)
{
    int guarded = kzt_xcb_route_is_guarded_consumer(symbol_name);
    int guest = kzt_xcb_route_must_stay_guest(symbol_name);

    if (guarded != expected_guarded) {
        fprintf(stderr, "%s: guarded got %d expected %d\n",
                symbol_name ? symbol_name : "(null)", guarded,
                expected_guarded);
        ++failures;
    }
    if (guest != expected_guest) {
        fprintf(stderr, "%s: guest got %d expected %d\n",
                symbol_name ? symbol_name : "(null)", guest,
                expected_guest);
        ++failures;
    }
}

int main(void)
{
    check_kind("xcb_flush", KZT_XCB_ROUTE_GUARDED_CONSUMER);
    check_kind("xcb_connection_has_error",
               KZT_XCB_ROUTE_GUARDED_CONSUMER);
    check_policy("xcb_flush", 1, 0);
    check_policy("xcb_connection_has_error", 1, 0);

    check_kind("xcb_connect", KZT_XCB_ROUTE_PRODUCER);
    check_kind("xcb_connect_to_display_with_auth_info",
               KZT_XCB_ROUTE_PRODUCER);
    check_kind("XGetXCBConnection", KZT_XCB_ROUTE_PRODUCER);
    check_policy("xcb_connect", 0, 1);
    check_policy("xcb_connect_to_display_with_auth_info", 0, 1);
    check_policy("XGetXCBConnection", 0, 1);

    check_kind("xcb_disconnect", KZT_XCB_ROUTE_LIFECYCLE);
    check_kind("XCloseDisplay", KZT_XCB_ROUTE_LIFECYCLE);
    check_policy("xcb_disconnect", 0, 1);
    check_policy("XCloseDisplay", 0, 1);

    check_kind("xcb_send_request", KZT_XCB_ROUTE_UNSUPPORTED);
    check_kind("xcb_flush_checked", KZT_XCB_ROUTE_UNSUPPORTED);
    check_policy("xcb_send_request", 0, 1);
    check_policy("xcb_flush_checked", 0, 1);

    check_kind("gtk_widget_show", KZT_XCB_ROUTE_NOT_XCB);
    check_kind("", KZT_XCB_ROUTE_NOT_XCB);
    check_kind(NULL, KZT_XCB_ROUTE_NOT_XCB);
    check_policy("gtk_widget_show", 0, 0);
    check_policy("", 0, 0);
    check_policy(NULL, 0, 0);

    if (failures) {
        fprintf(stderr, "kzt-xcb-route-policy: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-xcb-route-policy: contract tests passed");
    return 0;
}
