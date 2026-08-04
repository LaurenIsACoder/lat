#ifndef KZT_XCB_ROUTE_POLICY_H
#define KZT_XCB_ROUTE_POLICY_H

#include <string.h>

typedef enum kzt_xcb_route_kind {
    KZT_XCB_ROUTE_NOT_XCB = 0,
    KZT_XCB_ROUTE_GUARDED_CONSUMER,
    KZT_XCB_ROUTE_PRODUCER,
    KZT_XCB_ROUTE_LIFECYCLE,
    KZT_XCB_ROUTE_UNSUPPORTED,
} kzt_xcb_route_kind_t;

static inline kzt_xcb_route_kind_t kzt_xcb_route_classify(
    const char *symbol_name)
{
    if (!symbol_name) {
        return KZT_XCB_ROUTE_NOT_XCB;
    }

    if (strcmp(symbol_name, "xcb_flush") == 0 ||
        strcmp(symbol_name, "xcb_connection_has_error") == 0) {
        return KZT_XCB_ROUTE_GUARDED_CONSUMER;
    }
    if (strcmp(symbol_name, "xcb_connect") == 0 ||
        strcmp(symbol_name,
               "xcb_connect_to_display_with_auth_info") == 0 ||
        strcmp(symbol_name, "XGetXCBConnection") == 0) {
        return KZT_XCB_ROUTE_PRODUCER;
    }
    if (strcmp(symbol_name, "xcb_disconnect") == 0 ||
        strcmp(symbol_name, "XCloseDisplay") == 0) {
        return KZT_XCB_ROUTE_LIFECYCLE;
    }
    if (strncmp(symbol_name, "xcb_", 4) == 0) {
        return KZT_XCB_ROUTE_UNSUPPORTED;
    }

    return KZT_XCB_ROUTE_NOT_XCB;
}

static inline int kzt_xcb_route_is_guarded_consumer(
    const char *symbol_name)
{
    return kzt_xcb_route_classify(symbol_name) ==
           KZT_XCB_ROUTE_GUARDED_CONSUMER;
}

static inline int kzt_xcb_route_must_stay_guest(const char *symbol_name)
{
    kzt_xcb_route_kind_t kind = kzt_xcb_route_classify(symbol_name);

    return kind != KZT_XCB_ROUTE_NOT_XCB &&
           kind != KZT_XCB_ROUTE_GUARDED_CONSUMER;
}

#endif
