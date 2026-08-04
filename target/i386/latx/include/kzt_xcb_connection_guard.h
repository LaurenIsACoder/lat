#ifndef KZT_XCB_CONNECTION_GUARD_H
#define KZT_XCB_CONNECTION_GUARD_H

#include "kzt_xcb_connection_map.h"

int kzt_xcb_connection_guard_prepare(
    kzt_xcb_connection_map_t *map, void *guest);
int kzt_xcb_connection_guard_take(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease);
int kzt_xcb_connection_guard_acquire(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease);
int kzt_xcb_connection_guard_release(
    kzt_xcb_connection_map_t *map, void *native, void *guest);
int kzt_xcb_connection_guard_active_lease(
    kzt_xcb_connection_map_t *map, void *native, void *guest,
    kzt_xcb_connection_lease_t *lease);
void kzt_xcb_connection_guard_cancel(void);

#endif
