#ifndef KZT_XCB_CONNECTION_MAP_H
#define KZT_XCB_CONNECTION_MAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct kzt_xcb_connection_map kzt_xcb_connection_map_t;

typedef void (*kzt_xcb_connection_guest_destroy_fn)(void *guest,
                                                     void *opaque);

typedef enum kzt_xcb_connection_map_result {
    KZT_XCB_CONNECTION_MAP_ERROR = -1,
    KZT_XCB_CONNECTION_MAP_ADDED = 0,
    KZT_XCB_CONNECTION_MAP_UNCHANGED = 1,
} kzt_xcb_connection_map_result_t;

typedef struct kzt_xcb_connection_lease {
    void *guest;
    void *native;
    uint64_t generation;
    kzt_xcb_connection_map_t *_map;
    void *_entry;
    int _removal;
} kzt_xcb_connection_lease_t;

kzt_xcb_connection_map_t *kzt_xcb_connection_map_init(
    kzt_xcb_connection_guest_destroy_fn destroy_guest, void *opaque);
void kzt_xcb_connection_map_destroy(kzt_xcb_connection_map_t **map);

kzt_xcb_connection_map_result_t kzt_xcb_connection_map_register(
    kzt_xcb_connection_map_t *map, void *native, void *proposed_guest,
    void **canonical_guest, uint64_t *generation);

int kzt_xcb_connection_map_acquire_by_guest(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease);
int kzt_xcb_connection_map_acquire_by_native(
    kzt_xcb_connection_map_t *map, void *native,
    kzt_xcb_connection_lease_t *lease);
void kzt_xcb_connection_map_release_pair(
    kzt_xcb_connection_map_t *map, void *native, void *guest);
int kzt_xcb_connection_lease_lock_mirror(
    const kzt_xcb_connection_lease_t *lease);
void kzt_xcb_connection_lease_unlock_mirror(
    const kzt_xcb_connection_lease_t *lease);

int kzt_xcb_connection_map_begin_remove_by_guest(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease);
int kzt_xcb_connection_map_begin_remove_by_native(
    kzt_xcb_connection_map_t *map, void *native,
    kzt_xcb_connection_lease_t *lease);
void kzt_xcb_connection_map_finish_remove(
    kzt_xcb_connection_lease_t *lease);

size_t kzt_xcb_connection_map_size(kzt_xcb_connection_map_t *map);

#endif
