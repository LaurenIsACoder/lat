#ifndef KZT_XCB_QUEUE_MIRROR_H
#define KZT_XCB_QUEUE_MIRROR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int kzt_xcb_flush_state_is_supported(
    int queue_length, size_t queue_capacity,
    int fd_count, int fd_index, int writing, int socket_moving,
    uintptr_t return_socket, uintptr_t socket_closure)
{
    return queue_length >= 0 && (size_t)queue_length <= queue_capacity &&
           fd_count >= 0 && fd_count <= 16 &&
           fd_index >= 0 && fd_index <= fd_count &&
           !writing && !socket_moving && !return_socket && !socket_closure;
}

static inline size_t kzt_xcb_queue_copy(
    char *dest, size_t dest_capacity, int *dest_length,
    const char *source, size_t source_capacity, int source_length)
{
    size_t bytes = 0;

    if (source_length > 0 && dest && source) {
        bytes = (size_t)source_length;
        if (bytes > source_capacity) {
            bytes = source_capacity;
        }
        if (bytes > dest_capacity) {
            bytes = dest_capacity;
        }
        memcpy(dest, source, bytes);
    }
    if (dest_length) {
        *dest_length = (int)bytes;
    }
    return bytes;
}

#endif
