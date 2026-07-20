#ifndef KZT_GUEST_LIBRARY_ADAPTER_H
#define KZT_GUEST_LIBRARY_ADAPTER_H

#include <stdint.h>

#include "kzt_loader_callback_scope.h"

typedef struct box64context_s box64context_t;
typedef struct library_s library_t;

/* Shared production adapter used by wrappedlibc, wrappedlibdl, and loader
 * callback paths whenever one operation owns both exact values. */
void kzt_guest_library_note_loader_pair(box64context_t *context,
                                        uintptr_t link_map_addr,
                                        library_t *library);
void kzt_guest_library_note_loader_pair_pending(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library);
void kzt_guest_library_publish_loader_pair_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library);
void kzt_guest_library_publish_loader_observed_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr);

#endif
