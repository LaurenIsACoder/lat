#ifndef KZT_LOADER_CALLBACK_SCOPE_H
#define KZT_LOADER_CALLBACK_SCOPE_H

typedef struct kzt_guest_library_bindings kzt_guest_library_bindings_t;

/* A value token issued by one context-owned guest loader invocation. */
typedef struct kzt_guest_library_loader_scope {
    kzt_guest_library_bindings_t *bindings;
    unsigned long identity;
    unsigned long cookie;
    int prebind_refresh_pending;
} kzt_guest_library_loader_scope_t;

#endif
