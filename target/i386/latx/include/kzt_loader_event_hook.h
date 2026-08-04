#ifndef KZT_LOADER_EVENT_HOOK_H
#define KZT_LOADER_EVENT_HOOK_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_scope_layout.h"

typedef struct box64context_s box64context_t;

#define KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE 41
#define KZT_LOADER_EVENT_HOOK_GLIBC_2_28_BUILD_ID \
    "3b10a1b21d87ee3af8da437bce08fe1ca1a0aaff"
#define KZT_LOADER_EVENT_HOOK_GLIBC_2_39_BUILD_ID \
    "c591a5df63f461bfdafb01908ca16845b375fa37"
#define KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID \
    KZT_LOADER_EVENT_HOOK_GLIBC_2_39_BUILD_ID
#define KZT_LOADER_EVENT_HOOK_DEBUG_STATE_OFFSET 0x3630
#define KZT_LOADER_EVENT_HOOK_R_DEBUG_OFFSET 0x36e58

typedef struct kzt_loader_event_layout {
    kzt_guest_scope_layout_t scope_layout;
    uintptr_t debug_state_offset;
    uintptr_t r_debug_offset;
} kzt_loader_event_layout_t;

typedef enum kzt_loader_event_hook_result {
    KZT_LOADER_EVENT_HOOK_INSTALLED = 0,
    KZT_LOADER_EVENT_HOOK_FAIL_OPEN_DISABLED,
    KZT_LOADER_EVENT_HOOK_FAIL_OPEN_BUILD_ID_READ,
    KZT_LOADER_EVENT_HOOK_FAIL_OPEN_UNKNOWN_BUILD_ID,
    KZT_LOADER_EVENT_HOOK_FAIL_OPEN_PATTERN_MISMATCH,
} kzt_loader_event_hook_result_t;

typedef enum kzt_loader_lifecycle_result {
    KZT_LOADER_LIFECYCLE_OK = 0,
    KZT_LOADER_LIFECYCLE_DISABLED,
    KZT_LOADER_LIFECYCLE_INVALID,
    KZT_LOADER_LIFECYCLE_ALLOCATION,
    KZT_LOADER_LIFECYCLE_OVERFLOW,
} kzt_loader_lifecycle_result_t;

typedef struct kzt_loader_event_hook {
    char build_id[KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE];
    uintptr_t callback_addr;
    unsigned int link_map_reg;
    unsigned int installed;
    kzt_loader_event_hook_result_t result;
    kzt_guest_scope_layout_t scope_layout;
    uint64_t event_sequence;
    uintptr_t debug_state_addr;
    uintptr_t r_debug_addr;
    unsigned int lifecycle_enabled;
    unsigned int lifecycle_lock;
    unsigned int lifecycle_publishers;
    unsigned int lifecycle_result;
    unsigned int lifecycle_confirmed;
    unsigned int lifecycle_failed;
    size_t pending_delete_count;
    size_t pending_delete_capacity;
    struct kzt_loader_lifecycle_identity *pending_delete;
} kzt_loader_event_hook_t;

typedef struct kzt_loader_event {
    uintptr_t link_map_addr;
    uint64_t sequence;
    uint64_t published_ns;
} kzt_loader_event_t;

typedef enum kzt_loader_debug_state {
    KZT_LOADER_DEBUG_CONSISTENT = 0,
    KZT_LOADER_DEBUG_ADD = 1,
    KZT_LOADER_DEBUG_DELETE = 2,
} kzt_loader_debug_state_t;

typedef struct kzt_loader_lifecycle_identity {
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
} kzt_loader_lifecycle_identity_t;

typedef int (*kzt_loader_lifecycle_resolve_fn)(
    uintptr_t link_map_addr,
    kzt_loader_lifecycle_identity_t *identity,
    void *opaque);
typedef int (*kzt_loader_lifecycle_transition_fn)(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque);
typedef int (*kzt_loader_lifecycle_unload_fn)(
    const kzt_loader_lifecycle_identity_t *identity,
    void *opaque);

/* Installation-time parser for an x86_64 loader Build ID.  It is deliberately
 * outside the publish path, which only releases an already-authorized event. */
int kzt_loader_event_hook_read_build_id(
    const char *path, char build_id[KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE]);

int kzt_loader_event_hook_lookup_layout(
    const char *build_id, kzt_loader_event_layout_t *layout);

int kzt_loader_event_hook_install(kzt_loader_event_hook_t *hook,
                                  const char *build_id,
                                  uintptr_t callback_addr,
                                  unsigned int link_map_reg,
                                  int pattern_matched);

/* Test-only environment override for proving a known Build ID cannot bypass
 * an instruction-pattern mismatch. */
int kzt_loader_event_hook_pattern_allowed(int pattern_matched);

/* The callback-side interface: publish an exact link_map and no loader work. */
int kzt_loader_event_hook_publish(kzt_loader_event_hook_t *hook,
                                  uintptr_t link_map_addr,
                                  kzt_loader_event_t *event);

int kzt_loader_event_hook_enable_lifecycle(
    kzt_loader_event_hook_t *hook,
    uintptr_t debug_state_addr,
    uintptr_t r_debug_addr);
int kzt_loader_event_hook_publish_lifecycle(
    kzt_loader_event_hook_t *hook,
    kzt_loader_debug_state_t state,
    const uintptr_t *live_maps,
    size_t live_map_count,
    kzt_loader_lifecycle_resolve_fn resolve,
    kzt_loader_lifecycle_transition_fn prepare,
    kzt_loader_lifecycle_transition_fn cancel,
    kzt_loader_lifecycle_unload_fn unload,
    void *opaque);
int kzt_loader_event_hook_destroy(kzt_loader_event_hook_t *hook);
void kzt_loader_event_hook_context_init(kzt_loader_event_hook_t *hook);
void kzt_loader_event_hook_context_destroy(kzt_loader_event_hook_t *hook);

kzt_guest_scope_layout_t kzt_loader_event_hook_scope_layout(
    const kzt_loader_event_hook_t *hook);

const char *kzt_loader_event_hook_result_name(
    kzt_loader_event_hook_result_t result);

kzt_loader_lifecycle_result_t kzt_loader_event_hook_lifecycle_result(
    const kzt_loader_event_hook_t *hook);
int kzt_loader_event_hook_lifecycle_healthy(
    const kzt_loader_event_hook_t *hook);
int kzt_loader_lifecycle_runtime_healthy(box64context_t *context);

const char *kzt_loader_lifecycle_result_name(
    kzt_loader_lifecycle_result_t result);

#ifdef KZT_LOADER_EVENT_HOOK_TEST
void kzt_loader_event_hook_test_set_alloc_failure_after(long allocations);
#endif

#endif
