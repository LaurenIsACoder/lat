#ifndef KZT_GUEST_SYMBOL_SCOPE_H
#define KZT_GUEST_SYMBOL_SCOPE_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_link_map_reader.h"
#include "kzt_guest_scope_layout.h"
#include "kzt_patch_planner.h"

#define KZT_GUEST_SYMBOL_SCOPE_LIST_LIMIT 16
#define KZT_GUEST_SYMBOL_SCOPE_MAP_LIMIT 256

typedef enum kzt_guest_symbol_scope_status {
    KZT_GUEST_SYMBOL_SCOPE_SAFE = 0,
    KZT_GUEST_SYMBOL_SCOPE_GUEST_REQUIRED,
} kzt_guest_symbol_scope_status_t;

typedef enum kzt_guest_symbol_scope_reason {
    KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER = 0,
    KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_INCOMPLETE,
    KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_PROVIDER_BINDING,
    KZT_GUEST_SYMBOL_SCOPE_REASON_UNSUPPORTED_REFERENCE,
    KZT_GUEST_SYMBOL_SCOPE_REASON_PROVIDER_MISMATCH,
    KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_STALE,
    KZT_GUEST_SYMBOL_SCOPE_REASON_LAYOUT_UNSUPPORTED,
    KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_DUPLICATE,
    KZT_GUEST_SYMBOL_SCOPE_REASON_CROSS_NAMESPACE,
    KZT_GUEST_SYMBOL_SCOPE_REASON_SCOPE_SEMANTICS_UNSUPPORTED,
    KZT_GUEST_SYMBOL_SCOPE_REASON_AUDIT_UNSUPPORTED,
} kzt_guest_symbol_scope_reason_t;

typedef struct kzt_guest_symbol_scope_source {
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
    uintptr_t namespace_head;
    kzt_guest_scope_layout_t layout;
} kzt_guest_symbol_scope_source_t;

typedef struct kzt_guest_symbol_scope_request {
    kzt_guest_symbol_scope_source_t source;
    const char *symbol;
    kzt_symbol_version_evidence_t version_evidence;
    const char *version;
    unsigned char reference_binding;
    unsigned char reference_type;
    unsigned char reference_visibility;
} kzt_guest_symbol_scope_request_t;

typedef struct kzt_guest_symbol_scope_identity {
    kzt_guest_symbol_scope_source_t source;
    uintptr_t scope_array_addr;
    size_t scope_list_count;
    size_t scope_map_count;
    uint64_t value;
} kzt_guest_symbol_scope_identity_t;

typedef struct kzt_guest_symbol_scope_result {
    kzt_guest_symbol_scope_status_t status;
    kzt_guest_symbol_scope_reason_t reason;
    size_t candidate_count;
    int scope_complete;
    int lookup_order_known;
    uintptr_t selected_provider_link_map;
    uintptr_t selected_provider_address;
    unsigned char selected_provider_binding;
    unsigned char selected_provider_type;
    unsigned char selected_provider_visibility;
    uint64_t query_fingerprint;
    kzt_guest_symbol_scope_identity_t scope_identity;
} kzt_guest_symbol_scope_result_t;

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_discover(
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result);

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_check(
    const kzt_guest_symbol_scope_request_t *request,
    uintptr_t selected_provider_link_map,
    uintptr_t selected_provider_address,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result);

kzt_guest_symbol_scope_status_t kzt_guest_symbol_scope_revalidate(
    const kzt_guest_symbol_scope_result_t *proof,
    const kzt_guest_symbol_scope_request_t *request,
    const kzt_guest_link_map_reader_ops_t *reader_ops,
    kzt_guest_symbol_scope_result_t *result);

const char *kzt_guest_symbol_scope_reason_name(
    kzt_guest_symbol_scope_reason_t reason);

#endif
