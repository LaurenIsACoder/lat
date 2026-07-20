#ifndef KZT_OWNER_RESOLVER_H
#define KZT_OWNER_RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_guest_registry.h"
#include "kzt_patch_planner.h"

#define KZT_OWNER_RESOLVER_TEXT_LIMIT 256

typedef enum kzt_owner_resolver_status {
    KZT_OWNER_RESOLVER_RESOLVED = 0,
    KZT_OWNER_RESOLVER_INVALID_ARGUMENT,
    KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE,
    KZT_OWNER_RESOLVER_CURRENT_ADDRESS_MISSING,
    KZT_OWNER_RESOLVER_EXPECTED_ADDRESS_MISSING,
    KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND,
    KZT_OWNER_RESOLVER_EXPECTED_NOT_FOUND,
    KZT_OWNER_RESOLVER_CURRENT_AMBIGUOUS,
    KZT_OWNER_RESOLVER_EXPECTED_AMBIGUOUS,
    KZT_OWNER_RESOLVER_GENERATION_UNKNOWN,
} kzt_owner_resolver_status_t;

typedef struct kzt_owner_resolver_text {
    char soname[KZT_OWNER_RESOLVER_TEXT_LIMIT];
    char path[KZT_OWNER_RESOLVER_TEXT_LIMIT];
} kzt_owner_resolver_text_t;

typedef struct kzt_owner_resolution {
    kzt_owner_resolver_status_t status;
    kzt_patch_object_ref_t current_owner;
    kzt_patch_object_ref_t expected_owner;
    kzt_patch_owner_match_t owner_match;
    size_t current_match_count;
    size_t expected_match_count;
    kzt_owner_resolver_text_t current_text;
    kzt_owner_resolver_text_t expected_text;
} kzt_owner_resolution_t;

void kzt_owner_resolver_init(kzt_owner_resolution_t *resolution);

int kzt_owner_resolver_resolve_current(
    kzt_guest_registry_t *registry,
    uintptr_t current_address,
    uintptr_t expected_address,
    kzt_owner_resolution_t *resolution);

kzt_patch_owner_match_t kzt_owner_resolver_match_refs(
    const kzt_patch_object_ref_t *current_owner,
    const kzt_patch_object_ref_t *expected_owner);

const char *kzt_owner_resolver_status_name(
    kzt_owner_resolver_status_t status);

#endif
