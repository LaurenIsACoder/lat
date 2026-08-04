#include "kzt_owner_resolver.h"

#include <stdio.h>
#include <string.h>

typedef enum kzt_owner_lookup_status {
    KZT_OWNER_LOOKUP_RESOLVED = 0,
    KZT_OWNER_LOOKUP_NOT_FOUND,
    KZT_OWNER_LOOKUP_AMBIGUOUS,
} kzt_owner_lookup_status_t;

void kzt_owner_resolver_init(kzt_owner_resolution_t *resolution)
{
    if (!resolution) {
        return;
    }

    memset(resolution, 0, sizeof(*resolution));
    resolution->status = KZT_OWNER_RESOLVER_INVALID_ARGUMENT;
    resolution->owner_match = KZT_PATCH_OWNER_UNKNOWN;
}

static int kzt_owner_string_has_value(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK ||
           status == KZT_GUEST_FIELD_TRUNCATED;
}

static void kzt_owner_copy_text(char *dst, size_t dst_size,
                                const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

static void kzt_owner_ref_from_match(
    const kzt_guest_registry_address_match_t *match,
    kzt_owner_resolver_text_t *text,
    kzt_patch_object_ref_t *ref)
{
    const char *soname = NULL;
    const char *path = NULL;

    memset(ref, 0, sizeof(*ref));
    if (!match || !text) {
        return;
    }

    if (kzt_owner_string_has_value(match->soname_status)) {
        soname = match->soname;
    }
    if (kzt_owner_string_has_value(match->path_status)) {
        path = match->path;
    }
    kzt_owner_copy_text(text->soname, sizeof(text->soname), soname);
    kzt_owner_copy_text(text->path, sizeof(text->path), path);

    ref->known = 1;
    ref->link_map_addr = match->link_map_addr;
    ref->map_start = match->map_start;
    ref->map_end = match->map_end;
    ref->generation = match->generation;
    ref->soname = text->soname[0] ? text->soname : NULL;
    ref->path = text->path[0] ? text->path : NULL;
}

static kzt_owner_lookup_status_t kzt_owner_find_by_address(
    const kzt_guest_registry_address_match_t *match,
    kzt_owner_resolver_text_t *text,
    kzt_patch_object_ref_t *ref,
    size_t *match_count)
{
    memset(ref, 0, sizeof(*ref));
    if (text) {
        memset(text, 0, sizeof(*text));
    }
    if (match_count) {
        *match_count = 0;
    }

    if (!match || !ref) {
        return KZT_OWNER_LOOKUP_NOT_FOUND;
    }

    if (match_count) {
        *match_count = match->match_count;
    }
    if (match->match_count == 0) {
        return KZT_OWNER_LOOKUP_NOT_FOUND;
    }
    if (match->match_count > 1) {
        return KZT_OWNER_LOOKUP_AMBIGUOUS;
    }

    kzt_owner_ref_from_match(match, text, ref);
    return KZT_OWNER_LOOKUP_RESOLVED;
}

kzt_patch_owner_match_t kzt_owner_resolver_match_refs(
    const kzt_patch_object_ref_t *current_owner,
    const kzt_patch_object_ref_t *expected_owner)
{
    if (!current_owner || !expected_owner ||
        !current_owner->known || !expected_owner->known ||
        current_owner->link_map_addr == 0 ||
        expected_owner->link_map_addr == 0 ||
        current_owner->generation == 0 || expected_owner->generation == 0) {
        return KZT_PATCH_OWNER_UNKNOWN;
    }

    if (current_owner->link_map_addr == expected_owner->link_map_addr &&
        current_owner->generation == expected_owner->generation) {
        return KZT_PATCH_OWNER_MATCH;
    }

    return KZT_PATCH_OWNER_MISMATCH;
}

static kzt_owner_resolver_status_t kzt_owner_lookup_status_to_current(
    kzt_owner_lookup_status_t status)
{
    switch (status) {
    case KZT_OWNER_LOOKUP_RESOLVED:
        return KZT_OWNER_RESOLVER_RESOLVED;
    case KZT_OWNER_LOOKUP_AMBIGUOUS:
        return KZT_OWNER_RESOLVER_CURRENT_AMBIGUOUS;
    case KZT_OWNER_LOOKUP_NOT_FOUND:
        return KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND;
    }

    return KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND;
}

static kzt_owner_resolver_status_t kzt_owner_lookup_status_to_expected(
    kzt_owner_lookup_status_t status)
{
    switch (status) {
    case KZT_OWNER_LOOKUP_RESOLVED:
        return KZT_OWNER_RESOLVER_RESOLVED;
    case KZT_OWNER_LOOKUP_AMBIGUOUS:
        return KZT_OWNER_RESOLVER_EXPECTED_AMBIGUOUS;
    case KZT_OWNER_LOOKUP_NOT_FOUND:
        return KZT_OWNER_RESOLVER_EXPECTED_NOT_FOUND;
    }

    return KZT_OWNER_RESOLVER_EXPECTED_NOT_FOUND;
}

int kzt_owner_resolver_resolve_current(
    kzt_guest_registry_t *registry,
    uintptr_t current_address,
    uintptr_t expected_address,
    kzt_owner_resolution_t *resolution)
{
    kzt_guest_registry_address_pair_t pair;
    kzt_owner_lookup_status_t current_status;
    kzt_owner_lookup_status_t expected_status;

    if (!resolution) {
        return -1;
    }

    kzt_owner_resolver_init(resolution);
    resolution->status = KZT_OWNER_RESOLVER_RESOLVED;

    if (!registry) {
        resolution->status = KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE;
        return 0;
    }
    if (current_address == 0) {
        resolution->status = KZT_OWNER_RESOLVER_CURRENT_ADDRESS_MISSING;
        return 0;
    }
    if (expected_address == 0) {
        resolution->status = KZT_OWNER_RESOLVER_EXPECTED_ADDRESS_MISSING;
        return 0;
    }
    if (kzt_guest_registry_resolve_address_pair(
            registry, current_address, expected_address, &pair) != 0) {
        resolution->status = KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE;
        return 0;
    }

    current_status = kzt_owner_find_by_address(
        &pair.current, &resolution->current_text,
        &resolution->current_owner, &resolution->current_match_count);
    expected_status = kzt_owner_find_by_address(
        &pair.expected, &resolution->expected_text,
        &resolution->expected_owner, &resolution->expected_match_count);

    if (current_status != KZT_OWNER_LOOKUP_RESOLVED) {
        resolution->status = kzt_owner_lookup_status_to_current(
            current_status);
        goto out;
    }
    if (expected_status != KZT_OWNER_LOOKUP_RESOLVED) {
        resolution->status = kzt_owner_lookup_status_to_expected(
            expected_status);
        goto out;
    }

    resolution->owner_match = kzt_owner_resolver_match_refs(
        &resolution->current_owner, &resolution->expected_owner);
    if (resolution->owner_match == KZT_PATCH_OWNER_UNKNOWN) {
        resolution->status = KZT_OWNER_RESOLVER_GENERATION_UNKNOWN;
    }

out:
    return 0;
}

const char *kzt_owner_resolver_status_name(
    kzt_owner_resolver_status_t status)
{
    switch (status) {
    case KZT_OWNER_RESOLVER_RESOLVED:
        return "RESOLVED";
    case KZT_OWNER_RESOLVER_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE:
        return "REGISTRY_UNAVAILABLE";
    case KZT_OWNER_RESOLVER_CURRENT_ADDRESS_MISSING:
        return "CURRENT_ADDRESS_MISSING";
    case KZT_OWNER_RESOLVER_EXPECTED_ADDRESS_MISSING:
        return "EXPECTED_ADDRESS_MISSING";
    case KZT_OWNER_RESOLVER_CURRENT_NOT_FOUND:
        return "CURRENT_NOT_FOUND";
    case KZT_OWNER_RESOLVER_EXPECTED_NOT_FOUND:
        return "EXPECTED_NOT_FOUND";
    case KZT_OWNER_RESOLVER_CURRENT_AMBIGUOUS:
        return "CURRENT_AMBIGUOUS";
    case KZT_OWNER_RESOLVER_EXPECTED_AMBIGUOUS:
        return "EXPECTED_AMBIGUOUS";
    case KZT_OWNER_RESOLVER_GENERATION_UNKNOWN:
        return "GENERATION_UNKNOWN";
    }

    return "UNKNOWN";
}
