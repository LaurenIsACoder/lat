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

static int kzt_owner_field_ok(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK;
}

static int kzt_owner_string_has_value(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK ||
           status == KZT_GUEST_FIELD_TRUNCATED;
}

static const char *kzt_owner_snapshot_string(
    const kzt_guest_string_field_t *field)
{
    if (!field || !kzt_owner_string_has_value(field->status)) {
        return NULL;
    }

    return field->value;
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

static int kzt_owner_snapshot_has_valid_range(
    const kzt_guest_object_snapshot_t *snapshot)
{
    if (!snapshot) {
        return 0;
    }
    if (!kzt_owner_field_ok(snapshot->map_start.status) ||
        !kzt_owner_field_ok(snapshot->map_end.status)) {
        return 0;
    }

    return snapshot->map_start.value < snapshot->map_end.value;
}

static int kzt_owner_snapshot_contains(
    const kzt_guest_object_snapshot_t *snapshot,
    uintptr_t address)
{
    if (!kzt_owner_snapshot_has_valid_range(snapshot)) {
        return 0;
    }

    return address >= snapshot->map_start.value &&
           address < snapshot->map_end.value;
}

static void kzt_owner_ref_from_snapshot(
    const kzt_guest_object_snapshot_t *snapshot,
    kzt_owner_resolver_text_t *text,
    kzt_patch_object_ref_t *ref)
{
    const char *soname;
    const char *path;

    memset(ref, 0, sizeof(*ref));
    if (!snapshot || !text) {
        return;
    }

    soname = kzt_owner_snapshot_string(&snapshot->soname);
    path = kzt_owner_snapshot_string(&snapshot->path);
    kzt_owner_copy_text(text->soname, sizeof(text->soname), soname);
    kzt_owner_copy_text(text->path, sizeof(text->path), path);

    ref->known = 1;
    ref->link_map_addr = snapshot->link_map_addr;
    ref->map_start = snapshot->map_start.value;
    ref->map_end = snapshot->map_end.value;
    ref->generation = snapshot->generation;
    ref->soname = text->soname[0] ? text->soname : NULL;
    ref->path = text->path[0] ? text->path : NULL;
}

static kzt_owner_lookup_status_t kzt_owner_find_by_address(
    const kzt_guest_registry_dump_t *dump,
    uintptr_t address,
    kzt_owner_resolver_text_t *text,
    kzt_patch_object_ref_t *ref,
    size_t *match_count)
{
    const kzt_guest_object_snapshot_t *match = NULL;
    size_t i;
    size_t count = 0;

    memset(ref, 0, sizeof(*ref));
    if (text) {
        memset(text, 0, sizeof(*text));
    }
    if (match_count) {
        *match_count = 0;
    }

    if (!dump || !ref || address == 0) {
        return KZT_OWNER_LOOKUP_NOT_FOUND;
    }

    for (i = 0; i < dump->count; ++i) {
        if (dump->objects[i].state == KZT_GUEST_OBJECT_UNLOADING ||
            dump->objects[i].state == KZT_GUEST_OBJECT_DEAD) {
            continue;
        }
        if (!kzt_owner_snapshot_contains(&dump->objects[i], address)) {
            continue;
        }

        ++count;
        if (!match) {
            match = &dump->objects[i];
        }
    }

    if (match_count) {
        *match_count = count;
    }
    if (count == 0) {
        return KZT_OWNER_LOOKUP_NOT_FOUND;
    }
    if (count > 1) {
        return KZT_OWNER_LOOKUP_AMBIGUOUS;
    }

    kzt_owner_ref_from_snapshot(match, text, ref);
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
    kzt_guest_registry_dump_t dump = { 0 };
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
    if (kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        resolution->status = KZT_OWNER_RESOLVER_REGISTRY_UNAVAILABLE;
        return 0;
    }

    current_status = kzt_owner_find_by_address(
        &dump, current_address, &resolution->current_text,
        &resolution->current_owner, &resolution->current_match_count);
    expected_status = kzt_owner_find_by_address(
        &dump, expected_address, &resolution->expected_text,
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
    kzt_guest_registry_dump_free(&dump);
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
