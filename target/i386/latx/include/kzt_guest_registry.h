#ifndef KZT_GUEST_REGISTRY_H
#define KZT_GUEST_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

typedef struct kzt_guest_registry kzt_guest_registry_t;

typedef enum kzt_guest_object_state {
    KZT_GUEST_OBJECT_DISCOVERED = 0,
    KZT_GUEST_OBJECT_PARSED,
    KZT_GUEST_OBJECT_WRAPPER_READY,
    KZT_GUEST_OBJECT_PATCHED,
    KZT_GUEST_OBJECT_UNLOADING,
    KZT_GUEST_OBJECT_DEAD,
} kzt_guest_object_state_t;

typedef enum kzt_guest_field_status {
    KZT_GUEST_FIELD_OK = 0,
    KZT_GUEST_FIELD_UNKNOWN,
    KZT_GUEST_FIELD_READ_ERROR,
    KZT_GUEST_FIELD_TRUNCATED,
    KZT_GUEST_FIELD_NOT_PARSED,
} kzt_guest_field_status_t;

typedef enum kzt_guest_registry_result {
    KZT_GUEST_REGISTRY_ADDED = 0,
    KZT_GUEST_REGISTRY_UNCHANGED,
    KZT_GUEST_REGISTRY_UPDATED,
    KZT_GUEST_REGISTRY_CONFLICT,
    KZT_GUEST_REGISTRY_DISABLED,
    KZT_GUEST_REGISTRY_ERROR,
} kzt_guest_registry_result_t;

typedef struct kzt_guest_scalar_field {
    uintptr_t value;
    kzt_guest_field_status_t status;
} kzt_guest_scalar_field_t;

typedef struct kzt_guest_string_field {
    const char *value;
    kzt_guest_field_status_t status;
} kzt_guest_string_field_t;

typedef struct kzt_guest_object_observation {
    uintptr_t link_map_addr;
    kzt_guest_scalar_field_t load_bias;
    kzt_guest_scalar_field_t dynamic_addr;
    kzt_guest_scalar_field_t map_start;
    kzt_guest_scalar_field_t map_end;
    kzt_guest_scalar_field_t namespace_id;
    kzt_guest_string_field_t path;
    kzt_guest_string_field_t soname;
    kzt_guest_field_status_t dynamic_view_status;
} kzt_guest_object_observation_t;

typedef struct kzt_guest_object_snapshot {
    uintptr_t link_map_addr;
    kzt_guest_scalar_field_t load_bias;
    kzt_guest_scalar_field_t dynamic_addr;
    kzt_guest_scalar_field_t map_start;
    kzt_guest_scalar_field_t map_end;
    kzt_guest_scalar_field_t namespace_id;
    kzt_guest_string_field_t path;
    kzt_guest_string_field_t soname;
    kzt_guest_field_status_t dynamic_view_status;
    kzt_guest_object_state_t state;
    unsigned long generation;
} kzt_guest_object_snapshot_t;

typedef struct kzt_guest_registry_dump {
    kzt_guest_object_snapshot_t *objects;
    size_t count;
} kzt_guest_registry_dump_t;

typedef struct kzt_guest_registry_diagnostics {
    unsigned long observations;
    unsigned long added;
    unsigned long unchanged;
    unsigned long updated;
    unsigned long conflicts;
    unsigned long disabled;
    unsigned long errors;
    unsigned long init_failures;
    unsigned long allocation_failures;
} kzt_guest_registry_diagnostics_t;

kzt_guest_registry_t *kzt_guest_registry_init(void);
void kzt_guest_registry_destroy(kzt_guest_registry_t **registry);

kzt_guest_registry_result_t kzt_guest_registry_observe(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *observation);

int kzt_guest_registry_find_by_link_map(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_object_snapshot_t **snapshot);

int kzt_guest_registry_dump_snapshot(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_dump_t *dump);

int kzt_guest_registry_get_diagnostics(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_diagnostics_t *diagnostics);

void kzt_guest_object_snapshot_free(kzt_guest_object_snapshot_t *snapshot);
void kzt_guest_registry_dump_free(kzt_guest_registry_dump_t *dump);

#ifdef KZT_GUEST_REGISTRY_TEST
void kzt_guest_registry_test_set_alloc_failure_after(long allocations);
#endif

#endif
