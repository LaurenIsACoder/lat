#ifndef KZT_PATCH_SPIKE_WRITER_H
#define KZT_PATCH_SPIKE_WRITER_H

#include <stddef.h>
#include <stdint.h>

#include "kzt_patch_spike_guard.h"

typedef int (*kzt_patch_spike_slot_read_fn)(uintptr_t slot_addr,
                                            uintptr_t *value,
                                            void *opaque);
typedef int (*kzt_patch_spike_slot_write_fn)(uintptr_t slot_addr,
                                             uintptr_t value,
                                             void *opaque);

typedef struct kzt_patch_spike_permission_lease {
    uintptr_t guest_page;
    uintptr_t guest_page_length;
    int original_permissions;
    int checked;
    int was_writable;
    int write_enabled;
    int restore_attempted;
    int restored;
} kzt_patch_spike_permission_lease_t;

typedef int (*kzt_patch_spike_slot_permission_begin_fn)(
    uintptr_t slot_addr, kzt_patch_spike_permission_lease_t *lease,
    void *opaque);
typedef int (*kzt_patch_spike_slot_permission_end_fn)(
    kzt_patch_spike_permission_lease_t *lease, void *opaque);
typedef int (*kzt_patch_spike_slot_generation_validate_fn)(
    const kzt_patch_decision_t *decision, void *opaque);

typedef struct kzt_patch_spike_slot_ops {
    kzt_patch_spike_slot_read_fn read_slot;
    kzt_patch_spike_slot_write_fn write_slot;
    kzt_patch_spike_slot_permission_begin_fn begin_write;
    kzt_patch_spike_slot_permission_end_fn end_write;
    kzt_patch_spike_slot_generation_validate_fn validate_generation;
    void *opaque;
} kzt_patch_spike_slot_ops_t;

typedef struct kzt_patch_spike_record {
    int valid;

    kzt_patch_decision_kind_t decision_kind;
    kzt_patch_reason_t decision_reason;
    int allow_native_bridge;
    kzt_patch_table_kind_t table_kind;
    kzt_patch_relocation_type_t reloc_type;
    size_t entry_index;
    uintptr_t entry_addr;
    uintptr_t slot_addr;
    uintptr_t source_link_map;
    uintptr_t current_owner_link_map;
    unsigned long source_generation;
    unsigned long current_owner_generation;
    unsigned long dynamic_view_generation;

    int expected_value_present;
    uintptr_t expected_value;
    uintptr_t replacement_value;
    uintptr_t previous_value;
    uintptr_t observed_value;
    uintptr_t verified_value;
    uintptr_t rollback_value;

    const char *symbol_name;
    const char *wrapper_name;

    kzt_patch_spike_result_t result;
    kzt_patch_spike_failure_t failure;
    kzt_patch_spike_action_t action;
    int skip_legacy_write;
    unsigned long writes_remaining;

    int writer_called;
    int read_attempted;
    int expected_current_matched;
    int write_attempted;
    int write_succeeded;
    int verify_attempted;
    int verify_succeeded;
    int rollback_called;
    int rollback_succeeded;
    int rollback_verify_attempted;
    uintptr_t rollback_verified_value;
    int rollback_verify_succeeded;
    int generation_checked;
    int generation_matched;
    int permission_checked;
    uintptr_t permission_guest_page;
    uintptr_t permission_guest_page_length;
    int permission_original_permissions;
    int permission_was_writable;
    int permission_write_enabled;
    int permission_restore_attempted;
    int permission_restored;
} kzt_patch_spike_record_t;

void kzt_patch_spike_record_init(kzt_patch_spike_record_t *record,
                                 const kzt_patch_decision_t *decision);

int kzt_patch_spike_writer_try_apply(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    kzt_patch_spike_record_t *record);

int kzt_patch_spike_writer_try_apply_with_slot_ops(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_slot_ops_t *slot_ops,
    kzt_patch_spike_record_t *record);

#endif
