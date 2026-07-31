#include "kzt_patch_spike_writer.h"

#include <string.h>

typedef struct kzt_patch_spike_writer_state {
    const kzt_patch_spike_slot_ops_t *slot_ops;
    kzt_patch_spike_record_t *record;
    kzt_patch_spike_permission_lease_t permission_lease;
    int permission_active;
} kzt_patch_spike_writer_state_t;

static int kzt_patch_spike_direct_read(uintptr_t slot_addr,
                                       uintptr_t *value,
                                       void *opaque)
{
    volatile uintptr_t *slot = (volatile uintptr_t *)slot_addr;

    (void)opaque;
    if (!slot || !value) {
        return -1;
    }

    *value = *slot;
    return 0;
}

static int kzt_patch_spike_direct_write(uintptr_t slot_addr,
                                        uintptr_t value,
                                        void *opaque)
{
    volatile uintptr_t *slot = (volatile uintptr_t *)slot_addr;

    (void)opaque;
    if (!slot) {
        return -1;
    }

    *slot = value;
    return 0;
}

static const kzt_patch_spike_slot_ops_t kzt_patch_spike_direct_slot_ops = {
    .read_slot = kzt_patch_spike_direct_read,
    .write_slot = kzt_patch_spike_direct_write,
};

static int kzt_patch_spike_slot_ops_ready(
    const kzt_patch_spike_slot_ops_t *slot_ops)
{
    return slot_ops && slot_ops->read_slot && slot_ops->write_slot &&
           (slot_ops->begin_write != NULL) ==
               (slot_ops->end_write != NULL);
}

void kzt_patch_spike_record_init(kzt_patch_spike_record_t *record,
                                 const kzt_patch_decision_t *decision)
{
    if (!record) {
        return;
    }

    memset(record, 0, sizeof(*record));
    record->valid = 1;
    record->result = KZT_PATCH_SPIKE_RESULT_FAIL_OPEN;
    record->failure = KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT;
    record->action = KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY;

    if (!decision) {
        return;
    }

    record->decision_kind = decision->kind;
    record->decision_reason = decision->reason;
    record->allow_native_bridge = decision->allow_native_bridge;
    record->table_kind = decision->table_kind;
    record->reloc_type = decision->reloc_type;
    record->entry_index = decision->entry_index;
    record->entry_addr = decision->entry_addr;
    record->slot_addr = decision->slot_addr;
    record->source_link_map = decision->source.link_map_addr;
    record->current_owner_link_map = decision->current_owner.link_map_addr;
    record->source_generation = decision->source.generation;
    record->current_owner_generation = decision->current_owner.generation;
    record->dynamic_view_generation = decision->dynamic_view_generation;
    record->expected_value_present = decision->slot_current_value_present;
    record->expected_value = decision->slot_current_value;
    record->replacement_value = decision->bridge_target;
    record->symbol_name = decision->symbol_name;
    record->wrapper_name = decision->wrapper_name;
}

static void kzt_patch_spike_record_permission(
    kzt_patch_spike_record_t *record,
    const kzt_patch_spike_permission_lease_t *lease)
{
    if (!record || !lease) {
        return;
    }

    record->permission_checked = lease->checked;
    record->permission_guest_page = lease->guest_page;
    record->permission_guest_page_length = lease->guest_page_length;
    record->permission_original_permissions = lease->original_permissions;
    record->permission_was_writable = lease->was_writable;
    record->permission_write_enabled = lease->write_enabled;
    record->permission_restore_attempted = lease->restore_attempted;
    record->permission_restore_attempts = lease->restore_attempts;
    record->permission_restored = lease->restored;
}

static kzt_patch_spike_writer_status_t kzt_patch_spike_writer_finish_slot(
    const kzt_patch_decision_t *decision, void *opaque)
{
    kzt_patch_spike_writer_state_t *state = opaque;

    (void)decision;
    if (!state || !state->record) {
        return KZT_PATCH_SPIKE_WRITER_READ_FAILED;
    }
    if (!state->permission_active) {
        return KZT_PATCH_SPIKE_WRITER_OK;
    }

    state->permission_lease.restore_attempted = 1;
    ++state->permission_lease.restore_attempts;
    if (state->slot_ops->end_write &&
        state->slot_ops->end_write(&state->permission_lease,
                                   state->slot_ops->opaque) != 0) {
        kzt_patch_spike_record_permission(state->record,
                                          &state->permission_lease);
        return KZT_PATCH_SPIKE_WRITER_PERMISSION_RESTORE_FAILED;
    }
    state->permission_lease.restored = 1;
    kzt_patch_spike_record_permission(state->record,
                                      &state->permission_lease);
    state->permission_active = 0;
    return KZT_PATCH_SPIKE_WRITER_OK;
}

static kzt_patch_spike_writer_status_t kzt_patch_spike_writer_abort_slot(
    const kzt_patch_decision_t *decision, void *opaque,
    kzt_patch_spike_writer_status_t status)
{
    if (kzt_patch_spike_writer_finish_slot(decision, opaque) !=
        KZT_PATCH_SPIKE_WRITER_OK) {
        return KZT_PATCH_SPIKE_WRITER_PERMISSION_RESTORE_FAILED;
    }
    return status;
}

static int kzt_patch_spike_writer_decision_supported(
    const kzt_patch_decision_t *decision)
{
    return decision && decision->kind == KZT_PATCH_DECISION_APPROVED &&
           decision->reason == KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE &&
           decision->allow_native_bridge &&
           decision->reloc_type == KZT_PATCH_RELOCATION_JUMP_SLOT &&
           decision->slot_addr && decision->slot_current_value_present &&
           decision->bridge_target && decision->source.known &&
           decision->source.link_map_addr && decision->source.generation &&
           decision->dynamic_view_available &&
           decision->dynamic_view_generation &&
           decision->current_owner.known &&
           decision->current_owner.link_map_addr &&
           decision->current_owner.generation &&
           decision->owner_match == KZT_PATCH_OWNER_MATCH;
}

static kzt_patch_spike_writer_status_t kzt_patch_spike_writer_write_slot(
    const kzt_patch_decision_t *decision,
    uintptr_t expected_value,
    uintptr_t replacement_value,
    uintptr_t *previous_value,
    void *opaque)
{
    kzt_patch_spike_writer_state_t *state = opaque;
    kzt_patch_spike_record_t *record;
    uintptr_t observed_value = 0;

    if (!state || !kzt_patch_spike_slot_ops_ready(state->slot_ops) ||
        !state->record ||
        !kzt_patch_spike_writer_decision_supported(decision)) {
        return KZT_PATCH_SPIKE_WRITER_READ_FAILED;
    }

    record = state->record;
    if (state->slot_ops->validate_generation) {
        record->generation_checked = 1;
        if (state->slot_ops->validate_generation(decision,
                                                 state->slot_ops->opaque) != 0) {
            record->generation_matched = 0;
            return KZT_PATCH_SPIKE_WRITER_GENERATION_MISMATCH;
        }
        record->generation_matched = 1;
    }
    if (state->slot_ops->begin_write) {
        if (state->slot_ops->begin_write(decision->slot_addr,
                                         &state->permission_lease,
                                         state->slot_ops->opaque) != 0) {
            state->permission_active =
                state->permission_lease.write_enabled != 0;
            kzt_patch_spike_record_permission(record,
                                              &state->permission_lease);
            if (state->permission_active) {
                return kzt_patch_spike_writer_abort_slot(
                    decision, state,
                    KZT_PATCH_SPIKE_WRITER_PERMISSION_ENABLE_FAILED);
            }
            return KZT_PATCH_SPIKE_WRITER_PERMISSION_ENABLE_FAILED;
        }
        state->permission_active = 1;
        kzt_patch_spike_record_permission(record, &state->permission_lease);
    }
    record->read_attempted = 1;
    if (state->slot_ops->read_slot(decision->slot_addr, &observed_value,
                                   state->slot_ops->opaque) != 0) {
        return kzt_patch_spike_writer_abort_slot(
            decision, state, KZT_PATCH_SPIKE_WRITER_READ_FAILED);
    }

    record->observed_value = observed_value;
    record->previous_value = observed_value;
    if (previous_value) {
        *previous_value = observed_value;
    }

    if (observed_value != expected_value) {
        record->expected_current_matched = 0;
        return kzt_patch_spike_writer_abort_slot(
            decision, state, KZT_PATCH_SPIKE_WRITER_EXPECTED_MISMATCH);
    }

    record->expected_current_matched = 1;
    record->write_attempted = 1;
    if (state->slot_ops->write_slot(decision->slot_addr, replacement_value,
                                    state->slot_ops->opaque) != 0) {
        return kzt_patch_spike_writer_abort_slot(
            decision, state, KZT_PATCH_SPIKE_WRITER_WRITE_FAILED);
    }

    record->write_succeeded = 1;
    return KZT_PATCH_SPIKE_WRITER_OK;
}

static int kzt_patch_spike_writer_verify_slot(
    const kzt_patch_decision_t *decision,
    uintptr_t expected_value,
    void *opaque)
{
    kzt_patch_spike_writer_state_t *state = opaque;
    kzt_patch_spike_record_t *record;
    uintptr_t observed_value = 0;

    if (!state || !kzt_patch_spike_slot_ops_ready(state->slot_ops) ||
        !state->record || !decision || !decision->slot_addr) {
        return -1;
    }

    record = state->record;
    record->verify_attempted = 1;
    if (state->slot_ops->read_slot(decision->slot_addr, &observed_value,
                                   state->slot_ops->opaque) != 0) {
        return -1;
    }

    record->verified_value = observed_value;
    if (observed_value != expected_value) {
        return -1;
    }

    record->verify_succeeded = 1;
    return 0;
}

static int kzt_patch_spike_writer_rollback_slot(
    const kzt_patch_decision_t *decision,
    uintptr_t previous_value,
    void *opaque)
{
    kzt_patch_spike_writer_state_t *state = opaque;
    kzt_patch_spike_record_t *record;
    uintptr_t observed_value = 0;

    if (!state || !kzt_patch_spike_slot_ops_ready(state->slot_ops) ||
        !state->record || !decision || !decision->slot_addr) {
        return -1;
    }

    record = state->record;
    record->rollback_called = 1;
    record->rollback_value = previous_value;
    if (state->slot_ops->write_slot(decision->slot_addr, previous_value,
                                    state->slot_ops->opaque) != 0) {
        return -1;
    }

    record->rollback_succeeded = 1;
    record->rollback_verify_attempted = 1;
    if (state->slot_ops->read_slot(decision->slot_addr, &observed_value,
                                   state->slot_ops->opaque) != 0) {
        return -1;
    }
    record->rollback_verified_value = observed_value;
    if (observed_value != previous_value) {
        return -1;
    }
    record->rollback_verify_succeeded = 1;
    return 0;
}

static void kzt_patch_spike_record_finish(
    kzt_patch_spike_record_t *record,
    const kzt_patch_spike_outcome_t *outcome)
{
    if (!record || !outcome) {
        return;
    }

    record->result = outcome->result;
    record->failure = outcome->failure;
    record->action = outcome->action;
    record->skip_legacy_write = outcome->skip_legacy_write;
    record->writes_remaining = outcome->writes_remaining;
    record->writer_called = outcome->writer_called;
    record->rollback_called = record->rollback_called ||
                              outcome->rollback_called;
    record->previous_value = outcome->previous_value;
}

int kzt_patch_spike_writer_try_apply_with_slot_ops(
    kzt_patch_spike_guard_t *guard,
    const kzt_patch_decision_t *decision,
    const kzt_patch_spike_slot_ops_t *slot_ops,
    kzt_patch_spike_record_t *record)
{
    kzt_patch_spike_writer_state_t state;
    kzt_patch_spike_writer_ops_t writer_ops;
    kzt_patch_spike_outcome_t outcome;
    const kzt_patch_spike_slot_ops_t *effective_slot_ops = slot_ops;

    if (!effective_slot_ops) {
        effective_slot_ops = &kzt_patch_spike_direct_slot_ops;
    }

    kzt_patch_spike_record_init(record, decision);
    if (!guard || !record) {
        return -1;
    }

    if (!decision ||
        (decision->kind == KZT_PATCH_DECISION_APPROVED &&
         !kzt_patch_spike_writer_decision_supported(decision))) {
        record->result = KZT_PATCH_SPIKE_RESULT_FAIL_OPEN;
        record->failure = KZT_PATCH_SPIKE_FAILURE_INVALID_ARGUMENT;
        record->action = KZT_PATCH_SPIKE_ACTION_KEEP_LEGACY;
        record->writes_remaining =
            kzt_patch_spike_guard_budget_remaining(guard);
        return 0;
    }

    memset(&state, 0, sizeof(state));
    state.slot_ops = effective_slot_ops;
    state.record = record;
    writer_ops.write_slot = kzt_patch_spike_writer_write_slot;
    writer_ops.verify_slot = kzt_patch_spike_writer_verify_slot;
    writer_ops.rollback_slot = kzt_patch_spike_writer_rollback_slot;
    writer_ops.finish_slot = kzt_patch_spike_writer_finish_slot;
    writer_ops.opaque = &state;

    if (kzt_patch_spike_guard_try_write(guard, decision, &writer_ops,
                                        &outcome) != 0) {
        return -1;
    }

    kzt_patch_spike_record_finish(record, &outcome);
    return 0;
}

int kzt_patch_spike_writer_try_apply(kzt_patch_spike_guard_t *guard,
                                     const kzt_patch_decision_t *decision,
                                     kzt_patch_spike_record_t *record)
{
    return kzt_patch_spike_writer_try_apply_with_slot_ops(guard, decision,
                                                          NULL, record);
}
