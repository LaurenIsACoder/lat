#include "qemu/osdep.h"

#include "kzt_rela_stub_detector.h"

#include <stdint.h>

static int kzt_rela_add_load_bias(uintptr_t address, intptr_t load_bias,
                                  uintptr_t *runtime_address)
{
    uintptr_t magnitude;

    if (!runtime_address) {
        return 0;
    }
    if (load_bias >= 0) {
        magnitude = (uintptr_t)load_bias;
        if (address > UINTPTR_MAX - magnitude) {
            return 0;
        }
        *runtime_address = address + magnitude;
        return 1;
    }

    magnitude = (uintptr_t)(-(load_bias + 1)) + 1;
    if (address < magnitude) {
        return 0;
    }
    *runtime_address = address - magnitude;
    return 1;
}

static int kzt_rela_value_in_range(uintptr_t value, uintptr_t start,
                                   uintptr_t end)
{
    return start < end && value >= start && value < end;
}

static int kzt_rela_value_in_loaded_range(uintptr_t value,
                                          intptr_t load_bias,
                                          uintptr_t start,
                                          uintptr_t end)
{
    uintptr_t runtime_start;
    uintptr_t runtime_end;

    if (start >= end ||
        !kzt_rela_add_load_bias(start, load_bias, &runtime_start) ||
        !kzt_rela_add_load_bias(end, load_bias, &runtime_end)) {
        return 0;
    }

    return kzt_rela_value_in_range(value, runtime_start, runtime_end);
}

int kzt_rela_slot_current_is_unresolved_stub(
    uintptr_t slot_current_value, kzt_rela_stub_coordinate_t coordinate,
    intptr_t load_bias,
    uintptr_t plt_start, uintptr_t plt_end,
    uintptr_t gotplt_start, uintptr_t gotplt_end)
{
    if (!slot_current_value ||
        coordinate == KZT_RELA_STUB_COORDINATE_UNKNOWN) {
        return 0;
    }

    if (coordinate == KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW) {
        return kzt_rela_value_in_range(slot_current_value,
                                       plt_start, plt_end) ||
               kzt_rela_value_in_range(slot_current_value,
                                       gotplt_start, gotplt_end);
    }
    if (coordinate == KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED) {
        return kzt_rela_value_in_loaded_range(slot_current_value, load_bias,
                                              plt_start, plt_end) ||
               kzt_rela_value_in_loaded_range(slot_current_value, load_bias,
                                              gotplt_start, gotplt_end);
    }

    return 0;
}

kzt_rela_jump_slot_defer_plan_t kzt_rela_jump_slot_defer_plan(
    const kzt_rela_jump_slot_defer_input_t *input)
{
    kzt_rela_jump_slot_defer_plan_t plan = { 0, 0, 0 };
    int raw_stub;
    int runtime_stub;

    if (!input) {
        return plan;
    }

    raw_stub = kzt_rela_slot_current_is_unresolved_stub(
            input->slot_current_value,
            KZT_RELA_STUB_COORDINATE_LINK_TIME_RAW,
            input->load_bias, input->plt_start, input->plt_end,
            input->gotplt_start, input->gotplt_end);
    runtime_stub = kzt_rela_slot_current_is_unresolved_stub(
        input->slot_current_value,
        KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
        input->load_bias, input->plt_start, input->plt_end,
        input->gotplt_start, input->gotplt_end);
    plan.slot_is_unresolved_stub = raw_stub || runtime_stub;
    plan.should_defer = plan.slot_is_unresolved_stub &&
        !input->bind_is_local && !input->bindnow &&
        input->need_resolver_present;
    plan.should_add_delta = plan.should_defer && raw_stub && !runtime_stub;

    return plan;
}
