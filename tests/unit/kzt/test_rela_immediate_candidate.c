#include <stdio.h>
#include <string.h>

#include "elf.h"
#include "target/i386/latx/include/kzt_rela_immediate_candidate.h"

static int failures;

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got,
            expected);
    ++failures;
}

static void check_str(const char *name, const char *got,
                      const char *expected)
{
    if (got && expected && !strcmp(got, expected)) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
    ++failures;
}

static kzt_patch_object_ref_t object_ref(uintptr_t link_map_addr,
                                         unsigned long generation,
                                         const char *soname)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = link_map_addr,
        .map_start = 0x7000000000 + generation * 0x100000,
        .map_end = 0x7000009000 + generation * 0x100000,
        .generation = generation,
        .soname = soname,
        .path = soname,
    };
}

static kzt_rela_immediate_candidate_request_t base_request(void)
{
    return (kzt_rela_immediate_candidate_request_t) {
        .relocation_type = R_X86_64_JUMP_SLOT,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 4,
        .entry_addr = 0x7000100200,
        .source = object_ref(0x1110, 5, "librequester.so"),
        .dynamic_addr = 0x7000100000,
        .load_bias = 0x7000000000,
        .dynamic_view_generation = 18,
        .dynamic_view_available = 1,
        .slot_addr = 0x7000200088,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7100001234,
        .lazy_binding_deferred = 0,
        .symbol_index = 33,
        .symbol_name = "gtk_widget_show",
        .version = "GTK_3.0",
        .current_owner = object_ref(0x2220, 9, "libgtk-3.so"),
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
        .wrapper_name = "wrappedgtk3",
        .wrapper_symbol_version = "GTK_3.0",
        .bridge_target = 0x7200004560,
    };
}

static void test_immediate_jump_slot_builds_candidate_fields(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;
    const kzt_patch_candidate_t *candidate;

    check_int("jump_slot.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("jump_slot.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED);
    check_int("jump_slot.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NONE);
    check_int("jump_slot.candidate_present", result.candidate_present, 1);
    check_int("jump_slot.decision_present", result.decision_present, 1);

    candidate = &result.candidate;
    check_int("jump_slot.table", candidate->table_kind,
              KZT_PATCH_TABLE_PLT_RELA);
    check_ulong("jump_slot.entry_index", candidate->entry_index, 4);
    check_ulong("jump_slot.entry_addr", candidate->entry_addr,
                request.entry_addr);
    check_int("jump_slot.reloc", candidate->reloc_type,
              KZT_PATCH_RELOCATION_JUMP_SLOT);
    check_ulong("jump_slot.slot", candidate->slot_addr, request.slot_addr);
    check_int("jump_slot.current_present",
              candidate->slot_current_value_present, 1);
    check_ulong("jump_slot.current", candidate->slot_current_value,
                request.slot_current_value);
    check_int("jump_slot.lazy", candidate->lazy_binding_deferred, 0);
    check_ulong("jump_slot.symbol_index", candidate->symbol_index, 33);
    check_str("jump_slot.symbol", candidate->symbol_name,
              "gtk_widget_show");
    check_str("jump_slot.version", candidate->version, "GTK_3.0");
    check_int("jump_slot.owner", candidate->owner_match,
              KZT_PATCH_OWNER_MATCH);
    check_int("jump_slot.wrapper", candidate->wrapper_match,
              KZT_PATCH_WRAPPER_VERSION_MATCH);
    check_ulong("jump_slot.bridge", candidate->bridge_target,
                request.bridge_target);
    check_int("jump_slot.decision", result.decision.kind,
              KZT_PATCH_DECISION_APPROVED);
}

static void test_non_target_relocation_does_not_build_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.relocation_type = R_X86_64_RELATIVE;
    check_int("relative.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("relative.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("relative.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION);
    check_int("relative.candidate_present", result.candidate_present, 0);
    check_int("relative.decision_present", result.decision_present, 0);
}

static void test_glob_dat_keeps_legacy_path_without_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.relocation_type = R_X86_64_GLOB_DAT;
    request.table_kind = KZT_PATCH_TABLE_RELA;
    check_int("glob_dat.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("glob_dat.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("glob_dat.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_NON_TARGET_RELOCATION);
    check_int("glob_dat.candidate_present", result.candidate_present, 0);
}

static void test_deferred_lazy_binding_does_not_build_writable_candidate(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.lazy_binding_deferred = 1;
    check_int("lazy.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("lazy.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_SKIPPED);
    check_int("lazy.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_DEFERRED_LAZY_BINDING);
    check_int("lazy.candidate_present", result.candidate_present, 0);
}

static void test_missing_symbol_information_fails_open(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    request.symbol_name = NULL;
    check_int("missing_symbol.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("missing_symbol.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_FAIL_OPEN);
    check_int("missing_symbol.reason", result.reason,
              KZT_RELA_IMMEDIATE_CANDIDATE_REASON_MISSING_SYMBOL_NAME);
    check_int("missing_symbol.candidate_present", result.candidate_present, 0);
    check_int("missing_symbol.decision_present", result.decision_present, 0);
}

static void test_missing_owner_still_plans_but_keeps_legacy_decision(void)
{
    kzt_rela_immediate_candidate_request_t request = base_request();
    kzt_rela_immediate_candidate_result_t result;

    memset(&request.current_owner, 0, sizeof(request.current_owner));
    request.owner_match = KZT_PATCH_OWNER_UNKNOWN;
    request.wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    request.bridge_target = 0;

    check_int("owner_unknown.call",
              kzt_rela_immediate_jump_slot_plan(&request, &result), 0);
    check_int("owner_unknown.status", result.status,
              KZT_RELA_IMMEDIATE_CANDIDATE_PLANNED);
    check_int("owner_unknown.candidate_present", result.candidate_present, 1);
    check_int("owner_unknown.decision_present", result.decision_present, 1);
    check_int("owner_unknown.decision", result.decision.kind,
              KZT_PATCH_DECISION_UNSUPPORTED);
    check_int("owner_unknown.reason", result.decision.reason,
              KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER);
}

int main(void)
{
    test_immediate_jump_slot_builds_candidate_fields();
    test_non_target_relocation_does_not_build_candidate();
    test_glob_dat_keeps_legacy_path_without_candidate();
    test_deferred_lazy_binding_does_not_build_writable_candidate();
    test_missing_symbol_information_fails_open();
    test_missing_owner_still_plans_but_keeps_legacy_decision();

    if (failures) {
        fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }

    return 0;
}
