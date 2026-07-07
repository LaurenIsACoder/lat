#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_guest_dynamic_diagnostics.h"

#define TEST_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KZT_TEST_UNKNOWN_DYNAMIC_TAG 0x6000000d

static int failures;

static void check_true(const char *name, int condition)
{
    if (condition) {
        return;
    }

    fprintf(stderr, "%s: condition failed\n", name);
    ++failures;
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %d expected %d\n", name, got, expected);
    ++failures;
}

static void check_size(const char *name, size_t got, size_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %lu expected %lu\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_ulong(const char *name, unsigned long got,
                        unsigned long expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got %lu expected %lu\n", name, got, expected);
    ++failures;
}

static void check_u64(const char *name, uint64_t got, uint64_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%llx expected 0x%llx\n", name,
            (unsigned long long)got, (unsigned long long)expected);
    ++failures;
}

static void check_uintptr(const char *name, uintptr_t got, uintptr_t expected)
{
    if (got == expected) {
        return;
    }

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name,
            (unsigned long)got, (unsigned long)expected);
    ++failures;
}

static void check_str_contains(const char *name, const char *value,
                               const char *expected)
{
    if (value && expected && strstr(value, expected)) {
        return;
    }

    fprintf(stderr, "%s: '%s' does not contain '%s'\n", name,
            value ? value : "(null)", expected ? expected : "(null)");
    ++failures;
}

static kzt_guest_dynamic_field_t make_field(
    uint64_t value,
    kzt_guest_dynamic_address_semantics_t semantics)
{
    return (kzt_guest_dynamic_field_t) {
        .present = 1,
        .value = value,
        .address_semantics = semantics,
    };
}

static kzt_guest_dynamic_parse_result_t make_complete_result(void)
{
    kzt_guest_dynamic_parse_result_t result = {
        .status = KZT_GUEST_DYNAMIC_COMPLETE,
        .error = KZT_GUEST_DYNAMIC_ERROR_NONE,
        .entry_count = 12,
        .scan_limit = KZT_GUEST_DYNAMIC_SCAN_LIMIT,
        .view = {
            .dynamic_addr = 0x7000001000,
            .load_bias = 0x7000000000,
            .status = KZT_GUEST_DYNAMIC_COMPLETE,
            .entry_count = 12,
            .has_null = 1,
            .scan_limit = KZT_GUEST_DYNAMIC_SCAN_LIMIT,
            .symtab = make_field(0x7000010000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .strtab = make_field(0x7000020000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .syment = make_field(24, KZT_GUEST_DYNAMIC_SCALAR),
            .strsz = make_field(0x220, KZT_GUEST_DYNAMIC_SCALAR),
            .hash = make_field(0x7000030000,
                               KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .gnu_hash = make_field(0x7000040000,
                                   KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .versym = make_field(0x7000050000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .verneed = make_field(0x7000060000,
                                  KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .verneednum = make_field(2, KZT_GUEST_DYNAMIC_SCALAR),
            .verdef = make_field(0x7000070000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .verdefnum = make_field(1, KZT_GUEST_DYNAMIC_SCALAR),
            .rela = make_field(0x7000080000,
                               KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .relasz = make_field(0x60, KZT_GUEST_DYNAMIC_SCALAR),
            .relaent = make_field(24, KZT_GUEST_DYNAMIC_SCALAR),
            .rel = make_field(0x7000090000,
                              KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .relsz = make_field(0x40, KZT_GUEST_DYNAMIC_SCALAR),
            .relent = make_field(16, KZT_GUEST_DYNAMIC_SCALAR),
            .jmprel = make_field(0x70000a0000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .pltrelsz = make_field(0x30, KZT_GUEST_DYNAMIC_SCALAR),
            .pltrel = make_field(DT_RELA, KZT_GUEST_DYNAMIC_SCALAR),
            .pltgot = make_field(0x70000b0000,
                                 KZT_GUEST_DYNAMIC_RUNTIME_ADDRESS),
            .needed_offsets = { 0x10, 0x38 },
            .needed_count = 2,
            .needed_address_semantics =
                KZT_GUEST_DYNAMIC_STRING_TABLE_OFFSET,
        },
    };

    return result;
}

static const kzt_guest_dynamic_diagnostic_field_t *require_field(
    const kzt_guest_dynamic_diagnostic_report_t *report,
    const char *name)
{
    const kzt_guest_dynamic_diagnostic_field_t *field =
        kzt_guest_dynamic_diagnostic_find_field(report, name);

    check_true(name, field != NULL);
    return field;
}

static void assert_field_match(
    const kzt_guest_dynamic_diagnostic_report_t *report,
    const char *name,
    kzt_guest_dynamic_diagnostic_match_t expected)
{
    const kzt_guest_dynamic_diagnostic_field_t *field = require_field(report,
                                                                      name);

    if (!field) {
        return;
    }

    check_int(name, field->match, expected);
}

static void test_identical_views_are_matched(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;

    check_int("identical.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("identical.status", report.status_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    check_int("identical.entry-count", report.entry_count_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    check_int("identical.unknown-tags", report.unknown_tags_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    check_size("identical.field-count", report.field_count, 22);
    check_size("identical.matched", report.matched_count, report.field_count);
    check_size("identical.missing-old", report.missing_old_count, 0);
    check_size("identical.missing-new", report.missing_new_count, 0);
    check_size("identical.mismatch", report.mismatch_count, 0);
    check_size("identical.difference", report.difference_count, 0);
    check_size("identical.blocking", report.blocking_count, 0);
    assert_field_match(&report, "symtab",
                       KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    assert_field_match(&report, "needed_offsets",
                       KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
}

static void test_old_field_missing_from_new_is_reported(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;
    const kzt_guest_dynamic_diagnostic_field_t *field;

    memset(&new_result.view.strtab, 0, sizeof(new_result.view.strtab));
    check_int("missing-new.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);

    field = require_field(&report, "strtab");
    if (!field) {
        return;
    }

    check_int("missing-new.match", field->match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_NEW);
    check_true("missing-new.old-present", field->old_present);
    check_true("missing-new.new-present", !field->new_present);
    check_u64("missing-new.old-value", field->old_value, 0x7000020000);
    check_size("missing-new.count", report.missing_new_count, 1);
    check_size("missing-new.difference", report.difference_count, 1);
    check_size("missing-new.blocking", report.blocking_count, 0);
}

static void test_new_parser_incomplete_states_are_reported(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;

    new_result.status = KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    new_result.error = KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED;
    new_result.entry_count = KZT_GUEST_DYNAMIC_SCAN_LIMIT;
    new_result.view.status = KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    new_result.view.entry_count = KZT_GUEST_DYNAMIC_SCAN_LIMIT;
    new_result.view.has_null = 0;

    check_int("truncated.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("truncated.status-match", report.status_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH);
    check_int("truncated.new-status", report.new_status,
              KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL);
    check_int("truncated.new-error", report.new_error,
              KZT_GUEST_DYNAMIC_ERROR_SCAN_LIMIT_EXCEEDED);
    check_true("truncated.flag", report.new_truncated);
    check_size("truncated.blocking", report.blocking_count, 1);

    new_result = make_complete_result();
    new_result.status = KZT_GUEST_DYNAMIC_READ_ERROR;
    new_result.error = KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE;
    new_result.read_error_addr = 0x7000001080;
    new_result.entry_count = 8;
    new_result.view.status = KZT_GUEST_DYNAMIC_READ_ERROR;
    new_result.view.entry_count = 8;
    new_result.view.has_null = 0;

    check_int("read-error.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("read-error.status-match", report.status_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH);
    check_int("read-error.new-status", report.new_status,
              KZT_GUEST_DYNAMIC_READ_ERROR);
    check_int("read-error.new-error", report.new_error,
              KZT_GUEST_DYNAMIC_ERROR_READ_FAILURE);
    check_true("read-error.flag", report.new_read_error);
    check_uintptr("read-error.addr", report.new_read_error_addr,
                  0x7000001080);
    check_size("read-error.blocking", report.blocking_count, 1);
}

static void test_unknown_tag_difference_is_diagnostic_only(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;
    kzt_guest_dynamic_diagnostic_summary_t summary;
    char line[512];

    new_result.unknown_tag_count = 1;
    new_result.first_unknown_tag = KZT_TEST_UNKNOWN_DYNAMIC_TAG;
    new_result.first_unknown_tag_index = 3;
    new_result.view.unknown_tag_count = 1;
    new_result.view.first_unknown_tag = KZT_TEST_UNKNOWN_DYNAMIC_TAG;
    new_result.view.first_unknown_tag_index = 3;

    check_int("unknown.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("unknown.match", report.unknown_tags_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH);
    check_size("unknown.old-count", report.old_unknown_tag_count, 0);
    check_size("unknown.new-count", report.new_unknown_tag_count, 1);
    check_size("unknown.field-mismatch", report.mismatch_count, 0);
    check_size("unknown.difference", report.difference_count, 1);
    check_size("unknown.blocking", report.blocking_count, 0);

    check_int("unknown.summary",
              kzt_guest_dynamic_diagnostics_summarize(&report, 0xabc000, 9,
                                                      &summary),
              0);
    check_int("unknown.summary-kind", summary.first_difference_kind,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_UNKNOWN_TAGS);
    check_true("unknown.summary-new-present", summary.first_new_present);
    check_true("unknown.summary-new-tag",
               summary.first_new_tag == KZT_TEST_UNKNOWN_DYNAMIC_TAG);
    check_size("unknown.summary-new-index", summary.first_new_tag_index, 3);
    check_int("unknown.format",
              kzt_guest_dynamic_diagnostics_format_summary(&summary, line,
                                                           sizeof(line)), 0);
    check_str_contains("unknown.format-first", line, "first=unknown_tags");
}

static void test_needed_offsets_difference_is_reported(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;
    const kzt_guest_dynamic_diagnostic_field_t *field;

    new_result.view.needed_offsets[1] = 0x58;
    check_int("needed.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);

    field = require_field(&report, "needed_offsets");
    if (!field) {
        return;
    }

    check_int("needed.match", field->match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH);
    check_size("needed.old-count", field->old_count, 2);
    check_size("needed.new-count", field->new_count, 2);
    check_u64("needed.old-first", field->old_value, 0x10);
    check_u64("needed.new-first", field->new_value, 0x10);
    check_size("needed.mismatch", report.mismatch_count, 1);
    check_size("needed.difference", report.difference_count, 1);
    check_size("needed.blocking", report.blocking_count, 0);
}

static void test_error_status_is_blocking(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;
    kzt_guest_dynamic_diagnostic_summary_t summary;
    char line[512];

    old_result.status = KZT_GUEST_DYNAMIC_ERROR;
    old_result.error = KZT_GUEST_DYNAMIC_ERROR_INVALID_ARGUMENT;
    old_result.view.status = KZT_GUEST_DYNAMIC_ERROR;
    new_result.status = KZT_GUEST_DYNAMIC_ERROR;
    new_result.error = KZT_GUEST_DYNAMIC_ERROR_INVALID_ARGUMENT;
    new_result.view.status = KZT_GUEST_DYNAMIC_ERROR;

    check_int("error.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("error.status-match", report.status_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    check_size("error.difference", report.difference_count, 0);
    check_size("error.blocking", report.blocking_count, 2);

    check_int("error.summary",
              kzt_guest_dynamic_diagnostics_summarize(&report, 0xabc100, 10,
                                                      &summary),
              0);
    check_true("error.summary-blocking", summary.blocking);
    check_int("error.summary-kind", summary.first_difference_kind,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_STATUS);
    check_int("error.summary-match", summary.first_difference_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED);
    check_int("error.format",
              kzt_guest_dynamic_diagnostics_format_summary(&summary, line,
                                                           sizeof(line)), 0);
    check_str_contains("error.format-blocking", line, "blocking=1");
    check_str_contains("error.format-first", line, "first=status");
}

static void test_summary_includes_identity_and_first_field(void)
{
    kzt_guest_dynamic_parse_result_t old_result = make_complete_result();
    kzt_guest_dynamic_parse_result_t new_result = make_complete_result();
    kzt_guest_dynamic_diagnostic_report_t report;
    kzt_guest_dynamic_diagnostic_summary_t summary;
    char line[512];

    new_result.view.pltgot.value = 0x70000c0000;
    check_int("summary.compare",
              kzt_guest_dynamic_diagnostics_compare(&old_result, &new_result,
                                                    &report),
              0);
    check_int("summary.create",
              kzt_guest_dynamic_diagnostics_summarize(&report, 0xabcdef00,
                                                      17, &summary),
              0);

    check_uintptr("summary.link-map", summary.link_map_addr, 0xabcdef00);
    check_ulong("summary.generation", summary.generation, 17);
    check_true("summary.not-matched", !summary.matched);
    check_true("summary.not-blocking", !summary.blocking);
    check_size("summary.difference", summary.difference_count, 1);
    check_int("summary.kind", summary.first_difference_kind,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_FIELD);
    check_true("summary.name", !strcmp(summary.first_difference_name,
                                       "pltgot"));
    check_int("summary.match", summary.first_difference_match,
              KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH);
    check_true("summary.old-present", summary.first_old_present);
    check_true("summary.new-present", summary.first_new_present);
    check_u64("summary.old-value", summary.first_old_value, 0x70000b0000);
    check_u64("summary.new-value", summary.first_new_value, 0x70000c0000);

    check_int("summary.format",
              kzt_guest_dynamic_diagnostics_format_summary(&summary, line,
                                                           sizeof(line)), 0);
    check_str_contains("summary.format-object", line,
                       "link_map=0xabcdef00");
    check_str_contains("summary.format-generation", line,
                       "generation=17");
    check_str_contains("summary.format-first", line, "first=pltgot");
    check_str_contains("summary.format-differences", line,
                       "differences=1");
}

static int test_matches_filter(const char *name, int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--filter") && i + 1 < argc) {
            return strcmp(name, argv[i + 1]) == 0;
        }
    }

    return 1;
}

int main(int argc, char **argv)
{
    if (test_matches_filter("identical_views_are_matched", argc, argv)) {
        test_identical_views_are_matched();
    }
    if (test_matches_filter("old_field_missing_from_new_is_reported",
                            argc, argv)) {
        test_old_field_missing_from_new_is_reported();
    }
    if (test_matches_filter("new_parser_incomplete_states_are_reported",
                            argc, argv)) {
        test_new_parser_incomplete_states_are_reported();
    }
    if (test_matches_filter("unknown_tag_difference_is_diagnostic_only",
                            argc, argv)) {
        test_unknown_tag_difference_is_diagnostic_only();
    }
    if (test_matches_filter("needed_offsets_difference_is_reported",
                            argc, argv)) {
        test_needed_offsets_difference_is_reported();
    }
    if (test_matches_filter("error_status_is_blocking", argc, argv)) {
        test_error_status_is_blocking();
    }
    if (test_matches_filter("summary_includes_identity_and_first_field",
                            argc, argv)) {
        test_summary_includes_identity_and_first_field();
    }

    if (failures) {
        fprintf(stderr, "kzt-guest-dynamic-diagnostics: %d failure(s)\n",
                failures);
        return 1;
    }

    puts("kzt-guest-dynamic-diagnostics: selected contract tests passed");
    return 0;
}
