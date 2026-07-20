#include "kzt_guest_dynamic_diagnostics.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct kzt_guest_dynamic_field_spec {
    const char *name;
    size_t offset;
} kzt_guest_dynamic_field_spec_t;

static int kzt_guest_dynamic_status_is_blocking(
    kzt_guest_dynamic_status_t status)
{
    return status == KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL ||
           status == KZT_GUEST_DYNAMIC_READ_ERROR ||
           status == KZT_GUEST_DYNAMIC_ERROR;
}

static kzt_guest_dynamic_diagnostic_match_t kzt_guest_dynamic_compare_size(
    size_t old_value,
    size_t new_value)
{
    return old_value == new_value ? KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED :
                                    KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
}

static kzt_guest_dynamic_diagnostic_match_t kzt_guest_dynamic_compare_status(
    kzt_guest_dynamic_status_t old_status,
    kzt_guest_dynamic_status_t new_status)
{
    return old_status == new_status ? KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED :
                                      KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
}

static void kzt_guest_dynamic_count_field_match(
    kzt_guest_dynamic_diagnostic_report_t *report,
    kzt_guest_dynamic_diagnostic_match_t match)
{
    switch (match) {
    case KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED:
        ++report->matched_count;
        break;
    case KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_OLD:
        ++report->missing_old_count;
        break;
    case KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_NEW:
        ++report->missing_new_count;
        break;
    case KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH:
        ++report->mismatch_count;
        break;
    }
}

static void kzt_guest_dynamic_add_field_report(
    kzt_guest_dynamic_diagnostic_report_t *report,
    const kzt_guest_dynamic_diagnostic_field_t *field)
{
    if (report->field_count >= KZT_GUEST_DYNAMIC_DIAGNOSTIC_FIELD_LIMIT) {
        return;
    }

    report->fields[report->field_count++] = *field;
    kzt_guest_dynamic_count_field_match(report, field->match);
}

static kzt_guest_dynamic_diagnostic_match_t kzt_guest_dynamic_compare_field(
    const kzt_guest_dynamic_field_t *old_field,
    const kzt_guest_dynamic_field_t *new_field)
{
    if (!old_field->present && !new_field->present) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;
    }
    if (!old_field->present) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_OLD;
    }
    if (!new_field->present) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_NEW;
    }
    if (old_field->value != new_field->value ||
        old_field->address_semantics != new_field->address_semantics) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
    }

    return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;
}

static const kzt_guest_dynamic_field_t *kzt_guest_dynamic_field_at(
    const kzt_guest_dynamic_view_t *view,
    const kzt_guest_dynamic_field_spec_t *spec)
{
    return (const kzt_guest_dynamic_field_t *)((const char *)view +
                                               spec->offset);
}

static void kzt_guest_dynamic_compare_named_field(
    kzt_guest_dynamic_diagnostic_report_t *report,
    const kzt_guest_dynamic_view_t *old_view,
    const kzt_guest_dynamic_view_t *new_view,
    const kzt_guest_dynamic_field_spec_t *spec)
{
    const kzt_guest_dynamic_field_t *old_field =
        kzt_guest_dynamic_field_at(old_view, spec);
    const kzt_guest_dynamic_field_t *new_field =
        kzt_guest_dynamic_field_at(new_view, spec);
    kzt_guest_dynamic_diagnostic_field_t field = {
        .name = spec->name,
        .match = kzt_guest_dynamic_compare_field(old_field, new_field),
        .old_present = old_field->present,
        .old_value = old_field->value,
        .old_address_semantics = old_field->address_semantics,
        .new_present = new_field->present,
        .new_value = new_field->value,
        .new_address_semantics = new_field->address_semantics,
    };

    kzt_guest_dynamic_add_field_report(report, &field);
}

static int kzt_guest_dynamic_needed_offsets_equal(
    const kzt_guest_dynamic_view_t *old_view,
    const kzt_guest_dynamic_view_t *new_view)
{
    size_t i;

    if (old_view->needed_count != new_view->needed_count ||
        old_view->needed_address_semantics !=
            new_view->needed_address_semantics) {
        return 0;
    }

    for (i = 0; i < old_view->needed_count; ++i) {
        if (old_view->needed_offsets[i] != new_view->needed_offsets[i]) {
            return 0;
        }
    }

    return 1;
}

static void kzt_guest_dynamic_compare_needed_offsets(
    kzt_guest_dynamic_diagnostic_report_t *report,
    const kzt_guest_dynamic_view_t *old_view,
    const kzt_guest_dynamic_view_t *new_view)
{
    int old_present = old_view->needed_count > 0;
    int new_present = new_view->needed_count > 0;
    kzt_guest_dynamic_diagnostic_field_t field = {
        .name = "needed_offsets",
        .old_present = old_present,
        .old_value = old_present ? old_view->needed_offsets[0] : 0,
        .old_address_semantics = old_view->needed_address_semantics,
        .old_count = old_view->needed_count,
        .new_present = new_present,
        .new_value = new_present ? new_view->needed_offsets[0] : 0,
        .new_address_semantics = new_view->needed_address_semantics,
        .new_count = new_view->needed_count,
    };

    if (!old_present && !new_present) {
        field.match = KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;
    } else if (!old_present) {
        field.match = KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_OLD;
    } else if (!new_present) {
        field.match = KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISSING_NEW;
    } else if (!kzt_guest_dynamic_needed_offsets_equal(old_view, new_view)) {
        field.match = KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
    } else {
        field.match = KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;
    }

    kzt_guest_dynamic_add_field_report(report, &field);
}

static kzt_guest_dynamic_diagnostic_match_t kzt_guest_dynamic_compare_unknown(
    const kzt_guest_dynamic_parse_result_t *old_result,
    const kzt_guest_dynamic_parse_result_t *new_result)
{
    if (old_result->unknown_tag_count != new_result->unknown_tag_count) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
    }

    if (old_result->unknown_tag_count == 0) {
        return KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;
    }

    return old_result->first_unknown_tag == new_result->first_unknown_tag &&
           old_result->first_unknown_tag_index ==
               new_result->first_unknown_tag_index ?
           KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED :
           KZT_GUEST_DYNAMIC_DIAGNOSTIC_MISMATCH;
}

static size_t kzt_guest_dynamic_count_summary_differences(
    const kzt_guest_dynamic_diagnostic_report_t *report)
{
    size_t count = report->missing_old_count + report->missing_new_count +
                   report->mismatch_count;

    if (report->status_match != KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
        ++count;
    }
    if (report->entry_count_match != KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
        ++count;
    }
    if (report->unknown_tags_match != KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
        ++count;
    }

    return count;
}

static void kzt_guest_dynamic_summary_set_field(
    kzt_guest_dynamic_diagnostic_summary_t *summary,
    const kzt_guest_dynamic_diagnostic_field_t *field)
{
    summary->first_difference_kind =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_FIELD;
    summary->first_difference_name = field->name;
    summary->first_difference_match = field->match;
    summary->first_old_present = field->old_present;
    summary->first_new_present = field->new_present;
    summary->first_old_value = field->old_value;
    summary->first_new_value = field->new_value;
    summary->first_old_count = field->old_count;
    summary->first_new_count = field->new_count;
}

static void kzt_guest_dynamic_summary_set_status(
    kzt_guest_dynamic_diagnostic_summary_t *summary,
    const kzt_guest_dynamic_diagnostic_report_t *report)
{
    summary->first_difference_kind =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_STATUS;
    summary->first_difference_name = "status";
    summary->first_difference_match = report->status_match;
    summary->first_old_present = 1;
    summary->first_new_present = 1;
    summary->first_old_value = report->old_status;
    summary->first_new_value = report->new_status;
}

static void kzt_guest_dynamic_summary_set_entry_count(
    kzt_guest_dynamic_diagnostic_summary_t *summary,
    const kzt_guest_dynamic_diagnostic_report_t *report)
{
    summary->first_difference_kind =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_ENTRY_COUNT;
    summary->first_difference_name = "entry_count";
    summary->first_difference_match = report->entry_count_match;
    summary->first_old_present = 1;
    summary->first_new_present = 1;
    summary->first_old_count = report->old_entry_count;
    summary->first_new_count = report->new_entry_count;
}

static void kzt_guest_dynamic_summary_set_unknown_tags(
    kzt_guest_dynamic_diagnostic_summary_t *summary,
    const kzt_guest_dynamic_diagnostic_report_t *report)
{
    summary->first_difference_kind =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_UNKNOWN_TAGS;
    summary->first_difference_name = "unknown_tags";
    summary->first_difference_match = report->unknown_tags_match;
    summary->first_old_present = report->old_unknown_tag_count > 0;
    summary->first_new_present = report->new_unknown_tag_count > 0;
    summary->first_old_count = report->old_unknown_tag_count;
    summary->first_new_count = report->new_unknown_tag_count;
    summary->first_old_tag = report->old_first_unknown_tag;
    summary->first_new_tag = report->new_first_unknown_tag;
    summary->first_old_tag_index = report->old_first_unknown_tag_index;
    summary->first_new_tag_index = report->new_first_unknown_tag_index;
}

int kzt_guest_dynamic_diagnostics_summarize(
    const kzt_guest_dynamic_diagnostic_report_t *report,
    uintptr_t link_map_addr,
    unsigned long generation,
    kzt_guest_dynamic_diagnostic_summary_t *summary)
{
    size_t i;

    if (!report || !summary) {
        return -1;
    }

    memset(summary, 0, sizeof(*summary));
    summary->link_map_addr = link_map_addr;
    summary->generation = generation;
    summary->matched = report->difference_count == 0;
    summary->blocking = report->blocking_count > 0;
    summary->difference_count = report->difference_count;
    summary->blocking_count = report->blocking_count;
    summary->old_status = report->old_status;
    summary->new_status = report->new_status;
    summary->old_entry_count = report->old_entry_count;
    summary->new_entry_count = report->new_entry_count;
    summary->old_unknown_tag_count = report->old_unknown_tag_count;
    summary->new_unknown_tag_count = report->new_unknown_tag_count;
    summary->old_first_unknown_tag = report->old_first_unknown_tag;
    summary->new_first_unknown_tag = report->new_first_unknown_tag;
    summary->old_first_unknown_tag_index =
        report->old_first_unknown_tag_index;
    summary->new_first_unknown_tag_index =
        report->new_first_unknown_tag_index;
    summary->first_difference_kind =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_DIFFERENCE_NONE;
    summary->first_difference_name = "none";
    summary->first_difference_match =
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED;

    if (report->status_match != KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED ||
        report->blocking_count > 0) {
        kzt_guest_dynamic_summary_set_status(summary, report);
        return 0;
    }

    if (report->entry_count_match != KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
        kzt_guest_dynamic_summary_set_entry_count(summary, report);
        return 0;
    }

    if (report->unknown_tags_match !=
        KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
        kzt_guest_dynamic_summary_set_unknown_tags(summary, report);
        return 0;
    }

    for (i = 0; i < report->field_count; ++i) {
        if (report->fields[i].match !=
            KZT_GUEST_DYNAMIC_DIAGNOSTIC_MATCHED) {
            kzt_guest_dynamic_summary_set_field(summary,
                                               &report->fields[i]);
            return 0;
        }
    }

    return 0;
}

int kzt_guest_dynamic_diagnostics_format_summary(
    const kzt_guest_dynamic_diagnostic_summary_t *summary,
    char *buffer,
    size_t buffer_size)
{
    int written;
    const char *first_name;

    if (!summary || !buffer || buffer_size == 0) {
        return -1;
    }

    first_name = summary->first_difference_name ?
        summary->first_difference_name : "none";
    written = snprintf(
        buffer, buffer_size,
        "kzt_guest_dynamic_compare link_map=0x%lx generation=%lu "
        "matched=%d blocking=%d differences=%lu blocking_count=%lu "
        "first=%s kind=%d match=%d old_present=%d new_present=%d "
        "old_value=0x%llx new_value=0x%llx old_count=%lu new_count=%lu "
        "old_tag=%lld new_tag=%lld old_tag_index=%lu new_tag_index=%lu "
        "old_status=%d new_status=%d old_entries=%lu new_entries=%lu "
        "old_unknown_tags=%lu new_unknown_tags=%lu",
        (unsigned long)summary->link_map_addr, summary->generation,
        summary->matched, summary->blocking,
        (unsigned long)summary->difference_count,
        (unsigned long)summary->blocking_count, first_name,
        summary->first_difference_kind, summary->first_difference_match,
        summary->first_old_present, summary->first_new_present,
        (unsigned long long)summary->first_old_value,
        (unsigned long long)summary->first_new_value,
        (unsigned long)summary->first_old_count,
        (unsigned long)summary->first_new_count,
        (long long)summary->first_old_tag,
        (long long)summary->first_new_tag,
        (unsigned long)summary->first_old_tag_index,
        (unsigned long)summary->first_new_tag_index,
        summary->old_status, summary->new_status,
        (unsigned long)summary->old_entry_count,
        (unsigned long)summary->new_entry_count,
        (unsigned long)summary->old_unknown_tag_count,
        (unsigned long)summary->new_unknown_tag_count);

    if (written < 0 || (size_t)written >= buffer_size) {
        return -1;
    }

    return 0;
}

int kzt_guest_dynamic_diagnostics_compare(
    const kzt_guest_dynamic_parse_result_t *old_result,
    const kzt_guest_dynamic_parse_result_t *new_result,
    kzt_guest_dynamic_diagnostic_report_t *report)
{
    const kzt_guest_dynamic_view_t *old_view;
    const kzt_guest_dynamic_view_t *new_view;
    const kzt_guest_dynamic_field_spec_t fields[] = {
#define KZT_DYNAMIC_FIELD(name) \
        { #name, offsetof(kzt_guest_dynamic_view_t, name) }
        KZT_DYNAMIC_FIELD(symtab),
        KZT_DYNAMIC_FIELD(strtab),
        KZT_DYNAMIC_FIELD(syment),
        KZT_DYNAMIC_FIELD(strsz),
        KZT_DYNAMIC_FIELD(hash),
        KZT_DYNAMIC_FIELD(gnu_hash),
        KZT_DYNAMIC_FIELD(versym),
        KZT_DYNAMIC_FIELD(verneed),
        KZT_DYNAMIC_FIELD(verneednum),
        KZT_DYNAMIC_FIELD(verdef),
        KZT_DYNAMIC_FIELD(verdefnum),
        KZT_DYNAMIC_FIELD(rela),
        KZT_DYNAMIC_FIELD(relasz),
        KZT_DYNAMIC_FIELD(relaent),
        KZT_DYNAMIC_FIELD(rel),
        KZT_DYNAMIC_FIELD(relsz),
        KZT_DYNAMIC_FIELD(relent),
        KZT_DYNAMIC_FIELD(jmprel),
        KZT_DYNAMIC_FIELD(pltrelsz),
        KZT_DYNAMIC_FIELD(pltrel),
        KZT_DYNAMIC_FIELD(pltgot),
#undef KZT_DYNAMIC_FIELD
    };
    size_t i;

    if (!old_result || !new_result || !report) {
        return -1;
    }

    memset(report, 0, sizeof(*report));

    old_view = &old_result->view;
    new_view = &new_result->view;

    report->old_status = old_result->status;
    report->new_status = new_result->status;
    report->old_error = old_result->error;
    report->new_error = new_result->error;
    report->old_read_error_addr = old_result->read_error_addr;
    report->new_read_error_addr = new_result->read_error_addr;
    report->old_entry_count = old_result->entry_count;
    report->new_entry_count = new_result->entry_count;
    report->old_unknown_tag_count = old_result->unknown_tag_count;
    report->new_unknown_tag_count = new_result->unknown_tag_count;
    report->old_first_unknown_tag = old_result->first_unknown_tag;
    report->new_first_unknown_tag = new_result->first_unknown_tag;
    report->old_first_unknown_tag_index = old_result->first_unknown_tag_index;
    report->new_first_unknown_tag_index = new_result->first_unknown_tag_index;
    report->old_truncated = old_result->status ==
                            KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    report->new_truncated = new_result->status ==
                            KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL;
    report->old_read_error = old_result->status == KZT_GUEST_DYNAMIC_READ_ERROR;
    report->new_read_error = new_result->status == KZT_GUEST_DYNAMIC_READ_ERROR;
    report->status_match = kzt_guest_dynamic_compare_status(old_result->status,
                                                            new_result->status);
    report->entry_count_match = kzt_guest_dynamic_compare_size(
        old_result->entry_count, new_result->entry_count);
    report->unknown_tags_match = kzt_guest_dynamic_compare_unknown(old_result,
                                                                  new_result);

    if (kzt_guest_dynamic_status_is_blocking(old_result->status)) {
        ++report->blocking_count;
    }
    if (kzt_guest_dynamic_status_is_blocking(new_result->status)) {
        ++report->blocking_count;
    }

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        kzt_guest_dynamic_compare_named_field(report, old_view, new_view,
                                             &fields[i]);
    }
    kzt_guest_dynamic_compare_needed_offsets(report, old_view, new_view);
    report->difference_count = kzt_guest_dynamic_count_summary_differences(
        report);

    return 0;
}

const kzt_guest_dynamic_diagnostic_field_t *
kzt_guest_dynamic_diagnostic_find_field(
    const kzt_guest_dynamic_diagnostic_report_t *report,
    const char *name)
{
    size_t i;

    if (!report || !name) {
        return NULL;
    }

    for (i = 0; i < report->field_count; ++i) {
        if (!strcmp(report->fields[i].name, name)) {
            return &report->fields[i];
        }
    }

    return NULL;
}
