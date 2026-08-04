#include <stdio.h>
#include <string.h>

#include "target/i386/latx/include/kzt_patch_planner.h"

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

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void check_str(const char *name, const char *got, const char *expected)
{
    if (got && expected && !strcmp(got, expected)) {
        return;
    }

    fprintf(stderr, "%s: got '%s' expected '%s'\n", name,
            got ? got : "(null)", expected ? expected : "(null)");
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

static kzt_patch_object_ref_t object_ref(uintptr_t link_map_addr,
                                         unsigned long generation,
                                         const char *soname)
{
    return (kzt_patch_object_ref_t) {
        .known = 1,
        .link_map_addr = link_map_addr,
        .map_start = 0x7000000000 + generation * 0x100000,
        .map_end = 0x7000008000 + generation * 0x100000,
        .generation = generation,
        .soname = soname,
        .path = soname,
    };
}

static kzt_patch_candidate_t base_candidate(void)
{
    return (kzt_patch_candidate_t) {
        .source = object_ref(0x1000, 7, "librequester.so"),
        .dynamic_addr = 0x7000100000,
        .load_bias = 0x7000000000,
        .dynamic_view_generation = 42,
        .dynamic_view_available = 1,
        .table_kind = KZT_PATCH_TABLE_PLT_RELA,
        .entry_index = 3,
        .entry_addr = 0x7000100180,
        .reloc_type = KZT_PATCH_RELOCATION_JUMP_SLOT,
        .slot_addr = 0x7100000018,
        .slot_current_value_present = 1,
        .slot_current_value = 0x7200001000,
        .lazy_binding_deferred = 0,
        .symbol_index = 77,
        .symbol_name = "gtk_widget_show",
        .version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .version = "GTK_3.0",
        .current_owner = object_ref(0x2000, 12, "libgtk-3.so"),
        .owner_match = KZT_PATCH_OWNER_MATCH,
        .wrapper_match = KZT_PATCH_WRAPPER_VERSION_MATCH,
        .wrapper_name = "wrappedgtk3",
        .wrapper_version_evidence = KZT_SYMBOL_VERSION_VERSIONED,
        .wrapper_symbol_version = "GTK_3.0",
        .bridge_target = 0x7300002000,
    };
}

static void assert_decision(const char *name,
                            const kzt_patch_decision_t *decision,
                            kzt_patch_decision_kind_t expected_kind,
                            kzt_patch_reason_t expected_reason,
                            int expected_allow)
{
    char field[128];

    snprintf(field, sizeof(field), "%s.kind", name);
    check_int(field, decision->kind, expected_kind);
    snprintf(field, sizeof(field), "%s.reason", name);
    check_int(field, decision->reason, expected_reason);
    snprintf(field, sizeof(field), "%s.allow", name);
    check_int(field, decision->allow_native_bridge, expected_allow);
}

static void test_complete_evidence_approves_native_bridge(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;
    char line[768];

    check_int("approved.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("approved", &decision,
                    KZT_PATCH_DECISION_APPROVED,
                    KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE, 1);
    check_ulong("approved.link-map", decision.source.link_map_addr,
                candidate.source.link_map_addr);
    check_ulong("approved.source-generation", decision.source.generation,
                candidate.source.generation);
    check_ulong("approved.dynamic-addr", decision.dynamic_addr,
                candidate.dynamic_addr);
    check_ulong("approved.load-bias", decision.load_bias,
                candidate.load_bias);
    check_ulong("approved.dynamic-generation",
                decision.dynamic_view_generation,
                candidate.dynamic_view_generation);
    check_ulong("approved.entry-index", decision.entry_index,
                candidate.entry_index);
    check_ulong("approved.entry-addr", decision.entry_addr,
                candidate.entry_addr);
    check_ulong("approved.slot", decision.slot_addr, candidate.slot_addr);
    check_ulong("approved.current-got", decision.slot_current_value,
                candidate.slot_current_value);
    check_ulong("approved.symbol-index", decision.symbol_index,
                candidate.symbol_index);
    check_ulong("approved.owner", decision.current_owner.link_map_addr,
                candidate.current_owner.link_map_addr);
    check_ulong("approved.bridge", decision.bridge_target,
                candidate.bridge_target);
    check_str("approved.kind-name",
              kzt_patch_decision_kind_name(decision.kind), "APPROVED");
    check_str("approved.reason-name",
              kzt_patch_reason_name(decision.reason),
              "APPROVED_NATIVE_BRIDGE");

    check_int("approved.summary",
              kzt_patch_decision_format_summary(&decision, line,
                                                sizeof(line)), 0);
    check_str_contains("approved.summary-kind", line, "kind=APPROVED");
    check_str_contains("approved.summary-reason", line,
                       "reason=APPROVED_NATIVE_BRIDGE");
    check_str_contains("approved.summary-link-map", line,
                       "link_map=0x1000");
    check_str_contains("approved.summary-source-generation", line,
                       "source_generation=7");
    check_str_contains("approved.summary-dynamic-addr", line,
                       "dynamic_addr=0x7000100000");
    check_str_contains("approved.summary-load-bias", line,
                       "load_bias=0x7000000000");
    check_str_contains("approved.summary-dynamic-generation", line,
                       "dynamic_view_generation=42");
    check_str_contains("approved.summary-table", line, "table=PLT_RELA");
    check_str_contains("approved.summary-entry-index", line,
                       "entry_index=3");
    check_str_contains("approved.summary-entry-addr", line,
                       "entry_addr=0x7000100180");
    check_str_contains("approved.summary-reloc", line, "reloc=JUMP_SLOT");
    check_str_contains("approved.summary-slot", line,
                       "slot=0x7100000018");
    check_str_contains("approved.summary-symbol-index", line,
                       "symbol_index=77");
    check_str_contains("approved.summary-symbol", line,
                       "symbol=gtk_widget_show");
    check_str_contains("approved.summary-wrapper", line,
                       "wrapper=wrappedgtk3");
}

static void test_unsupported_relocation_is_not_guessed(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.reloc_type = KZT_PATCH_RELOCATION_RELATIVE;

    check_int("unsupported-relocation.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("unsupported-relocation", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_UNSUPPORTED_RELOCATION, 0);
    check_str("unsupported-relocation.name",
              kzt_patch_relocation_type_name(decision.reloc_type),
              "RELATIVE");
}

static void test_dynamic_view_unavailable_is_unsupported(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;
    char line[768];

    candidate.dynamic_view_available = 0;

    check_int("dynamic-unavailable.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("dynamic-unavailable", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_UNAVAILABLE_DYNAMIC_VIEW, 0);
    check_int("dynamic-unavailable.summary",
              kzt_patch_decision_format_summary(&decision, line,
                                                sizeof(line)), 0);
    check_str_contains("dynamic-unavailable.summary", line,
                       "dynamic_view_available=0");
}

static void test_owner_unknown_is_unsupported(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    memset(&candidate.current_owner, 0, sizeof(candidate.current_owner));
    candidate.owner_match = KZT_PATCH_OWNER_UNKNOWN;

    check_int("owner-unknown.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("owner-unknown", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_UNAVAILABLE_OWNER, 0);
}

static void test_owner_mismatch_is_a_stable_rejection(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;
    char line[768];

    candidate.current_owner = object_ref(0x3000, 13, "libpreload.so");
    candidate.owner_match = KZT_PATCH_OWNER_MISMATCH;

    check_int("owner-mismatch.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("owner-mismatch", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_OWNER_MISMATCH, 0);
    check_str("owner-mismatch.kind-name",
              kzt_patch_decision_kind_name(decision.kind), "REJECTED");
    check_str("owner-mismatch.owner-match-name",
              kzt_patch_owner_match_name(decision.owner_match),
              "MISMATCH");
    check_int("owner-mismatch.summary",
              kzt_patch_decision_format_summary(&decision, line,
                                                sizeof(line)), 0);
    check_str_contains("owner-mismatch.summary-owner", line,
                       "current_owner=0x3000");
    check_str_contains("owner-mismatch.summary-match", line,
                       "owner_match=MISMATCH");
}

static void test_wrapper_version_mismatch_is_rejected(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.wrapper_match = KZT_PATCH_WRAPPER_VERSION_MISMATCH;
    candidate.wrapper_symbol_version = "GTK_2.0";

    check_int("version-mismatch.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("version-mismatch", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_VERSION_MISMATCH, 0);
    check_str("version-mismatch.kind-name",
              kzt_patch_decision_kind_name(decision.kind), "REJECTED");
}

static void test_no_wrapper_rejects_to_keep_guest_target(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.wrapper_match = KZT_PATCH_WRAPPER_NO_WRAPPER;
    candidate.wrapper_name = NULL;
    candidate.wrapper_symbol_version = NULL;
    candidate.bridge_target = 0;

    check_int("no-wrapper.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("no-wrapper", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_NO_WRAPPER, 0);
    check_str("no-wrapper.match-name",
              kzt_patch_wrapper_match_name(decision.wrapper_match),
              "NO_WRAPPER");
}

static void test_lazy_deferred_is_not_patched_yet(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;
    char line[768];

    candidate.lazy_binding_deferred = 1;
    candidate.current_owner.known = 0;
    candidate.owner_match = KZT_PATCH_OWNER_UNKNOWN;

    check_int("lazy-deferred.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("lazy-deferred", &decision,
                    KZT_PATCH_DECISION_DEFERRED,
                    KZT_PATCH_REASON_DEFERRED_LAZY_BINDING, 0);
    check_str("lazy-deferred.kind-name",
              kzt_patch_decision_kind_name(decision.kind), "DEFERRED");
    check_int("lazy-deferred.summary",
              kzt_patch_decision_format_summary(&decision, line,
                                                sizeof(line)), 0);
    check_str_contains("lazy-deferred.summary", line,
                       "lazy_deferred=1");
}

static void test_symbol_only_wrapper_rejects_to_keep_guest_target(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.wrapper_match = KZT_PATCH_WRAPPER_SYMBOL_ONLY;
    candidate.wrapper_symbol_version = NULL;

    check_int("symbol-only.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("symbol-only", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_WRAPPER_SYMBOL_ONLY, 0);
    check_str("symbol-only.match-name",
              kzt_patch_wrapper_match_name(decision.wrapper_match),
              "SYMBOL_ONLY");
}

static void test_missing_symbol_version_is_malformed_input(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.version = NULL;

    check_int("missing-version.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("missing-version", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, 0);
}

static void test_confirmed_unversioned_evidence_is_approved(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    candidate.version = NULL;
    candidate.wrapper_match = KZT_PATCH_WRAPPER_UNVERSIONED_MATCH;
    candidate.wrapper_version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    candidate.wrapper_symbol_version = NULL;

    check_int("unversioned.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("unversioned", &decision,
                    KZT_PATCH_DECISION_APPROVED,
                    KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE, 1);
    check_int("unversioned.evidence", decision.version_evidence,
              KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED);
}

static void test_unknown_and_error_version_evidence_are_rejected(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;
    kzt_symbol_version_evidence_t evidence[] = {
        KZT_SYMBOL_VERSION_UNKNOWN,
        KZT_SYMBOL_VERSION_ERROR,
    };
    size_t i;

    for (i = 0; i < sizeof(evidence) / sizeof(evidence[0]); ++i) {
        candidate = base_candidate();
        candidate.version_evidence = evidence[i];
        check_int("untrusted-version.decide",
                  kzt_patch_planner_decide(&candidate, &decision), 0);
        assert_decision("untrusted-version", &decision,
                        KZT_PATCH_DECISION_UNSUPPORTED,
                        KZT_PATCH_REASON_INPUT_MALFORMED_SYMBOL_VERSION, 0);
    }
}

static void test_no_manifest_is_unavailable_input(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    candidate.wrapper_name = NULL;
    candidate.wrapper_symbol_version = NULL;

    check_int("no-manifest.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("no-manifest", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_UNAVAILABLE_WRAPPER_MANIFEST, 0);
}

static void test_bridge_target_is_required_for_approval(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.bridge_target = 0;

    check_int("missing-bridge.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("missing-bridge", &decision,
                    KZT_PATCH_DECISION_UNSUPPORTED,
                    KZT_PATCH_REASON_INPUT_UNAVAILABLE_BRIDGE_TARGET, 0);
}

static void test_guest_owned_dlclose_is_kept_guest(void)
{
    kzt_patch_candidate_t candidate = base_candidate();
    kzt_patch_decision_t decision;

    candidate.symbol_name = "dlclose";
    candidate.version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    candidate.version = NULL;
    candidate.wrapper_version_evidence =
        KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED;
    candidate.wrapper_symbol_version = NULL;
    candidate.wrapper_match = KZT_PATCH_WRAPPER_UNVERSIONED_MATCH;

    check_int("guest-dlclose.policy",
              kzt_patch_symbol_must_stay_guest(candidate.symbol_name), 1);
    check_int("guest-dlclose.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("guest-dlclose", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_KEEP_GUEST, 0);

    candidate.symbol_name = "free";
    check_int("guest-free.policy",
              kzt_patch_symbol_must_stay_guest(candidate.symbol_name), 1);
    check_int("guest-free.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("guest-free", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_KEEP_GUEST, 0);

    check_int("guest-__free.policy",
              kzt_patch_symbol_must_stay_guest("__free"), 1);
    check_int("guest-__libc_free.policy",
              kzt_patch_symbol_must_stay_guest("__libc_free"), 1);
    check_int("guest-realloc.policy",
              kzt_patch_symbol_must_stay_guest("realloc"), 1);
    check_int("guest-XOpenDisplay.policy",
              kzt_patch_symbol_must_stay_guest("XOpenDisplay"), 1);
    check_int("guest-XCloseDisplay.policy",
              kzt_patch_symbol_must_stay_guest("XCloseDisplay"), 1);
    check_int("guest-XGetXCBConnection.policy",
              kzt_patch_symbol_must_stay_guest("XGetXCBConnection"), 1);
    check_int("guest-XSetEventQueueOwner.policy",
              kzt_patch_symbol_must_stay_guest("XSetEventQueueOwner"), 1);
    check_int("native-xcb-connection.policy",
              kzt_patch_symbol_must_stay_guest("xcb_connection_has_error"), 0);
    check_int("native-xcb-flush.policy",
              kzt_patch_symbol_must_stay_guest("xcb_flush"), 0);
    check_int("guest-xcb-connect.policy",
              kzt_patch_symbol_must_stay_guest("xcb_connect"), 1);
    check_int("guest-xcb-connect-auth.policy",
              kzt_patch_symbol_must_stay_guest(
                  "xcb_connect_to_display_with_auth_info"), 1);
    check_int("guest-xcb-disconnect.policy",
              kzt_patch_symbol_must_stay_guest("xcb_disconnect"), 1);
    check_int("guest-xcb-unknown.policy",
              kzt_patch_symbol_must_stay_guest("xcb_send_request"), 1);
    check_int("dlopen.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dlopen"), 1);
    check_int("dlmopen.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dlmopen"), 1);
    check_int("dlsym.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dlsym"), 1);
    check_int("dlvsym.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dlvsym"), 1);
    check_int("dlinfo.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dlinfo"), 1);
    check_int("dladdr.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dladdr"), 1);
    check_int("dladdr1.requires-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("dladdr1"), 1);
    check_int("dlerror.is-prebind-anchor",
              kzt_patch_symbol_requires_dlerror_prebind("dlerror"), 0);
    check_int("ordinary-symbol.no-dlerror-prebind",
              kzt_patch_symbol_requires_dlerror_prebind("puts"), 0);

    candidate = base_candidate();
    candidate.symbol_name = "xcb_flush";
    check_int("native-xcb-flush.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("native-xcb-flush", &decision,
                    KZT_PATCH_DECISION_APPROVED,
                    KZT_PATCH_REASON_APPROVED_NATIVE_BRIDGE, 1);

    candidate.symbol_name = "xcb_send_request";
    check_int("guest-xcb-unknown.decide",
              kzt_patch_planner_decide(&candidate, &decision), 0);
    assert_decision("guest-xcb-unknown", &decision,
                    KZT_PATCH_DECISION_REJECTED,
                    KZT_PATCH_REASON_POLICY_KEEP_GUEST, 0);
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
    if (test_matches_filter("complete_evidence_approves_native_bridge",
                            argc, argv)) {
        test_complete_evidence_approves_native_bridge();
    }
    if (test_matches_filter("unsupported_relocation_is_not_guessed",
                            argc, argv)) {
        test_unsupported_relocation_is_not_guessed();
    }
    if (test_matches_filter("dynamic_view_unavailable_is_unsupported",
                            argc, argv)) {
        test_dynamic_view_unavailable_is_unsupported();
    }
    if (test_matches_filter("owner_unknown_is_unsupported", argc, argv)) {
        test_owner_unknown_is_unsupported();
    }
    if (test_matches_filter("owner_mismatch_is_a_stable_rejection",
                            argc, argv)) {
        test_owner_mismatch_is_a_stable_rejection();
    }
    if (test_matches_filter("wrapper_version_mismatch_is_rejected",
                            argc, argv)) {
        test_wrapper_version_mismatch_is_rejected();
    }
    if (test_matches_filter("no_wrapper_rejects_to_keep_guest_target",
                            argc, argv)) {
        test_no_wrapper_rejects_to_keep_guest_target();
    }
    if (test_matches_filter("lazy_deferred_is_not_patched_yet",
                            argc, argv)) {
        test_lazy_deferred_is_not_patched_yet();
    }
    if (test_matches_filter("symbol_only_wrapper_rejects_to_keep_guest_target",
                            argc, argv)) {
        test_symbol_only_wrapper_rejects_to_keep_guest_target();
    }
    if (test_matches_filter("missing_symbol_version_is_malformed_input",
                            argc, argv)) {
        test_missing_symbol_version_is_malformed_input();
    }
    if (test_matches_filter("confirmed_unversioned_evidence_is_approved",
                            argc, argv)) {
        test_confirmed_unversioned_evidence_is_approved();
    }
    if (test_matches_filter(
            "unknown_and_error_version_evidence_are_rejected", argc, argv)) {
        test_unknown_and_error_version_evidence_are_rejected();
    }
    if (test_matches_filter("no_manifest_is_unavailable_input", argc, argv)) {
        test_no_manifest_is_unavailable_input();
    }
    if (test_matches_filter("bridge_target_is_required_for_approval",
                            argc, argv)) {
        test_bridge_target_is_required_for_approval();
    }
    if (test_matches_filter("guest_owned_dlclose_is_kept_guest",
                            argc, argv)) {
        test_guest_owned_dlclose_is_kept_guest();
    }

    if (failures) {
        fprintf(stderr, "kzt-patch-planner: %d failure(s)\n", failures);
        return 1;
    }

    puts("kzt-patch-planner: selected contract tests passed");
    return 0;
}
