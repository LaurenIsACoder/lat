#include "kzt_wrapper_probe.h"

#include <string.h>

static int kzt_wrapper_probe_string_empty(const char *value)
{
    return !value || !value[0];
}

static int kzt_wrapper_probe_string_equal(const char *left,
                                          const char *right)
{
    if (kzt_wrapper_probe_string_empty(left) ||
        kzt_wrapper_probe_string_empty(right)) {
        return 0;
    }

    return strcmp(left, right) == 0;
}

static int kzt_wrapper_probe_entry_matches_symbol(
    const kzt_wrapper_probe_entry_t *entry,
    const kzt_wrapper_probe_request_t *request)
{
    return entry && request &&
           kzt_wrapper_probe_string_equal(entry->symbol_name,
                                          request->symbol_name);
}

static int kzt_wrapper_probe_entry_has_valid_version_evidence(
    const kzt_wrapper_probe_entry_t *entry)
{
    return entry && kzt_symbol_version_evidence_valid(
                        entry->symbol_version_evidence,
                        entry->symbol_version);
}

static int kzt_wrapper_probe_entry_matches_version(
    const kzt_wrapper_probe_entry_t *entry,
    const kzt_wrapper_probe_request_t *request)
{
    return entry && request && kzt_symbol_version_evidence_matches(
        entry->symbol_version_evidence, entry->symbol_version,
        request->symbol_version_evidence, request->symbol_version);
}

static void kzt_wrapper_probe_result_reset(kzt_wrapper_probe_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
    result->wrapper_version_evidence = KZT_SYMBOL_VERSION_UNKNOWN;
    result->bridge_source = KZT_WRAPPER_PROBE_BRIDGE_NONE;
}

static void kzt_wrapper_probe_result_from_entry(
    kzt_wrapper_probe_result_t *result,
    kzt_patch_wrapper_match_t match,
    const kzt_wrapper_probe_entry_t *entry)
{
    result->wrapper_match = match;
    result->wrapper_name = entry ? entry->wrapper_name : NULL;
    result->wrapper_version_evidence = entry ?
        entry->wrapper_version_evidence : KZT_SYMBOL_VERSION_UNKNOWN;
    result->wrapper_symbol_version = entry ? entry->wrapper_symbol_version : NULL;
    result->native_symbol = entry ? entry->native_symbol : 0;
}

static void kzt_wrapper_probe_fill_bridge_request(
    const kzt_wrapper_probe_entry_t *entry,
    const kzt_wrapper_probe_request_t *request,
    kzt_wrapper_probe_bridge_request_t *bridge_request)
{
    memset(bridge_request, 0, sizeof(*bridge_request));
    bridge_request->symbol_name = request->symbol_name;
    bridge_request->symbol_version_evidence =
        request->symbol_version_evidence;
    bridge_request->symbol_version = request->symbol_version;
    bridge_request->wrapper_name = entry->wrapper_name;
    bridge_request->wrapper_version_evidence =
        entry->wrapper_version_evidence;
    bridge_request->wrapper_symbol_version = entry->wrapper_symbol_version;
    bridge_request->native_symbol = entry->native_symbol;
}

static void kzt_wrapper_probe_resolve_bridge(
    const kzt_wrapper_probe_entry_t *entry,
    const kzt_wrapper_probe_request_t *request,
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops,
    kzt_wrapper_probe_result_t *result)
{
    kzt_wrapper_probe_bridge_request_t bridge_request;
    uintptr_t target;

    if (!entry || !entry->native_symbol || !bridge_ops) {
        return;
    }

    if (bridge_ops->check_bridge) {
        target = bridge_ops->check_bridge(entry->native_symbol,
                                          bridge_ops->opaque);
        if (target) {
            result->bridge_target = target;
            result->bridge_source = KZT_WRAPPER_PROBE_BRIDGE_CACHE;
            return;
        }
    }

    if (!bridge_ops->add_bridge) {
        return;
    }

    kzt_wrapper_probe_fill_bridge_request(entry, request, &bridge_request);
    target = bridge_ops->add_bridge(&bridge_request, bridge_ops->opaque);
    if (target) {
        result->bridge_target = target;
        result->bridge_source = KZT_WRAPPER_PROBE_BRIDGE_ADD_BRIDGE;
    }
}

int kzt_wrapper_probe_minimal_manifest(
    const kzt_wrapper_probe_manifest_t *manifest,
    const kzt_wrapper_probe_request_t *request,
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops,
    kzt_wrapper_probe_result_t *result)
{
    const kzt_wrapper_probe_entry_t *first_symbol_only = NULL;
    const kzt_wrapper_probe_entry_t *first_version_mismatch = NULL;
    const kzt_wrapper_probe_entry_t *version_match = NULL;
    size_t i;

    if (!result) {
        return -1;
    }

    kzt_wrapper_probe_result_reset(result);
    if (!request || kzt_wrapper_probe_string_empty(request->symbol_name)) {
        return -1;
    }

    if (!manifest || !manifest->available || !manifest->entries) {
        result->wrapper_match = KZT_PATCH_WRAPPER_NO_MANIFEST;
        return 0;
    }

    for (i = 0; i < manifest->entry_count; ++i) {
        const kzt_wrapper_probe_entry_t *entry = &manifest->entries[i];

        if (!kzt_wrapper_probe_entry_matches_symbol(entry, request)) {
            continue;
        }

        if (!kzt_wrapper_probe_entry_has_valid_version_evidence(entry) ||
            !kzt_symbol_version_evidence_valid(
                entry->wrapper_version_evidence,
                entry->wrapper_symbol_version)) {
            if (!first_symbol_only) {
                first_symbol_only = entry;
            }
            continue;
        }

        if (!first_version_mismatch) {
            first_version_mismatch = entry;
        }

        if (kzt_wrapper_probe_entry_matches_version(entry, request)) {
            version_match = entry;
            break;
        }
    }

    if (version_match) {
        kzt_wrapper_probe_result_from_entry(
            result,
            request->symbol_version_evidence ==
                    KZT_SYMBOL_VERSION_CONFIRMED_UNVERSIONED
                ? KZT_PATCH_WRAPPER_UNVERSIONED_MATCH
                : KZT_PATCH_WRAPPER_VERSION_MATCH,
            version_match);
        kzt_wrapper_probe_resolve_bridge(version_match, request, bridge_ops,
                                         result);
        return 0;
    }

    if (first_version_mismatch) {
        kzt_wrapper_probe_result_from_entry(
            result, KZT_PATCH_WRAPPER_VERSION_MISMATCH,
            first_version_mismatch);
        return 0;
    }

    if (first_symbol_only) {
        kzt_wrapper_probe_result_from_entry(
            result, KZT_PATCH_WRAPPER_SYMBOL_ONLY, first_symbol_only);
        return 0;
    }

    result->wrapper_match = KZT_PATCH_WRAPPER_NO_WRAPPER;
    return 0;
}

void kzt_wrapper_probe_apply_to_candidate(
    const kzt_wrapper_probe_result_t *probe,
    kzt_patch_candidate_t *candidate)
{
    if (!probe || !candidate) {
        return;
    }

    candidate->wrapper_match = probe->wrapper_match;
    candidate->wrapper_name = probe->wrapper_name;
    candidate->wrapper_version_evidence =
        probe->wrapper_version_evidence;
    candidate->wrapper_symbol_version = probe->wrapper_symbol_version;
    candidate->bridge_target = probe->bridge_target;
}

void kzt_wrapper_probe_apply_to_decision_request(
    const kzt_wrapper_probe_result_t *probe,
    kzt_patch_wrapper_match_t *wrapper_match,
    const char **wrapper_name,
    const char **wrapper_symbol_version,
    uintptr_t *bridge_target)
{
    if (!probe) {
        return;
    }
    if (wrapper_match) {
        *wrapper_match = probe->wrapper_match;
    }
    if (wrapper_name) {
        *wrapper_name = probe->wrapper_name;
    }
    if (wrapper_symbol_version) {
        *wrapper_symbol_version = probe->wrapper_symbol_version;
    }
    if (bridge_target) {
        *bridge_target = probe->bridge_target;
    }
}
