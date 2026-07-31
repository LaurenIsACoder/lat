#include "kzt_wrapper_bridge_provider.h"

#include <string.h>

static int kzt_wrapper_bridge_provider_string_empty(const char *value)
{
    return !value || !value[0];
}

static int kzt_wrapper_bridge_provider_string_equal(const char *left,
                                                     const char *right)
{
    return !kzt_wrapper_bridge_provider_string_empty(left) &&
           !kzt_wrapper_bridge_provider_string_empty(right) &&
           strcmp(left, right) == 0;
}

static uintptr_t kzt_wrapper_bridge_provider_check_bridge(
    uintptr_t native_symbol, void *opaque)
{
    kzt_wrapper_bridge_provider_t *provider = opaque;

    if (!provider || !provider->runtime_ops.check_bridge ||
        native_symbol != provider->match.native_symbol) {
        return 0;
    }

    return provider->runtime_ops.check_bridge(
        &provider->match, provider->runtime_ops.opaque);
}

static uintptr_t kzt_wrapper_bridge_provider_add_bridge(
    const kzt_wrapper_probe_bridge_request_t *request, void *opaque)
{
    kzt_wrapper_bridge_provider_t *provider = opaque;
    uintptr_t created;
    uintptr_t verified;

    if (!provider || !request || !provider->runtime_ops.add_bridge ||
        !provider->runtime_ops.check_bridge ||
        request->native_symbol != provider->match.native_symbol ||
        !kzt_wrapper_bridge_provider_string_equal(
            request->symbol_name, provider->entry.symbol_name) ||
        !kzt_symbol_version_evidence_matches(
            request->symbol_version_evidence, request->symbol_version,
            provider->entry.symbol_version_evidence,
            provider->entry.symbol_version) ||
        !kzt_wrapper_bridge_provider_string_equal(
            request->wrapper_name, provider->entry.wrapper_name) ||
        !kzt_symbol_version_evidence_matches(
            request->wrapper_version_evidence,
            request->wrapper_symbol_version,
            provider->entry.wrapper_version_evidence,
            provider->entry.wrapper_symbol_version)) {
        return 0;
    }

    created = provider->runtime_ops.add_bridge(
        &provider->match, request, provider->runtime_ops.opaque);
    if (!created) {
        return 0;
    }
    verified = provider->runtime_ops.check_bridge(
        &provider->match, provider->runtime_ops.opaque);
    return verified == created ? created : 0;
}

int kzt_wrapper_bridge_provider_prepare_with_version_evidence(
    kzt_wrapper_bridge_provider_t *provider, void *const *libraries,
    size_t library_count, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    const kzt_wrapper_bridge_provider_runtime_ops_t *runtime_ops)
{
    kzt_wrapper_bridge_provider_match_t selected;
    size_t selected_count = 0;
    size_t i;

    if (!provider) {
        return -1;
    }
    memset(provider, 0, sizeof(*provider));
    memset(&selected, 0, sizeof(selected));

    if (!libraries || !runtime_ops || !runtime_ops->inspect_library ||
        !runtime_ops->check_bridge ||
        kzt_wrapper_bridge_provider_string_empty(symbol_name) ||
        !kzt_symbol_version_evidence_valid(version_evidence,
                                           symbol_version)) {
        return 0;
    }

    for (i = 0; i < library_count; ++i) {
        kzt_wrapper_bridge_provider_match_t candidate;
        size_t j;
        int duplicate = 0;
        int status;

        if (!libraries[i]) {
            continue;
        }
        for (j = 0; j < i; ++j) {
            if (libraries[j] == libraries[i]) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        memset(&candidate, 0, sizeof(candidate));
        status = runtime_ops->inspect_library(
            libraries[i], symbol_name, symbol_version, &candidate,
            runtime_ops->opaque);
        if (status < 0) {
            return 0;
        }
        if (status == 0) {
            continue;
        }
        if (!candidate.abi_wrapper || !candidate.native_symbol ||
            !candidate.context_owner || !candidate.wrapper_provider ||
            !candidate.native_lookup_handle ||
            (!candidate.native_owner &&
             !candidate.retained_provider_handle) ||
            !candidate.bridge_owner || !candidate.bridge_storage ||
            candidate.stack_bytes < 0 || !candidate.native_name[0] ||
            (!!candidate.resolved_bridge_target !=
             !!candidate.resolved_bridge_exact) ||
            (!candidate.resolved_bridge_target &&
             !runtime_ops->add_bridge) ||
            !candidate.wrapper_provider_lifetime_bound ||
            !candidate.native_owner_lifetime_bound ||
            !candidate.bridge_owner_lifetime_bound ||
            kzt_wrapper_bridge_provider_string_empty(candidate.wrapper_name)) {
            return 0;
        }

        selected = candidate;
        if (++selected_count != 1) {
            return 0;
        }
    }

    if (selected_count != 1) {
        return 0;
    }

    provider->match = selected;
    provider->runtime_ops = *runtime_ops;
    provider->entry.symbol_name = symbol_name;
    provider->entry.symbol_version_evidence = version_evidence;
    provider->entry.symbol_version = symbol_version;
    provider->entry.wrapper_name = selected.wrapper_name;
    provider->entry.wrapper_version_evidence = version_evidence;
    provider->entry.wrapper_symbol_version = symbol_version;
    provider->entry.native_symbol = selected.native_symbol;
    provider->manifest.available = 1;
    provider->manifest.manifest_name = selected.wrapper_name;
    provider->manifest.entries = &provider->entry;
    provider->manifest.entry_count = 1;
    provider->bridge_ops.check_bridge =
        kzt_wrapper_bridge_provider_check_bridge;
    if (runtime_ops->add_bridge && !selected.resolved_bridge_exact) {
        provider->bridge_ops.add_bridge =
            kzt_wrapper_bridge_provider_add_bridge;
    }
    provider->bridge_ops.opaque = provider;
    return 1;
}

int kzt_wrapper_bridge_provider_prepare(
    kzt_wrapper_bridge_provider_t *provider, void *const *libraries,
    size_t library_count, const char *symbol_name,
    const char *symbol_version,
    const kzt_wrapper_bridge_provider_runtime_ops_t *runtime_ops)
{
    return kzt_wrapper_bridge_provider_prepare_with_version_evidence(
        provider, libraries, library_count, symbol_name,
        kzt_wrapper_bridge_provider_string_empty(symbol_version)
            ? KZT_SYMBOL_VERSION_UNKNOWN
            : KZT_SYMBOL_VERSION_VERSIONED,
        symbol_version, runtime_ops);
}
