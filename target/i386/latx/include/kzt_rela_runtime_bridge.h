#ifndef KZT_RELA_RUNTIME_BRIDGE_H
#define KZT_RELA_RUNTIME_BRIDGE_H

#include <stdint.h>

#include "kzt_wrapper_bridge_provider.h"

typedef struct box64context_s box64context_t;
typedef struct library_s library_t;

int kzt_rela_runtime_wrapper_provider_prepare(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, const char *symbol_name,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider);

int kzt_rela_runtime_wrapper_provider_prepare_with_version_evidence(
    box64context_t *context, library_t *resolved_provider,
    uintptr_t resolved_target, const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider);

int kzt_rela_runtime_wrapper_provider_discover(
    box64context_t *context, library_t *resolved_provider,
    const char *symbol_name, const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider);

int kzt_rela_runtime_wrapper_provider_discover_with_version_evidence(
    box64context_t *context, library_t *resolved_provider,
    const char *symbol_name,
    kzt_symbol_version_evidence_t version_evidence,
    const char *symbol_version,
    kzt_wrapper_bridge_provider_t *provider);

#endif
