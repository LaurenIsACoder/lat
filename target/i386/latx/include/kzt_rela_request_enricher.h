#ifndef KZT_RELA_REQUEST_ENRICHER_H
#define KZT_RELA_REQUEST_ENRICHER_H

#include <stdint.h>

#include "kzt_guest_registry.h"
#include "kzt_owner_resolver.h"
#include "kzt_rela_immediate_candidate.h"
#include "kzt_wrapper_probe.h"

#define KZT_RELA_REQUEST_ENRICHER_TEXT_LIMIT 256

typedef struct kzt_rela_request_enricher_text {
    char soname[KZT_RELA_REQUEST_ENRICHER_TEXT_LIMIT];
    char path[KZT_RELA_REQUEST_ENRICHER_TEXT_LIMIT];
} kzt_rela_request_enricher_text_t;

typedef struct kzt_rela_request_enricher_input {
    kzt_guest_registry_t *registry;
    int slot_current_value_is_unresolved_stub;
    const kzt_wrapper_probe_manifest_t *wrapper_manifest;
    const kzt_wrapper_probe_bridge_ops_t *bridge_ops;
} kzt_rela_request_enricher_input_t;

typedef struct kzt_rela_request_enricher_result {
    int source_present;
    int dynamic_view_present;
    int owner_present;
    int wrapper_present;
    kzt_patch_object_ref_t source;
    kzt_rela_request_enricher_text_t source_text;
    kzt_owner_resolution_t owner_resolution;
    kzt_wrapper_probe_result_t wrapper_probe;
} kzt_rela_request_enricher_result_t;

void kzt_rela_request_enricher_result_init(
    kzt_rela_request_enricher_result_t *result);

int kzt_rela_immediate_request_enrich(
    kzt_rela_immediate_candidate_request_t *request,
    const kzt_rela_request_enricher_input_t *input,
    kzt_rela_request_enricher_result_t *result);

#endif
