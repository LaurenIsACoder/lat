#ifndef KZT_LAZY_PREBIND_SCOPE_H
#define KZT_LAZY_PREBIND_SCOPE_H

#include <stdint.h>

#include "kzt_guest_symbol_scope.h"

#define KZT_LAZY_PREBIND_TEXT_MAX 128

typedef struct kzt_lazy_prebind_scope kzt_lazy_prebind_scope_t;

typedef enum kzt_lazy_prebind_lease_operation {
    KZT_LAZY_PREBIND_LEASE_READ = 0,
    KZT_LAZY_PREBIND_LEASE_PUBLISH,
    KZT_LAZY_PREBIND_LEASE_REVOKE,
} kzt_lazy_prebind_lease_operation_t;

typedef struct kzt_lazy_prebind_identity {
    uintptr_t link_map_addr;
    unsigned long generation;
    uintptr_t namespace_id;
} kzt_lazy_prebind_identity_t;

typedef enum kzt_lazy_prebind_mutation {
    KZT_LAZY_PREBIND_MUTATION_LOADER_EVENT = 0,
    KZT_LAZY_PREBIND_MUTATION_DLOPEN,
    KZT_LAZY_PREBIND_MUTATION_DLCLOSE,
    KZT_LAZY_PREBIND_MUTATION_DLMOPEN,
    KZT_LAZY_PREBIND_MUTATION_RETIRE,
} kzt_lazy_prebind_mutation_t;

typedef enum kzt_lazy_prebind_claim_result {
    KZT_LAZY_PREBIND_CLAIM_CREATED = 0,
    KZT_LAZY_PREBIND_CLAIM_REUSED,
    KZT_LAZY_PREBIND_CLAIM_CONFLICT,
    KZT_LAZY_PREBIND_CLAIM_RETIRED,
    KZT_LAZY_PREBIND_CLAIM_FAIL_OPEN,
} kzt_lazy_prebind_claim_result_t;

typedef struct kzt_lazy_prebind_record {
    kzt_lazy_prebind_identity_t source;
    kzt_lazy_prebind_identity_t provider;
    uintptr_t slot_addr;
    uintptr_t expected_slot;
    unsigned long relocation_index;
    uintptr_t bridge_target;
    unsigned long bridge_generation;
    int bridge_custom_wrapper;
    /* Set only for a process-resident source whose loader wrapper ownership
     * cannot change across dlopen/dlclose namespace mutations. */
    int loader_mutation_invariant;
    kzt_symbol_version_evidence_t version_evidence;
    char symbol[KZT_LAZY_PREBIND_TEXT_MAX];
    char version[KZT_LAZY_PREBIND_TEXT_MAX];
    kzt_guest_symbol_scope_result_t scope_proof;
    uint64_t scope_epoch;
} kzt_lazy_prebind_record_t;

typedef struct kzt_lazy_prebind_lease {
    kzt_lazy_prebind_scope_t *scope;
    void *entry;
    kzt_lazy_prebind_record_t record;
    kzt_lazy_prebind_lease_operation_t operation;
    int active;
} kzt_lazy_prebind_lease_t;

kzt_lazy_prebind_scope_t *kzt_lazy_prebind_scope_init(void);
void kzt_lazy_prebind_scope_destroy(kzt_lazy_prebind_scope_t **scope);

uint64_t kzt_lazy_prebind_scope_epoch(kzt_lazy_prebind_scope_t *scope);
uint64_t kzt_lazy_prebind_scope_mutate(
    kzt_lazy_prebind_scope_t *scope, kzt_lazy_prebind_mutation_t mutation);

/* True only while this exact source has a current published custom dlerror
 * bridge.  Process-resident records can remain current across mutations;
 * other records are invalidated with their scope epoch. */
int kzt_lazy_prebind_scope_has_native_dlerror(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *source);

kzt_lazy_prebind_claim_result_t kzt_lazy_prebind_scope_claim(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *record);

/* `expected` may omit provider/bridge fields to request the exact cached
 * source/slot/symbol/version record for the current scope epoch. */
int kzt_lazy_prebind_scope_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *expected,
    kzt_lazy_prebind_lease_t *lease);
int kzt_lazy_prebind_scope_lease_published(
    const kzt_lazy_prebind_lease_t *lease);
void kzt_lazy_prebind_scope_release(kzt_lazy_prebind_lease_t *lease);

/* Only one current record owner can publish a speculative bridge.  The
 * caller must CAS expected_slot to bridge_target before finish(..., 1). */
int kzt_lazy_prebind_scope_publish_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *expected,
    kzt_lazy_prebind_lease_t *lease);
void kzt_lazy_prebind_scope_publish_finish(kzt_lazy_prebind_lease_t *lease,
                                           int published);

/* After mutate or retire has closed an entry, return one speculative bridge
 * that still needs bridge_target -> expected_slot CAS.  `identity == NULL`
 * revokes every closed entry.  Return 0 for one lease, 1 when exhausted. */
int kzt_lazy_prebind_scope_revoke_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *identity,
    kzt_lazy_prebind_lease_t *lease);
void kzt_lazy_prebind_scope_revoke_finish(kzt_lazy_prebind_lease_t *lease,
                                          int revoked);

/* A lease can become non-writable while it is held when retire or a scope
 * mutation wins.  Call this immediately before the final slot validation. */
int kzt_lazy_prebind_scope_lease_valid(
    const kzt_lazy_prebind_lease_t *lease);

/* Invalidates source and provider records for one exact retired generation,
 * then drains only the matching record leases. */
int kzt_lazy_prebind_scope_retire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *identity);

#endif
