#include "kzt_lazy_prebind_scope.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"

typedef struct kzt_lazy_prebind_entry {
    kzt_lazy_prebind_record_t record;
    unsigned long leases;
    int transitioning;
    int published;
    int retired;
    struct kzt_lazy_prebind_entry *next;
} kzt_lazy_prebind_entry_t;

struct kzt_lazy_prebind_scope {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    uint64_t epoch;
    kzt_lazy_prebind_entry_t *entries;
};

static int kzt_lazy_prebind_identity_valid(
    const kzt_lazy_prebind_identity_t *identity)
{
    return identity && identity->link_map_addr && identity->generation &&
           identity->namespace_id == 0;
}

static int kzt_lazy_prebind_identity_equal(
    const kzt_lazy_prebind_identity_t *left,
    const kzt_lazy_prebind_identity_t *right)
{
    return left && right && left->link_map_addr == right->link_map_addr &&
           left->generation == right->generation &&
           left->namespace_id == right->namespace_id;
}

static int kzt_lazy_prebind_text_valid(const char *text)
{
    return text && text[0] && strnlen(text, KZT_LAZY_PREBIND_TEXT_MAX) <
           KZT_LAZY_PREBIND_TEXT_MAX;
}

static int kzt_lazy_prebind_record_key_valid(
    const kzt_lazy_prebind_record_t *record)
{
    return record && kzt_lazy_prebind_identity_valid(&record->source) &&
           record->slot_addr && record->expected_slot &&
           kzt_lazy_prebind_text_valid(record->symbol) &&
           kzt_symbol_version_evidence_valid(record->version_evidence,
                                             record->version);
}

static int kzt_lazy_prebind_record_valid(
    const kzt_lazy_prebind_record_t *record)
{
    return kzt_lazy_prebind_record_key_valid(record) &&
           (!record->loader_mutation_invariant ||
            (record->bridge_custom_wrapper &&
             kzt_patch_symbol_is_loader_route_family(record->symbol))) &&
           kzt_lazy_prebind_identity_valid(&record->provider) &&
           record->bridge_target && record->bridge_generation &&
           record->bridge_generation == record->provider.generation &&
           record->scope_proof.status == KZT_GUEST_SYMBOL_SCOPE_SAFE &&
           record->scope_proof.reason ==
               KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER &&
           record->scope_proof.scope_complete &&
           record->scope_proof.lookup_order_known &&
           record->scope_proof.selected_provider_link_map ==
               record->provider.link_map_addr &&
           record->scope_proof.selected_provider_address &&
           record->scope_proof.selected_provider_binding == STB_GLOBAL &&
           record->scope_proof.selected_provider_type == STT_FUNC &&
           record->scope_proof.selected_provider_visibility == STV_DEFAULT &&
           record->scope_proof.scope_identity.source.link_map_addr ==
               record->source.link_map_addr &&
           record->scope_proof.scope_identity.source.generation ==
               record->source.generation &&
           record->scope_proof.scope_identity.source.namespace_id ==
               record->source.namespace_id;
}

static int kzt_lazy_prebind_record_key_equal(
    const kzt_lazy_prebind_record_t *left,
    const kzt_lazy_prebind_record_t *right)
{
    return kzt_lazy_prebind_identity_equal(&left->source, &right->source) &&
           left->slot_addr == right->slot_addr &&
           left->expected_slot == right->expected_slot &&
           left->relocation_index == right->relocation_index &&
           left->version_evidence == right->version_evidence &&
           strcmp(left->symbol, right->symbol) == 0 &&
           strcmp(left->version, right->version) == 0;
}

static int kzt_lazy_prebind_record_equal(
    const kzt_lazy_prebind_record_t *left,
    const kzt_lazy_prebind_record_t *right)
{
    return kzt_lazy_prebind_record_key_equal(left, right) &&
           kzt_lazy_prebind_identity_equal(&left->provider,
                                            &right->provider) &&
           left->bridge_target == right->bridge_target &&
           left->bridge_generation == right->bridge_generation &&
           left->loader_mutation_invariant ==
               right->loader_mutation_invariant &&
           left->scope_proof.selected_provider_address ==
               right->scope_proof.selected_provider_address &&
           left->scope_proof.selected_provider_binding ==
               right->scope_proof.selected_provider_binding &&
           left->scope_proof.selected_provider_type ==
               right->scope_proof.selected_provider_type &&
           left->scope_proof.selected_provider_visibility ==
               right->scope_proof.selected_provider_visibility &&
           left->scope_proof.query_fingerprint ==
               right->scope_proof.query_fingerprint &&
           memcmp(&left->scope_proof.scope_identity,
                  &right->scope_proof.scope_identity,
                  sizeof(left->scope_proof.scope_identity)) == 0;
}

static int kzt_lazy_prebind_entry_matches_request(
    const kzt_lazy_prebind_entry_t *entry,
    const kzt_lazy_prebind_record_t *expected, uint64_t epoch)
{
    if (!entry || !expected || entry->retired || entry->transitioning ||
        entry->record.scope_epoch != epoch ||
        !kzt_lazy_prebind_record_key_equal(&entry->record, expected)) {
        return 0;
    }
    if (expected->provider.link_map_addr &&
        !kzt_lazy_prebind_identity_equal(&entry->record.provider,
                                          &expected->provider)) {
        return 0;
    }
    if (expected->bridge_target &&
        (entry->record.bridge_target != expected->bridge_target ||
         entry->record.bridge_generation != expected->bridge_generation)) {
        return 0;
    }
    return 1;
}

static int kzt_lazy_prebind_entry_matches_identity(
    const kzt_lazy_prebind_entry_t *entry,
    const kzt_lazy_prebind_identity_t *identity)
{
    return !identity ||
           kzt_lazy_prebind_identity_equal(&entry->record.source, identity) ||
           kzt_lazy_prebind_identity_equal(&entry->record.provider, identity);
}

static void kzt_lazy_prebind_scope_release_entry_locked(
    kzt_lazy_prebind_scope_t *scope, kzt_lazy_prebind_entry_t *entry)
{
    if (!scope || !entry || !entry->leases) {
        return;
    }
    --entry->leases;
    if (!entry->leases) {
        pthread_cond_broadcast(&scope->changed);
    }
}

static void kzt_lazy_prebind_scope_wait_all_leases_locked(
    kzt_lazy_prebind_scope_t *scope)
{
    for (;;) {
        kzt_lazy_prebind_entry_t *entry;
        unsigned long leases = 0;

        for (entry = scope->entries; entry; entry = entry->next) {
            leases += entry->leases;
        }
        if (!leases) {
            return;
        }
        pthread_cond_wait(&scope->changed, &scope->lock);
    }
}

static void kzt_lazy_prebind_scope_prune_closed_locked(
    kzt_lazy_prebind_scope_t *scope)
{
    kzt_lazy_prebind_entry_t **cursor;

    if (!scope) {
        return;
    }
    cursor = &scope->entries;
    while (*cursor) {
        kzt_lazy_prebind_entry_t *entry = *cursor;

        if (!entry->leases && !entry->transitioning && !entry->published &&
            (entry->retired || entry->record.scope_epoch != scope->epoch)) {
            *cursor = entry->next;
            free(entry);
            continue;
        }
        cursor = &entry->next;
    }
}

kzt_lazy_prebind_scope_t *kzt_lazy_prebind_scope_init(void)
{
    kzt_lazy_prebind_scope_t *scope = calloc(1, sizeof(*scope));

    if (!scope) {
        return NULL;
    }
    if (pthread_mutex_init(&scope->lock, NULL) != 0) {
        free(scope);
        return NULL;
    }
    if (pthread_cond_init(&scope->changed, NULL) != 0) {
        pthread_mutex_destroy(&scope->lock);
        free(scope);
        return NULL;
    }
    scope->epoch = 1;
    return scope;
}

void kzt_lazy_prebind_scope_destroy(kzt_lazy_prebind_scope_t **scope_ptr)
{
    kzt_lazy_prebind_scope_t *scope;
    kzt_lazy_prebind_entry_t *entry;

    if (!scope_ptr || !(scope = *scope_ptr)) {
        return;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        entry->retired = 1;
    }
    kzt_lazy_prebind_scope_wait_all_leases_locked(scope);
    entry = scope->entries;
    scope->entries = NULL;
    pthread_mutex_unlock(&scope->lock);
    while (entry) {
        kzt_lazy_prebind_entry_t *next = entry->next;

        free(entry);
        entry = next;
    }
    pthread_cond_destroy(&scope->changed);
    pthread_mutex_destroy(&scope->lock);
    free(scope);
    *scope_ptr = NULL;
}

uint64_t kzt_lazy_prebind_scope_epoch(kzt_lazy_prebind_scope_t *scope)
{
    uint64_t epoch = 0;

    if (!scope) {
        return 0;
    }
    pthread_mutex_lock(&scope->lock);
    epoch = scope->epoch;
    pthread_mutex_unlock(&scope->lock);
    return epoch;
}

uint64_t kzt_lazy_prebind_scope_mutate(
    kzt_lazy_prebind_scope_t *scope, kzt_lazy_prebind_mutation_t mutation)
{
    kzt_lazy_prebind_entry_t *entry;

    (void)mutation;
    if (!scope) {
        return 0;
    }
    pthread_mutex_lock(&scope->lock);
    if (scope->epoch == UINT64_MAX) {
        scope->epoch = 1;
        for (entry = scope->entries; entry; entry = entry->next) {
            entry->retired = 1;
        }
    } else {
        ++scope->epoch;
    }
    kzt_lazy_prebind_scope_wait_all_leases_locked(scope);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!entry->retired && entry->published &&
            entry->record.loader_mutation_invariant) {
            entry->record.scope_epoch = scope->epoch;
        }
    }
    kzt_lazy_prebind_scope_prune_closed_locked(scope);
    pthread_cond_broadcast(&scope->changed);
    pthread_mutex_unlock(&scope->lock);
    return kzt_lazy_prebind_scope_epoch(scope);
}

int kzt_lazy_prebind_scope_has_native_dlerror(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *source)
{
    kzt_lazy_prebind_entry_t *entry;
    int found = 0;

    if (!scope || !kzt_lazy_prebind_identity_valid(source)) {
        return 0;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!entry->retired && entry->published &&
            entry->record.scope_epoch == scope->epoch &&
            entry->record.bridge_custom_wrapper &&
            strcmp(entry->record.symbol, "dlerror") == 0 &&
            kzt_lazy_prebind_identity_equal(
                &entry->record.source, source)) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&scope->lock);
    return found;
}

kzt_lazy_prebind_claim_result_t kzt_lazy_prebind_scope_claim(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *record)
{
    kzt_lazy_prebind_entry_t *entry;
    kzt_lazy_prebind_entry_t *created;

    if (!scope || !kzt_lazy_prebind_record_valid(record)) {
        return KZT_LAZY_PREBIND_CLAIM_FAIL_OPEN;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!kzt_lazy_prebind_record_key_equal(&entry->record, record)) {
            continue;
        }
        if (entry->retired) {
            pthread_mutex_unlock(&scope->lock);
            return KZT_LAZY_PREBIND_CLAIM_RETIRED;
        }
        if (entry->record.scope_epoch != scope->epoch) {
            continue;
        }
        pthread_mutex_unlock(&scope->lock);
        return kzt_lazy_prebind_record_equal(&entry->record, record) ?
            KZT_LAZY_PREBIND_CLAIM_REUSED :
            KZT_LAZY_PREBIND_CLAIM_CONFLICT;
    }
    created = calloc(1, sizeof(*created));
    if (!created) {
        pthread_mutex_unlock(&scope->lock);
        return KZT_LAZY_PREBIND_CLAIM_FAIL_OPEN;
    }
    created->record = *record;
    created->record.scope_epoch = scope->epoch;
    created->next = scope->entries;
    scope->entries = created;
    pthread_mutex_unlock(&scope->lock);
    return KZT_LAZY_PREBIND_CLAIM_CREATED;
}

int kzt_lazy_prebind_scope_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *expected,
    kzt_lazy_prebind_lease_t *lease)
{
    kzt_lazy_prebind_entry_t *entry;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!scope || !lease || !kzt_lazy_prebind_record_key_valid(expected)) {
        return -1;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!kzt_lazy_prebind_entry_matches_request(entry, expected,
                                                    scope->epoch)) {
            continue;
        }
        ++entry->leases;
        lease->scope = scope;
        lease->entry = entry;
        lease->record = entry->record;
        lease->active = 1;
        pthread_mutex_unlock(&scope->lock);
        return 0;
    }
    pthread_mutex_unlock(&scope->lock);
    return -1;
}

int kzt_lazy_prebind_scope_lease_published(
    const kzt_lazy_prebind_lease_t *lease)
{
    const kzt_lazy_prebind_entry_t *entry;
    int published = 0;

    if (!lease || !lease->active || !lease->scope || !lease->entry) {
        return 0;
    }
    entry = lease->entry;
    pthread_mutex_lock(&lease->scope->lock);
    published = !entry->retired && entry->published &&
                entry->record.scope_epoch == lease->scope->epoch &&
                entry->record.scope_epoch == lease->record.scope_epoch &&
                kzt_lazy_prebind_record_equal(
                    &entry->record, &lease->record);
    pthread_mutex_unlock(&lease->scope->lock);
    return published;
}

void kzt_lazy_prebind_scope_release(kzt_lazy_prebind_lease_t *lease)
{
    kzt_lazy_prebind_entry_t *entry;

    if (!lease || !lease->active || !lease->scope || !lease->entry) {
        return;
    }
    if (lease->operation == KZT_LAZY_PREBIND_LEASE_PUBLISH) {
        kzt_lazy_prebind_scope_publish_finish(lease, 0);
        return;
    }
    if (lease->operation == KZT_LAZY_PREBIND_LEASE_REVOKE) {
        kzt_lazy_prebind_scope_revoke_finish(lease, 0);
        return;
    }
    entry = lease->entry;
    pthread_mutex_lock(&lease->scope->lock);
    kzt_lazy_prebind_scope_release_entry_locked(lease->scope, entry);
    pthread_mutex_unlock(&lease->scope->lock);
    memset(lease, 0, sizeof(*lease));
}

int kzt_lazy_prebind_scope_publish_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_record_t *expected,
    kzt_lazy_prebind_lease_t *lease)
{
    kzt_lazy_prebind_entry_t *entry;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!scope || !lease || !kzt_lazy_prebind_record_valid(expected)) {
        return -1;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (entry->retired || entry->transitioning || entry->published ||
            entry->leases || entry->record.scope_epoch != scope->epoch ||
            !kzt_lazy_prebind_record_equal(&entry->record, expected)) {
            continue;
        }
        entry->transitioning = 1;
        ++entry->leases;
        lease->scope = scope;
        lease->entry = entry;
        lease->record = entry->record;
        lease->operation = KZT_LAZY_PREBIND_LEASE_PUBLISH;
        lease->active = 1;
        pthread_mutex_unlock(&scope->lock);
        return 0;
    }
    pthread_mutex_unlock(&scope->lock);
    return -1;
}

void kzt_lazy_prebind_scope_publish_finish(kzt_lazy_prebind_lease_t *lease,
                                           int published)
{
    kzt_lazy_prebind_entry_t *entry;

    if (!lease || !lease->active || !lease->scope || !lease->entry ||
        lease->operation != KZT_LAZY_PREBIND_LEASE_PUBLISH) {
        return;
    }
    entry = lease->entry;
    pthread_mutex_lock(&lease->scope->lock);
    if (entry->transitioning) {
        entry->transitioning = 0;
        if (published) {
            entry->published = 1;
        }
    }
    kzt_lazy_prebind_scope_release_entry_locked(lease->scope, entry);
    kzt_lazy_prebind_scope_prune_closed_locked(lease->scope);
    pthread_mutex_unlock(&lease->scope->lock);
    memset(lease, 0, sizeof(*lease));
}

int kzt_lazy_prebind_scope_revoke_acquire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *identity,
    kzt_lazy_prebind_lease_t *lease)
{
    kzt_lazy_prebind_entry_t *entry;

    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
    if (!scope || !lease ||
        (identity && !kzt_lazy_prebind_identity_valid(identity))) {
        return -1;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!entry->published || entry->transitioning ||
            (!entry->retired && entry->record.scope_epoch == scope->epoch) ||
            !kzt_lazy_prebind_entry_matches_identity(entry, identity)) {
            continue;
        }
        entry->transitioning = 1;
        ++entry->leases;
        lease->scope = scope;
        lease->entry = entry;
        lease->record = entry->record;
        lease->operation = KZT_LAZY_PREBIND_LEASE_REVOKE;
        lease->active = 1;
        pthread_mutex_unlock(&scope->lock);
        return 0;
    }
    pthread_mutex_unlock(&scope->lock);
    return 1;
}

void kzt_lazy_prebind_scope_revoke_finish(kzt_lazy_prebind_lease_t *lease,
                                          int revoked)
{
    kzt_lazy_prebind_entry_t *entry;

    if (!lease || !lease->active || !lease->scope || !lease->entry ||
        lease->operation != KZT_LAZY_PREBIND_LEASE_REVOKE) {
        return;
    }
    entry = lease->entry;
    pthread_mutex_lock(&lease->scope->lock);
    if (entry->transitioning) {
        entry->transitioning = 0;
        if (revoked) {
            entry->published = 0;
        }
    }
    kzt_lazy_prebind_scope_release_entry_locked(lease->scope, entry);
    kzt_lazy_prebind_scope_prune_closed_locked(lease->scope);
    pthread_mutex_unlock(&lease->scope->lock);
    memset(lease, 0, sizeof(*lease));
}

int kzt_lazy_prebind_scope_lease_valid(
    const kzt_lazy_prebind_lease_t *lease)
{
    const kzt_lazy_prebind_entry_t *entry;
    int valid = 0;

    if (!lease || !lease->active || !lease->scope || !lease->entry) {
        return 0;
    }
    entry = lease->entry;
    pthread_mutex_lock(&lease->scope->lock);
    valid = !entry->retired && entry->leases &&
            entry->record.scope_epoch == lease->scope->epoch &&
            entry->record.scope_epoch == lease->record.scope_epoch &&
            kzt_lazy_prebind_record_equal(&entry->record, &lease->record);
    pthread_mutex_unlock(&lease->scope->lock);
    return valid;
}

int kzt_lazy_prebind_scope_retire(
    kzt_lazy_prebind_scope_t *scope,
    const kzt_lazy_prebind_identity_t *identity)
{
    kzt_lazy_prebind_entry_t *entry;
    int found = 0;

    if (!scope || !kzt_lazy_prebind_identity_valid(identity)) {
        return -1;
    }
    pthread_mutex_lock(&scope->lock);
    for (entry = scope->entries; entry; entry = entry->next) {
        if (!entry->record.loader_mutation_invariant &&
            (kzt_lazy_prebind_identity_equal(
                 &entry->record.source, identity) ||
             kzt_lazy_prebind_identity_equal(
                 &entry->record.provider, identity))) {
            entry->retired = 1;
            found = 1;
        }
    }
    if (!found) {
        pthread_mutex_unlock(&scope->lock);
        return 0;
    }
    for (;;) {
        unsigned long leases = 0;

        for (entry = scope->entries; entry; entry = entry->next) {
            if (!entry->record.loader_mutation_invariant && entry->retired &&
                (kzt_lazy_prebind_identity_equal(&entry->record.source,
                                                  identity) ||
                 kzt_lazy_prebind_identity_equal(&entry->record.provider,
                                                  identity))) {
                leases += entry->leases;
            }
        }
        if (!leases) {
            break;
        }
        pthread_cond_wait(&scope->changed, &scope->lock);
    }
    pthread_mutex_unlock(&scope->lock);
    return 0;
}
