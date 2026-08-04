#include "kzt_lazy_prebind_scope.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "elf.h"
#define CHECK(label, condition)                                             \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s: FAIL\\n", label);                       \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

static kzt_lazy_prebind_record_t record_for(unsigned long generation,
                                            uintptr_t slot)
{
    kzt_lazy_prebind_record_t record = { 0 };

    record.source = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = 0x1000,
        .generation = generation,
        .namespace_id = 0,
    };
    record.provider = (kzt_lazy_prebind_identity_t) {
        .link_map_addr = 0x2000,
        .generation = 9,
        .namespace_id = 0,
    };
    record.slot_addr = slot;
    record.expected_slot = 0x3000;
    record.relocation_index = 7;
    record.bridge_target = 0x4000;
    record.bridge_generation = 9;
    record.version_evidence = KZT_SYMBOL_VERSION_VERSIONED;
    strcpy(record.symbol, "dlerror");
    strcpy(record.version, "GLIBC_2.34");
    record.scope_proof.status = KZT_GUEST_SYMBOL_SCOPE_SAFE;
    record.scope_proof.reason = KZT_GUEST_SYMBOL_SCOPE_REASON_SELECTED_PROVIDER;
    record.scope_proof.scope_complete = 1;
    record.scope_proof.lookup_order_known = 1;
    record.scope_proof.selected_provider_link_map = record.provider.link_map_addr;
    record.scope_proof.selected_provider_address = 0x5000;
    record.scope_proof.selected_provider_binding = STB_GLOBAL;
    record.scope_proof.selected_provider_type = STT_FUNC;
    record.scope_proof.selected_provider_visibility = STV_DEFAULT;
    record.scope_proof.query_fingerprint = 0x6000;
    record.scope_proof.scope_identity = (kzt_guest_symbol_scope_identity_t) {
        .source = {
            .link_map_addr = record.source.link_map_addr,
            .generation = record.source.generation,
            .namespace_id = record.source.namespace_id,
            .namespace_head = record.source.link_map_addr,
            .layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF,
        },
        .scope_array_addr = 0x7000,
        .scope_list_count = 1,
        .scope_map_count = 2,
        .value = 0x8000,
    };
    return record;
}

typedef struct retire_race {
    kzt_lazy_prebind_scope_t *scope;
    kzt_lazy_prebind_identity_t identity;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int finished;
    int result;
} retire_race_t;

typedef struct mutation_race {
    kzt_lazy_prebind_scope_t *scope;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int finished;
    uint64_t epoch;
} mutation_race_t;

static void *retire_worker(void *opaque)
{
    retire_race_t *race = opaque;

    pthread_mutex_lock(&race->lock);
    race->started = 1;
    pthread_cond_broadcast(&race->cond);
    pthread_mutex_unlock(&race->lock);
    race->result = kzt_lazy_prebind_scope_retire(race->scope, &race->identity);
    pthread_mutex_lock(&race->lock);
    race->finished = 1;
    pthread_cond_broadcast(&race->cond);
    pthread_mutex_unlock(&race->lock);
    return NULL;
}

static void *mutation_worker(void *opaque)
{
    mutation_race_t *race = opaque;

    pthread_mutex_lock(&race->lock);
    race->started = 1;
    pthread_cond_broadcast(&race->cond);
    pthread_mutex_unlock(&race->lock);
    race->epoch = kzt_lazy_prebind_scope_mutate(
        race->scope, KZT_LAZY_PREBIND_MUTATION_DLOPEN);
    pthread_mutex_lock(&race->lock);
    race->finished = 1;
    pthread_cond_broadcast(&race->cond);
    pthread_mutex_unlock(&race->lock);
    return NULL;
}

static int wait_for(retire_race_t *race, int *value, int expected,
                    long milliseconds)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += milliseconds * 1000 * 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&race->lock);
    while (*value < expected &&
           pthread_cond_timedwait(&race->cond, &race->lock, &deadline) == 0) {
    }
    pthread_mutex_unlock(&race->lock);
    return *value >= expected;
}

static int wait_for_mutation(mutation_race_t *race, int *value, int expected,
                             long milliseconds)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += milliseconds * 1000 * 1000;
    if (deadline.tv_nsec >= 1000 * 1000 * 1000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000 * 1000 * 1000;
    }
    pthread_mutex_lock(&race->lock);
    while (*value < expected &&
           pthread_cond_timedwait(&race->cond, &race->lock, &deadline) == 0) {
    }
    pthread_mutex_unlock(&race->lock);
    return *value >= expected;
}

static void test_epoch_invalidates_and_replaces_record(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t record = record_for(1, 0x2000);
    kzt_lazy_prebind_lease_t lease = { 0 };

    CHECK("epoch scope", scope != NULL);
    CHECK("epoch starts one", kzt_lazy_prebind_scope_epoch(scope) == 1);
    CHECK("epoch first claim", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("epoch first acquire", kzt_lazy_prebind_scope_acquire(
          scope, &record, &lease) == 0);
    CHECK("epoch claimed record is not published",
          !kzt_lazy_prebind_scope_lease_published(&lease));
    CHECK("epoch exact provider", lease.record.provider.link_map_addr == 0x2000 &&
          lease.record.provider.generation == 9);
    kzt_lazy_prebind_scope_release(&lease);
    CHECK("epoch advance", kzt_lazy_prebind_scope_mutate(
          scope, KZT_LAZY_PREBIND_MUTATION_DLOPEN) == 2);
    CHECK("epoch old rejected", kzt_lazy_prebind_scope_acquire(
          scope, &record, &lease) != 0);
    CHECK("epoch replace claim", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("epoch replace acquire", kzt_lazy_prebind_scope_acquire(
          scope, &record, &lease) == 0 && lease.record.scope_epoch == 2);
    kzt_lazy_prebind_scope_release(&lease);
    kzt_lazy_prebind_scope_destroy(&scope);
}

static void test_retire_waits_lease_and_rejects_address_reuse(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t old_record = record_for(1, 0x2100);
    kzt_lazy_prebind_record_t new_record = record_for(2, 0x2100);
    kzt_lazy_prebind_lease_t lease = { 0 };
    retire_race_t race = {
        .scope = scope,
        .identity = old_record.source,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("retire scope", scope != NULL);
    CHECK("retire claim", kzt_lazy_prebind_scope_claim(scope, &old_record) ==
          KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("retire acquire", kzt_lazy_prebind_scope_acquire(scope, &old_record,
                                                              &lease) == 0);
    CHECK("retire thread", pthread_create(&thread, NULL, retire_worker, &race) == 0);
    CHECK("retire starts", wait_for(&race, &race.started, 1, 100));
    CHECK("retire waits lease", !wait_for(&race, &race.finished, 1, 30));
    CHECK("retire stale acquire blocked", kzt_lazy_prebind_scope_acquire(
          scope, &old_record, &(kzt_lazy_prebind_lease_t){ 0 }) != 0);
    kzt_lazy_prebind_scope_release(&lease);
    CHECK("retire finishes", wait_for(&race, &race.finished, 1, 100));
    CHECK("retire result", race.result == 0);
    CHECK("retire join", pthread_join(thread, NULL) == 0);
    CHECK("reuse old claim rejected", kzt_lazy_prebind_scope_claim(
          scope, &old_record) == KZT_LAZY_PREBIND_CLAIM_RETIRED);
    CHECK("reuse new generation claim", kzt_lazy_prebind_scope_claim(
          scope, &new_record) == KZT_LAZY_PREBIND_CLAIM_CREATED);
    kzt_lazy_prebind_scope_destroy(&scope);
    pthread_cond_destroy(&race.cond);
    pthread_mutex_destroy(&race.lock);
}

static void test_incomplete_proof_fails_open(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t record = record_for(1, 0x2200);

    CHECK("invalid scope", scope != NULL);
    record.version[0] = '\0';
    CHECK("invalid version", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_FAIL_OPEN);
    record = record_for(1, 0x2200);
    record.scope_proof.scope_complete = 0;
    CHECK("incomplete proof", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_FAIL_OPEN);
    kzt_lazy_prebind_scope_destroy(&scope);
}

static void test_changed_scope_identity_is_not_reused(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t original = record_for(1, 0x2250);
    kzt_lazy_prebind_record_t changed = original;

    CHECK("scope identity cache", scope != NULL);
    CHECK("scope identity first claim",
          kzt_lazy_prebind_scope_claim(scope, &original) ==
              KZT_LAZY_PREBIND_CLAIM_CREATED);
    changed.scope_proof.scope_identity.value ^= 1;
    CHECK("scope identity conflict",
          kzt_lazy_prebind_scope_claim(scope, &changed) ==
              KZT_LAZY_PREBIND_CLAIM_CONFLICT);
    CHECK("scope identity epoch",
          kzt_lazy_prebind_scope_mutate(
              scope, KZT_LAZY_PREBIND_MUTATION_LOADER_EVENT) == 2);
    CHECK("scope identity replacement",
          kzt_lazy_prebind_scope_claim(scope, &changed) ==
              KZT_LAZY_PREBIND_CLAIM_CREATED);
    kzt_lazy_prebind_scope_destroy(&scope);
}

static void test_publication_is_unique_and_mutation_drains(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t record = record_for(1, 0x2300);
    kzt_lazy_prebind_lease_t publish = { 0 };
    kzt_lazy_prebind_lease_t competing = { 0 };
    kzt_lazy_prebind_lease_t revoke = { 0 };
    mutation_race_t race = {
        .scope = scope,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };
    pthread_t thread;

    CHECK("publish scope", scope != NULL);
    CHECK("publish claim", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("publish first lease", kzt_lazy_prebind_scope_publish_acquire(
          scope, &record, &publish) == 0);
    CHECK("publish single writer", kzt_lazy_prebind_scope_publish_acquire(
          scope, &record, &competing) != 0);
    CHECK("publish mutation thread", pthread_create(
          &thread, NULL, mutation_worker, &race) == 0);
    CHECK("publish mutation starts", wait_for_mutation(
          &race, &race.started, 1, 100));
    CHECK("publish mutation waits lease", !wait_for_mutation(
          &race, &race.finished, 1, 30));
    kzt_lazy_prebind_scope_publish_finish(&publish, 1);
    CHECK("publish mutation finishes", wait_for_mutation(
          &race, &race.finished, 1, 100));
    CHECK("publish mutation epoch", race.epoch == 2);
    CHECK("publish mutation join", pthread_join(thread, NULL) == 0);
    CHECK("publish revoke lease", kzt_lazy_prebind_scope_revoke_acquire(
          scope, NULL, &revoke) == 0);
    CHECK("publish revoke record", revoke.record.slot_addr == record.slot_addr &&
          revoke.record.bridge_target == record.bridge_target);
    kzt_lazy_prebind_scope_revoke_finish(&revoke, 1);
    CHECK("publish revoke one shot", kzt_lazy_prebind_scope_revoke_acquire(
          scope, NULL, &(kzt_lazy_prebind_lease_t){ 0 }) == 1);
    kzt_lazy_prebind_scope_destroy(&scope);
    pthread_cond_destroy(&race.cond);
    pthread_mutex_destroy(&race.lock);
}

static void test_loader_invariant_survives_loader_retire_prepare(
    const char *symbol)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t record = record_for(1, 0x2400);
    kzt_lazy_prebind_lease_t publish = { 0 };
    kzt_lazy_prebind_lease_t read = { 0 };
    kzt_lazy_prebind_lease_t revoke = { 0 };

    record.bridge_custom_wrapper = 1;
    record.loader_mutation_invariant = 1;
    strcpy(record.symbol, symbol);
    CHECK("invariant scope", scope != NULL);
    CHECK("invariant claim", kzt_lazy_prebind_scope_claim(scope, &record) ==
          KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("invariant publish", kzt_lazy_prebind_scope_publish_acquire(
          scope, &record, &publish) == 0);
    kzt_lazy_prebind_scope_publish_finish(&publish, 1);
    CHECK("invariant dlerror publication query",
          kzt_lazy_prebind_scope_has_native_dlerror(
              scope, &record.source) == (strcmp(symbol, "dlerror") == 0));
    CHECK("invariant published lease acquire",
          kzt_lazy_prebind_scope_acquire(scope, &record, &read) == 0);
    CHECK("invariant published lease state",
          kzt_lazy_prebind_scope_lease_published(&read));
    kzt_lazy_prebind_scope_release(&read);
    CHECK("invariant mutate", kzt_lazy_prebind_scope_mutate(
          scope, KZT_LAZY_PREBIND_MUTATION_DLOPEN) == 2);
    CHECK("invariant remains current", kzt_lazy_prebind_scope_acquire(
          scope, &record, &read) == 0 && read.record.scope_epoch == 2);
    kzt_lazy_prebind_scope_release(&read);
    CHECK("invariant not globally revoked",
          kzt_lazy_prebind_scope_revoke_acquire(
              scope, NULL, &revoke) == 1);
    CHECK("invariant retire prepare ignored", kzt_lazy_prebind_scope_retire(
          scope, &record.source) == 0);
    CHECK("invariant remains after retire prepare",
          kzt_lazy_prebind_scope_acquire(scope, &record, &read) == 0);
    kzt_lazy_prebind_scope_release(&read);
    CHECK("invariant dlerror query survives mutation",
          kzt_lazy_prebind_scope_has_native_dlerror(
              scope, &record.source) == (strcmp(symbol, "dlerror") == 0));
    CHECK("invariant exact revoke blocked",
          kzt_lazy_prebind_scope_revoke_acquire(
              scope, &record.source, &revoke) == 1);
    kzt_lazy_prebind_scope_destroy(&scope);
}

static void test_source_dlerror_publication_expires_with_scope(void)
{
    kzt_lazy_prebind_scope_t *scope = kzt_lazy_prebind_scope_init();
    kzt_lazy_prebind_record_t record = record_for(1, 0x2500);
    kzt_lazy_prebind_lease_t publish = { 0 };

    record.bridge_custom_wrapper = 1;
    CHECK("source dlerror scope", scope != NULL);
    CHECK("source dlerror claim", kzt_lazy_prebind_scope_claim(
          scope, &record) == KZT_LAZY_PREBIND_CLAIM_CREATED);
    CHECK("source dlerror publish", kzt_lazy_prebind_scope_publish_acquire(
          scope, &record, &publish) == 0);
    kzt_lazy_prebind_scope_publish_finish(&publish, 1);
    CHECK("source dlerror current", kzt_lazy_prebind_scope_has_native_dlerror(
          scope, &record.source));
    CHECK("source dlerror mutate", kzt_lazy_prebind_scope_mutate(
          scope, KZT_LAZY_PREBIND_MUTATION_DLOPEN) == 2);
    CHECK("source dlerror expired", !kzt_lazy_prebind_scope_has_native_dlerror(
          scope, &record.source));
    kzt_lazy_prebind_scope_destroy(&scope);
}

int main(void)
{
    test_epoch_invalidates_and_replaces_record();
    test_retire_waits_lease_and_rejects_address_reuse();
    test_incomplete_proof_fails_open();
    test_changed_scope_identity_is_not_reused();
    test_publication_is_unique_and_mutation_drains();
    test_source_dlerror_publication_expires_with_scope();
    test_loader_invariant_survives_loader_retire_prepare("dlerror");
    test_loader_invariant_survives_loader_retire_prepare("dlopen");
    puts("kzt-lazy-prebind-scope: all tests passed");
    return 0;
}
