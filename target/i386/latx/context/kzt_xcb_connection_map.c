#include "kzt_xcb_connection_map.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct kzt_xcb_connection_entry {
    void *guest;
    void *native;
    uint64_t generation;
    pthread_mutex_t operation_lock;
    unsigned long users;
    int closing;
    int removal_pending;
    int removing;
    struct kzt_xcb_connection_entry *next;
} kzt_xcb_connection_entry_t;

struct kzt_xcb_connection_map {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    kzt_xcb_connection_guest_destroy_fn destroy_guest;
    void *destroy_opaque;
    kzt_xcb_connection_entry_t *entries;
    size_t count;
    uint64_t next_generation;
    unsigned long active_removals;
    int teardown;
};

typedef struct kzt_xcb_remove_wait_cleanup {
    kzt_xcb_connection_map_t *map;
    kzt_xcb_connection_entry_t *entry;
} kzt_xcb_remove_wait_cleanup_t;

static int kzt_xcb_cancel_disable(void)
{
    int old_state = PTHREAD_CANCEL_ENABLE;

    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
    return old_state;
}

static void kzt_xcb_cancel_restore(int old_state)
{
    (void)pthread_setcancelstate(old_state, NULL);
}

static void kzt_xcb_remove_wait_cancel(void *opaque)
{
    kzt_xcb_remove_wait_cleanup_t *cleanup = opaque;

    cleanup->entry->removal_pending = 0;
    if (!cleanup->map->teardown) {
        cleanup->entry->closing = 0;
    }
    pthread_cond_broadcast(&cleanup->map->changed);
    pthread_mutex_unlock(&cleanup->map->lock);
}

static int kzt_xcb_connection_entry_init(
    kzt_xcb_connection_entry_t *entry)
{
    pthread_mutexattr_t attr;
    int status;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }
    status = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (status == 0) {
        status = pthread_mutex_init(&entry->operation_lock, &attr);
    }
    pthread_mutexattr_destroy(&attr);
    return status == 0 ? 0 : -1;
}

static void kzt_xcb_connection_entry_free(
    kzt_xcb_connection_entry_t *entry)
{
    pthread_mutex_destroy(&entry->operation_lock);
    free(entry);
}

static void kzt_xcb_connection_lease_clear(
    kzt_xcb_connection_lease_t *lease)
{
    if (lease) {
        memset(lease, 0, sizeof(*lease));
    }
}

static kzt_xcb_connection_entry_t *kzt_xcb_connection_find_guest(
    kzt_xcb_connection_map_t *map, void *guest)
{
    kzt_xcb_connection_entry_t *entry;

    for (entry = map->entries; entry; entry = entry->next) {
        if (entry->guest == guest) {
            return entry;
        }
    }
    return NULL;
}

static kzt_xcb_connection_entry_t *kzt_xcb_connection_find_native(
    kzt_xcb_connection_map_t *map, void *native)
{
    kzt_xcb_connection_entry_t *entry;

    for (entry = map->entries; entry; entry = entry->next) {
        if (entry->native == native) {
            return entry;
        }
    }
    return NULL;
}

static void kzt_xcb_connection_publish_lease(
    kzt_xcb_connection_map_t *map, kzt_xcb_connection_entry_t *entry,
    int removal, kzt_xcb_connection_lease_t *lease)
{
    lease->guest = entry->guest;
    lease->native = entry->native;
    lease->generation = entry->generation;
    lease->_map = map;
    lease->_entry = entry;
    lease->_removal = removal;
}

static int kzt_xcb_connection_has_users_or_pending(
    const kzt_xcb_connection_map_t *map)
{
    const kzt_xcb_connection_entry_t *entry;

    for (entry = map->entries; entry; entry = entry->next) {
        if (entry->users || entry->removal_pending || entry->removing) {
            return 1;
        }
    }
    return map->active_removals != 0;
}

kzt_xcb_connection_map_t *kzt_xcb_connection_map_init(
    kzt_xcb_connection_guest_destroy_fn destroy_guest, void *opaque)
{
    kzt_xcb_connection_map_t *map;

    if (!destroy_guest) {
        return NULL;
    }
    map = calloc(1, sizeof(*map));
    if (!map) {
        return NULL;
    }
    if (pthread_mutex_init(&map->lock, NULL) != 0) {
        free(map);
        return NULL;
    }
    if (pthread_cond_init(&map->changed, NULL) != 0) {
        pthread_mutex_destroy(&map->lock);
        free(map);
        return NULL;
    }
    map->destroy_guest = destroy_guest;
    map->destroy_opaque = opaque;
    map->next_generation = 1;
    return map;
}

void kzt_xcb_connection_map_destroy(kzt_xcb_connection_map_t **map_ptr)
{
    kzt_xcb_connection_map_t *map;
    kzt_xcb_connection_entry_t *entry;
    int old_cancel_state;

    if (!map_ptr || !(map = *map_ptr)) {
        return;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    map->teardown = 1;
    for (entry = map->entries; entry; entry = entry->next) {
        entry->closing = 1;
    }
    pthread_cond_broadcast(&map->changed);
    while (kzt_xcb_connection_has_users_or_pending(map)) {
        pthread_cond_wait(&map->changed, &map->lock);
    }
    entry = map->entries;
    map->entries = NULL;
    map->count = 0;
    pthread_mutex_unlock(&map->lock);

    while (entry) {
        kzt_xcb_connection_entry_t *next = entry->next;

        map->destroy_guest(entry->guest, map->destroy_opaque);
        kzt_xcb_connection_entry_free(entry);
        entry = next;
    }
    pthread_cond_destroy(&map->changed);
    pthread_mutex_destroy(&map->lock);
    free(map);
    *map_ptr = NULL;
    kzt_xcb_cancel_restore(old_cancel_state);
}

kzt_xcb_connection_map_result_t kzt_xcb_connection_map_register(
    kzt_xcb_connection_map_t *map, void *native, void *proposed_guest,
    void **canonical_guest, uint64_t *generation)
{
    kzt_xcb_connection_entry_t *entry;
    kzt_xcb_connection_entry_t *created;
    int old_cancel_state;

    if (canonical_guest) {
        *canonical_guest = NULL;
    }
    if (generation) {
        *generation = 0;
    }
    if (!map || !native || !proposed_guest || !canonical_guest ||
        !generation) {
        return KZT_XCB_CONNECTION_MAP_ERROR;
    }

    created = calloc(1, sizeof(*created));
    if (!created) {
        return KZT_XCB_CONNECTION_MAP_ERROR;
    }
    if (kzt_xcb_connection_entry_init(created) != 0) {
        free(created);
        return KZT_XCB_CONNECTION_MAP_ERROR;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    if (map->teardown) {
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_connection_entry_free(created);
        kzt_xcb_cancel_restore(old_cancel_state);
        return KZT_XCB_CONNECTION_MAP_ERROR;
    }
    entry = kzt_xcb_connection_find_native(map, native);
    if (entry) {
        if (entry->closing) {
            pthread_mutex_unlock(&map->lock);
            kzt_xcb_connection_entry_free(created);
            kzt_xcb_cancel_restore(old_cancel_state);
            return KZT_XCB_CONNECTION_MAP_ERROR;
        }
        *canonical_guest = entry->guest;
        *generation = entry->generation;
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_connection_entry_free(created);
        kzt_xcb_cancel_restore(old_cancel_state);
        return KZT_XCB_CONNECTION_MAP_UNCHANGED;
    }
    if (kzt_xcb_connection_find_guest(map, proposed_guest) ||
        map->next_generation == 0) {
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_connection_entry_free(created);
        kzt_xcb_cancel_restore(old_cancel_state);
        return KZT_XCB_CONNECTION_MAP_ERROR;
    }

    created->native = native;
    created->guest = proposed_guest;
    created->generation = map->next_generation++;
    created->next = map->entries;
    map->entries = created;
    ++map->count;
    *canonical_guest = created->guest;
    *generation = created->generation;
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_cancel_restore(old_cancel_state);
    return KZT_XCB_CONNECTION_MAP_ADDED;
}

static int kzt_xcb_connection_acquire(
    kzt_xcb_connection_map_t *map, void *key, int by_guest,
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_connection_entry_t *entry;
    int old_cancel_state;

    kzt_xcb_connection_lease_clear(lease);
    if (!map || !key || !lease) {
        return -1;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    entry = by_guest ? kzt_xcb_connection_find_guest(map, key)
                     : kzt_xcb_connection_find_native(map, key);
    if (map->teardown || !entry || entry->closing) {
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_cancel_restore(old_cancel_state);
        return -1;
    }
    ++entry->users;
    kzt_xcb_connection_publish_lease(map, entry, 0, lease);
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_cancel_restore(old_cancel_state);
    return 0;
}

int kzt_xcb_connection_map_acquire_by_guest(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease)
{
    return kzt_xcb_connection_acquire(map, guest, 1, lease);
}

int kzt_xcb_connection_map_acquire_by_native(
    kzt_xcb_connection_map_t *map, void *native,
    kzt_xcb_connection_lease_t *lease)
{
    return kzt_xcb_connection_acquire(map, native, 0, lease);
}

void kzt_xcb_connection_map_release_pair(
    kzt_xcb_connection_map_t *map, void *native, void *guest)
{
    kzt_xcb_connection_entry_t *entry;
    int old_cancel_state;

    if (!map || !native || !guest) {
        return;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    entry = kzt_xcb_connection_find_native(map, native);
    if (entry && entry->guest == guest && entry->users) {
        --entry->users;
        if (!entry->users) {
            pthread_cond_broadcast(&map->changed);
        }
    }
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_cancel_restore(old_cancel_state);
}

int kzt_xcb_connection_lease_lock_mirror(
    const kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_connection_entry_t *entry;

    if (!lease || lease->_removal || !lease->_map || !lease->_entry ||
        !lease->native || !lease->guest) {
        return -1;
    }
    entry = lease->_entry;
    return pthread_mutex_lock(&entry->operation_lock) == 0 ? 0 : -1;
}

void kzt_xcb_connection_lease_unlock_mirror(
    const kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_connection_entry_t *entry;

    if (!lease || lease->_removal || !lease->_entry) {
        return;
    }
    entry = lease->_entry;
    (void)pthread_mutex_unlock(&entry->operation_lock);
}

static int kzt_xcb_connection_map_begin_remove(
    kzt_xcb_connection_map_t *map, void *key, int by_guest,
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_connection_entry_t *entry;
    kzt_xcb_remove_wait_cleanup_t cleanup;
    int old_cancel_state;
    int wait_status = 0;

    kzt_xcb_connection_lease_clear(lease);
    if (!map || !key || !lease) {
        return -1;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    entry = by_guest ? kzt_xcb_connection_find_guest(map, key)
                     : kzt_xcb_connection_find_native(map, key);
    if (map->teardown || !entry || entry->closing) {
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_cancel_restore(old_cancel_state);
        return -1;
    }
    entry->closing = 1;
    entry->removal_pending = 1;
    cleanup = (kzt_xcb_remove_wait_cleanup_t) {
        .map = map,
        .entry = entry,
    };
    pthread_cleanup_push(kzt_xcb_remove_wait_cancel, &cleanup);
    kzt_xcb_cancel_restore(old_cancel_state);
    while (entry->users && wait_status == 0) {
        wait_status = pthread_cond_wait(&map->changed, &map->lock);
    }
    (void)kzt_xcb_cancel_disable();
    pthread_cleanup_pop(0);
    if (wait_status != 0) {
        entry->removal_pending = 0;
        if (!map->teardown) {
            entry->closing = 0;
        }
        pthread_cond_broadcast(&map->changed);
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_cancel_restore(old_cancel_state);
        return -1;
    }
    entry->removal_pending = 0;
    entry->removing = 1;
    ++map->active_removals;
    kzt_xcb_connection_publish_lease(map, entry, 1, lease);
    pthread_cond_broadcast(&map->changed);
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_cancel_restore(old_cancel_state);
    return 0;
}

int kzt_xcb_connection_map_begin_remove_by_guest(
    kzt_xcb_connection_map_t *map, void *guest,
    kzt_xcb_connection_lease_t *lease)
{
    return kzt_xcb_connection_map_begin_remove(
        map, guest, 1, lease);
}

int kzt_xcb_connection_map_begin_remove_by_native(
    kzt_xcb_connection_map_t *map, void *native,
    kzt_xcb_connection_lease_t *lease)
{
    return kzt_xcb_connection_map_begin_remove(
        map, native, 0, lease);
}

void kzt_xcb_connection_map_finish_remove(
    kzt_xcb_connection_lease_t *lease)
{
    kzt_xcb_connection_map_t *map;
    kzt_xcb_connection_entry_t *entry;
    kzt_xcb_connection_entry_t **cursor;
    int old_cancel_state;

    if (!lease || !lease->_removal || !(map = lease->_map) ||
        !(entry = lease->_entry)) {
        return;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    cursor = &map->entries;
    while (*cursor && *cursor != entry) {
        cursor = &(*cursor)->next;
    }
    if (*cursor != entry || !entry->removing) {
        pthread_mutex_unlock(&map->lock);
        kzt_xcb_cancel_restore(old_cancel_state);
        return;
    }
    *cursor = entry->next;
    --map->count;
    entry->removing = 0;
    pthread_mutex_unlock(&map->lock);

    map->destroy_guest(entry->guest, map->destroy_opaque);
    kzt_xcb_connection_entry_free(entry);

    pthread_mutex_lock(&map->lock);
    if (map->active_removals) {
        --map->active_removals;
    }
    pthread_cond_broadcast(&map->changed);
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_connection_lease_clear(lease);
    kzt_xcb_cancel_restore(old_cancel_state);
}

size_t kzt_xcb_connection_map_size(kzt_xcb_connection_map_t *map)
{
    size_t count;
    int old_cancel_state;

    if (!map) {
        return 0;
    }
    old_cancel_state = kzt_xcb_cancel_disable();
    pthread_mutex_lock(&map->lock);
    count = map->teardown ? 0 : map->count;
    pthread_mutex_unlock(&map->lock);
    kzt_xcb_cancel_restore(old_cancel_state);
    return count;
}
