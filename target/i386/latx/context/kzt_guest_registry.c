#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "kzt_guest_registry.h"

#define KZT_GUEST_REGISTRY_INITIAL_CAPACITY 8

struct kzt_guest_registry {
    pthread_mutex_t lock;
    int lock_ready;
    int disabled;
    kzt_guest_object_snapshot_t *objects;
    size_t count;
    size_t capacity;
    unsigned long next_generation;
    kzt_guest_registry_diagnostics_t diagnostics;
    kzt_guest_registry_diagnostic_config_t diagnostic_config;
    kzt_guest_registry_event_summary_t diagnostic_events[
        KZT_GUEST_REGISTRY_RESULT_COUNT];
};

#ifdef KZT_GUEST_REGISTRY_TEST
static long test_alloc_failure_after = -1;

void kzt_guest_registry_test_set_alloc_failure_after(long allocations)
{
    test_alloc_failure_after = allocations;
}
#endif

static void *kzt_registry_calloc(size_t count, size_t size)
{
#ifdef KZT_GUEST_REGISTRY_TEST
    if (test_alloc_failure_after == 0) {
        return NULL;
    }
    if (test_alloc_failure_after > 0) {
        --test_alloc_failure_after;
    }
#endif
    return calloc(count, size);
}

static void kzt_registry_free(void *ptr)
{
    free(ptr);
}

static char *kzt_registry_strdup(const char *value)
{
    size_t len;
    char *copy;

    if (!value) {
        value = "";
    }

    len = strlen(value);
    copy = kzt_registry_calloc(len + 1, 1);
    if (!copy) {
        return NULL;
    }

    memcpy(copy, value, len);
    return copy;
}

static int kzt_field_is_reliable(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK;
}

static int kzt_string_status_has_snapshot(kzt_guest_field_status_t status)
{
    return status == KZT_GUEST_FIELD_OK ||
           status == KZT_GUEST_FIELD_TRUNCATED;
}

static void kzt_free_string_field(kzt_guest_string_field_t *field)
{
    if (!field) {
        return;
    }

    kzt_registry_free((void *)field->value);
    field->value = NULL;
}

static int kzt_copy_string_field(kzt_guest_string_field_t *dst,
                                 const kzt_guest_string_field_t *src)
{
    dst->status = src->status;
    dst->value = NULL;

    if (!kzt_string_status_has_snapshot(src->status)) {
        return 0;
    }

    dst->value = kzt_registry_strdup(src->value);
    return dst->value ? 0 : -1;
}

static int kzt_dynamic_field_equal(
    const kzt_guest_dynamic_field_t *left,
    const kzt_guest_dynamic_field_t *right)
{
    return left->present == right->present &&
           left->value == right->value &&
           left->address_semantics == right->address_semantics;
}

static int kzt_dynamic_needed_equal(
    const kzt_guest_dynamic_view_t *left,
    const kzt_guest_dynamic_view_t *right)
{
    size_t i;

    if (left->needed_count != right->needed_count) {
        return 0;
    }

    if (left->needed_count > 0 &&
        left->needed_address_semantics != right->needed_address_semantics) {
        return 0;
    }

    for (i = 0; i < left->needed_count; ++i) {
        if (left->needed_offsets[i] != right->needed_offsets[i]) {
            return 0;
        }
    }

    return 1;
}

static int kzt_dynamic_view_equal(
    const kzt_guest_dynamic_view_t *left,
    const kzt_guest_dynamic_view_t *right)
{
    return left->dynamic_addr == right->dynamic_addr &&
           left->load_bias == right->load_bias &&
           left->status == right->status &&
           left->entry_count == right->entry_count &&
           left->has_null == right->has_null &&
           left->scan_limit == right->scan_limit &&
           left->unknown_tag_count == right->unknown_tag_count &&
           left->first_unknown_tag == right->first_unknown_tag &&
           left->first_unknown_tag_index == right->first_unknown_tag_index &&
           kzt_dynamic_field_equal(&left->symtab, &right->symtab) &&
           kzt_dynamic_field_equal(&left->strtab, &right->strtab) &&
           kzt_dynamic_field_equal(&left->syment, &right->syment) &&
           kzt_dynamic_field_equal(&left->strsz, &right->strsz) &&
           kzt_dynamic_field_equal(&left->hash, &right->hash) &&
           kzt_dynamic_field_equal(&left->gnu_hash, &right->gnu_hash) &&
           kzt_dynamic_field_equal(&left->versym, &right->versym) &&
           kzt_dynamic_field_equal(&left->verneed, &right->verneed) &&
           kzt_dynamic_field_equal(&left->verneednum, &right->verneednum) &&
           kzt_dynamic_field_equal(&left->verdef, &right->verdef) &&
           kzt_dynamic_field_equal(&left->verdefnum, &right->verdefnum) &&
           kzt_dynamic_field_equal(&left->rela, &right->rela) &&
           kzt_dynamic_field_equal(&left->relasz, &right->relasz) &&
           kzt_dynamic_field_equal(&left->relaent, &right->relaent) &&
           kzt_dynamic_field_equal(&left->rel, &right->rel) &&
           kzt_dynamic_field_equal(&left->relsz, &right->relsz) &&
           kzt_dynamic_field_equal(&left->relent, &right->relent) &&
           kzt_dynamic_field_equal(&left->jmprel, &right->jmprel) &&
           kzt_dynamic_field_equal(&left->pltrelsz, &right->pltrelsz) &&
           kzt_dynamic_field_equal(&left->pltrel, &right->pltrel) &&
           kzt_dynamic_field_equal(&left->pltgot, &right->pltgot) &&
           kzt_dynamic_needed_equal(left, right);
}

static kzt_guest_field_status_t kzt_dynamic_view_field_status(
    const kzt_guest_dynamic_view_t *view)
{
    switch (view->status) {
    case KZT_GUEST_DYNAMIC_COMPLETE:
        return KZT_GUEST_FIELD_OK;
    case KZT_GUEST_DYNAMIC_TRUNCATED_NO_NULL:
        return KZT_GUEST_FIELD_TRUNCATED;
    case KZT_GUEST_DYNAMIC_READ_ERROR:
        return KZT_GUEST_FIELD_READ_ERROR;
    case KZT_GUEST_DYNAMIC_ERROR:
        return KZT_GUEST_FIELD_READ_ERROR;
    }

    return KZT_GUEST_FIELD_UNKNOWN;
}

static void kzt_free_snapshot_strings(kzt_guest_object_snapshot_t *snapshot)
{
    if (!snapshot) {
        return;
    }

    kzt_free_string_field(&snapshot->path);
    kzt_free_string_field(&snapshot->soname);
    memset(&snapshot->dynamic_view, 0, sizeof(snapshot->dynamic_view));
}

static void kzt_free_snapshot_array(kzt_guest_object_snapshot_t *objects,
                                    size_t count)
{
    size_t i;

    if (!objects) {
        return;
    }

    for (i = 0; i < count; ++i) {
        kzt_free_snapshot_strings(&objects[i]);
    }
    kzt_registry_free(objects);
}

static int kzt_copy_snapshot(kzt_guest_object_snapshot_t *dst,
                             const kzt_guest_object_snapshot_t *src)
{
    *dst = *src;
    dst->path.value = NULL;
    dst->soname.value = NULL;

    if (kzt_copy_string_field(&dst->path, &src->path) != 0) {
        return -1;
    }
    if (kzt_copy_string_field(&dst->soname, &src->soname) != 0) {
        kzt_free_string_field(&dst->path);
        return -1;
    }

    return 0;
}

static int kzt_snapshot_from_observation(
    kzt_guest_object_snapshot_t *snapshot,
    const kzt_guest_object_observation_t *observation,
    unsigned long generation)
{
    memset(snapshot, 0, sizeof(*snapshot));

    snapshot->link_map_addr = observation->link_map_addr;
    snapshot->load_bias = observation->load_bias;
    snapshot->dynamic_addr = observation->dynamic_addr;
    snapshot->map_start = observation->map_start;
    snapshot->map_end = observation->map_end;
    snapshot->namespace_id = observation->namespace_id;
    snapshot->dynamic_view_status = observation->dynamic_view_status;
    snapshot->state = KZT_GUEST_OBJECT_DISCOVERED;
    snapshot->generation = generation;

    if (kzt_copy_string_field(&snapshot->path, &observation->path) != 0) {
        return -1;
    }
    if (kzt_copy_string_field(&snapshot->soname, &observation->soname) != 0) {
        kzt_free_string_field(&snapshot->path);
        return -1;
    }

    return 0;
}

static int kzt_scalar_conflicts(const kzt_guest_scalar_field_t *current,
                                const kzt_guest_scalar_field_t *incoming)
{
    return kzt_field_is_reliable(current->status) &&
           kzt_field_is_reliable(incoming->status) &&
           current->value != incoming->value;
}

static int kzt_string_conflicts(const kzt_guest_string_field_t *current,
                                const kzt_guest_string_field_t *incoming)
{
    const char *left;
    const char *right;

    if (!kzt_field_is_reliable(current->status) ||
        !kzt_field_is_reliable(incoming->status)) {
        return 0;
    }

    left = current->value ? current->value : "";
    right = incoming->value ? incoming->value : "";
    return strcmp(left, right) != 0;
}

static int kzt_update_scalar_field(kzt_guest_scalar_field_t *current,
                                   const kzt_guest_scalar_field_t *incoming)
{
    if (kzt_field_is_reliable(current->status) ||
        !kzt_field_is_reliable(incoming->status)) {
        return 0;
    }

    *current = *incoming;
    return 1;
}

static int kzt_update_string_field(kzt_guest_string_field_t *current,
                                   const kzt_guest_string_field_t *incoming)
{
    char *copy;

    if (kzt_field_is_reliable(current->status) ||
        !kzt_field_is_reliable(incoming->status)) {
        return 0;
    }

    copy = kzt_registry_strdup(incoming->value);
    if (!copy) {
        return -1;
    }

    kzt_free_string_field(current);
    current->value = copy;
    current->status = incoming->status;
    return 1;
}

static int kzt_update_status_field(kzt_guest_field_status_t *current,
                                   kzt_guest_field_status_t incoming)
{
    if (kzt_field_is_reliable(*current) ||
        !kzt_field_is_reliable(incoming)) {
        return 0;
    }

    *current = incoming;
    return 1;
}

static int kzt_observation_conflicts(
    const kzt_guest_object_snapshot_t *current,
    const kzt_guest_object_observation_t *incoming)
{
    return kzt_scalar_conflicts(&current->load_bias,
                                &incoming->load_bias) ||
           kzt_scalar_conflicts(&current->dynamic_addr,
                                &incoming->dynamic_addr) ||
           kzt_scalar_conflicts(&current->map_start,
                                &incoming->map_start) ||
           kzt_scalar_conflicts(&current->map_end,
                                &incoming->map_end) ||
           kzt_scalar_conflicts(&current->namespace_id,
                                &incoming->namespace_id) ||
           kzt_string_conflicts(&current->path, &incoming->path) ||
           kzt_string_conflicts(&current->soname, &incoming->soname);
}

static int kzt_update_snapshot(kzt_guest_object_snapshot_t *current,
                               const kzt_guest_object_observation_t *incoming,
                               int *updated)
{
    int ret;

    *updated |= kzt_update_scalar_field(&current->load_bias,
                                        &incoming->load_bias);
    *updated |= kzt_update_scalar_field(&current->dynamic_addr,
                                        &incoming->dynamic_addr);
    *updated |= kzt_update_scalar_field(&current->map_start,
                                        &incoming->map_start);
    *updated |= kzt_update_scalar_field(&current->map_end,
                                        &incoming->map_end);
    *updated |= kzt_update_scalar_field(&current->namespace_id,
                                        &incoming->namespace_id);

    ret = kzt_update_string_field(&current->path, &incoming->path);
    if (ret < 0) {
        return -1;
    }
    *updated |= ret;

    ret = kzt_update_string_field(&current->soname, &incoming->soname);
    if (ret < 0) {
        return -1;
    }
    *updated |= ret;

    *updated |= kzt_update_status_field(&current->dynamic_view_status,
                                        incoming->dynamic_view_status);
    return 0;
}

static ssize_t kzt_find_object_index(kzt_guest_registry_t *registry,
                                     uintptr_t link_map_addr)
{
    size_t i;

    for (i = 0; i < registry->count; ++i) {
        if (registry->objects[i].link_map_addr == link_map_addr) {
            return (ssize_t)i;
        }
    }

    return -1;
}

static int kzt_registry_ensure_capacity(kzt_guest_registry_t *registry)
{
    kzt_guest_object_snapshot_t *objects;
    size_t new_capacity;

    if (registry->count < registry->capacity) {
        return 0;
    }

    new_capacity = registry->capacity ?
        registry->capacity * 2 : KZT_GUEST_REGISTRY_INITIAL_CAPACITY;
    objects = kzt_registry_calloc(new_capacity, sizeof(*objects));
    if (!objects) {
        ++registry->diagnostics.allocation_failures;
        return -1;
    }

    if (registry->objects) {
        memcpy(objects, registry->objects,
               registry->count * sizeof(*registry->objects));
        kzt_registry_free(registry->objects);
    }

    registry->objects = objects;
    registry->capacity = new_capacity;
    return 0;
}

static const char *kzt_registry_result_name(kzt_guest_registry_result_t result)
{
    switch (result) {
    case KZT_GUEST_REGISTRY_ADDED:
        return "added";
    case KZT_GUEST_REGISTRY_UNCHANGED:
        return "unchanged";
    case KZT_GUEST_REGISTRY_UPDATED:
        return "updated";
    case KZT_GUEST_REGISTRY_CONFLICT:
        return "conflict";
    case KZT_GUEST_REGISTRY_DISABLED:
        return "disabled";
    case KZT_GUEST_REGISTRY_ERROR:
        return "error";
    case KZT_GUEST_REGISTRY_RESULT_COUNT:
        break;
    }

    return "unknown";
}

static const char *kzt_guest_field_status_name(
    kzt_guest_field_status_t status)
{
    switch (status) {
    case KZT_GUEST_FIELD_OK:
        return "ok";
    case KZT_GUEST_FIELD_UNKNOWN:
        return "unknown";
    case KZT_GUEST_FIELD_READ_ERROR:
        return "read_error";
    case KZT_GUEST_FIELD_TRUNCATED:
        return "truncated";
    case KZT_GUEST_FIELD_NOT_PARSED:
        return "not_parsed";
    }

    return "invalid";
}

static void kzt_registry_note_counter(kzt_guest_registry_t *registry,
                                      kzt_guest_registry_result_t result)
{
    switch (result) {
    case KZT_GUEST_REGISTRY_ADDED:
        ++registry->diagnostics.added;
        break;
    case KZT_GUEST_REGISTRY_UNCHANGED:
        ++registry->diagnostics.unchanged;
        break;
    case KZT_GUEST_REGISTRY_UPDATED:
        ++registry->diagnostics.updated;
        break;
    case KZT_GUEST_REGISTRY_CONFLICT:
        ++registry->diagnostics.conflicts;
        break;
    case KZT_GUEST_REGISTRY_DISABLED:
        ++registry->diagnostics.disabled;
        break;
    case KZT_GUEST_REGISTRY_ERROR:
        ++registry->diagnostics.errors;
        break;
    case KZT_GUEST_REGISTRY_RESULT_COUNT:
        break;
    }
}

static void kzt_registry_init_empty_diagnostic(
    kzt_guest_registry_observation_diagnostic_t *diagnostic,
    kzt_guest_registry_result_t result,
    uintptr_t link_map_addr)
{
    if (!diagnostic) {
        return;
    }

    memset(diagnostic, 0, sizeof(*diagnostic));
    diagnostic->result = result;
    diagnostic->link_map_addr = link_map_addr;
}

static void kzt_registry_note_result(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_result_t result,
    uintptr_t link_map_addr,
    unsigned long generation,
    kzt_guest_registry_observation_diagnostic_t *diagnostic)
{
    kzt_guest_registry_event_summary_t *event = NULL;
    int emitted = 0;

    kzt_registry_note_counter(registry, result);

    if (registry->diagnostic_config.enabled &&
        result < KZT_GUEST_REGISTRY_RESULT_COUNT) {
        event = &registry->diagnostic_events[result];
        event->result = result;
        ++event->observed;
        event->last_link_map_addr = link_map_addr;
        event->last_generation = generation;
        if (event->emitted < registry->diagnostic_config.throttle_limit) {
            ++event->emitted;
            emitted = 1;
        } else {
            ++event->suppressed;
        }
    }

    if (!diagnostic) {
        return;
    }

    memset(diagnostic, 0, sizeof(*diagnostic));
    diagnostic->enabled = registry->diagnostic_config.enabled;
    diagnostic->emitted = emitted;
    diagnostic->result = result;
    diagnostic->link_map_addr = link_map_addr;
    diagnostic->generation = generation;
    diagnostic->object_count = registry->count;
    diagnostic->counters = registry->diagnostics;
    if (event) {
        diagnostic->result_observations = event->observed;
        diagnostic->result_suppressed = event->suppressed;
    }
}

kzt_guest_registry_t *kzt_guest_registry_init(void)
{
    kzt_guest_registry_t *registry;

    registry = kzt_registry_calloc(1, sizeof(*registry));
    if (!registry) {
        return NULL;
    }

    if (pthread_mutex_init(&registry->lock, NULL) != 0) {
        kzt_registry_free(registry);
        return NULL;
    }

    registry->lock_ready = 1;
    registry->next_generation = 1;
    registry->capacity = KZT_GUEST_REGISTRY_INITIAL_CAPACITY;
    registry->objects = kzt_registry_calloc(registry->capacity,
                                            sizeof(*registry->objects));
    if (!registry->objects) {
        registry->capacity = 0;
        registry->disabled = 1;
        ++registry->diagnostics.init_failures;
        ++registry->diagnostics.allocation_failures;
    }

    return registry;
}

void kzt_guest_registry_destroy(kzt_guest_registry_t **registry_ptr)
{
    kzt_guest_registry_t *registry;

    if (!registry_ptr || !*registry_ptr) {
        return;
    }

    registry = *registry_ptr;
    *registry_ptr = NULL;

    if (registry->lock_ready) {
        pthread_mutex_lock(&registry->lock);
        registry->disabled = 1;
        pthread_mutex_unlock(&registry->lock);
    }

    kzt_free_snapshot_array(registry->objects, registry->count);
    registry->objects = NULL;
    registry->count = 0;
    registry->capacity = 0;

    if (registry->lock_ready) {
        pthread_mutex_destroy(&registry->lock);
    }

    kzt_registry_free(registry);
}

kzt_guest_registry_result_t kzt_guest_registry_observe(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *observation)
{
    return kzt_guest_registry_observe_with_diagnostic(registry, observation,
                                                      NULL);
}

kzt_guest_registry_result_t kzt_guest_registry_observe_with_diagnostic(
    kzt_guest_registry_t *registry,
    const kzt_guest_object_observation_t *observation,
    kzt_guest_registry_observation_diagnostic_t *diagnostic)
{
    kzt_guest_registry_result_t result;
    ssize_t index;
    int updated = 0;
    uintptr_t link_map_addr = observation ? observation->link_map_addr : 0;
    unsigned long generation = 0;

    if (!registry) {
        kzt_registry_init_empty_diagnostic(diagnostic,
                                           KZT_GUEST_REGISTRY_DISABLED,
                                           link_map_addr);
        return KZT_GUEST_REGISTRY_DISABLED;
    }

    pthread_mutex_lock(&registry->lock);
    ++registry->diagnostics.observations;

    if (registry->disabled) {
        result = KZT_GUEST_REGISTRY_DISABLED;
        goto out;
    }

    if (!observation || observation->link_map_addr == 0) {
        result = KZT_GUEST_REGISTRY_ERROR;
        goto out;
    }

    index = kzt_find_object_index(registry, observation->link_map_addr);
    if (index < 0) {
        if (kzt_registry_ensure_capacity(registry) != 0) {
            result = KZT_GUEST_REGISTRY_ERROR;
            goto out;
        }
        generation = registry->next_generation;
        if (kzt_snapshot_from_observation(&registry->objects[registry->count],
                                          observation, generation) != 0) {
            ++registry->diagnostics.allocation_failures;
            result = KZT_GUEST_REGISTRY_ERROR;
            goto out;
        }
        ++registry->next_generation;
        ++registry->count;
        result = KZT_GUEST_REGISTRY_ADDED;
        goto out;
    }

    generation = registry->objects[index].generation;
    if (kzt_observation_conflicts(&registry->objects[index], observation)) {
        result = KZT_GUEST_REGISTRY_CONFLICT;
        goto out;
    }

    if (kzt_update_snapshot(&registry->objects[index], observation,
                            &updated) != 0) {
        ++registry->diagnostics.allocation_failures;
        result = KZT_GUEST_REGISTRY_ERROR;
        goto out;
    }

    result = updated ? KZT_GUEST_REGISTRY_UPDATED :
                       KZT_GUEST_REGISTRY_UNCHANGED;

out:
    kzt_registry_note_result(registry, result, link_map_addr, generation,
                             diagnostic);
    pthread_mutex_unlock(&registry->lock);
    return result;
}

int kzt_guest_registry_find_by_link_map(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_object_snapshot_t **snapshot)
{
    ssize_t index;

    if (snapshot) {
        *snapshot = NULL;
    }
    if (!registry || !snapshot || link_map_addr == 0) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    if (registry->disabled) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    index = kzt_find_object_index(registry, link_map_addr);
    if (index < 0) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    *snapshot = kzt_registry_calloc(1, sizeof(**snapshot));
    if (!*snapshot) {
        ++registry->diagnostics.allocation_failures;
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    if (kzt_copy_snapshot(*snapshot, &registry->objects[index]) != 0) {
        ++registry->diagnostics.allocation_failures;
        kzt_registry_free(*snapshot);
        *snapshot = NULL;
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    pthread_mutex_unlock(&registry->lock);
    return 0;
}

kzt_guest_registry_result_t kzt_guest_registry_commit_dynamic_view(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    const kzt_guest_dynamic_view_t *view)
{
    kzt_guest_object_snapshot_t *object;
    kzt_guest_field_status_t status;
    kzt_guest_registry_result_t result;
    ssize_t index;

    if (!registry) {
        return KZT_GUEST_REGISTRY_DISABLED;
    }

    if (!view || link_map_addr == 0) {
        return KZT_GUEST_REGISTRY_ERROR;
    }

    pthread_mutex_lock(&registry->lock);
    if (registry->disabled) {
        result = KZT_GUEST_REGISTRY_DISABLED;
        goto out;
    }

    index = kzt_find_object_index(registry, link_map_addr);
    if (index < 0) {
        result = KZT_GUEST_REGISTRY_ERROR;
        goto out;
    }

    object = &registry->objects[index];
    status = kzt_dynamic_view_field_status(view);
    if (object->dynamic_view_status == status &&
        kzt_dynamic_view_equal(&object->dynamic_view, view)) {
        result = KZT_GUEST_REGISTRY_UNCHANGED;
        goto out;
    }

    object->dynamic_view = *view;
    object->dynamic_view_status = status;
    if (status == KZT_GUEST_FIELD_OK) {
        object->state = KZT_GUEST_OBJECT_PARSED;
    } else if (object->state == KZT_GUEST_OBJECT_PARSED) {
        object->state = KZT_GUEST_OBJECT_DISCOVERED;
    }
    result = KZT_GUEST_REGISTRY_UPDATED;

out:
    pthread_mutex_unlock(&registry->lock);
    return result;
}

int kzt_guest_registry_find_dynamic_view(
    kzt_guest_registry_t *registry,
    uintptr_t link_map_addr,
    kzt_guest_dynamic_view_t *view,
    kzt_guest_field_status_t *status,
    unsigned long *generation)
{
    ssize_t index;

    if (view) {
        memset(view, 0, sizeof(*view));
    }
    if (status) {
        *status = KZT_GUEST_FIELD_NOT_PARSED;
    }
    if (generation) {
        *generation = 0;
    }
    if (!registry || !view || link_map_addr == 0) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    if (registry->disabled) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    index = kzt_find_object_index(registry, link_map_addr);
    if (index < 0) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    *view = registry->objects[index].dynamic_view;
    if (status) {
        *status = registry->objects[index].dynamic_view_status;
    }
    if (generation) {
        *generation = registry->objects[index].generation;
    }

    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int kzt_guest_registry_dump_snapshot(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_dump_t *dump)
{
    size_t i;

    if (dump) {
        dump->objects = NULL;
        dump->count = 0;
    }
    if (!registry || !dump) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    if (registry->disabled) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    if (registry->count == 0) {
        pthread_mutex_unlock(&registry->lock);
        return 0;
    }

    dump->objects = kzt_registry_calloc(registry->count,
                                        sizeof(*dump->objects));
    if (!dump->objects) {
        ++registry->diagnostics.allocation_failures;
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    for (i = 0; i < registry->count; ++i) {
        if (kzt_copy_snapshot(&dump->objects[i], &registry->objects[i]) != 0) {
            ++registry->diagnostics.allocation_failures;
            kzt_free_snapshot_array(dump->objects, i + 1);
            dump->objects = NULL;
            dump->count = 0;
            pthread_mutex_unlock(&registry->lock);
            return -1;
        }
    }
    dump->count = registry->count;

    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int kzt_guest_registry_get_diagnostics(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_diagnostics_t *diagnostics)
{
    if (!registry || !diagnostics) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    *diagnostics = registry->diagnostics;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int kzt_guest_registry_configure_diagnostics(
    kzt_guest_registry_t *registry,
    const kzt_guest_registry_diagnostic_config_t *config)
{
    if (!registry || !config) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    registry->diagnostic_config.enabled = !!config->enabled;
    registry->diagnostic_config.throttle_limit =
        config->throttle_limit ? config->throttle_limit : 1;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int kzt_guest_registry_get_diagnostic_report(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_diagnostic_report_t *report)
{
    if (!registry || !report) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    memset(report, 0, sizeof(*report));
    report->config = registry->diagnostic_config;
    report->counters = registry->diagnostics;
    memcpy(report->events, registry->diagnostic_events,
           sizeof(report->events));
    report->event_count = KZT_GUEST_REGISTRY_RESULT_COUNT;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int kzt_guest_registry_note_diagnostic(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_result_t result,
    uintptr_t link_map_addr,
    kzt_guest_registry_observation_diagnostic_t *diagnostic)
{
    if (!registry || result >= KZT_GUEST_REGISTRY_RESULT_COUNT) {
        kzt_registry_init_empty_diagnostic(diagnostic, result, link_map_addr);
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    kzt_registry_note_result(registry, result, link_map_addr, 0, diagnostic);
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

static int kzt_guest_registry_dump_emit(
    kzt_guest_registry_dump_sink_fn sink,
    void *opaque,
    const char *fmt,
    ...)
{
    char line[1024];
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (len < 0) {
        return -1;
    }

    line[sizeof(line) - 1] = '\0';
    return sink(line, opaque);
}

static int kzt_guest_registry_dump_emit_scalar(
    kzt_guest_registry_dump_sink_fn sink,
    void *opaque,
    const char *name,
    kzt_guest_scalar_field_t field)
{
    return kzt_guest_registry_dump_emit(
        sink, opaque, "%s=0x%lx(%s)", name, (unsigned long)field.value,
        kzt_guest_field_status_name(field.status));
}

int kzt_guest_registry_dump_text(
    kzt_guest_registry_t *registry,
    kzt_guest_registry_dump_sink_fn sink,
    void *opaque)
{
    kzt_guest_registry_diagnostic_report_t report;
    kzt_guest_registry_dump_t dump = { 0 };
    size_t i;
    int ret = -1;

    if (!registry || !sink) {
        return -1;
    }

    if (kzt_guest_registry_get_diagnostic_report(registry, &report) != 0) {
        return -1;
    }
    if (kzt_guest_registry_dump_snapshot(registry, &dump) != 0) {
        return -1;
    }

    if (kzt_guest_registry_dump_emit(
            sink, opaque,
            "kzt_guest_registry diagnostics enabled=%d throttle_limit=%lu "
            "observations=%lu added=%lu unchanged=%lu updated=%lu "
            "conflicts=%lu disabled=%lu errors=%lu init_failures=%lu "
            "allocation_failures=%lu objects=%lu",
            report.config.enabled, report.config.throttle_limit,
            report.counters.observations, report.counters.added,
            report.counters.unchanged, report.counters.updated,
            report.counters.conflicts, report.counters.disabled,
            report.counters.errors, report.counters.init_failures,
            report.counters.allocation_failures,
            (unsigned long)dump.count) != 0) {
        goto out;
    }

    for (i = 0; i < report.event_count; ++i) {
        const kzt_guest_registry_event_summary_t *event = &report.events[i];

        if (event->observed == 0) {
            continue;
        }
        if (kzt_guest_registry_dump_emit(
                sink, opaque,
                "kzt_guest_registry event result=%s observed=%lu "
                "emitted=%lu suppressed=%lu last_link_map=0x%lx "
                "last_generation=%lu",
                kzt_registry_result_name(event->result), event->observed,
                event->emitted, event->suppressed,
                (unsigned long)event->last_link_map_addr,
                event->last_generation) != 0) {
            goto out;
        }
    }

    for (i = 0; i < dump.count; ++i) {
        const kzt_guest_object_snapshot_t *object = &dump.objects[i];

        if (kzt_guest_registry_dump_emit(
                sink, opaque,
                "kzt_guest_registry object link_map=0x%lx generation=%lu "
                "state=%d ",
                (unsigned long)object->link_map_addr, object->generation,
                object->state) != 0 ||
            kzt_guest_registry_dump_emit_scalar(sink, opaque, "load_bias",
                                                object->load_bias) != 0 ||
            kzt_guest_registry_dump_emit_scalar(sink, opaque, " dynamic_addr",
                                                object->dynamic_addr) != 0 ||
            kzt_guest_registry_dump_emit_scalar(sink, opaque, " map_start",
                                                object->map_start) != 0 ||
            kzt_guest_registry_dump_emit_scalar(sink, opaque, " map_end",
                                                object->map_end) != 0 ||
            kzt_guest_registry_dump_emit(
                sink, opaque,
                " namespace_id=0x%lx(%s) dynamic_view=%s path_status=%s "
                "path=\"%s\" soname_status=%s soname=\"%s\"",
                (unsigned long)object->namespace_id.value,
                kzt_guest_field_status_name(object->namespace_id.status),
                kzt_guest_field_status_name(object->dynamic_view_status),
                kzt_guest_field_status_name(object->path.status),
                object->path.value ? object->path.value : "",
                kzt_guest_field_status_name(object->soname.status),
                object->soname.value ? object->soname.value : "") != 0) {
            goto out;
        }
    }

    ret = 0;

out:
    kzt_guest_registry_dump_free(&dump);
    return ret;
}

void kzt_guest_object_snapshot_free(kzt_guest_object_snapshot_t *snapshot)
{
    if (!snapshot) {
        return;
    }

    kzt_free_snapshot_strings(snapshot);
    kzt_registry_free(snapshot);
}

void kzt_guest_registry_dump_free(kzt_guest_registry_dump_t *dump)
{
    if (!dump) {
        return;
    }

    kzt_free_snapshot_array(dump->objects, dump->count);
    dump->objects = NULL;
    dump->count = 0;
}
