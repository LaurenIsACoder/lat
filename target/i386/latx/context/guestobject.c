#include <pthread.h>
#include <stddef.h>
#include <string.h>

#include "debug.h"
#include "guestobject.h"

typedef struct guest_object_s {
    uintptr_t link_map_addr;
    uintptr_t load_bias;
    uintptr_t dynamic_addr;
    uintptr_t map_start;
    uintptr_t map_end;
    char *name;
    guest_object_state_t state;
    unsigned int observations;
    unsigned long generation;
} guest_object_t;

struct guest_object_registry_s {
    guest_object_t *objects;
    size_t size;
    size_t capacity;
    unsigned long next_generation;
    pthread_mutex_t lock;
};

/*
 * The registry is the identity layer between loader notifications and later
 * patch planning.  It is keyed by link_map address because names can be empty
 * or reused, while a live link_map entry is the stable object handle observed
 * from the guest loader.
 */
static guest_object_t *FindGuestObjectByLinkMap(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr)
{
    for (size_t i = 0; i < registry->size; ++i) {
        if (registry->objects[i].link_map_addr == link_map_addr) {
            return &registry->objects[i];
        }
    }
    return NULL;
}

static void FillGuestObjectLookup(
    const guest_object_t *object,
    guest_object_lookup_t *lookup)
{
    lookup->link_map_addr = object->link_map_addr;
    lookup->load_bias = object->load_bias;
    lookup->dynamic_addr = object->dynamic_addr;
    lookup->map_start = object->map_start;
    lookup->map_end = object->map_end;
    lookup->name = object->name;
    lookup->state = object->state;
    lookup->generation = object->generation;
}

static int GuestObjectChanged(
    const guest_object_t *object,
    uintptr_t load_bias,
    uintptr_t dynamic_addr,
    const char *name)
{
    return object->load_bias != load_bias
        || object->dynamic_addr != dynamic_addr
        || strcmp(object->name, name);
}

static int GrowGuestObjectRegistry(guest_object_registry_t *registry)
{
    if (registry->size < registry->capacity) {
        return 0;
    }

    size_t new_capacity = registry->capacity ? registry->capacity * 2 : 16;
    guest_object_t *objects = box_realloc(
        registry->objects, new_capacity * sizeof(guest_object_t));
    if (!objects) {
        return -1;
    }

    memset(objects + registry->capacity, 0,
           (new_capacity - registry->capacity) * sizeof(guest_object_t));
    registry->objects = objects;
    registry->capacity = new_capacity;
    return 0;
}

guest_object_registry_t *NewGuestObjectRegistry(void)
{
    guest_object_registry_t *registry =
        box_calloc(1, sizeof(guest_object_registry_t));
    if (!registry) {
        return NULL;
    }

    if (pthread_mutex_init(&registry->lock, NULL)) {
        box_free(registry);
        return NULL;
    }

    registry->next_generation = 1;
    return registry;
}

void FreeGuestObjectRegistry(guest_object_registry_t **registry)
{
    if (!registry || !*registry) {
        return;
    }

    guest_object_registry_t *current = *registry;
    for (size_t i = 0; i < current->size; ++i) {
        box_free(current->objects[i].name);
    }
    box_free(current->objects);
    pthread_mutex_destroy(&current->lock);
    box_free(current);
    *registry = NULL;
}

guest_object_observation_t ObserveGuestObject(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t load_bias,
    uintptr_t dynamic_addr,
    const char *name)
{
    if (!registry || !link_map_addr) {
        return GUEST_OBJECT_OBSERVE_INVALID;
    }

    const char *object_name = name ? name : "";
    pthread_mutex_lock(&registry->lock);

    guest_object_t *object = FindGuestObjectByLinkMap(registry, link_map_addr);
    if (object) {
        ++object->observations;
        if (!GuestObjectChanged(object, load_bias, dynamic_addr, object_name)) {
            pthread_mutex_unlock(&registry->lock);
            return GUEST_OBJECT_OBSERVE_UNCHANGED;
        }

        char *new_name = box_strdup(object_name);
        if (!new_name) {
            pthread_mutex_unlock(&registry->lock);
            return GUEST_OBJECT_OBSERVE_INVALID;
        }

        box_free(object->name);
        object->name = new_name;
        object->load_bias = load_bias;
        object->dynamic_addr = dynamic_addr;
        object->map_start = 0;
        object->map_end = 0;
        object->state = GUEST_OBJECT_DISCOVERED;
        object->generation = registry->next_generation++;
        pthread_mutex_unlock(&registry->lock);
        return GUEST_OBJECT_OBSERVE_CHANGED;
    }

    if (GrowGuestObjectRegistry(registry)) {
        pthread_mutex_unlock(&registry->lock);
        return GUEST_OBJECT_OBSERVE_INVALID;
    }

    char *new_name = box_strdup(object_name);
    if (!new_name) {
        pthread_mutex_unlock(&registry->lock);
        return GUEST_OBJECT_OBSERVE_INVALID;
    }

    object = &registry->objects[registry->size++];
    object->link_map_addr = link_map_addr;
    object->load_bias = load_bias;
    object->dynamic_addr = dynamic_addr;
    object->name = new_name;
    object->state = GUEST_OBJECT_DISCOVERED;
    object->observations = 1;
    object->generation = registry->next_generation++;
    pthread_mutex_unlock(&registry->lock);
    return GUEST_OBJECT_OBSERVE_NEW;
}

/*
 * Address lookup is intentionally range based.  Later GOT patch decisions see
 * only the current guest address stored in a slot, so they need a way to map
 * that address back to the guest object chosen by the guest loader.
 */
int SetGuestObjectMapRange(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t map_start,
    uintptr_t map_end)
{
    if (!registry || !link_map_addr || map_start >= map_end) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    guest_object_t *object = FindGuestObjectByLinkMap(registry, link_map_addr);
    if (!object) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    object->map_start = map_start;
    object->map_end = map_end;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int LookupGuestObjectByAddress(
    guest_object_registry_t *registry,
    uintptr_t addr,
    guest_object_lookup_t *lookup)
{
    if (!registry || !addr || !lookup) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    for (size_t i = 0; i < registry->size; ++i) {
        const guest_object_t *object = &registry->objects[i];
        if (object->map_start && addr >= object->map_start
            && addr < object->map_end) {
            FillGuestObjectLookup(object, lookup);
            pthread_mutex_unlock(&registry->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&registry->lock);
    return -1;
}

guest_object_process_result_t BeginGuestObjectProcessing(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr)
{
    if (!registry || !link_map_addr) {
        return GUEST_OBJECT_PROCESS_INVALID;
    }

    pthread_mutex_lock(&registry->lock);
    guest_object_t *object = FindGuestObjectByLinkMap(registry, link_map_addr);
    if (!object) {
        pthread_mutex_unlock(&registry->lock);
        return GUEST_OBJECT_PROCESS_INVALID;
    }

    guest_object_process_result_t result;
    switch (object->state) {
        case GUEST_OBJECT_DISCOVERED:
        case GUEST_OBJECT_FAILED:
            object->state = GUEST_OBJECT_PROCESSING;
            result = GUEST_OBJECT_PROCESS_STARTED;
            break;
        case GUEST_OBJECT_PROCESSING:
            result = GUEST_OBJECT_PROCESS_IN_PROGRESS;
            break;
        case GUEST_OBJECT_WRAPPED:
        case GUEST_OBJECT_EMULATED:
            result = GUEST_OBJECT_PROCESS_DONE;
            break;
        default:
            result = GUEST_OBJECT_PROCESS_INVALID;
            break;
    }

    pthread_mutex_unlock(&registry->lock);
    return result;
}

int SetGuestObjectState(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    guest_object_state_t state)
{
    if (!registry || !link_map_addr) {
        return -1;
    }

    pthread_mutex_lock(&registry->lock);
    guest_object_t *object = FindGuestObjectByLinkMap(registry, link_map_addr);
    if (!object) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    object->state = state;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

const char *GuestObjectStateName(guest_object_state_t state)
{
    switch (state) {
        case GUEST_OBJECT_DISCOVERED:
            return "discovered";
        case GUEST_OBJECT_PROCESSING:
            return "processing";
        case GUEST_OBJECT_WRAPPED:
            return "wrapped";
        case GUEST_OBJECT_EMULATED:
            return "emulated";
        case GUEST_OBJECT_FAILED:
            return "failed";
    }
    return "unknown";
}
