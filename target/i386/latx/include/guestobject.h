#ifndef __GUESTOBJECT_H_
#define __GUESTOBJECT_H_

#include <stdint.h>

typedef struct guest_object_registry_s guest_object_registry_t;

typedef enum guest_object_state_e {
    GUEST_OBJECT_DISCOVERED = 0,
    GUEST_OBJECT_PROCESSING,
    GUEST_OBJECT_WRAPPED,
    GUEST_OBJECT_EMULATED,
    GUEST_OBJECT_FAILED,
} guest_object_state_t;

typedef enum guest_object_observation_e {
    GUEST_OBJECT_OBSERVE_INVALID = -1,
    GUEST_OBJECT_OBSERVE_UNCHANGED = 0,
    GUEST_OBJECT_OBSERVE_NEW,
    GUEST_OBJECT_OBSERVE_CHANGED,
} guest_object_observation_t;

typedef enum guest_object_process_result_e {
    GUEST_OBJECT_PROCESS_INVALID = -1,
    GUEST_OBJECT_PROCESS_STARTED = 0,
    GUEST_OBJECT_PROCESS_IN_PROGRESS,
} guest_object_process_result_t;

guest_object_registry_t *NewGuestObjectRegistry(void);
void FreeGuestObjectRegistry(guest_object_registry_t **registry);

guest_object_observation_t ObserveGuestObject(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t load_bias,
    uintptr_t dynamic_addr,
    const char *name);

int SetGuestObjectMapRange(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    uintptr_t map_start,
    uintptr_t map_end);

guest_object_process_result_t BeginGuestObjectProcessing(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr);

int SetGuestObjectState(
    guest_object_registry_t *registry,
    uintptr_t link_map_addr,
    guest_object_state_t state);

const char *GuestObjectStateName(guest_object_state_t state);

#endif
