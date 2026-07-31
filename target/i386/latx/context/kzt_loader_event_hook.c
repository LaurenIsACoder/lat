#include "kzt_loader_event_hook.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES 64

typedef struct kzt_loader_lifecycle_identity_buffer {
    kzt_loader_lifecycle_identity_t *identities;
    size_t count;
    size_t capacity;
    kzt_loader_lifecycle_identity_t inline_identities[
        KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES];
} kzt_loader_lifecycle_identity_buffer_t;

#ifdef KZT_LOADER_EVENT_HOOK_TEST
static long hook_fail_after = -1;

void kzt_loader_event_hook_test_set_alloc_failure_after(long allocations)
{
    hook_fail_after = allocations;
}
#endif

static int kzt_loader_event_hook_allocation_allowed(void)
{
#ifdef KZT_LOADER_EVENT_HOOK_TEST
    if (hook_fail_after == 0) {
        return 0;
    }
    if (hook_fail_after > 0) {
        --hook_fail_after;
    }
#endif
    return 1;
}

static void *kzt_loader_event_hook_malloc(size_t size)
{
    return kzt_loader_event_hook_allocation_allowed() ? malloc(size) : NULL;
}

static void *kzt_loader_event_hook_calloc(size_t count, size_t size)
{
    return kzt_loader_event_hook_allocation_allowed()
               ? calloc(count, size)
               : NULL;
}

static size_t kzt_loader_event_hook_align(size_t value)
{
    return (value + 3U) & ~3U;
}

static void kzt_loader_event_hook_lifecycle_lock(
    kzt_loader_event_hook_t *hook)
{
    while (__atomic_test_and_set(&hook->lifecycle_lock,
                                 __ATOMIC_ACQUIRE)) {
    }
}

static void kzt_loader_event_hook_lifecycle_unlock(
    kzt_loader_event_hook_t *hook)
{
    __atomic_clear(&hook->lifecycle_lock, __ATOMIC_RELEASE);
}

static int kzt_loader_event_hook_publisher_leave(
    kzt_loader_event_hook_t *hook, int result,
    kzt_loader_lifecycle_result_t lifecycle_result)
{
    __atomic_store_n(&hook->lifecycle_result, lifecycle_result,
                     __ATOMIC_RELEASE);
    __atomic_sub_fetch(&hook->lifecycle_publishers, 1U, __ATOMIC_RELEASE);
    return result;
}

static void kzt_loader_lifecycle_identity_buffer_init(
    kzt_loader_lifecycle_identity_buffer_t *buffer)
{
    memset(buffer, 0, sizeof(*buffer));
    buffer->identities = buffer->inline_identities;
    buffer->capacity = KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES;
}

static void kzt_loader_lifecycle_identity_buffer_release(
    kzt_loader_lifecycle_identity_buffer_t *buffer)
{
    if (buffer->identities != buffer->inline_identities) {
        free(buffer->identities);
    }
    memset(buffer, 0, sizeof(*buffer));
}

static kzt_loader_lifecycle_result_t
kzt_loader_lifecycle_capacity_for(
    size_t current, size_t required, size_t *capacity)
{
    size_t next = current ? current : KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES;

    if (!capacity || required > SIZE_MAX /
            sizeof(kzt_loader_lifecycle_identity_t)) {
        return KZT_LOADER_LIFECYCLE_OVERFLOW;
    }
    while (next < required) {
        if (next > SIZE_MAX / 2) {
            return KZT_LOADER_LIFECYCLE_OVERFLOW;
        }
        next *= 2;
    }
    *capacity = next;
    return KZT_LOADER_LIFECYCLE_OK;
}

static kzt_loader_lifecycle_result_t
kzt_loader_lifecycle_identity_buffer_reserve(
    kzt_loader_lifecycle_identity_buffer_t *buffer, size_t required)
{
    kzt_loader_lifecycle_identity_t *identities;
    kzt_loader_lifecycle_result_t result;
    size_t capacity;

    if (required <= buffer->capacity) {
        return KZT_LOADER_LIFECYCLE_OK;
    }
    result = kzt_loader_lifecycle_capacity_for(
        buffer->capacity, required, &capacity);
    if (result != KZT_LOADER_LIFECYCLE_OK) {
        return result;
    }
    identities = kzt_loader_event_hook_malloc(
        capacity * sizeof(*identities));
    if (!identities) {
        return KZT_LOADER_LIFECYCLE_ALLOCATION;
    }
    memcpy(identities, buffer->identities,
           buffer->count * sizeof(*identities));
    if (buffer->identities != buffer->inline_identities) {
        free(buffer->identities);
    }
    buffer->identities = identities;
    buffer->capacity = capacity;
    return KZT_LOADER_LIFECYCLE_OK;
}

static kzt_loader_lifecycle_result_t
kzt_loader_lifecycle_identity_buffer_append(
    kzt_loader_lifecycle_identity_buffer_t *buffer,
    const kzt_loader_lifecycle_identity_t *identity)
{
    kzt_loader_lifecycle_result_t result;

    if (buffer->count == SIZE_MAX) {
        return KZT_LOADER_LIFECYCLE_OVERFLOW;
    }
    result = kzt_loader_lifecycle_identity_buffer_reserve(
        buffer, buffer->count + 1);
    if (result != KZT_LOADER_LIFECYCLE_OK) {
        return result;
    }
    buffer->identities[buffer->count++] = *identity;
    return KZT_LOADER_LIFECYCLE_OK;
}

static void kzt_loader_lifecycle_cancel_buffer(
    const kzt_loader_lifecycle_identity_buffer_t *buffer,
    kzt_loader_lifecycle_transition_fn cancel, void *opaque)
{
    size_t index;

    for (index = 0; index < buffer->count; ++index) {
        (void)cancel(&buffer->identities[index], opaque);
    }
}

static kzt_loader_lifecycle_result_t
kzt_loader_event_hook_append_pending(
    kzt_loader_event_hook_t *hook,
    const kzt_loader_lifecycle_identity_buffer_t *incoming)
{
    kzt_loader_lifecycle_identity_t *replacement = NULL;
    size_t replacement_capacity = 0;

    for (;;) {
        kzt_loader_lifecycle_identity_t *old;
        kzt_loader_lifecycle_result_t result;
        size_t required;
        size_t capacity;

        kzt_loader_event_hook_lifecycle_lock(hook);
        if (!__atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE)) {
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_DISABLED;
        }
        if (hook->pending_delete_count > SIZE_MAX - incoming->count) {
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_OVERFLOW;
        }
        required = hook->pending_delete_count + incoming->count;
        if (hook->pending_delete &&
            required <= hook->pending_delete_capacity) {
            memcpy(hook->pending_delete + hook->pending_delete_count,
                   incoming->identities,
                   incoming->count * sizeof(*incoming->identities));
            hook->pending_delete_count = required;
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_OK;
        }
        result = kzt_loader_lifecycle_capacity_for(
            hook->pending_delete_capacity, required, &capacity);
        kzt_loader_event_hook_lifecycle_unlock(hook);
        if (result != KZT_LOADER_LIFECYCLE_OK) {
            free(replacement);
            return result;
        }
        if (capacity > replacement_capacity) {
            free(replacement);
            replacement = kzt_loader_event_hook_malloc(
                capacity * sizeof(*replacement));
            if (!replacement) {
                return KZT_LOADER_LIFECYCLE_ALLOCATION;
            }
            replacement_capacity = capacity;
        }

        kzt_loader_event_hook_lifecycle_lock(hook);
        if (!__atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE)) {
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_DISABLED;
        }
        if (hook->pending_delete_count > SIZE_MAX - incoming->count) {
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_OVERFLOW;
        }
        required = hook->pending_delete_count + incoming->count;
        if (hook->pending_delete &&
            required <= hook->pending_delete_capacity) {
            memcpy(hook->pending_delete + hook->pending_delete_count,
                   incoming->identities,
                   incoming->count * sizeof(*incoming->identities));
            hook->pending_delete_count = required;
            kzt_loader_event_hook_lifecycle_unlock(hook);
            free(replacement);
            return KZT_LOADER_LIFECYCLE_OK;
        }
        if (required > replacement_capacity) {
            kzt_loader_event_hook_lifecycle_unlock(hook);
            continue;
        }
        old = hook->pending_delete;
        if (hook->pending_delete_count) {
            memcpy(replacement, old,
                   hook->pending_delete_count * sizeof(*replacement));
        }
        memcpy(replacement + hook->pending_delete_count,
               incoming->identities,
               incoming->count * sizeof(*replacement));
        hook->pending_delete = replacement;
        hook->pending_delete_capacity = replacement_capacity;
        hook->pending_delete_count = required;
        replacement = NULL;
        replacement_capacity = 0;
        kzt_loader_event_hook_lifecycle_unlock(hook);
        free(old);
        return KZT_LOADER_LIFECYCLE_OK;
    }
}

static void kzt_loader_event_hook_take_pending(
    kzt_loader_event_hook_t *hook,
    kzt_loader_lifecycle_identity_buffer_t *pending)
{
    kzt_loader_lifecycle_identity_buffer_init(pending);
    kzt_loader_event_hook_lifecycle_lock(hook);
    if (hook->pending_delete_count <= pending->capacity) {
        if (hook->pending_delete_count) {
            memcpy(pending->identities, hook->pending_delete,
                   hook->pending_delete_count *
                       sizeof(*pending->identities));
        }
        pending->count = hook->pending_delete_count;
    } else {
        pending->identities = hook->pending_delete;
        pending->count = hook->pending_delete_count;
        pending->capacity = hook->pending_delete_capacity;
        hook->pending_delete = NULL;
        hook->pending_delete_capacity = 0;
    }
    hook->pending_delete_count = 0;
    kzt_loader_event_hook_lifecycle_unlock(hook);
}

static int kzt_loader_event_hook_live_maps_valid(
    const uintptr_t *live_maps, size_t live_map_count)
{
    size_t i;
    size_t j;

    if (live_map_count && !live_maps) {
        return 0;
    }
    for (i = 0; i < live_map_count; ++i) {
        if (!live_maps[i]) {
            return 0;
        }
        for (j = 0; j < i; ++j) {
            if (live_maps[j] == live_maps[i]) {
                return 0;
            }
        }
    }
    return 1;
}

static int kzt_loader_event_hook_map_present(
    uintptr_t link_map_addr,
    const uintptr_t *live_maps,
    size_t live_map_count)
{
    size_t i;

    for (i = 0; i < live_map_count; ++i) {
        if (live_maps[i] == link_map_addr) {
            return 1;
        }
    }
    return 0;
}

static int kzt_loader_lifecycle_identity_equal(
    const kzt_loader_lifecycle_identity_t *left,
    const kzt_loader_lifecycle_identity_t *right)
{
    return left->link_map_addr == right->link_map_addr &&
        left->generation == right->generation &&
        left->namespace_id == right->namespace_id;
}

static int kzt_loader_event_hook_hex(char *out, size_t out_size,
                                     const unsigned char *input, size_t size)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (!out || !input || out_size < size * 2U + 1U) {
        return -1;
    }
    for (i = 0; i < size; ++i) {
        out[i * 2U] = digits[input[i] >> 4];
        out[i * 2U + 1U] = digits[input[i] & 0x0fU];
    }
    out[size * 2U] = '\0';
    return 0;
}

static int kzt_loader_event_hook_read_note(FILE *file, size_t note_size,
                                           char build_id[
                                               KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE])
{
    size_t consumed = 0;

    while (consumed + sizeof(Elf64_Nhdr) <= note_size) {
        Elf64_Nhdr note;
        unsigned char name[4] = { 0 };
        unsigned char descriptor[20] = { 0 };
        size_t name_size;
        size_t descriptor_size;

        if (fread(&note, sizeof(note), 1, file) != 1) {
            return -1;
        }
        consumed += sizeof(note);
        name_size = kzt_loader_event_hook_align(note.n_namesz);
        descriptor_size = kzt_loader_event_hook_align(note.n_descsz);
        if (name_size > note_size - consumed ||
            descriptor_size > note_size - consumed - name_size) {
            return -1;
        }
        if (note.n_namesz > sizeof(name) || note.n_descsz > sizeof(descriptor)) {
            if (fseek(file, (long)(name_size + descriptor_size), SEEK_CUR) != 0) {
                return -1;
            }
            consumed += name_size + descriptor_size;
            continue;
        }
        if (note.n_namesz && fread(name, 1, note.n_namesz, file) != note.n_namesz) {
            return -1;
        }
        if (name_size > note.n_namesz &&
            fseek(file, (long)(name_size - note.n_namesz), SEEK_CUR) != 0) {
            return -1;
        }
        if (note.n_descsz &&
            fread(descriptor, 1, note.n_descsz, file) != note.n_descsz) {
            return -1;
        }
        if (descriptor_size > note.n_descsz &&
            fseek(file, (long)(descriptor_size - note.n_descsz), SEEK_CUR) != 0) {
            return -1;
        }
        consumed += name_size + descriptor_size;
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
            memcmp(name, "GNU", 4) == 0 && note.n_descsz == 20) {
            return kzt_loader_event_hook_hex(build_id,
                                             KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE,
                                             descriptor, note.n_descsz);
        }
    }
    return -1;
}

int kzt_loader_event_hook_read_build_id(
    const char *path, char build_id[KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE])
{
    FILE *file;
    Elf64_Ehdr header;
    Elf64_Phdr program_header;
    size_t index;
    int result = -1;

    if (!path || !build_id) {
        return -1;
    }
    build_id[0] = '\0';
    file = fopen(path, "rb");
    if (!file) {
        return -1;
    }
    if (fread(&header, sizeof(header), 1, file) != 1 ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_X86_64 ||
        header.e_phentsize != sizeof(program_header)) {
        goto out;
    }
    for (index = 0; index < header.e_phnum; ++index) {
        if (fseek(file, (long)(header.e_phoff +
                               index * sizeof(program_header)), SEEK_SET) != 0 ||
            fread(&program_header, sizeof(program_header), 1, file) != 1) {
            goto out;
        }
        if (program_header.p_type != PT_NOTE ||
            program_header.p_filesz < sizeof(Elf64_Nhdr) ||
            fseek(file, (long)program_header.p_offset, SEEK_SET) != 0) {
            continue;
        }
        if (kzt_loader_event_hook_read_note(file,
                                             (size_t)program_header.p_filesz,
                                             build_id) == 0) {
            result = 0;
            break;
        }
    }
out:
    fclose(file);
    return result;
}

static int kzt_loader_event_hook_disabled(void)
{
    const char *value = getenv("LATX_KZT_LOADER_EVENT_HOOK");

    return value && strcmp(value, "0") == 0;
}

int kzt_loader_event_hook_pattern_allowed(int pattern_matched)
{
    const char *value = getenv("LATX_KZT_LOADER_EVENT_FORCE_PATTERN_MISMATCH");

    return pattern_matched && !(value && strcmp(value, "1") == 0);
}

int kzt_loader_event_hook_install(kzt_loader_event_hook_t *hook,
                                  const char *build_id,
                                  uintptr_t callback_addr,
                                  unsigned int link_map_reg,
                                  int pattern_matched)
{
    kzt_loader_event_hook_result_t result = KZT_LOADER_EVENT_HOOK_INSTALLED;

    if (!hook) {
        return -1;
    }
    memset(hook, 0, sizeof(*hook));
    if (kzt_loader_event_hook_disabled()) {
        result = KZT_LOADER_EVENT_HOOK_FAIL_OPEN_DISABLED;
    } else if (!build_id) {
        result = KZT_LOADER_EVENT_HOOK_FAIL_OPEN_BUILD_ID_READ;
    } else if (strcmp(build_id, KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID) != 0) {
        result = KZT_LOADER_EVENT_HOOK_FAIL_OPEN_UNKNOWN_BUILD_ID;
    } else if (!pattern_matched || !callback_addr || link_map_reg > 15) {
        result = KZT_LOADER_EVENT_HOOK_FAIL_OPEN_PATTERN_MISMATCH;
    }
    hook->result = result;
    if (result != KZT_LOADER_EVENT_HOOK_INSTALLED) {
        return -1;
    }
    memcpy(hook->build_id, build_id, KZT_LOADER_EVENT_HOOK_BUILD_ID_SIZE);
    hook->callback_addr = callback_addr;
    hook->link_map_reg = link_map_reg;
    hook->scope_layout = KZT_GUEST_SCOPE_LAYOUT_GLIBC_2_39_C591A5DF;
    __atomic_store_n(&hook->installed, 1U, __ATOMIC_RELEASE);
    return 0;
}

int kzt_loader_event_hook_publish(kzt_loader_event_hook_t *hook,
                                  uintptr_t link_map_addr,
                                  kzt_loader_event_t *event)
{
    struct timespec timestamp;

    if (!hook || !event || !link_map_addr ||
        !__atomic_load_n(&hook->installed, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    memset(event, 0, sizeof(*event));
    event->link_map_addr = link_map_addr;
    event->sequence = __atomic_add_fetch(&hook->event_sequence, 1,
                                         __ATOMIC_RELAXED);
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &timestamp) == 0) {
        event->published_ns = (uint64_t)timestamp.tv_sec * 1000000000ULL +
                              (uint64_t)timestamp.tv_nsec;
    }
    return 0;
}

int kzt_loader_event_hook_enable_lifecycle(
    kzt_loader_event_hook_t *hook,
    uintptr_t debug_state_addr,
    uintptr_t r_debug_addr)
{
    kzt_loader_lifecycle_identity_t *pending;

    if (!hook || !debug_state_addr || !r_debug_addr ||
        !__atomic_load_n(&hook->installed, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&hook->lifecycle_publishers, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    pending = kzt_loader_event_hook_calloc(
        KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES, sizeof(*pending));
    if (!pending) {
        __atomic_store_n(&hook->lifecycle_result,
                         KZT_LOADER_LIFECYCLE_ALLOCATION,
                         __ATOMIC_RELEASE);
        return -1;
    }
    kzt_loader_event_hook_lifecycle_lock(hook);
    if (hook->pending_delete_count ||
        __atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&hook->lifecycle_publishers, __ATOMIC_ACQUIRE)) {
        kzt_loader_event_hook_lifecycle_unlock(hook);
        free(pending);
        return -1;
    }
    free(hook->pending_delete);
    hook->pending_delete = pending;
    hook->pending_delete_count = 0;
    hook->pending_delete_capacity =
        KZT_LOADER_LIFECYCLE_INLINE_IDENTITIES;
    hook->debug_state_addr = debug_state_addr;
    hook->r_debug_addr = r_debug_addr;
    kzt_loader_event_hook_lifecycle_unlock(hook);
    __atomic_store_n(&hook->lifecycle_enabled, 1U, __ATOMIC_RELEASE);
    __atomic_store_n(&hook->lifecycle_result, KZT_LOADER_LIFECYCLE_OK,
                     __ATOMIC_RELEASE);
    return 0;
}

int kzt_loader_event_hook_publish_lifecycle(
    kzt_loader_event_hook_t *hook,
    kzt_loader_debug_state_t state,
    const uintptr_t *live_maps,
    size_t live_map_count,
    kzt_loader_lifecycle_resolve_fn resolve,
    kzt_loader_lifecycle_transition_fn prepare,
    kzt_loader_lifecycle_transition_fn cancel,
    kzt_loader_lifecycle_unload_fn unload,
    void *opaque)
{
    kzt_loader_lifecycle_identity_buffer_t pending;
    kzt_loader_lifecycle_result_t lifecycle_result;
    size_t i;

    if (!hook || !resolve || !prepare || !cancel || !unload ||
        !__atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    __atomic_add_fetch(&hook->lifecycle_publishers, 1U, __ATOMIC_ACQUIRE);
    if (!__atomic_load_n(&hook->lifecycle_enabled, __ATOMIC_ACQUIRE)) {
        return kzt_loader_event_hook_publisher_leave(
            hook, -1, KZT_LOADER_LIFECYCLE_DISABLED);
    }
    if (!kzt_loader_event_hook_live_maps_valid(live_maps, live_map_count) ||
        (state != KZT_LOADER_DEBUG_CONSISTENT &&
         state != KZT_LOADER_DEBUG_ADD &&
         state != KZT_LOADER_DEBUG_DELETE)) {
        kzt_loader_event_hook_take_pending(hook, &pending);
        kzt_loader_lifecycle_cancel_buffer(&pending, cancel, opaque);
        kzt_loader_lifecycle_identity_buffer_release(&pending);
        return kzt_loader_event_hook_publisher_leave(
            hook, -1, KZT_LOADER_LIFECYCLE_INVALID);
    }

    if (state == KZT_LOADER_DEBUG_DELETE) {
        kzt_loader_lifecycle_identity_buffer_init(&pending);

        for (i = 0; i < live_map_count; ++i) {
            kzt_loader_lifecycle_identity_t identity = { 0 };

            if (resolve(live_maps[i], &identity, opaque) != 0 ||
                identity.link_map_addr != live_maps[i] ||
                !identity.generation || prepare(&identity, opaque) != 0) {
                continue;
            }
            lifecycle_result =
                kzt_loader_lifecycle_identity_buffer_append(
                    &pending, &identity);
            if (lifecycle_result != KZT_LOADER_LIFECYCLE_OK) {
                (void)cancel(&identity, opaque);
                kzt_loader_lifecycle_cancel_buffer(
                    &pending, cancel, opaque);
                kzt_loader_lifecycle_identity_buffer_release(&pending);
                return kzt_loader_event_hook_publisher_leave(
                    hook, -1, lifecycle_result);
            }
        }
        lifecycle_result = kzt_loader_event_hook_append_pending(
            hook, &pending);
        if (lifecycle_result != KZT_LOADER_LIFECYCLE_OK) {
            kzt_loader_lifecycle_cancel_buffer(&pending, cancel, opaque);
        }
        kzt_loader_lifecycle_identity_buffer_release(&pending);
        return kzt_loader_event_hook_publisher_leave(
            hook, lifecycle_result == KZT_LOADER_LIFECYCLE_OK ? 0 : -1,
            lifecycle_result);
    }
    if (state == KZT_LOADER_DEBUG_ADD) {
        return kzt_loader_event_hook_publisher_leave(
            hook, 0, KZT_LOADER_LIFECYCLE_OK);
    }

    kzt_loader_event_hook_take_pending(hook, &pending);

    for (i = 0; i < pending.count; ++i) {
        kzt_loader_lifecycle_identity_t current = { 0 };

        if (!kzt_loader_event_hook_map_present(
                pending.identities[i].link_map_addr,
                live_maps, live_map_count)) {
            unload(&pending.identities[i], opaque);
        } else if (resolve(
                       pending.identities[i].link_map_addr,
                       &current, opaque) == 0 &&
                   !kzt_loader_lifecycle_identity_equal(
                       &pending.identities[i], &current)) {
            unload(&pending.identities[i], opaque);
        } else {
            (void)cancel(&pending.identities[i], opaque);
        }
    }
    kzt_loader_lifecycle_identity_buffer_release(&pending);
    return kzt_loader_event_hook_publisher_leave(
        hook, 0, KZT_LOADER_LIFECYCLE_OK);
}

int kzt_loader_event_hook_destroy(kzt_loader_event_hook_t *hook)
{
    if (!hook) {
        return -1;
    }
    __atomic_store_n(&hook->lifecycle_enabled, 0U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&hook->lifecycle_publishers, __ATOMIC_ACQUIRE)) {
    }
    kzt_loader_event_hook_lifecycle_lock(hook);
    if (hook->pending_delete_count) {
        kzt_loader_event_hook_lifecycle_unlock(hook);
        __atomic_store_n(&hook->lifecycle_enabled, 1U, __ATOMIC_RELEASE);
        return -1;
    }
    free(hook->pending_delete);
    hook->pending_delete = NULL;
    hook->pending_delete_count = 0;
    hook->pending_delete_capacity = 0;
    hook->debug_state_addr = 0;
    hook->r_debug_addr = 0;
    kzt_loader_event_hook_lifecycle_unlock(hook);
    __atomic_store_n(&hook->installed, 0U, __ATOMIC_RELEASE);
    return 0;
}

kzt_guest_scope_layout_t kzt_loader_event_hook_scope_layout(
    const kzt_loader_event_hook_t *hook)
{
    if (!hook ||
        !__atomic_load_n(&hook->installed, __ATOMIC_ACQUIRE) ||
        hook->result != KZT_LOADER_EVENT_HOOK_INSTALLED ||
        strcmp(hook->build_id,
               KZT_LOADER_EVENT_HOOK_SUPPORTED_BUILD_ID) != 0) {
        return KZT_GUEST_SCOPE_LAYOUT_UNSUPPORTED;
    }
    return hook->scope_layout;
}

const char *kzt_loader_event_hook_result_name(
    kzt_loader_event_hook_result_t result)
{
    switch (result) {
    case KZT_LOADER_EVENT_HOOK_INSTALLED:
        return "INSTALLED";
    case KZT_LOADER_EVENT_HOOK_FAIL_OPEN_DISABLED:
        return "DISABLED";
    case KZT_LOADER_EVENT_HOOK_FAIL_OPEN_BUILD_ID_READ:
        return "BUILD_ID_READ";
    case KZT_LOADER_EVENT_HOOK_FAIL_OPEN_UNKNOWN_BUILD_ID:
        return "UNKNOWN_BUILD_ID";
    case KZT_LOADER_EVENT_HOOK_FAIL_OPEN_PATTERN_MISMATCH:
        return "PATTERN_MISMATCH";
    }
    return "INVALID";
}

kzt_loader_lifecycle_result_t kzt_loader_event_hook_lifecycle_result(
    const kzt_loader_event_hook_t *hook)
{
    if (!hook) {
        return KZT_LOADER_LIFECYCLE_INVALID;
    }
    return __atomic_load_n(&hook->lifecycle_result, __ATOMIC_ACQUIRE);
}

const char *kzt_loader_lifecycle_result_name(
    kzt_loader_lifecycle_result_t result)
{
    switch (result) {
    case KZT_LOADER_LIFECYCLE_OK:
        return "OK";
    case KZT_LOADER_LIFECYCLE_DISABLED:
        return "DISABLED";
    case KZT_LOADER_LIFECYCLE_INVALID:
        return "INVALID";
    case KZT_LOADER_LIFECYCLE_ALLOCATION:
        return "ALLOCATION";
    case KZT_LOADER_LIFECYCLE_OVERFLOW:
        return "OVERFLOW";
    }
    return "INVALID";
}
