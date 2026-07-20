#include "kzt_guest_library_adapter.h"

#include "box64context.h"
#include "kzt_guest_library_binding.h"
#include "library.h"
#include "library_private.h"

static kzt_guest_library_object_type_t loader_object_type(library_t *library)
{
    return library && library->type == LIB_WRAPPED
               ? KZT_GUEST_LIBRARY_OBJECT_WRAPPED
               : library && library->type == LIB_EMULATED
                     ? KZT_GUEST_LIBRARY_OBJECT_EMULATED
                     : KZT_GUEST_LIBRARY_OBJECT_UNSUPPORTED;
}

void kzt_guest_library_note_loader_pair(box64context_t *context,
                                        uintptr_t link_map_addr,
                                        library_t *library)
{
#ifdef CONFIG_LATX_KZT
    kzt_guest_library_object_type_t type;
    if (!context || !link_map_addr || !library) return;
    type = loader_object_type(library);
    (void)kzt_guest_library_publish_loader_pair(
        KztGuestLibraryBindingsForContext(context), link_map_addr, library,
        type);
#else
    (void)context;
    (void)link_map_addr;
    (void)library;
#endif
}

void kzt_guest_library_note_loader_pair_pending(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library)
{
#ifdef CONFIG_LATX_KZT
    if (!context || !scope || !link_map_addr || !library) return;
    (void)kzt_guest_library_loader_scope_note_pair(
        scope, link_map_addr, library, loader_object_type(library));
#else
    (void)context; (void)scope; (void)link_map_addr; (void)library;
#endif
}

void kzt_guest_library_publish_loader_pair_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr, library_t *library)
{
#ifdef CONFIG_LATX_KZT
    if (!context || !scope || !link_map_addr || !library) return;
    (void)kzt_guest_library_loader_scope_publish_pair(
        scope, link_map_addr, library, loader_object_type(library));
#else
    (void)context; (void)scope; (void)link_map_addr; (void)library;
#endif
}

void kzt_guest_library_publish_loader_observed_scoped(
    box64context_t *context,
    const kzt_guest_library_loader_scope_t *scope,
    uintptr_t link_map_addr)
{
#ifdef CONFIG_LATX_KZT
    if (!context || !scope || !link_map_addr) return;
    (void)kzt_guest_library_loader_scope_publish_observed(
        scope, link_map_addr);
#else
    (void)context; (void)scope; (void)link_map_addr;
#endif
}
