#ifndef KZT_GUEST_DL_INIT_H
#define KZT_GUEST_DL_INIT_H

#include "box64context.h"
#include "kzt_guest_dl_api.h"
#include "kzt_guest_dl_state.h"

const kzt_guest_dl_entries_t *kzt_guest_dl_init_entries(
    box64context_t *context, kzt_guest_dl_entries_t *fallback);

static inline const kzt_guest_dl_entries_t *kzt_guest_dl_entries_for_call(
    box64context_t *context, kzt_guest_dl_entries_t *fallback)
{
    const kzt_guest_dl_entries_t *entries =
        context && context->dlprivate
            ? kzt_guest_dl_api_load_entries(context->dlprivate)
            : NULL;

    return entries ? entries : kzt_guest_dl_init_entries(context, fallback);
}

#endif
