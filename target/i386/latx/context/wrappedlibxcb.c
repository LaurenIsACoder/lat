/*
 * This file is derived from Box64.
 *
 * SPDX-FileCopyrightText: 2020 ptitSeb
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

#include "wrappedlibs.h"

#include "debug.h"
#include "wrapper.h"
#include "bridge.h"
#include "library_private.h"
#include "callback.h"
#include "librarian.h"
#include "box64context.h"
#include "kzt_guest_cancel_scope.h"

const char* libxcbName = "libxcb.so.1";
#define LIBNAME libxcb

#include "generated/wrappedlibxcbtypes.h"
#include "wrappercallback.h"
#include "myalign.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

EXPORT void* my_xcb_wait_for_event(void* v1);
EXPORT void* my_xcb_wait_for_event(void* v1)
{
    void *native = align_xcb_connection(v1);
    kzt_guest_cancel_scope_t cancel = { 0 };
    void* ret;

    if (!native)
        return NULL;
    pthread_cleanup_push(kzt_guest_cancel_scope_cleanup, &cancel);
    kzt_guest_cancel_scope_begin(my_context, &cancel);
    ret = my->xcb_wait_for_event(native);
    kzt_guest_cancel_scope_end(&cancel);
    pthread_cleanup_pop(0);
    unalign_xcb_connection(native, v1);
    return ret;
}
EXPORT int32_t my_xcb_flush(void* v1);
EXPORT int32_t my_xcb_flush(void* v1)
{
    void *native = align_xcb_connection(v1);
    int32_t ret;

    if (!native)
        return 0;
    ret = my->xcb_flush(native);
    unalign_xcb_connection(native, v1);
    return ret;
}

EXPORT void* my_xcb_wait_for_reply(void* v1, uint32_t v2, void* v3);
EXPORT void* my_xcb_wait_for_reply(void* v1, uint32_t v2, void* v3)
{
    void *native = align_xcb_connection(v1);
    kzt_guest_cancel_scope_t cancel = { 0 };
    void* ret;

    if (!native)
        return NULL;
    pthread_cleanup_push(kzt_guest_cancel_scope_cleanup, &cancel);
    kzt_guest_cancel_scope_begin(my_context, &cancel);
    ret = my->xcb_wait_for_reply(native, v2, v3);
    kzt_guest_cancel_scope_end(&cancel);
    pthread_cleanup_pop(0);
    unalign_xcb_connection(native, v1);
    return ret;
}

EXPORT void* my_xcb_wait_for_reply64(void* v1, uint64_t v2, void* v3);
EXPORT void* my_xcb_wait_for_reply64(void* v1, uint64_t v2, void* v3)
{
    void *native = align_xcb_connection(v1);
    kzt_guest_cancel_scope_t cancel = { 0 };
    void* ret;

    if (!native)
        return NULL;
    pthread_cleanup_push(kzt_guest_cancel_scope_cleanup, &cancel);
    kzt_guest_cancel_scope_begin(my_context, &cancel);
    ret = my->xcb_wait_for_reply64(native, v2, v3);
    kzt_guest_cancel_scope_end(&cancel);
    pthread_cleanup_pop(0);
    unalign_xcb_connection(native, v1);
    return ret;
}

EXPORT void* my_xcb_wait_for_special_event(void* v1, void* v2);
EXPORT void* my_xcb_wait_for_special_event(void* v1, void* v2)
{
    void *native = align_xcb_connection(v1);
    kzt_guest_cancel_scope_t cancel = { 0 };
    void* ret;

    if (!native)
        return NULL;
    pthread_cleanup_push(kzt_guest_cancel_scope_cleanup, &cancel);
    kzt_guest_cancel_scope_begin(my_context, &cancel);
    ret = my->xcb_wait_for_special_event(native, v2);
    kzt_guest_cancel_scope_end(&cancel);
    pthread_cleanup_pop(0);
    unalign_xcb_connection(native, v1);
    return ret;
}

EXPORT void* my_xcb_connect(void* dispname, void* screen)
{
	return add_xcb_connection(my->xcb_connect(dispname, screen));
}

EXPORT void my_xcb_disconnect(void* conn)
{
	kzt_xcb_connection_lease_t lease = { 0 };
	int old_cancel_state = PTHREAD_CANCEL_ENABLE;

	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state);
	if (begin_xcb_connection_disconnect(conn, &lease) != 0) {
		(void)pthread_setcancelstate(old_cancel_state, NULL);
		return;
	}
	my->xcb_disconnect(lease.native);
	finish_xcb_connection_disconnect(&lease);
	(void)pthread_setcancelstate(old_cancel_state, NULL);
}
#pragma GCC diagnostic pop

#define CUSTOM_INIT \
     getMy(lib);


#define CUSTOM_FINI \
    freeMy();

#include "wrappedlib_init.h"
