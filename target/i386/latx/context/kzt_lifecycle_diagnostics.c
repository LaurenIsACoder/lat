#include "kzt_lifecycle_diagnostics.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct kzt_lifecycle_diagnostic_counter {
    unsigned long count;
    uint64_t total_ns;
} kzt_lifecycle_diagnostic_counter_t;

static int diagnostics_enabled = -1;
static int diagnostics_reported;
static kzt_lifecycle_diagnostic_counter_t
    diagnostics[KZT_LIFECYCLE_STAGE_COUNT];

int kzt_lifecycle_diagnostics_enabled(void)
{
    int enabled = __atomic_load_n(&diagnostics_enabled, __ATOMIC_RELAXED);

    if (enabled < 0) {
        const char *value = getenv("LATX_KZT_LIFECYCLE_DIAGNOSTICS");
        int detected = value && value[0] && value[0] != '0';

        if (!__atomic_compare_exchange_n(
                &diagnostics_enabled, &enabled, detected, 0,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            detected = enabled;
        }
        enabled = detected;
    }
    return enabled;
}

uint64_t kzt_lifecycle_diagnostics_now(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000000000ULL +
           (uint64_t)value.tv_nsec;
}

void kzt_lifecycle_diagnostics_add(
    kzt_lifecycle_diagnostic_stage_t stage, uint64_t duration_ns)
{
    if (stage < 0 || stage >= KZT_LIFECYCLE_STAGE_COUNT || !duration_ns) {
        return;
    }
    __atomic_fetch_add(&diagnostics[stage].count, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(
        &diagnostics[stage].total_ns, duration_ns, __ATOMIC_RELAXED);
}

void kzt_lifecycle_diagnostics_report(void)
{
    if (!kzt_lifecycle_diagnostics_enabled() ||
        __atomic_exchange_n(&diagnostics_reported, 1, __ATOMIC_RELAXED)) {
        return;
    }

    fprintf(stderr,
            "kzt_lifecycle_summary schema=1 "
            "scope_invalidate_count=%lu scope_invalidate_ns=%" PRIu64 " "
            "guest_dlopen_count=%lu guest_dlopen_ns=%" PRIu64 " "
            "dlopen_finish_count=%lu dlopen_finish_ns=%" PRIu64 " "
            "guest_dlclose_count=%lu guest_dlclose_ns=%" PRIu64 " "
            "unload_probe_count=%lu unload_probe_ns=%" PRIu64 " "
            "registry_retire_count=%lu registry_retire_ns=%" PRIu64 " "
            "binding_cleanup_count=%lu binding_cleanup_ns=%" PRIu64 " "
            "reobserve_count=%lu reobserve_ns=%" PRIu64 " "
            "prebind_refresh_count=%lu prebind_refresh_ns=%" PRIu64 " "
            "scoped_reobserve_count=%lu scoped_reobserve_ns=%" PRIu64 " "
            "scoped_prebind_refresh_count=%lu "
            "scoped_prebind_refresh_ns=%" PRIu64 " "
            "target_prepare_count=%lu target_prepare_ns=%" PRIu64 "\n",
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPE_INVALIDATE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPE_INVALIDATE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_GUEST_DLOPEN].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_GUEST_DLOPEN].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_DLOPEN_FINISH].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_DLOPEN_FINISH].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_GUEST_DLCLOSE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_GUEST_DLCLOSE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_UNLOAD_PROBE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_UNLOAD_PROBE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_REGISTRY_RETIRE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_REGISTRY_RETIRE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_BINDING_CLEANUP].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_BINDING_CLEANUP].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_REOBSERVE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_REOBSERVE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_PREBIND_REFRESH].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_PREBIND_REFRESH].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPED_REOBSERVE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPED_REOBSERVE].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPED_PREBIND_REFRESH].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_SCOPED_PREBIND_REFRESH].total_ns,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_TARGET_PREPARE].count,
                __ATOMIC_RELAXED),
            __atomic_load_n(
                &diagnostics[KZT_LIFECYCLE_TARGET_PREPARE].total_ns,
                __ATOMIC_RELAXED));
}
