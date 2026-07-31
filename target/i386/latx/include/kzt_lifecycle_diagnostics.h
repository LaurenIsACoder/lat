#ifndef KZT_LIFECYCLE_DIAGNOSTICS_H
#define KZT_LIFECYCLE_DIAGNOSTICS_H

#include <stdint.h>

typedef enum kzt_lifecycle_diagnostic_stage {
    KZT_LIFECYCLE_SCOPE_INVALIDATE = 0,
    KZT_LIFECYCLE_GUEST_DLOPEN,
    KZT_LIFECYCLE_DLOPEN_FINISH,
    KZT_LIFECYCLE_GUEST_DLCLOSE,
    KZT_LIFECYCLE_UNLOAD_PROBE,
    KZT_LIFECYCLE_REGISTRY_RETIRE,
    KZT_LIFECYCLE_BINDING_CLEANUP,
    KZT_LIFECYCLE_REOBSERVE,
    KZT_LIFECYCLE_PREBIND_REFRESH,
    KZT_LIFECYCLE_SCOPED_REOBSERVE,
    KZT_LIFECYCLE_SCOPED_PREBIND_REFRESH,
    KZT_LIFECYCLE_TARGET_PREPARE,
    KZT_LIFECYCLE_STAGE_COUNT,
} kzt_lifecycle_diagnostic_stage_t;

int kzt_lifecycle_diagnostics_enabled(void);
uint64_t kzt_lifecycle_diagnostics_now(void);
void kzt_lifecycle_diagnostics_add(
    kzt_lifecycle_diagnostic_stage_t stage, uint64_t duration_ns);
void kzt_lifecycle_diagnostics_report(void);

#endif
