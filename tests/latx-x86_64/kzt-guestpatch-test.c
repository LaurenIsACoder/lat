#include "guestpatch.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check_int(const char *name, unsigned long got,
                      unsigned long expected)
{
    if (got == expected)
        return;

    fprintf(stderr, "%s: got 0x%lx expected 0x%lx\n", name, got, expected);
    ++failures;
}

static void check_string(const char *name, const char *got,
                         const char *expected)
{
    if (got && !strcmp(got, expected))
        return;

    fprintf(stderr, "%s: got \"%s\" expected \"%s\"\n",
            name, got ? got : "(null)", expected);
    ++failures;
}

static void test_patch_decision_defaults(void)
{
    KztPatchDecision decision;

    KztPatchDecisionInit(&decision);

    check_int("defaults.version", (unsigned long)decision.symbol_version,
              (unsigned long)-1);
    check_int("defaults.reason", decision.reason, KZT_PATCH_REASON_NONE);
    check_string("defaults.reason-name",
                 KztPatchDecisionReasonName(decision.reason), "none");
}

static void test_patch_decision_names(void)
{
    check_string("reason.local",
                 KztPatchDecisionReasonName(KZT_PATCH_REASON_LOCAL_SYMBOL),
                 "local-symbol");
    check_string("reason.global",
                 KztPatchDecisionReasonName(KZT_PATCH_REASON_GLOBAL_SYMBOL),
                 "global-symbol");
    check_string("reason.lazy-resolved",
                 KztPatchDecisionReasonName(
                     KZT_PATCH_REASON_LAZY_BINDING_RESOLVED),
                 "lazy-binding-resolved");
    check_string("reason.plt-resolver",
                 KztPatchDecisionReasonName(KZT_PATCH_REASON_PLT_RESOLVER),
                 "plt-resolver");
    check_string("reloc.glob",
                 KztPatchRelocationTypeName(R_X86_64_GLOB_DAT),
                 "R_X86_64_GLOB_DAT");
    check_string("reloc.jump",
                 KztPatchRelocationTypeName(R_X86_64_JUMP_SLOT),
                 "R_X86_64_JUMP_SLOT");
    check_string("reloc.unknown", KztPatchRelocationTypeName(-1),
                 "unknown");
}

static void test_patch_decision_format(void)
{
    KztPatchDecision decision;
    char buffer[512];
    size_t size;

    KztPatchDecisionInit(&decision);
    decision.object = "libfoo.so";
    decision.object_base = 0x100000;
    decision.relocation = (void *)0x2000;
    decision.relocation_index = 7;
    decision.relocation_type = R_X86_64_JUMP_SLOT;
    decision.symbol = "eglGetProcAddress";
    decision.symbol_version = 3;
    decision.symbol_version_name = "EGL_1.5";
    decision.slot = 0x3000;
    decision.old_target = 0x4000;
    decision.old_owner = "libEGL.so.1";
    decision.old_owner_base = 0x5000;
    decision.new_bridge = 0x6000;
    decision.new_owner = "wrappedlibegl";
    decision.new_owner_base = 0x7000;
    decision.reason = KZT_PATCH_REASON_GLOBAL_SYMBOL;

    size = KztFormatPatchDecision(buffer, sizeof(buffer), &decision);
    check_int("format.nonempty", size > 0, 1);
    check_int("format.contains-symbol",
              strstr(buffer, "symbol=eglGetProcAddress") != NULL, 1);
    check_int("format.contains-reason",
              strstr(buffer, "reason=global-symbol") != NULL, 1);
    check_int("format.contains-bridge",
              strstr(buffer, "new_bridge=0x6000") != NULL, 1);
}

int main(void)
{
    test_patch_decision_defaults();
    test_patch_decision_names();
    test_patch_decision_format();

    if (failures)
        return 1;

    puts("KZT guestpatch tests passed");
    return 0;
}
