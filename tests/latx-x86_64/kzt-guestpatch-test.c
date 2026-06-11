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
    check_int("defaults.owner-relation", decision.owner_relation,
              KZT_PATCH_OWNER_RELATION_UNKNOWN);
    check_int("defaults.shadow-result", decision.shadow_result,
              KZT_PATCH_SHADOW_DISABLED);
    check_int("defaults.target-source", decision.target_source,
              KZT_PATCH_TARGET_MAPLIB);
    check_int("defaults.has-target", KztPatchDecisionHasTarget(&decision), 0);
    check_string("defaults.reason-name",
                 KztPatchDecisionReasonName(decision.reason), "none");
    check_string("defaults.owner-relation-name",
                 KztPatchOwnerRelationName(decision.owner_relation),
                 "unknown");
    check_string("defaults.shadow-result-name",
                 KztPatchShadowResultName(decision.shadow_result),
                 "disabled");
    check_string("defaults.target-source-name",
                 KztPatchTargetSourceName(decision.target_source), "maplib");
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
    check_string("reason.guest-owner-target",
                 KztPatchDecisionReasonName(
                     KZT_PATCH_REASON_GUEST_OWNER_TARGET),
                 "guest-owner-target");
    check_string("reloc.glob",
                 KztPatchRelocationTypeName(R_X86_64_GLOB_DAT),
                 "R_X86_64_GLOB_DAT");
    check_string("reloc.jump",
                 KztPatchRelocationTypeName(R_X86_64_JUMP_SLOT),
                 "R_X86_64_JUMP_SLOT");
    check_string("reloc.unknown", KztPatchRelocationTypeName(-1),
                 "unknown");
    check_string("owner-relation.match",
                 KztPatchOwnerRelationName(KZT_PATCH_OWNER_RELATION_MATCH),
                 "match");
    check_string("owner-relation.mismatch",
                 KztPatchOwnerRelationName(KZT_PATCH_OWNER_RELATION_MISMATCH),
                 "mismatch");
    check_int("owner-relation-for.match",
              KztPatchOwnerRelationForNames("/x/libfoo.so", "libfoo.so"),
              KZT_PATCH_OWNER_RELATION_MATCH);
    check_int("owner-relation-for.mismatch",
              KztPatchOwnerRelationForNames("/x/libfoo.so", "libbar.so"),
              KZT_PATCH_OWNER_RELATION_MISMATCH);
    check_string("shadow.match",
                 KztPatchShadowResultName(KZT_PATCH_SHADOW_MATCH), "match");
    check_string("shadow.no-maplib-target",
                 KztPatchShadowResultName(
                     KZT_PATCH_SHADOW_NO_MAPLIB_TARGET),
                 "no-maplib-target");
    check_string("shadow.self-plt",
                 KztPatchShadowResultName(KZT_PATCH_SHADOW_SELF_PLT),
                 "self-plt");
    check_string("shadow.no-wrapper",
                 KztPatchShadowResultName(KZT_PATCH_SHADOW_NO_WRAPPER),
                 "no-wrapper");
    check_string("shadow.missing",
                 KztPatchShadowResultName(KZT_PATCH_SHADOW_SYMBOL_MISSING),
                 "symbol-missing");
    check_string("target-source.maplib",
                 KztPatchTargetSourceName(KZT_PATCH_TARGET_MAPLIB), "maplib");
    check_string("target-source.guest",
                 KztPatchTargetSourceName(KZT_PATCH_TARGET_GUEST_OWNER),
                 "guest-owner");
}

static void test_patch_decision_format(void)
{
    KztPatchDecision decision;
    char buffer[1024];
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
    decision.old_guest_object = "guest-libEGL.so.1";
    decision.old_guest_object_base = 0x5500;
    decision.maplib_bridge = 0x5800;
    decision.maplib_owner = "maplibegl";
    decision.maplib_owner_base = 0x5900;
    decision.maplib_owner_relation = KZT_PATCH_OWNER_RELATION_MISMATCH;
    decision.new_bridge = 0x6000;
    decision.new_owner = "wrappedlibegl";
    decision.new_owner_base = 0x7000;
    decision.guest_owner_bridge = 0x8000;
    decision.guest_owner_library = "libEGL.so.1";
    decision.guest_owner = "guest-libEGL.so.1";
    decision.guest_owner_base = 0x5500;
    decision.guest_owner_relation = KZT_PATCH_OWNER_RELATION_MATCH;
    decision.reason = KZT_PATCH_REASON_GLOBAL_SYMBOL;
    decision.owner_relation = KZT_PATCH_OWNER_RELATION_MISMATCH;
    decision.shadow_result = KZT_PATCH_SHADOW_MATCH;
    decision.target_source = KZT_PATCH_TARGET_GUEST_OWNER;

    size = KztFormatPatchDecision(buffer, sizeof(buffer), &decision);
    check_int("format.nonempty", size > 0, 1);
    check_int("format.contains-symbol",
              strstr(buffer, "symbol=eglGetProcAddress") != NULL, 1);
    check_int("format.contains-reason",
              strstr(buffer, "reason=global-symbol") != NULL, 1);
    check_int("format.contains-bridge",
              strstr(buffer, "new_bridge=0x6000") != NULL, 1);
    check_int("format.contains-maplib-bridge",
              strstr(buffer, "maplib_bridge=0x5800") != NULL, 1);
    check_int("format.contains-maplib-owner",
              strstr(buffer, "maplib_owner=maplibegl") != NULL, 1);
    check_int("format.contains-maplib-owner-relation",
              strstr(buffer, "maplib_owner_relation=mismatch") != NULL, 1);
    check_int("format.contains-guest-object",
              strstr(buffer, "old_guest_object=guest-libEGL.so.1") != NULL,
              1);
    check_int("format.contains-owner-relation",
              strstr(buffer, "owner_relation=mismatch") != NULL, 1);
    check_int("format.contains-guest-owner-bridge",
              strstr(buffer, "guest_owner_bridge=0x8000") != NULL, 1);
    check_int("format.contains-guest-owner-library",
              strstr(buffer, "guest_owner_library=libEGL.so.1") != NULL, 1);
    check_int("format.contains-guest-owner-relation",
              strstr(buffer, "guest_owner_relation=match") != NULL, 1);
    check_int("format.contains-shadow-result",
              strstr(buffer, "shadow_result=match") != NULL, 1);
    check_int("format.contains-target-source",
              strstr(buffer, "target_source=guest-owner") != NULL, 1);
}

static void test_patch_decision_select_guest_owner(void)
{
    KztPatchDecision decision;

    KztPatchDecisionInit(&decision);
    decision.old_guest_object = "/guest/old-guest.so";
    KztPatchDecisionSetMaplibTarget(&decision, 0x1000, "maplib-owner",
                                    0x2000);
    decision.guest_owner_bridge = 0x3000;
    decision.guest_owner_library = "libold-guest.so";
    decision.guest_owner = "old-guest.so";
    decision.guest_owner_base = 0x4000;

    KztPatchDecisionSelectGuestOwnerTarget(&decision);

    check_int("select-guest.has-target", KztPatchDecisionHasTarget(&decision),
              1);
    check_int("select-guest.bridge", decision.new_bridge, 0x3000);
    check_string("select-guest.owner", decision.new_owner, "old-guest.so");
    check_int("select-guest.owner-base", decision.new_owner_base, 0x4000);
    check_int("select-guest.owner-relation", decision.owner_relation,
              KZT_PATCH_OWNER_RELATION_MATCH);
    check_int("select-guest.source", decision.target_source,
              KZT_PATCH_TARGET_GUEST_OWNER);
    check_int("select-guest.maplib-preserved", decision.maplib_bridge,
              0x1000);
    check_string("select-guest.maplib-owner-preserved",
                 decision.maplib_owner, "maplib-owner");
}

static void test_patch_decision_maplib_target(void)
{
    KztPatchDecision decision;

    KztPatchDecisionInit(&decision);
    decision.old_guest_object = "/guest/libEGL.so.1";

    KztPatchDecisionSetMaplibTarget(&decision, 0x1000, "libEGL.so.1",
                                    0x2000);

    check_int("maplib-target.has-target", KztPatchDecisionHasTarget(&decision),
              1);
    check_int("maplib-target.maplib-bridge", decision.maplib_bridge, 0x1000);
    check_string("maplib-target.maplib-owner", decision.maplib_owner,
                 "libEGL.so.1");
    check_int("maplib-target.maplib-owner-base", decision.maplib_owner_base,
              0x2000);
    check_int("maplib-target.maplib-relation", decision.maplib_owner_relation,
              KZT_PATCH_OWNER_RELATION_MATCH);
    check_int("maplib-target.new-bridge", decision.new_bridge, 0x1000);
    check_string("maplib-target.new-owner", decision.new_owner,
                 "libEGL.so.1");
    check_int("maplib-target.new-owner-base", decision.new_owner_base,
              0x2000);
    check_int("maplib-target.owner-relation", decision.owner_relation,
              KZT_PATCH_OWNER_RELATION_MATCH);
    check_int("maplib-target.source", decision.target_source,
              KZT_PATCH_TARGET_MAPLIB);
}

static void test_patch_decision_guest_owner_result(void)
{
    KztPatchDecision decision;

    KztPatchDecisionInit(&decision);
    KztPatchDecisionSetGuestOwnerFailure(&decision,
                                         KZT_PATCH_SHADOW_NO_WRAPPER);
    check_int("guest-result.failure", decision.shadow_result,
              KZT_PATCH_SHADOW_NO_WRAPPER);

    KztPatchDecisionInit(&decision);
    decision.maplib_bridge = 0x1000;
    decision.new_bridge = decision.maplib_bridge;
    KztPatchDecisionSetGuestOwnerTarget(&decision, 0x1000, "libc.so.6",
                                        "libc-owner", 0x2000, 0);
    check_int("guest-result.match", decision.shadow_result,
              KZT_PATCH_SHADOW_MATCH);
    check_int("guest-result.match-relation", decision.guest_owner_relation,
              KZT_PATCH_OWNER_RELATION_MAPLIB_ONLY);
    check_int("guest-result.match-source", decision.target_source,
              KZT_PATCH_TARGET_MAPLIB);

    KztPatchDecisionSetGuestOwnerTarget(&decision, 0x3000, "libc.so.6",
                                        "libc-owner", 0x4000, 0);
    check_int("guest-result.mismatch", decision.shadow_result,
              KZT_PATCH_SHADOW_MISMATCH);

    KztPatchDecisionInit(&decision);
    decision.old_guest_object = "/guest/libc.so.6";
    KztPatchDecisionSetGuestOwnerTarget(&decision, 0x5000, "libc.so.6",
                                        "libc.so.6", 0x6000, 1);
    check_int("guest-result.no-maplib", decision.shadow_result,
              KZT_PATCH_SHADOW_NO_MAPLIB_TARGET);
    check_int("guest-result.no-maplib-source", decision.target_source,
              KZT_PATCH_TARGET_GUEST_OWNER);
    check_int("guest-result.no-maplib-bridge", decision.new_bridge, 0x5000);
    check_int("guest-result.no-maplib-relation", decision.owner_relation,
              KZT_PATCH_OWNER_RELATION_MATCH);
    check_int("guest-result.no-maplib-guest-relation",
              decision.guest_owner_relation, KZT_PATCH_OWNER_RELATION_MATCH);
}

int main(void)
{
    test_patch_decision_defaults();
    test_patch_decision_names();
    test_patch_decision_format();
    test_patch_decision_maplib_target();
    test_patch_decision_select_guest_owner();
    test_patch_decision_guest_owner_result();

    if (failures)
        return 1;

    puts("KZT guestpatch tests passed");
    return 0;
}
