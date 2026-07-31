#!/usr/bin/env python3
import pathlib
import sys


def body(text, signature):
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


root = pathlib.Path(sys.argv[1]).resolve()
registry_h = (root / "target/i386/latx/include/kzt_guest_registry.h").read_text()
registry = (root / "target/i386/latx/context/kzt_guest_registry.c").read_text()
adapter = (root / "target/i386/latx/context/kzt_observation_adapter.c").read_text()
myalign = (root / "target/i386/latx/context/myalign.c").read_text()
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text()
dl_api = (root / "target/i386/latx/context/kzt_guest_dl_api.c").read_text()
meson = (root / "target/i386/latx/context/meson.build").read_text()

for required in (
    "KZT_GUEST_GOT_PLT_INJECTION_APPLYING",
    "kzt_guest_registry_got_plt_injection_claim(",
    "kzt_guest_registry_got_plt_injection_finish(",
    "kzt_guest_registry_got_plt_injection_claimed(",
):
    if required not in registry_h:
        raise AssertionError(f"Registry lacks per-generation injection state: {required}")

claim = body(registry, "kzt_guest_registry_got_plt_injection_claim(")
for required in (
    "kzt_registry_got_plt_view_complete(view)",
    "KZT_GUEST_GOT_PLT_INJECTION_APPLYING",
    "KZT_GUEST_GOT_PLT_INJECTION_ALREADY_APPLIED",
    "KZT_GUEST_GOT_PLT_INJECTION_IN_PROGRESS",
):
    if required not in claim:
        raise AssertionError(f"claim loses exact fail-open behavior: {required}")

callback = body(adapter, "int kzt_observe_guest_object_from_callback(")
observe = callback.find("kzt_observe_guest_object(request,")
per_object = callback.find("request->per_object_flow(")
legacy = callback.find("request->legacy_flow(request->link_map_addr,")
if not (0 <= observe < per_object):
    raise AssertionError("per-object injection is not ordered after observation")
if "observation_result == KZT_OBSERVATION_ADAPTER_ADDED" not in callback or \
        "observation_result == KZT_OBSERVATION_ADAPTER_UPDATED" not in callback:
    raise AssertionError("per-object injection is not limited to committed objects")
if "observation_result == KZT_OBSERVATION_ADAPTER_CONFLICT" in callback[
        per_object - 160:per_object + 80]:
    raise AssertionError("per-object injection accepts conflicted objects")

hook = body(myalign, "static int kzt_tb_callback_per_object_got_plt(")
for required in (
    "kzt_per_object_got_plt_apply(",
    ".apply = KztPerObjectGotPltWrite,",
    "kzt_tb_callback_materialize_binding(link_map_addr, opaque)",
):
    if required not in hook:
        raise AssertionError(f"loader hook misses new injection handoff: {required}")

writer = body(elfloader, "int KztPerObjectGotPltWrite(")
for required in (
    "view->status != KZT_GUEST_DYNAMIC_COMPLETE",
    "kzt_per_object_dynamic_field_runtime(&view->pltgot",
    "kzt_per_object_plt_layout(jmprel_runtime, pltrelsz, load_bias",
    "head->plt = plt_start",
    "guest_link_map != link_map_addr",
    "kzt_guest_registry_publish_lazy_resolver(",
    "kzt_elfloader_write_guest_word(resolver.link_map_slot",
    "kzt_elfloader_write_guest_word(resolver.resolver_slot",
):
    if required not in writer:
        raise AssertionError(f"runtime Dynamic View writer lacks {required}")
for forbidden in ("LoadAndCheckElfHeader", "LoadNeededLibs", "RelocateElfPlt("):
    if forbidden in writer:
        raise AssertionError(f"new writer must not depend on legacy flow: {forbidden}")

relocate = body(elfloader, "int RelocateElfPlt(")
if "kzt_per_object_got_plt_apply(&request, &result)" not in relocate:
    raise AssertionError("main/object RelocateElfPlt path does not enter new chain")
if "kzt_guest_registry_got_plt_injection_claimed(" not in relocate:
    raise AssertionError("RelocateElfPlt does not suppress a duplicate claimed write")

close = body(dl_api, "int kzt_guest_dl_api_dlclose(")
if "KztPerObjectGotPltRelease(" in close:
    raise AssertionError("dlclose releases runtime state without an unload fact")

unload = body(dl_api, "int kzt_guest_dl_api_publish_unload(")
retire = unload.find("kzt_guest_registry_finish_loader_unload(")
release = unload.find("KztPerObjectGotPltRelease(lazy_resolver.object_head)")
if not (0 <= retire < release):
    raise AssertionError(
        "precise unload does not release the Registry-owned runtime header"
    )

prepare = body(dl_api, "int kzt_guest_dl_api_prepare_unload(")
if "kzt_guest_registry_begin_loader_unload(" not in prepare:
    raise AssertionError("RT_DELETE does not close Registry lease admission")

if "'kzt_per_object_got_plt.c'" not in meson:
    raise AssertionError("per-object module is not linked into production")

print("WI-1056 per-object GOT/PLT source contract: PASS")
