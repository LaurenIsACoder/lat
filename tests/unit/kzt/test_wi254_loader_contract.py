#!/usr/bin/env python3
import pathlib
import re
import sys


root = pathlib.Path(sys.argv[1])
context = root / "target/i386/latx/context"
include = root / "target/i386/latx/include"


def read(path):
    return path.read_text(encoding="utf-8")


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


binding = read(context / "kzt_guest_library_binding.c")
box_header = read(include / "box64context.h")
box_context = read(context / "box64context.c")
library = read(context / "library.c")
librarian = read(context / "librarian.c")
elfloader = read(context / "elfloader.c")
wrapped_dl = read(context / "wrappedlibdl.c")
wrapped_libc = read(context / "wrappedlibc.c")
guest_dl_api = read(context / "kzt_guest_dl_api.c")

# No process-lifetime registry/gate/singleton is permitted.
for forbidden in ("call_gate", "gate_next", "call_gate_bindings"):
    assert forbidden not in binding, forbidden
assert "kzt_guest_library_access_t kzt_guest_library_access;" in box_header
assert "KztGuestLibraryLookupForContext" in box_context
assert "kzt_guest_library_access_begin_teardown" in box_context

# Both exports use one guest-first implementation.  Wrapper attachment consumes
# the exact AddNeeded result only after guest success and never replaces the
# guest handle.
for name, text in (("wrappedlibdl", wrapped_dl), ("wrappedlibc", wrapped_libc)):
    body = function_body(
        text, "void* my_dlopen(void *filename, int flag){")
    assert "kzt_guest_dl_api_dlopen" in body, name
    assert "AddNeededLibWithLibrary" not in body, name
    assert "dlopen_recycle_transaction" not in body, name

shared_open = function_body(
    guest_dl_api, "uint64_t kzt_guest_dl_api_dlopen(")
guest_open = shared_open.index("kzt_guest_library_run_dlopen_scoped")
attach = shared_open.index("AddNeededLibWithLibrary", guest_open)
finish = shared_open.index(
    "kzt_guest_dl_api_finish_dlopen_scoped", attach)
assert guest_open < attach < finish
assert "&library" in shared_open
assert "return guest_handle" in shared_open
assert "GetLibInternal" not in shared_open
assert "kzt_guest_library_loader_scope_begin" not in shared_open
assert "kzt_guest_library_loader_scope_end" not in shared_open
assert "RunFunctionWithState" not in shared_open

# Loader publication remains shared, while symbol lookup no longer performs a
# hidden reopen.  Both exports use the shared guest-authoritative lookup.
for name, text in (("wrappedlibdl", wrapped_dl), ("wrappedlibc", wrapped_libc)):
    dlsym_body = function_body(
        text, "void* my_dlsym(void *handle, void *symbol)\n{")
    assert "kzt_guest_dl_api_dlsym" in dlsym_body, name
    assert "run_guest_dlopen_scoped" not in dlsym_body, name
    assert "AddNeededLib" not in dlsym_body, name

shared_dlsym = function_body(
    guest_dl_api,
    "kzt_guest_dl_symbol_result_t kzt_guest_dl_api_dlsym(",
)
guest_lookup = shared_dlsym.index("kzt_guest_library_run_dlsym")
select = shared_dlsym.index(
    "kzt_guest_library_select_symbol_result", guest_lookup)
assert guest_lookup < select

# Reload cannot reactivate or publish until all failure-returning reload work
# has completed.
reload_body = function_body(library, "int ReloadLibrary(library_t* lib)")
reactivate = reload_body.index("kzt_guest_library_reactivate")
assert reload_body.rfind("return 1", 0, reactivate) >= 0
assert reload_body.index("RelocateElfPlt") < reactivate
assert reload_body.index("kzt_guest_library_note_loader_pair", reactivate) > reactivate

# A production library is tracked before it can become visible.  Tracking is
# metadata only: failure preserves the established loader path.  Inactivation
# and final free use only the exact x86 link_map hint, closing and then removing
# any binding before the library allocation can disappear.
native_init = function_body(library, "static void initNativeLib(")
assert "(void)kzt_guest_library_track(" in native_init
assert "KztGuestLibraryBindingsForContext(context), lib" in native_init
inactive_body = function_body(library, "void InactiveLibrary(library_t* lib)")
assert "kzt_guest_library_inactivate(" in inactive_body
assert "KztGuestLibraryBindingsForContext(lib->context)" in inactive_body
assert "KztGuestRegistryForContext(lib->context)" in inactive_body
assert "(uintptr_t)lib->x86linkmap" in inactive_body
free_body = function_body(library, "void Free1Library(library_t **lib)")
assert "kzt_guest_library_unbind(" in free_body
assert "KztGuestLibraryBindingsForContext((*lib)->context)" in free_body
assert "KztGuestRegistryForContext((*lib)->context)" in free_body
assert "(uintptr_t)(*lib)->x86linkmap" in free_body
assert free_body.index("kzt_guest_library_unbind(") < free_body.index(
    "box_free(*lib)"
)

# The real PLT loader uses the tested status seam and returns before resolver
# injection when the underlying RELA worker fails.
plt_body = function_body(
    elfloader,
    "int RelocateElfPlt(lib_t *maplib, lib_t *local_maplib, int bindnow, elfheader_t* head)",
)
apply = plt_body.index("elf_plt_relocation_apply")
failure_return = plt_body.index("return -1", apply)
resolver = plt_body.index("if(need_resolver)")
assert apply < failure_return < resolver

# The exact API preserves AddNeededLib's historical return behavior while
# clearing output on failure and publishing only the final successful choice.
exact_body = function_body(librarian, "int AddNeededLibWithLibrary(")
assert "if (exact_library) *exact_library = NULL;" in exact_body
assert "if (!add_result && exact_library)" in exact_body
assert re.search(r"return\s+0\s*;", exact_body)

print("WI-254 loader/context white-box contract: PASS")
