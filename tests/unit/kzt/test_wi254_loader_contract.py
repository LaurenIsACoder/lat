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

# No process-lifetime registry/gate/singleton is permitted.
for forbidden in ("call_gate", "gate_next", "call_gate_bindings"):
    assert forbidden not in binding, forbidden
assert "kzt_guest_library_access_t kzt_guest_library_access;" in box_header
assert "KztGuestLibraryLookupForContext" in box_context
assert "kzt_guest_library_access_begin_teardown" in box_context

# Both real wrapped dlopen implementations consume the exact AddNeeded result
# directly and never perform a second name lookup for the selected instance.
for name, text in (("wrappedlibdl", wrapped_dl), ("wrappedlibc", wrapped_libc)):
    body = function_body(text, "void* my_dlopen(void *filename, int flag){")
    assert "AddNeededLibWithLibrary" in body, name
    assert "lib = GetLibInternal(rfilename)" not in body, name
    assert "&lib) || !lib" in body, name
    assert "dlopen_recycle_transaction(" in body, name
    assert "recycle_prepare" in body, name
    assert "recycle_rollback" in body, name
    reset = function_body(
        text,
        "static void recycle_reset_loader_state(dlopen_recycle_context_t *recycle)",
    )
    for cleared in (
        "recycle->library->x86linkmap = NULL",
        "recycle->header->delta = 0",
        "lm->l_addr = 0",
        "LatxResetElf(recycle->header)",
    ):
        assert cleared in reset, (name, cleared)
    call = function_body(text, "static int callx86dlopen(")
    assert "h->delta = ret->l_addr" in call, name
    assert "lm->l_addr = ret->l_addr" in call, name
    assert "h->latx_hasfix = 1" in call, name
    fixed = call.index("h->latx_hasfix = 1")
    finish = call.index("finish_guest_dlopen_scoped", fixed)
    assert fixed < finish, name

# Both redlopen success branches publish the exact returned link_map/library
# pair before the follow-up x86 dlsym.
for name, text in (("wrappedlibdl", wrapped_dl), ("wrappedlibc", wrapped_libc)):
    finish_body = function_body(text, "static void finish_guest_dlopen_scoped(")
    assert "kzt_guest_library_publish_loader_pair_scoped" in finish_body, name
    assert "kzt_guest_library_publish_loader_observed_scoped" in finish_body, name
    assert finish_body.index("publish_loader_pair_scoped") < \
        finish_body.index("loader_scope_end"), name
    redlopen = text.index("//redlopen")
    publish = text.index("finish_guest_dlopen_scoped(", redlopen)
    dlsym = text.index("x86dlsym", publish)
    assert redlopen < publish < dlsym, name

# Reload cannot reactivate or publish until all failure-returning reload work
# has completed.
reload_body = function_body(library, "int ReloadLibrary(library_t* lib)")
reactivate = reload_body.index("kzt_guest_library_reactivate")
assert reload_body.rfind("return 1", 0, reactivate) >= 0
assert reload_body.index("RelocateElfPlt") < reactivate
assert reload_body.index("kzt_guest_library_note_loader_pair", reactivate) > reactivate

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
