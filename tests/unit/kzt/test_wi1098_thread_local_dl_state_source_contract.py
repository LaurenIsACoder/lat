#!/usr/bin/env python3
from pathlib import Path
import sys


root = Path(sys.argv[1]).resolve()
context_header = (
    root / "target/i386/latx/include/box64context.h"
).read_text(encoding="utf-8")
cpu_header = (root / "target/i386/cpu.h").read_text(encoding="utf-8")
cpu_source = (root / "target/i386/cpu.c").read_text(encoding="utf-8")
main_source = (root / "linux-user/main.c").read_text(encoding="utf-8")
box_context = (
    root / "target/i386/latx/context/box64context.c"
).read_text(encoding="utf-8")
dl_api = (
    root / "target/i386/latx/context/kzt_guest_dl_api.c"
).read_text(encoding="utf-8")
dl_init = (
    root / "target/i386/latx/context/kzt_guest_dl_init.c"
).read_text(encoding="utf-8")
latx_config = (
    root / "target/i386/latx/latx-config.c"
).read_text(encoding="utf-8")
myalign = (
    root / "target/i386/latx/context/myalign.c"
).read_text(encoding="utf-8")
wrapped_sources = [
    (
        root / "target/i386/latx/context/wrappedlibc.c"
    ).read_text(encoding="utf-8"),
    (
        root / "target/i386/latx/context/wrappedlibdl.c"
    ).read_text(encoding="utf-8"),
]

if "kzt_guest_dlerror_state_t kzt_guest_dlerror_state;" not in cpu_header:
    raise AssertionError("x86_64 CPU state does not own dlerror state")
if "memset(&new_env->kzt_guest_dlerror_state" not in main_source:
    raise AssertionError("cpu_copy inherits the parent dlerror owner")
if "new_env->kzt_guest_dlerror_state.dlerror_slow_required = 0" not in main_source:
    raise AssertionError("new guest thread does not initialize dlerror clean state")
if "kzt_guest_dl_api_free_errors(&cpu->env.kzt_guest_dlerror_state)" not in cpu_source:
    raise AssertionError("CPU destruction does not release thread dlerror state")
reset_start = cpu_source.find("static void x86_cpu_reset(DeviceState *dev)")
reset_end = cpu_source.find("\n#ifndef CONFIG_USER_ONLY", reset_start)
reset_body = cpu_source[reset_start:reset_end]
reset_clear = reset_body.find("memset(env, 0, offsetof(CPUX86State, end_reset_fields))")
reset_clean = reset_body.find(
    "env->kzt_guest_dlerror_state.dlerror_slow_required = 0"
)
if min(reset_start, reset_end, reset_clear, reset_clean) < 0 or \
        reset_clear >= reset_clean:
    raise AssertionError("CPU reset does not reinitialize dlerror clean state")
if "dl->legacy_error.dlerror_slow_required = 1" not in box_context:
    raise AssertionError("legacy dlerror owner does not initialize conservatively")
if "kzt_guest_dl_api_bind_current_thread(&env->kzt_guest_dlerror_state)" \
        not in latx_config:
    raise AssertionError("LATX thread initialization does not bind the dlerror fast mirror")

if "kzt_guest_dl_entry_state_t guest_dl_entries;" not in context_header:
    raise AssertionError("context does not own the guest dl entry publication state")
if "kzt_guest_dl_api_entry_state_destroy(ctx->dlprivate)" not in box_context:
    raise AssertionError("context destruction does not close guest dl initialization")

for source in wrapped_sources:
    if "init_x86dlfun" in source:
        raise AssertionError("libc/libdl still has a private guest dl initializer")
    if "kzt_guest_dl_entries_for_call(my_context" not in source:
        raise AssertionError("libc/libdl does not share the guest dl initializer")
    if "#define CLEARERR guest_error_was_clean = " \
            "kzt_guest_dl_api_begin_call(error_state);" not in source or \
            source.count("\n    CLEARERR") < 8:
        raise AssertionError("libc/libdl does not conservatively begin every guest DL call")
    if source.count("kzt_guest_dl_api_finish_success(") < 7:
        raise AssertionError("libc/libdl does not preserve clean state after proven success")
    start = source.find("char* my_dlerror(void)\n{")
    end = source.find("\nint my_dladdr1", start)
    if start < 0 or end < 0:
        raise AssertionError("libc/libdl dlerror wrapper is missing")
    dlerror_body = source[start:end]
    state_check = dlerror_body.find("if (fast_result)")
    slow = dlerror_body.find("kzt_guest_dlerror_slow_path(")
    fast_return = dlerror_body.find("return fast_result;")
    if min(state_check, slow, fast_return) < 0 or not (
            state_check < slow < fast_return):
        raise AssertionError(
            "dlerror does not isolate conservative state on the cold path"
        )
    if "char *fast_result" not in dlerror_body:
        raise AssertionError("dlerror clean state is not returned without materialization")
    if "#define DLERROR_FAST_RESULT() " \
            "kzt_guest_dl_api_current_fast_result()" not in source or \
            "DLERROR_FAST_RESULT()" not in dlerror_body:
        raise AssertionError("dlerror hot path still dereferences the CPU state owner")
    if "kzt_guest_dl_entries_t fallback" in dlerror_body:
        raise AssertionError("hot dlerror wrapper retains cold fallback state")
    for field in (
        "->x86dlopen",
        "->x86dlmopen",
        "->x86dlsym",
        "->x86dlclose",
        "->x86dladdr",
        "->x86dladdr1",
        "->x86dlinfo",
        "->x86dlvsym",
        "->x86dlerror",
    ):
        if field in source:
            raise AssertionError(f"wrapper still observes mutable field {field}")

for required in (
    "kzt_guest_dl_entries_t local = { 0 };",
    "kzt_guest_dl_entries_complete(&local)",
    "__ATOMIC_RELEASE",
    "__ATOMIC_ACQUIRE",
    "pthread_equal(state->initializer, pthread_self())",
    "state->teardown",
    "state->slow_users",
):
    if required not in dl_api:
        raise AssertionError(f"guest dl publication lacks {required}")

if dl_init.count("freeElfFromFile(&header)") != 2:
    raise AssertionError("guest dl resolver does not release transient headers")
if "FindInCollection(path, &context->box64_ld_lib)" not in dl_init:
    raise AssertionError("guest dl resolver retry duplicates the hwcaps path")
if "kzt_wine_init_x86(opaque, entries->dlsym)" not in dl_init:
    raise AssertionError("guest dl prepare is not bound to the owning context")
for required in (
    "load_addr = h ? loadSoaddrFromMap(tmp) : 0;",
    "if (!h || !load_addr)",
    "void freeElfFromFile(elfheader_t **header)",
    "box_free(tmp);",
):
    if required not in myalign:
        raise AssertionError(f"safe guest ELF retry lacks {required}")

print("WI-1098 thread-local guest dl state source contract: PASS")
