#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 /path/to/latx-x86_64 [guest-ld-prefix]" >&2
    exit 2
fi

latx=$1
ld_prefix=${2:-/usr/gnemul/lat-x86_64}

if [ ! -x "$latx" ]; then
    echo "missing executable LATX binary: $latx" >&2
    exit 2
fi
case $latx in
    /*) ;;
    *) latx=$(pwd)/$latx ;;
esac

if ! command -v clang >/dev/null 2>&1; then
    echo "skip: clang is required to build x86_64 guest fixtures" >&2
    exit 77
fi

if [ ! -e "$ld_prefix/lib64/ld-linux-x86-64.so.2" ] &&
   [ ! -e "$ld_prefix/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ]; then
    echo "skip: x86_64 guest loader not found under $ld_prefix" >&2
    exit 77
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/latx-kzt-loader.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

guest_lib_dir="$ld_prefix/usr/lib/x86_64-linux-gnu"

run_guest()
{
    name=$1
    expected=$2
    program=$3
    workdir=${4:-}

    set +e
    if [ -n "$workdir" ]; then
        (cd "$workdir" && LATX_KZT=1 "$latx" -L "$ld_prefix" "$program") \
            >"$tmpdir/$name.out" 2>"$tmpdir/$name.err"
    else
        LATX_KZT=1 "$latx" -L "$ld_prefix" "$program" \
            >"$tmpdir/$name.out" 2>"$tmpdir/$name.err"
    fi
    status=$?
    set -e

    if [ "$status" -ne "$expected" ]; then
        echo "$name failed: expected exit $expected, got $status" >&2
        cat "$tmpdir/$name.err" >&2
        exit 1
    fi
}

cat >"$tmpdir/dynamic-no-needed-exit.S" <<'EOF'
    .global _start
_start:
    mov $60, %rax
    mov $42, %rdi
    syscall
EOF

if ! clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        "$tmpdir/dynamic-no-needed-exit.S" \
        -o "$tmpdir/dynamic-no-needed-exit" \
        >"$tmpdir/clang.out" 2>"$tmpdir/clang.err"; then
    echo "skip: failed to build x86_64 no-NEEDED guest fixture" >&2
    cat "$tmpdir/clang.err" >&2
    exit 77
fi

run_guest dynamic-no-needed 42 "$tmpdir/dynamic-no-needed-exit"

if [ -e "$guest_lib_dir/libc.so.6" ] && [ -e "$guest_lib_dir/libdl.so.2" ]; then
    cat >"$tmpdir/helper.S" <<'EOF'
    .text
    .global helper_value
helper_value:
    mov $5, %eax
    ret
EOF

    cat >"$tmpdir/plugin.S" <<'EOF'
    .text
    .global plugin_value
plugin_value:
    call helper_value@PLT
    add $118, %eax
    ret
EOF

    cat >"$tmpdir/mixed-main.S" <<EOF
    .global _start
_start:
    lea plugin_path(%rip), %rdi
    mov \$2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_open
    mov %rax, %r12
    lea plugin_path(%rip), %rdi
    mov \$2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_open
    mov %rax, %r13
    cmp %r12, %r13
    jne fail_reopen
    mov %rax, %rdi
    lea sym_name(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_sym
    call *%rax
    cmp \$123, %eax
    jne fail_call
    mov %r13, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_close
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_close
    lea plugin_path(%rip), %rdi
    mov \$2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_reopen_after_close
    mov %rax, %r12
    mov %rax, %rdi
    lea sym_name(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_sym_after_close
    call *%rax
    cmp \$123, %eax
    jne fail_call_after_close
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_close_after_reopen
    lea plugin_path(%rip), %rdi
    mov \$0x102, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_global_open
    mov %rax, %r12
    xor %rdi, %rdi
    lea sym_name(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_global_sym
    call *%rax
    cmp \$123, %eax
    jne fail_global_call
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_global_close
    mov \$-1, %rdi
    lea plugin_path(%rip), %rsi
    mov \$2, %edx
    call dlmopen@PLT
    test %rax, %rax
    je fail_dlmopen
    mov %rax, %r12
    mov %rax, %rdi
    mov \$1, %esi
    lea lmid_slot(%rip), %rdx
    call dlinfo@PLT
    test %eax, %eax
    jne fail_dlmopen_lmid
    mov lmid_slot(%rip), %rax
    test %rax, %rax
    je fail_dlmopen_lmid
    mov %r12, %rdi
    lea sym_name(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_dlmopen_sym
    call *%rax
    cmp \$123, %eax
    jne fail_dlmopen_call
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_dlmopen_close
    xor %edi, %edi
    call exit@PLT
fail_open:
    mov \$93, %edi
    call exit@PLT
fail_sym:
    mov \$94, %edi
    call exit@PLT
fail_call:
    mov \$95, %edi
    call exit@PLT
fail_reopen:
    mov \$96, %edi
    call exit@PLT
fail_reopen_after_close:
    mov \$97, %edi
    call exit@PLT
fail_sym_after_close:
    mov \$98, %edi
    call exit@PLT
fail_call_after_close:
    mov \$99, %edi
    call exit@PLT
fail_global_open:
    mov \$100, %edi
    call exit@PLT
fail_global_sym:
    mov \$101, %edi
    call exit@PLT
fail_global_call:
    mov \$102, %edi
    call exit@PLT
fail_close:
    mov \$107, %edi
    call exit@PLT
fail_close_after_reopen:
    mov \$108, %edi
    call exit@PLT
fail_global_close:
    mov \$109, %edi
    call exit@PLT
fail_dlmopen:
    mov \$110, %edi
    call exit@PLT
fail_dlmopen_lmid:
    mov \$111, %edi
    call exit@PLT
fail_dlmopen_sym:
    mov \$112, %edi
    call exit@PLT
fail_dlmopen_call:
    mov \$113, %edi
    call exit@PLT
fail_dlmopen_close:
    mov \$114, %edi
    call exit@PLT
    .section .rodata
plugin_path:
    .asciz "$tmpdir/libplugin.so"
sym_name:
    .asciz "plugin_value"
    .bss
    .align 8
lmid_slot:
    .quad 0
EOF

    clang --target=x86_64-linux-gnu -nostdlib -shared -fPIC -fuse-ld=lld \
        "$tmpdir/helper.S" -Wl,-soname,libhelper.so \
        -o "$tmpdir/libhelper.so"
    clang --target=x86_64-linux-gnu -nostdlib -shared -fPIC -fuse-ld=lld \
        "$tmpdir/plugin.S" -L"$tmpdir" -lhelper -Wl,-rpath,"$tmpdir" \
        -o "$tmpdir/libplugin.so"
    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        "$tmpdir/mixed-main.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/mixed-main"

    run_guest mixed-soname-dlopen-dlsym 0 "$tmpdir/mixed-main"

    cat >"$tmpdir/self-main.S" <<'EOF'
    .text
    .global _start
_start:
    xor %edi, %edi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_self_open
    mov %rax, %r12
    xor %edi, %edi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_self_reopen
    cmp %r12, %rax
    jne fail_self_reopen
    mov %rax, %rdi
    lea self_sym(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_self_sym
    call *%rax
    cmp $77, %eax
    jne fail_self_call
    xor %edi, %edi
    call exit@PLT
fail_self_open:
    mov $103, %edi
    call exit@PLT
fail_self_reopen:
    mov $104, %edi
    call exit@PLT
fail_self_sym:
    mov $105, %edi
    call exit@PLT
fail_self_call:
    mov $106, %edi
    call exit@PLT
    .global self_value
    .type self_value,@function
self_value:
    mov $77, %eax
    ret
    .section .rodata
self_sym:
    .asciz "self_value"
EOF

    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        -Wl,--export-dynamic \
        "$tmpdir/self-main.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/self-main"

    run_guest self-dlopen-dlsym 0 "$tmpdir/self-main"

    cat >"$tmpdir/dladdr-main.S" <<'EOF'
    .text
    .global _start
_start:
    sub $64, %rsp
    lea dladdr_target(%rip), %rdi
    mov %rsp, %rsi
    call dladdr@PLT
    test %eax, %eax
    je fail_dladdr
    add $64, %rsp
    xor %edi, %edi
    call exit@PLT
fail_dladdr:
    add $64, %rsp
    mov $112, %edi
    call exit@PLT
dladdr_target:
    ret
EOF

    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        -Wl,--export-dynamic \
        "$tmpdir/dladdr-main.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/dladdr-main"

    run_guest dladdr-explicit-args 0 "$tmpdir/dladdr-main"

    cat >"$tmpdir/dlinfo-main.S" <<'EOF'
    .text
    .global _start
_start:
    xor %edi, %edi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_open
    mov %rax, %rdi
    mov $2, %esi
    lea link_map_slot(%rip), %rdx
    call dlinfo@PLT
    test %eax, %eax
    jne fail_dlinfo
    mov link_map_slot(%rip), %rax
    test %rax, %rax
    je fail_link_map
    xor %edi, %edi
    call exit@PLT
fail_open:
    mov $113, %edi
    call exit@PLT
fail_dlinfo:
    mov $114, %edi
    call exit@PLT
fail_link_map:
    mov $115, %edi
    call exit@PLT
    .bss
    .align 8
link_map_slot:
    .quad 0
EOF

    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        "$tmpdir/dlinfo-main.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/dlinfo-main"

    run_guest dlinfo-linkmap 0 "$tmpdir/dlinfo-main"

    cat >"$tmpdir/dlvsym-main.S" <<'EOF'
    .text
    .global _start
_start:
    lea missing_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    jne fail_missing_open
    call dlerror@PLT
    test %rax, %rax
    je fail_missing_error
    xor %edi, %edi
    lea exit_sym(%rip), %rsi
    lea bad_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    jne fail_bad_version
    call dlerror@PLT
    test %rax, %rax
    je fail_bad_version_error
    xor %edi, %edi
    lea exit_sym(%rip), %rsi
    lea good_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    je fail_good_version
    mov $-1, %rdi
    lea exit_sym(%rip), %rsi
    lea bad_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    jne fail_next_bad_version
    call dlerror@PLT
    test %rax, %rax
    je fail_next_bad_version_error
    mov $-1, %rdi
    lea exit_sym(%rip), %rsi
    lea good_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    je fail_next_good_version
    lea plugin_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_plugin_open
    mov %rax, %r12
    mov %rax, %rdi
    lea plugin_sym(%rip), %rsi
    lea bad_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    jne fail_handle_bad_version
    mov %r12, %rdi
    lea plugin_sym(%rip), %rsi
    lea plugin_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    je fail_handle_good_version
    xor %edi, %edi
    call exit@PLT
fail_bad_version:
    mov $116, %edi
    call exit@PLT
fail_bad_version_error:
    mov $121, %edi
    call exit@PLT
fail_good_version:
    mov $117, %edi
    call exit@PLT
fail_plugin_open:
    mov $118, %edi
    call exit@PLT
fail_handle_bad_version:
    mov $119, %edi
    call exit@PLT
fail_handle_good_version:
    mov $120, %edi
    call exit@PLT
fail_missing_open:
    mov $122, %edi
    call exit@PLT
fail_missing_error:
    mov $123, %edi
    call exit@PLT
fail_next_bad_version:
    mov $124, %edi
    call exit@PLT
fail_next_bad_version_error:
    mov $125, %edi
    call exit@PLT
fail_next_good_version:
    mov $126, %edi
    call exit@PLT
    .section .rodata
exit_sym:
    .asciz "exit"
missing_name:
    .asciz "./libdoesnotexist-kzt.so"
plugin_name:
    .asciz "./libversplugin.so"
plugin_sym:
    .asciz "versioned_value"
bad_ver:
    .asciz "GLIBC_999.0"
good_ver:
    .asciz "GLIBC_2.2.5"
plugin_ver:
    .asciz "VERS_1"
EOF

    cat >"$tmpdir/vers-plugin.S" <<'EOF'
    .text
    .global versioned_value
versioned_value:
    mov $9, %eax
    ret
EOF

    cat >"$tmpdir/vers-plugin.map" <<'EOF'
VERS_1 {
    global: versioned_value;
};
EOF

    clang --target=x86_64-linux-gnu -nostdlib -shared -fPIC -fuse-ld=lld \
        "$tmpdir/vers-plugin.S" -Wl,--version-script,"$tmpdir/vers-plugin.map" \
        -Wl,-soname,libversplugin.so -o "$tmpdir/libversplugin.so"
    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        "$tmpdir/dlvsym-main.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/dlvsym-main"

    run_guest dlvsym-versioned-default 0 "$tmpdir/dlvsym-main" "$tmpdir"
else
    echo "skip: guest libc/libdl not found under $guest_lib_dir" >&2
fi

if [ -e "$guest_lib_dir/libGL.so.1" ] && [ -e "$guest_lib_dir/libEGL.so.1" ] &&
   [ -e "$guest_lib_dir/libc.so.6" ] && [ -e "$guest_lib_dir/libdl.so.2" ]; then
    cat >"$tmpdir/gl-egl-dlsym.S" <<'EOF'
    .global _start
_start:
    lea gl_name(%rip), %rdi
    mov $6, %esi
    call dlopen@PLT
    test %rax, %rax
    jne fail_gl_unloaded_noload
    lea gl_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_gl_open
    mov %rax, %r12
    mov %rax, %rdi
    mov $2, %esi
    lea gl_link_map_slot(%rip), %rdx
    call dlinfo@PLT
    test %eax, %eax
    jne fail_gl_dlinfo
    mov gl_link_map_slot(%rip), %rax
    test %rax, %rax
    je fail_gl_dlinfo
    cmp %r12, %rax
    jne fail_gl_dlopen_handle
    mov %rax, %rdi
    lea glx_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_gl_dlinfo_handle
    mov %r12, %rdi
    mov $1, %esi
    lea gl_lmid_slot(%rip), %rdx
    call dlinfo@PLT
    test %eax, %eax
    jne fail_gl_dlinfo_lmid
    mov %r12, %rax
    mov %rax, %rdi
    lea glx_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_gl_sym
    mov %r12, %rdi
    lea gl_missing_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    jne fail_gl_missing_sym
    call dlerror@PLT
    test %rax, %rax
    je fail_gl_missing_sym_error
    mov %r12, %rdi
    lea glx_proc(%rip), %rsi
    lea gl_bad_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    jne fail_gl_bad_dlvsym
    call dlerror@PLT
    test %rax, %rax
    je fail_gl_bad_dlvsym_error
    lea gl_name(%rip), %rdi
    mov $6, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_gl_noload
    cmp %r12, %rax
    jne fail_gl_noload
    mov %rax, %r13
    mov %r13, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_gl_noload_close
    mov %r12, %rdi
    lea glx_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_gl_noload_ref
    mov %r12, %rdi
    call dlclose@PLT
    mov %r12, %rdi
    lea glx_proc(%rip), %rsi
    lea gl_bad_ver(%rip), %rdx
    call dlvsym@PLT
    test %rax, %rax
    jne fail_gl_closed_dlvsym
    mov %r12, %rdi
    mov $2, %esi
    lea gl_link_map_slot(%rip), %rdx
    call dlinfo@PLT
    test %eax, %eax
    je fail_gl_closed_dlinfo
    call dlerror@PLT
    test %rax, %rax
    je fail_gl_closed_dlinfo_error
    call dlerror@PLT
    test %rax, %rax
    jne fail_gl_closed_dlinfo_error
    lea gl_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_gl_reopen
    mov %rax, %r12
    mov %rax, %rdi
    lea glx_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_gl_reopen_sym
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    jne fail_gl_reopen_close
    mov %r12, %rdi
    call dlclose@PLT
    test %eax, %eax
    je fail_gl_double_close

    lea egl_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_egl_open
    mov %rax, %r12
    mov %rax, %rdi
    lea egl_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_egl_sym
    mov %r12, %rdi
    call dlclose@PLT

    xor %edi, %edi
    call exit@PLT
fail_gl_open:
    mov $96, %edi
    call exit@PLT
fail_gl_unloaded_noload:
    mov $109, %edi
    call exit@PLT
fail_gl_sym:
    mov $97, %edi
    call exit@PLT
fail_gl_missing_sym:
    mov $118, %edi
    call exit@PLT
fail_gl_missing_sym_error:
    mov $119, %edi
    call exit@PLT
fail_gl_bad_dlvsym:
    mov $116, %edi
    call exit@PLT
fail_gl_bad_dlvsym_error:
    mov $117, %edi
    call exit@PLT
fail_gl_noload:
    mov $106, %edi
    call exit@PLT
fail_gl_noload_close:
    mov $107, %edi
    call exit@PLT
fail_gl_noload_ref:
    mov $108, %edi
    call exit@PLT
fail_gl_dlinfo:
    mov $100, %edi
    call exit@PLT
fail_gl_dlopen_handle:
    mov $115, %edi
    call exit@PLT
fail_gl_dlinfo_handle:
    mov $111, %edi
    call exit@PLT
fail_gl_dlinfo_lmid:
    mov $110, %edi
    call exit@PLT
fail_gl_closed_dlinfo:
    mov $101, %edi
    call exit@PLT
fail_gl_closed_dlinfo_error:
    mov $114, %edi
    call exit@PLT
fail_gl_closed_dlvsym:
    mov $112, %edi
    call exit@PLT
fail_gl_reopen:
    mov $102, %edi
    call exit@PLT
fail_gl_reopen_sym:
    mov $103, %edi
    call exit@PLT
fail_gl_reopen_close:
    mov $104, %edi
    call exit@PLT
fail_gl_double_close:
    mov $105, %edi
    call exit@PLT
fail_egl_open:
    mov $98, %edi
    call exit@PLT
fail_egl_sym:
    mov $99, %edi
    call exit@PLT
    .section .rodata
gl_name:
    .asciz "libGL.so.1"
glx_proc:
    .asciz "glXGetProcAddressARB"
gl_missing_proc:
    .asciz "kztDefinitelyMissingGLSymbol"
gl_bad_ver:
    .asciz "GLIBC_999.0"
egl_name:
    .asciz "libEGL.so.1"
egl_proc:
    .asciz "eglGetProcAddress"
    .bss
    .align 8
gl_link_map_slot:
    .quad 0
gl_lmid_slot:
    .quad 0
EOF

    clang --target=x86_64-linux-gnu -nostdlib -pie -fuse-ld=lld \
        -Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2 \
        "$tmpdir/gl-egl-dlsym.S" "$guest_lib_dir/libdl.so.2" \
        "$guest_lib_dir/libc.so.6" -o "$tmpdir/gl-egl-dlsym"

    run_guest gl-egl-dlsym 0 "$tmpdir/gl-egl-dlsym"
else
    echo "skip: guest libGL/libEGL/libc/libdl set not found under $guest_lib_dir" >&2
fi

echo "KZT loader regressions passed"
