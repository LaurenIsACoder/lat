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

    set +e
    LATX_KZT=1 "$latx" -L "$ld_prefix" "$program" \
        >"$tmpdir/$name.out" 2>"$tmpdir/$name.err"
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
    mov %rax, %rdi
    lea sym_name(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_sym
    call *%rax
    cmp \$123, %eax
    jne fail_call
    mov %r12, %rdi
    call dlclose@PLT
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
    .section .rodata
plugin_path:
    .asciz "$tmpdir/libplugin.so"
sym_name:
    .asciz "plugin_value"
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
else
    echo "skip: guest libc/libdl not found under $guest_lib_dir" >&2
fi

if [ -e "$guest_lib_dir/libGL.so.1" ] && [ -e "$guest_lib_dir/libEGL.so.1" ] &&
   [ -e "$guest_lib_dir/libc.so.6" ] && [ -e "$guest_lib_dir/libdl.so.2" ]; then
    cat >"$tmpdir/gl-egl-dlsym.S" <<'EOF'
    .global _start
_start:
    lea gl_name(%rip), %rdi
    mov $2, %esi
    call dlopen@PLT
    test %rax, %rax
    je fail_gl_open
    mov %rax, %r12
    mov %rax, %rdi
    lea glx_proc(%rip), %rsi
    call dlsym@PLT
    test %rax, %rax
    je fail_gl_sym
    mov %r12, %rdi
    call dlclose@PLT

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
fail_gl_sym:
    mov $97, %edi
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
egl_name:
    .asciz "libEGL.so.1"
egl_proc:
    .asciz "eglGetProcAddress"
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
