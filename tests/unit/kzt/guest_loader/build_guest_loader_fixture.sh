#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
guest_root=${KZT_GUEST_ROOT:-}
build_dir=${KZT_GUEST_BUILD_DIR:-${TMPDIR:-/tmp}/wi600-guest-loader}
guest_cc=${KZT_GUEST_CC:-x86_64-linux-gnu-gcc}
guest_readelf=${KZT_GUEST_READELF:-readelf}

read -r -a cc_flags <<< "${KZT_GUEST_CC_FLAGS:-}"
read -r -a linker_flags <<< "${KZT_GUEST_LDFLAGS:-}"
read -r -a launcher_flags <<< "${KZT_GUEST_CC_LAUNCHER_FLAGS:-}"

usage()
{
    echo "usage: $0 --guest-root DIR [--output DIR]" >&2
}

inconclusive()
{
    echo "WI-600 guest loader fixture: INCONCLUSIVE: $*" >&2
    exit 77
}

fail()
{
    echo "WI-600 guest loader fixture: FAIL: $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --guest-root)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            guest_root=$2
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            build_dir=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

[[ -n $guest_root ]] || inconclusive \
    "guest root was not provided with --guest-root or KZT_GUEST_ROOT"
[[ -d $guest_root ]] || inconclusive "guest root not found: $guest_root"
command -v "$guest_cc" >/dev/null 2>&1 || inconclusive \
    "x86-64 guest compiler not found: $guest_cc"
command -v "$guest_readelf" >/dev/null 2>&1 || inconclusive \
    "ELF inspection tool not found: $guest_readelf"
if [[ -n ${KZT_GUEST_CC_LAUNCHER:-} ]]; then
    command -v "$KZT_GUEST_CC_LAUNCHER" >/dev/null 2>&1 || inconclusive \
        "compiler launcher not found: $KZT_GUEST_CC_LAUNCHER"
fi

find_guest_file()
{
    local relative

    for relative in "$@"; do
        if [[ -f $guest_root/$relative ]]; then
            printf '%s\n' "$guest_root/$relative"
            return 0
        fi
    done
    return 1
}

if [[ -n ${KZT_GUEST_DYNAMIC_LINKER:-} ]]; then
    dynamic_linker=$KZT_GUEST_DYNAMIC_LINKER
    [[ $dynamic_linker == /* ]] || inconclusive \
        "KZT_GUEST_DYNAMIC_LINKER must be a guest-absolute path"
    [[ -f $guest_root$dynamic_linker ]] || inconclusive \
        "guest dynamic linker not found: $guest_root$dynamic_linker"
else
    dynamic_linker_host=$(find_guest_file \
        lib64/ld-linux-x86-64.so.2 \
        lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
        usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2) || inconclusive \
        "x86-64 dynamic linker not found under $guest_root"
    dynamic_linker=/${dynamic_linker_host#"$guest_root"/}
fi

if [[ -n ${KZT_GUEST_LIBC:-} ]]; then
    guest_libc=$KZT_GUEST_LIBC
    [[ -f $guest_libc ]] || inconclusive \
        "KZT_GUEST_LIBC not found: $guest_libc"
else
    guest_libc=$(find_guest_file \
        lib/x86_64-linux-gnu/libc.so.6 \
        usr/lib/x86_64-linux-gnu/libc.so.6 \
        lib64/libc.so.6 \
        usr/lib64/libc.so.6 \
        lib/libc.so.6 \
        usr/lib/libc.so.6) || inconclusive \
        "x86-64 libc.so.6 not found under $guest_root"
fi

if [[ -n ${KZT_GUEST_LIBDL:-} ]]; then
    guest_libdl=$KZT_GUEST_LIBDL
    [[ -f $guest_libdl ]] || inconclusive \
        "KZT_GUEST_LIBDL not found: $guest_libdl"
else
    guest_libdl=$(find_guest_file \
        lib/x86_64-linux-gnu/libdl.so.2 \
        usr/lib/x86_64-linux-gnu/libdl.so.2 \
        lib64/libdl.so.2 \
        usr/lib64/libdl.so.2 \
        lib/libdl.so.2 \
        usr/lib/libdl.so.2) || inconclusive \
        "x86-64 libdl.so.2 not found under $guest_root"
fi

run_cc()
{
    if [[ -n ${KZT_GUEST_CC_LAUNCHER:-} ]]; then
        "$KZT_GUEST_CC_LAUNCHER" "${launcher_flags[@]}" \
            "$guest_cc" "${cc_flags[@]}" "$@"
    else
        "$guest_cc" "${cc_flags[@]}" "$@"
    fi
}

build_shared()
{
    local source=$1
    local soname=$2
    shift 2

    run_cc --sysroot="$guest_root" -O2 -ffreestanding -fno-builtin \
        -fno-stack-protector -fPIC -nostdlib -shared \
        "$script_dir/$source" "$@" "${linker_flags[@]}" \
        -Wl,-soname,"$soname" -o "$build_dir/$soname" || fail \
        "could not build $soname"
}

build_program()
{
    local source=$1
    local output=$2

    run_cc --sysroot="$guest_root" -O2 -ffreestanding -fno-builtin \
        -fno-stack-protector -fPIE -nostdlib -pie \
        -I"$script_dir" "$script_dir/$source" \
        -Wl,-e,_start -Wl,--dynamic-linker,"$dynamic_linker" \
        -Wl,--no-as-needed "$guest_libdl" "$guest_libc" \
        -Wl,--allow-shlib-undefined "${linker_flags[@]}" \
        -o "$build_dir/$output" || fail "could not build $output"
}

mkdir -p "$build_dir"
rm -f \
    "$build_dir/libwi600_helper.so" \
    "$build_dir/libwi600_plugin.so" \
    "$build_dir/libwi600_visibility.so" \
    "$build_dir/libwi600_namespace.so" \
    "$build_dir/libwi600_versions.so" \
    "$build_dir/libwi1065_constructor.so" \
    "$build_dir/libwi1065_partial_relro.so" \
    "$build_dir/libwi1065_full_relro.so" \
    "$build_dir/dependency-reopen" \
    "$build_dir/visibility-noload" \
    "$build_dir/namespace-isolation" \
    "$build_dir/symbol-versions-errors" \
    "$build_dir/wrapped-library-handle" \
    "$build_dir/wi1065-loader-events"

build_shared helper.c libwi600_helper.so
build_shared plugin.c libwi600_plugin.so \
    -Wl,--no-as-needed "$build_dir/libwi600_helper.so" \
    '-Wl,-rpath,$ORIGIN'
build_shared visibility.c libwi600_visibility.so
build_shared namespace.c libwi600_namespace.so
build_shared versions.c libwi600_versions.so \
    -Wl,--version-script,"$script_dir/versions.map"
build_shared wi1065_constructor.c libwi1065_constructor.so -Wl,-z,relro
build_shared wi1065_relro.c libwi1065_partial_relro.so -Wl,-z,relro
build_shared wi1065_relro.c libwi1065_full_relro.so -Wl,-z,relro,-z,now

build_program dependency_reopen.c dependency-reopen
build_program visibility_noload.c visibility-noload
build_program namespace_isolation.c namespace-isolation
build_program symbol_versions_errors.c symbol-versions-errors
build_program wrapped_library_handle.c wrapped-library-handle
build_program wi1065_loader_events.c wi1065-loader-events

fixture_files=(
    libwi600_helper.so
    libwi600_plugin.so
    libwi600_visibility.so
    libwi600_namespace.so
    libwi600_versions.so
    libwi1065_constructor.so
    libwi1065_partial_relro.so
    libwi1065_full_relro.so
    dependency-reopen
    visibility-noload
    namespace-isolation
    symbol-versions-errors
    wrapped-library-handle
    wi1065-loader-events
)

for fixture_file in "${fixture_files[@]}"; do
    header=$("$guest_readelf" -h "$build_dir/$fixture_file") || fail \
        "could not inspect $fixture_file"
    grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' \
        <<< "$header" || inconclusive \
        "$guest_cc did not produce x86-64 ELF: $fixture_file"
done

plugin_dynamic=$("$guest_readelf" -d "$build_dir/libwi600_plugin.so") || \
    fail "could not inspect plugin dependencies"
grep -Fq 'Shared library: [libwi600_helper.so]' \
    <<< "$plugin_dynamic" || fail \
    "plugin does not retain its helper DT_NEEDED dependency"

version_symbols=$("$guest_readelf" -Ws "$build_dir/libwi600_versions.so") || \
    fail "could not inspect versioned symbols"
grep -Fq 'wi600_versioned_value@WI600_1.0' <<< "$version_symbols" || fail \
    "versioned DSO is missing WI600_1.0"
grep -Fq 'wi600_versioned_value@@WI600_2.0' <<< "$version_symbols" || fail \
    "versioned DSO is missing default WI600_2.0"

partial_relro=$("$guest_readelf" -l "$build_dir/libwi1065_partial_relro.so") || fail \
    "could not inspect partial RELRO fixture"
full_relro=$("$guest_readelf" -l "$build_dir/libwi1065_full_relro.so") || fail \
    "could not inspect full RELRO fixture"
full_dynamic=$("$guest_readelf" -d "$build_dir/libwi1065_full_relro.so") || fail \
    "could not inspect full RELRO dynamic tags"
grep -Fq 'GNU_RELRO' <<< "$partial_relro" || fail \
    "partial RELRO fixture is missing GNU_RELRO"
grep -Fq 'GNU_RELRO' <<< "$full_relro" || fail \
    "full RELRO fixture is missing GNU_RELRO"
grep -Eq '(BIND_NOW|FLAGS.*NOW)' <<< "$full_dynamic" || fail \
    "full RELRO fixture is missing BIND_NOW"

printf 'WI-600 guest loader fixture: PASS\n'
printf 'Fixture directory: %s\n' "$build_dir"
printf 'Guest root: %s\n' "$guest_root"
printf 'Run: python3 tests/unit/kzt/test_real_guest_loader_gate.py \\\n'
printf '  --baseline-latx <old-latx> --candidate-latx <new-latx> \\\n'
printf '  --guest-root %q --fixture-dir %q\n' "$guest_root" "$build_dir"
