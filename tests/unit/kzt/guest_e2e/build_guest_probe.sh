#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir=${KZT_GUEST_BUILD_DIR:-${TMPDIR:-/tmp}/kzt-guest-e2e}
guest_cc=${KZT_GUEST_CC:-x86_64-linux-gnu-gcc}
guest_readelf=${KZT_GUEST_READELF:-readelf}
guest_libc=${KZT_GUEST_LIBC:--lc}

read -r -a cc_flags <<< "${KZT_GUEST_CC_FLAGS:-}"
read -r -a launcher_flags <<< "${KZT_GUEST_CC_LAUNCHER_FLAGS:-}"

run_cc()
{
    if [[ -n ${KZT_GUEST_CC_LAUNCHER:-} ]]; then
        "${KZT_GUEST_CC_LAUNCHER}" "${launcher_flags[@]}" \
            "$guest_cc" "${cc_flags[@]}" "$@"
    else
        "$guest_cc" "${cc_flags[@]}" "$@"
    fi
}

mkdir -p "$build_dir"

run_cc -O2 -fPIC -shared -nostdlib \
    -I"$script_dir" \
    "$script_dir/kzt_guest_probe.c" \
    "$guest_libc" \
    -o "$build_dir/libkzt_guest_probe.so"

run_cc -O2 -nostdlib -Wl,-e,_start \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_guest_probe \
    -o "$build_dir/kzt_guest_main"

header=$($guest_readelf -h "$build_dir/kzt_guest_main")
if ! grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' \
        <<< "$header"; then
    echo "Guest main is not an x86-64 ELF." >&2
    exit 1
fi

relocations=$($guest_readelf -rW "$build_dir/libkzt_guest_probe.so")
uname_jump_slots=$(grep -Ec \
    'R_X86_64_(JUMP_SLOT|JUMP_SLO).*uname(@|[[:space:]])' \
    <<< "$relocations" || true)
if [[ $uname_jump_slots -ne 1 ]]; then
    echo "Guest DSO must contain exactly one lazy uname JUMP_SLOT." >&2
    exit 1
fi

symbols=$($guest_readelf -Ws "$build_dir/libkzt_guest_probe.so")
uname_versions=$(sed -n \
    's/.* UND uname@\(GLIBC_[^[:space:]]*\).*/\1/p' \
    <<< "$symbols" | sort -u)
if [[ -z $uname_versions || $uname_versions == *$'\n'* ]]; then
    echo "Guest DSO must require one versioned uname symbol." >&2
    exit 1
fi
printf '%s\n' "$uname_versions" > "$build_dir/guest-symbol-version.txt"

dynamic=$($guest_readelf -d "$build_dir/libkzt_guest_probe.so")
if grep -Eq '(BIND_NOW|FLAGS.*NOW)' <<< "$dynamic"; then
    echo "Guest DSO must use lazy binding." >&2
    exit 1
fi

main_dynamic=$($guest_readelf -d "$build_dir/kzt_guest_main")
if ! grep -Fq 'Shared library: [libkzt_guest_probe.so]' \
        <<< "$main_dynamic"; then
    echo "Guest main is not linked to the probe DSO." >&2
    exit 1
fi

printf 'Guest fixture built in %s\n' "$build_dir"
printf 'uname version: %s\n' "$uname_versions"
printf 'Run: python3 tests/unit/kzt/test_real_guest_e2e.py '\''\n'
printf '  --latx <latx-x86_64> --guest-root <amd64-root> '\''\n'
printf '  --host-libc <loongarch-libc.so.6> '\''\n'
printf '  --fixture-dir %q\n' "$build_dir"
