#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
e2e_symbol=dlerror
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

run_cc -O2 -nostdlib -Wl,-e,_start -Wl,-z,now \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_guest_probe \
    -o "$build_dir/kzt_guest_main"

run_cc -O2 -fPIC -shared -nostdlib \
    -I"$script_dir" \
    "$script_dir/kzt_guest_perf_probe.c" \
    "$guest_libc" \
    -o "$build_dir/libkzt_guest_perf_probe.so"

run_cc -O2 -fno-plt -nostdlib -Wl,-e,_start \
    -I"$script_dir" \
    "$script_dir/kzt_guest_perf_start.S" \
    "$script_dir/kzt_guest_perf_main.c" \
    -L"$build_dir" -lkzt_guest_perf_probe \
    -o "$build_dir/kzt_guest_perf_main"

header=$($guest_readelf -h "$build_dir/kzt_guest_main")
if ! grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' \
        <<< "$header"; then
    echo "Guest main is not an x86-64 ELF." >&2
    exit 1
fi

perf_header=$($guest_readelf -h "$build_dir/kzt_guest_perf_main")
if ! grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' \
        <<< "$perf_header"; then
    echo "Guest performance main is not an x86-64 ELF." >&2
    exit 1
fi

relocations=$($guest_readelf -rW "$build_dir/libkzt_guest_probe.so")
e2e_jump_slots=$(grep -Ec \
    "R_X86_64_(JUMP_SLOT|JUMP_SLO).*${e2e_symbol}(@|[[:space:]])" \
    <<< "$relocations" || true)
if [[ $e2e_jump_slots -ne 1 ]]; then
    echo "Guest DSO must contain exactly one lazy ${e2e_symbol} JUMP_SLOT." >&2
    exit 1
fi

perf_relocations=$(
    $guest_readelf -rW "$build_dir/libkzt_guest_perf_probe.so"
)
perf_jump_slot_count=$(grep -Ec \
    'R_X86_64_(JUMP_SLOT|JUMP_SLO)' \
    <<< "$perf_relocations" || true)
if [[ $perf_jump_slot_count -ne 1 ]]; then
    echo "Guest performance DSO must contain exactly one JUMP_SLOT." >&2
    exit 1
fi
perf_versioned_dlerror_jump_slots=$(grep -Ec \
    "R_X86_64_(JUMP_SLOT|JUMP_SLO).*${e2e_symbol}@GLIBC_[^[:space:]]*" \
    <<< "$perf_relocations" || true)
if [[ $perf_versioned_dlerror_jump_slots -ne 1 ]]; then
    echo "Guest performance DSO JUMP_SLOT must be versioned ${e2e_symbol}." >&2
    exit 1
fi

symbols=$($guest_readelf -Ws "$build_dir/libkzt_guest_probe.so")
e2e_versions=$(sed -n \
    "s/.* UND ${e2e_symbol}@\\(GLIBC_[^[:space:]]*\\).*/\\1/p" \
    <<< "$symbols" | sort -u)
if [[ -z $e2e_versions || $e2e_versions == *$'\n'* ]]; then
    echo "Guest DSO must require one versioned ${e2e_symbol} symbol." >&2
    exit 1
fi
printf '%s\n' "$e2e_versions" > "$build_dir/guest-symbol-version.txt"
printf '%s\n' "$e2e_symbol" > "$build_dir/guest-symbol-name.txt"

preemption_version_script="$build_dir/kzt-guest-preemption-provider.map"
printf '%s {\n    global:\n        dlerror;\n    local:\n        *;\n};\n' \
    "$e2e_versions" > "$preemption_version_script"

run_cc -O2 -fPIC -shared -nostdlib \
    -DKZT_PREEMPTION_PROVIDER=1 \
    -Wl,--version-script="$preemption_version_script" \
    "$script_dir/kzt_guest_preemption_provider.c" \
    -o "$build_dir/libkzt_preempt_a.so"

run_cc -O2 -fPIC -shared -nostdlib \
    -DKZT_PREEMPTION_PROVIDER=2 \
    -Wl,--version-script="$preemption_version_script" \
    "$script_dir/kzt_guest_preemption_provider.c" \
    -o "$build_dir/libkzt_preempt_b.so"

run_cc -O2 -fPIC -shared -nostdlib \
    -DKZT_PREEMPTION_PROVIDER=0 \
    -Wl,--version-script="$preemption_version_script" \
    "$script_dir/kzt_guest_preemption_provider.c" \
    -o "$build_dir/libkzt_preempt_weak.so"

run_cc -O2 -fPIC -shared -nostdlib \
    -DKZT_PREEMPTION_PROVIDER=3 \
    -Wl,--version-script="$preemption_version_script" \
    "$script_dir/kzt_guest_preemption_provider.c" \
    -o "$build_dir/libkzt_local_preempt.so"

run_cc -O2 -nostdlib -Wl,-e,_start -Wl,-z,now \
    -Wl,--no-as-needed \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_preempt_a -lkzt_guest_probe \
    -o "$build_dir/kzt_guest_preempt_a_main"

run_cc -O2 -nostdlib -Wl,-e,_start -Wl,-z,now \
    -Wl,--no-as-needed \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_preempt_a -lkzt_preempt_b -lkzt_guest_probe \
    -o "$build_dir/kzt_guest_preempt_ab_main"

run_cc -O2 -nostdlib -Wl,-e,_start -Wl,-z,now \
    -Wl,--no-as-needed \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_preempt_weak -lkzt_guest_probe \
    -o "$build_dir/kzt_guest_preempt_weak_main"

run_cc -O2 -nostdlib -Wl,-e,_start -Wl,-z,now \
    -DKZT_GUEST_LOAD_LOCAL_PREEMPTION_GROUP=1 \
    -Wl,--no-as-needed \
    -I"$script_dir" \
    "$script_dir/kzt_guest_main.c" \
    -L"$build_dir" -lkzt_preempt_a -lkzt_guest_probe \
    "$guest_libc" \
    -o "$build_dir/kzt_guest_local_scope_main"

needed_order()
{
    "$guest_readelf" -d "$1" |
        sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
        paste -sd: -
}

if [[ $(needed_order "$build_dir/kzt_guest_preempt_a_main") != \
        "libkzt_preempt_a.so:libkzt_guest_probe.so" ]]; then
    echo "Strong preemption main has the wrong DT_NEEDED order." >&2
    exit 1
fi
if [[ $(needed_order "$build_dir/kzt_guest_preempt_ab_main") != \
        "libkzt_preempt_a.so:libkzt_preempt_b.so:libkzt_guest_probe.so" ]]; then
    echo "Two-provider main has the wrong DT_NEEDED order." >&2
    exit 1
fi
if [[ $(needed_order "$build_dir/kzt_guest_preempt_weak_main") != \
        "libkzt_preempt_weak.so:libkzt_guest_probe.so" ]]; then
    echo "Weak preemption main has the wrong DT_NEEDED order." >&2
    exit 1
fi

strong_a_symbols=$(
    "$guest_readelf" -Ws "$build_dir/libkzt_preempt_a.so"
)
strong_b_symbols=$(
    "$guest_readelf" -Ws "$build_dir/libkzt_preempt_b.so"
)
weak_symbols=$(
    "$guest_readelf" -Ws "$build_dir/libkzt_preempt_weak.so"
)
local_symbols=$(
    "$guest_readelf" -Ws "$build_dir/libkzt_local_preempt.so"
)
if [[ $(grep -Ec \
        "FUNC[[:space:]]+GLOBAL.*dlerror@@${e2e_versions}([[:space:]]|$)" \
        <<< "$strong_a_symbols") -ne 1 ||
      $(grep -Ec \
        "FUNC[[:space:]]+GLOBAL.*dlerror@@${e2e_versions}([[:space:]]|$)" \
        <<< "$strong_b_symbols") -ne 1 ]]; then
    echo "Strong providers do not export the required dlerror version." >&2
    exit 1
fi
if [[ $(grep -Ec \
        "FUNC[[:space:]]+WEAK.*dlerror@@${e2e_versions}([[:space:]]|$)" \
        <<< "$weak_symbols") -ne 1 ]]; then
    echo "Weak provider does not export the required dlerror version." >&2
    exit 1
fi
if [[ $(grep -Ec \
        "FUNC[[:space:]]+GLOBAL.*dlerror@@${e2e_versions}([[:space:]]|$)" \
        <<< "$local_symbols") -ne 1 ]]; then
    echo "RTLD_LOCAL provider does not export the required dlerror version." >&2
    exit 1
fi

local_main_needed=$(needed_order "$build_dir/kzt_guest_local_scope_main")
if [[ $local_main_needed != \
      "libkzt_preempt_a.so:libkzt_guest_probe.so:libc.so.6" ]]; then
    echo "RTLD_LOCAL isolation main has the wrong DT_NEEDED set." >&2
    exit 1
fi
if [[ $local_main_needed == *libkzt_local_preempt.so* ]]; then
    echo "RTLD_LOCAL provider must not be a startup dependency." >&2
    exit 1
fi

perf_symbols=$($guest_readelf -Ws "$build_dir/libkzt_guest_perf_probe.so")
perf_versions=$(sed -n \
    "s/.* UND ${e2e_symbol}@\\(GLIBC_[^[:space:]]*\\).*/\\1/p" \
    <<< "$perf_symbols" | sort -u)
if [[ -z $perf_versions || $perf_versions == *$'\n'* ]]; then
    echo "Guest performance DSO must require one versioned ${e2e_symbol} symbol." >&2
    exit 1
fi
printf '%s\n' "$perf_versions" > "$build_dir/guest-performance-symbol-version.txt"
printf '%s\n' "$e2e_symbol" > "$build_dir/guest-performance-symbol-name.txt"

dynamic=$($guest_readelf -d "$build_dir/libkzt_guest_probe.so")
if grep -Eq '(BIND_NOW|FLAGS.*NOW)' <<< "$dynamic"; then
    echo "Guest DSO must use lazy binding." >&2
    exit 1
fi

perf_dynamic=$($guest_readelf -d "$build_dir/libkzt_guest_perf_probe.so")
if grep -Eq '(BIND_NOW|FLAGS.*NOW)' <<< "$perf_dynamic"; then
    echo "Guest performance DSO must use lazy binding." >&2
    exit 1
fi

main_dynamic=$($guest_readelf -d "$build_dir/kzt_guest_main")
if ! grep -Fq 'Shared library: [libkzt_guest_probe.so]' \
        <<< "$main_dynamic"; then
    echo "Guest main is not linked to the probe DSO." >&2
    exit 1
fi

main_relocations=$($guest_readelf -rW "$build_dir/kzt_guest_main")
probe_jump_slots=$(grep -Ec \
    'R_X86_64_(JUMP_SLOT|JUMP_SLO).*kzt_guest_probe(@|[[:space:]])' \
    <<< "$main_relocations" || true)
if [[ $probe_jump_slots -ne 1 ]]; then
    echo "Guest main must contain exactly one kzt_guest_probe JUMP_SLOT." >&2
    exit 1
fi
if ! grep -Eq '(BIND_NOW|FLAGS.*NOW)' <<< "$main_dynamic"; then
    echo "Guest main must bind kzt_guest_probe at startup." >&2
    exit 1
fi

perf_main_dynamic=$($guest_readelf -d "$build_dir/kzt_guest_perf_main")
if ! grep -Fq 'Shared library: [libkzt_guest_perf_probe.so]' \
        <<< "$perf_main_dynamic"; then
    echo "Guest performance main is not linked to its probe DSO." >&2
    exit 1
fi
perf_main_relocations=$($guest_readelf -rW "$build_dir/kzt_guest_perf_main")
perf_main_jump_slots=$(grep -Ec 'R_X86_64_(JUMP_SLOT|JUMP_SLO)' \
    <<< "$perf_main_relocations" || true)
if [[ $perf_main_jump_slots -ne 0 ]]; then
    echo "Guest performance main must not contain a lazy JUMP_SLOT." >&2
    exit 1
fi

run_cc --version > "$build_dir/guest-compiler.txt"
{
    printf 'KZT_GUEST_CC=%q\n' "$guest_cc"
    printf 'KZT_GUEST_CC_FLAGS=%q\n' "${KZT_GUEST_CC_FLAGS:-}"
    printf 'KZT_GUEST_CC_LAUNCHER=%q\n' "${KZT_GUEST_CC_LAUNCHER:-}"
    printf 'KZT_GUEST_CC_LAUNCHER_FLAGS=%q\n' \
        "${KZT_GUEST_CC_LAUNCHER_FLAGS:-}"
    printf 'KZT_GUEST_LIBC=%q\n' "$guest_libc"
    printf '%s\n' \
        'performance DSO: -O2 -fPIC -shared -nostdlib' \
        'performance main: -O2 -fno-plt -nostdlib -Wl,-e,_start' \
        'E2E main: -O2 -nostdlib -Wl,-e,_start -Wl,-z,now' \
        'E2E DSO: lazy dlerror JUMP_SLOT required' \
        'performance DSO: lazy versioned dlerror JUMP_SLOT required'
} > "$build_dir/guest-build-parameters.txt"

printf 'Guest fixture built in %s\n' "$build_dir"
printf '%s version: %s\n' "$e2e_symbol" "$e2e_versions"
printf 'Run: python3 tests/unit/kzt/test_real_guest_e2e.py '\''\n'
printf '  --latx <latx-x86_64> --guest-root <amd64-root> '\''\n'
printf '  --host-libc <loongarch-libc.so.6> '\''\n'
printf '  --fixture-dir %q\n' "$build_dir"
printf 'Performance: python3 tests/unit/kzt/test_real_guest_performance.py '\''\n'
printf '  --baseline-latx <old-release-latx> '\''\n'
printf '  --candidate-latx <candidate-release-latx> '\''\n'
printf '  --guest-root <amd64-root> --fixture-dir %q '\''\n' "$build_dir"
printf '  --cpu <cpu> --output-dir <result-dir>\n'
