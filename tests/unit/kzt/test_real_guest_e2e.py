#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


SUCCESS_PATTERN = re.compile(
    r"KZT_GUEST_E2E_OK calls=2 slot=(0x[0-9a-f]+) "
    r"before=(0x[0-9a-f]+) after_first=(0x[0-9a-f]+) "
    r"after_second=(0x[0-9a-f]+) first_ns=(0x[0-9a-f]+) "
    r"second_ns=(0x[0-9a-f]+)"
)
TARGET_SYMBOL = "uname"


def parse_record(line):
    record = {}
    for field in line.split():
        if "=" in field:
            key, value = field.split("=", 1)
            record[key] = value
    return record


def symbol_records(output, prefix):
    records = []
    for line in output.splitlines():
        marker = line.find(prefix)
        if marker >= 0:
            record = parse_record(line[marker:])
            if record.get("symbol") == TARGET_SYMBOL:
                records.append((line, record))
    return records


def require(condition, message, output=None):
    if condition:
        return
    if output:
        message = f"{message}\n--- guest output ---\n{output.rstrip()}"
    raise RuntimeError(message)


def verify_cross_arch_version(args):
    guest_version = (
        args.fixture_dir / "guest-symbol-version.txt"
    ).read_text(encoding="utf-8").strip()
    completed = subprocess.run(
        [args.readelf, "-Ws", str(args.host_libc)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    require(completed.returncode == 0,
            "Could not inspect the host libc symbol versions.",
            completed.stdout)
    host_versions = set(re.findall(
        rf"\b{TARGET_SYMBOL}@@?(GLIBC_[^\s]+)", completed.stdout
    ))
    require(len(host_versions) == 1,
            "Host libc must expose one inspectable uname symbol version.",
            completed.stdout)
    host_version = next(iter(host_versions))
    require(host_version != guest_version,
            "Cross-architecture fixture requires different guest and host "
            "uname versions.")
    print(
        f"Cross-architecture versions: guest={guest_version} "
        f"host={host_version}"
    )


def run_mode(args, mode, budget, expected_writer, expected_fallback):
    executable = args.fixture_dir / "kzt_guest_main"
    command = [
        str(args.latx),
        "-L",
        str(args.guest_root),
        "-E",
        f"LD_LIBRARY_PATH={args.fixture_dir}",
        str(executable),
    ]
    environment = os.environ.copy()
    environment.update(
        {
            "LATX_KZT": "1",
            "LATX_KZT_REGISTRY_DIAGNOSTICS": "1",
            "LATX_KZT_LAZY_DIAGNOSTICS": "1",
            "LATX_KZT_PATCH_SPIKE": "1",
            "LATX_KZT_PATCH_SPIKE_WRITE": "1",
            "LATX_KZT_PATCH_SPIKE_BUDGET": str(budget),
        }
    )
    completed = subprocess.run(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    output = completed.stdout
    log_path = args.log_dir / f"real-guest-{mode}.log"
    log_path.write_text(output, encoding="utf-8")

    require(completed.returncode == 0,
            f"{mode} mode exited with {completed.returncode}.", output)
    success_matches = SUCCESS_PATTERN.findall(output)
    require(len(success_matches) == 1,
            f"{mode} mode did not complete both uname calls.", output)
    slot, before, after_first, after_second, first_ns, second_ns = (
        int(value, 16) for value in success_matches[0]
    )
    require(slot != 0 and before != 0,
            f"{mode} mode reported an invalid uname GOT slot.", output)
    require(after_first != before,
            f"{mode} mode did not replace the unresolved uname slot.", output)
    require(after_second == after_first,
            f"{mode} mode changed the uname slot on the second call.", output)
    require(first_ns > 0 and second_ns > 0,
            f"{mode} mode did not report call timings.", output)

    rela_records = symbol_records(output, "kzt_rela_diagnostic ")
    require(len(rela_records) == 1,
            f"{mode} mode expected one uname relocation record, "
            f"found {len(rela_records)}.", output)
    _, rela = rela_records[0]
    require(rela.get("decision") == "APPROVED",
            f"{mode} mode did not approve the uname patch.", output)
    require(rela.get("writer_result") == expected_writer,
            f"{mode} mode writer result is not {expected_writer}.", output)
    require(rela.get("legacy_fallback") == expected_fallback,
            f"{mode} mode legacy fallback is not {expected_fallback}.", output)
    if expected_writer == "APPLIED":
        require(int(rela.get("bridge_target", "0"), 16) == after_first,
                f"{mode} mode GOT value does not match the approved bridge.",
                output)

    resolver_entries = symbol_records(output, "kzt_lazy_resolver_entry ")
    require(len(resolver_entries) == 1,
            f"{mode} mode entered the uname resolver "
            f"{len(resolver_entries)} times instead of once.", output)

    lazy_records = symbol_records(output, "kzt_lazy_diagnostic ")
    require(len(lazy_records) == 1,
            f"{mode} mode resolved uname more than once or missed it; "
            f"found {len(lazy_records)} lazy records.", output)
    return log_path


def existing_directory(value):
    path = Path(value).resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Directory does not exist: {path}")
    return path


def existing_file(value):
    path = Path(value).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"File does not exist: {path}")
    return path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the KZT real x86-64 guest lazy-binding gate."
    )
    parser.add_argument("--latx", required=True, type=existing_file)
    parser.add_argument("--guest-root", required=True, type=existing_directory)
    parser.add_argument("--host-libc", required=True, type=existing_file)
    parser.add_argument("--fixture-dir", required=True, type=existing_directory)
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.log_dir is None:
        args.log_dir = args.fixture_dir / "logs"
    else:
        args.log_dir = args.log_dir.resolve()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    require((args.fixture_dir / "kzt_guest_main").is_file(),
            "Fixture directory is missing kzt_guest_main.")
    require((args.fixture_dir / "libkzt_guest_probe.so").is_file(),
            "Fixture directory is missing libkzt_guest_probe.so.")
    require((args.fixture_dir / "guest-symbol-version.txt").is_file(),
            "Fixture directory is missing guest-symbol-version.txt.")
    return args


def main():
    args = parse_args()
    verify_cross_arch_version(args)
    normal_log = run_mode(args, "applied", 1, "APPLIED", "0")
    fail_open_log = run_mode(
        args, "fail-open", 0, "BUDGET_EXHAUSTED", "1"
    )
    print("KZT real guest E2E: PASS")
    print(f"Applied log: {normal_log}")
    print(f"Fail-open log: {fail_open_log}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"KZT real guest E2E: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
