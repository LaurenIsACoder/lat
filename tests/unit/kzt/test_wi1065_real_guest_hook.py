#!/usr/bin/env python3
"""Execute and validate the WI-1065 x86_64 loader-event evidence fixture."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


PASS_MARKER = "WI600_GUEST_LOADER_PASS wi1065-loader-events"
EVENT_PREFIX = "kzt_loader_event "
REQUIRED_MARKERS = (
    "WI1065_STARTUP",
    "WI1065_CONSTRUCTOR",
    "WI1065_RELRO partial",
    "WI1065_RELRO full",
    "WI1065_DLCLOSE full",
    "WI1065_THREADS_PASS",
    PASS_MARKER,
)


def parse_record(line):
    return {
        key: value
        for key, value in (
            field.split("=", 1) for field in line.split() if "=" in field
        )
    }


def require(condition, message, output):
    if not condition:
        raise RuntimeError(f"{message}\n--- guest output ---\n{output.rstrip()}")


def environment(fixture_dir, disabled=False, force_pattern_mismatch=False):
    values = os.environ.copy()
    for name in list(values):
        if name.startswith("LATX_KZT"):
            values.pop(name)
    for name in (
        "LD_AUDIT", "LD_BIND_NOW", "LD_DEBUG", "LD_DEBUG_OUTPUT",
        "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_PROFILE",
    ):
        values.pop(name, None)
    values.update({
        "LATX_AOT": "0",
        "LATX_KZT": "2",
        "LATX_KZT_LAZY_DIAGNOSTICS": "0",
        "LATX_KZT_REGISTRY_DIAGNOSTICS": "1",
        "LATX_KZT_PATCH_SPIKE": "1",
        "LATX_KZT_PATCH_SPIKE_WRITE": "1",
        "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
        "LD_LIBRARY_PATH": str(fixture_dir),
    })
    if disabled:
        values["LATX_KZT_LOADER_EVENT_HOOK"] = "0"
    if force_pattern_mismatch:
        values["LATX_KZT_LOADER_EVENT_FORCE_PATTERN_MISMATCH"] = "1"
    return values


def run_guest(latx, guest_root, fixture_dir, timeout, disabled=False,
              force_pattern_mismatch=False):
    command = [str(latx), "-L", str(guest_root),
               str(fixture_dir / "wi1065-loader-events")]
    completed = subprocess.run(
        command, cwd=fixture_dir,
        env=environment(fixture_dir, disabled, force_pattern_mismatch),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=timeout, check=False,
    )
    return command, completed


def event_records(output, phase):
    return [
        (index, parse_record(line))
        for index, line in enumerate(output.splitlines())
        if line.startswith(EVENT_PREFIX) and f"phase={phase}" in line
    ]


def marker_index(output, marker):
    for index, line in enumerate(output.splitlines()):
        if line == marker:
            return index
    return -1


def verify_known(output):
    require("phase=install result=INSTALLED" in output,
            "known Build ID did not install the event hook", output)
    for marker in REQUIRED_MARKERS:
        require(marker_index(output, marker) >= 0,
                f"missing fixture marker {marker}", output)

    published = event_records(output, "published")
    consumed = event_records(output, "consumed")
    require(published, "known Build ID produced no events", output)
    published_by_sequence = {item[1].get("sequence"): item for item in published}
    consumed_by_sequence = {item[1].get("sequence"): item for item in consumed}
    require(len(published_by_sequence) == len(published),
            "publisher duplicated an event sequence", output)
    require(set(published_by_sequence) == set(consumed_by_sequence),
            "candidate events were lost or not consumed", output)
    sequences = [int(record["sequence"], 0) for _, record in published]
    require(sequences == list(range(1, len(sequences) + 1)),
            "event sequence is not contiguous", output)
    for sequence, (_, published_record) in published_by_sequence.items():
        consumed_index, consumed_record = consumed_by_sequence[sequence]
        published_index = published_by_sequence[sequence][0]
        require(consumed_index > published_index and
                consumed_record.get("link_map") == published_record.get("link_map"),
                "consumer did not process the exact published link_map", output)
        require(int(consumed_record.get("runtime_ns", "-1"), 0) >= 0,
                "consumer timing evidence is missing", output)

    startup = marker_index(output, "WI1065_STARTUP")
    constructor = marker_index(output, "WI1065_CONSTRUCTOR")
    partial = marker_index(output, "WI1065_RELRO partial")
    full = marker_index(output, "WI1065_RELRO full")
    threads = marker_index(output, "WI1065_THREADS_PASS")
    require(published[0][0] < startup,
            "startup event was not published before guest startup", output)
    require(any(index < constructor for index, _ in consumed),
            "no event was consumed before constructor", output)
    require(any(index < partial for index, _ in consumed) and
            any(index < full for index, _ in consumed),
            "RELRO fixture did not observe loader events before completion", output)
    require(any(index < threads for index, _ in published),
            "multithread loader fixture published no events", output)


def verify_disabled(output):
    require(PASS_MARKER in output,
            "disabled hook did not roll back to guest-loader behavior", output)
    require("phase=install result=DISABLED" in output and
            "rollback=disabled" in output,
            "disabled hook did not report its rollback", output)
    require(not event_records(output, "published") and
            not event_records(output, "consumed"),
            "disabled hook still executed callback events", output)


def verify_fail_open(output, expected_result):
    require(PASS_MARKER in output,
            f"{expected_result} did not preserve guest-loader behavior", output)
    require(f"phase=install result={expected_result}" in output and
            "rollback=disabled" in output,
            f"{expected_result} did not report fail-open rollback", output)
    require(not event_records(output, "published") and
            not event_records(output, "consumed"),
            f"{expected_result} still executed callback events", output)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--latx", required=True, type=Path)
    parser.add_argument("--guest-root", required=True, type=Path)
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--log-dir", required=True, type=Path)
    parser.add_argument("--unknown-guest-root", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    for path, label in ((args.latx, "LATX"), (args.fixture_dir, "fixture"),
                        (args.guest_root, "guest root")):
        if not path.exists():
            parser.error(f"{label} does not exist: {path}")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    args.latx = args.latx.resolve()
    args.guest_root = args.guest_root.resolve()
    args.fixture_dir = args.fixture_dir.resolve()
    if args.unknown_guest_root:
        if not args.unknown_guest_root.is_dir():
            parser.error(f"unknown guest root does not exist: {args.unknown_guest_root}")
        args.unknown_guest_root = args.unknown_guest_root.resolve()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    args.log_dir = args.log_dir.resolve()
    return args


def main():
    args = parse_args()
    known_command, known = run_guest(args.latx, args.guest_root,
                                     args.fixture_dir, args.timeout)
    disabled_command, disabled = run_guest(args.latx, args.guest_root,
                                           args.fixture_dir, args.timeout,
                                           disabled=True)
    mismatch_command, mismatch = run_guest(
        args.latx, args.guest_root, args.fixture_dir, args.timeout,
        force_pattern_mismatch=True)
    (args.log_dir / "known.log").write_text(known.stdout, encoding="utf-8")
    (args.log_dir / "disabled.log").write_text(disabled.stdout, encoding="utf-8")
    (args.log_dir / "pattern-mismatch.log").write_text(
        mismatch.stdout, encoding="utf-8")
    require(known.returncode == 0, f"known run exited {known.returncode}",
            known.stdout)
    require(disabled.returncode == 0,
            f"disabled run exited {disabled.returncode}", disabled.stdout)
    require(mismatch.returncode == 0,
            f"pattern mismatch run exited {mismatch.returncode}", mismatch.stdout)
    verify_known(known.stdout)
    verify_disabled(disabled.stdout)
    verify_fail_open(mismatch.stdout, "PATTERN_MISMATCH")
    unknown_command = None
    unknown = None
    if args.unknown_guest_root:
        unknown_command, unknown = run_guest(
            args.latx, args.unknown_guest_root, args.fixture_dir, args.timeout)
        (args.log_dir / "unknown-build-id.log").write_text(
            unknown.stdout, encoding="utf-8")
        require(unknown.returncode == 0,
                f"unknown Build ID run exited {unknown.returncode}", unknown.stdout)
        verify_fail_open(unknown.stdout, "UNKNOWN_BUILD_ID")
    report = {
        "known_command": known_command,
        "disabled_command": disabled_command,
        "pattern_mismatch_command": mismatch_command,
        "unknown_build_id_command": unknown_command,
        "published_events": len(event_records(known.stdout, "published")),
        "consumed_events": len(event_records(known.stdout, "consumed")),
        "unknown_build_id_checked": unknown is not None,
        "result": "PASS",
    }
    (args.log_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("WI-1065 real guest hook: PASS")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"WI-1065 real guest hook: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
