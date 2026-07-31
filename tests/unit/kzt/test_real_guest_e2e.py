#!/usr/bin/env python3
import argparse
from pathlib import Path
import subprocess
import sys

import test_wi849_real_guest_preemption as preemption


SCENARIOS = (
    {
        **preemption.SCENARIOS[0],
        "name": "wi601-direct",
    },
    {
        **preemption.SCENARIOS[1],
        "name": "wi601-guest-handoff",
    },
)


def run_scenario(args, scenario):
    return preemption.run_scenario(args, scenario)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the WI-601 real guest direct and guest-handoff gate."
    )
    parser.add_argument(
        "--latx", required=True, type=preemption.existing_file
    )
    parser.add_argument(
        "--guest-root", required=True, type=preemption.existing_directory
    )
    parser.add_argument(
        "--fixture-dir", required=True, type=preemption.existing_directory
    )
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    args.log_dir = (
        args.log_dir.resolve()
        if args.log_dir
        else args.fixture_dir / "wi601-real-guest-logs"
    )
    args.log_dir.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS:
        executable = args.fixture_dir / scenario["executable"]
        if not executable.is_file():
            parser.error(f"Fixture is missing {executable.name}.")
    return args


def main():
    args = parse_args()
    logs = [run_scenario(args, scenario) for scenario in SCENARIOS]
    print("KZT WI-601 real guest E2E: PASS")
    for log in logs:
        print(f"log: {log}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"KZT WI-601 real guest E2E: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
