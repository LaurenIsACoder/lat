#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys

from test_real_guest_e2e import SUCCESS_PATTERN, existing_directory, existing_file


MODES = {
    "legacy": {"LATX_KZT": "0"},
    "fail_open": {
        "LATX_KZT": "1",
        "LATX_KZT_PATCH_SPIKE": "1",
        "LATX_KZT_PATCH_SPIKE_WRITE": "1",
        "LATX_KZT_PATCH_SPIKE_BUDGET": "0",
    },
    "applied": {
        "LATX_KZT": "1",
        "LATX_KZT_PATCH_SPIKE": "1",
        "LATX_KZT_PATCH_SPIKE_WRITE": "1",
        "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
    },
}


def run_once(args, mode):
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT"):
            environment.pop(name)
    environment.update(MODES[mode])
    completed = subprocess.run(
        [
            str(args.latx), "-L", str(args.guest_root),
            "-E", f"LD_LIBRARY_PATH={args.fixture_dir}",
            str(args.fixture_dir / "kzt_guest_main"),
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{mode} exited with {completed.returncode}:\n{completed.stdout}"
        )
    matches = SUCCESS_PATTERN.findall(completed.stdout)
    if len(matches) != 1:
        raise RuntimeError(f"{mode} did not emit one timing record")
    values = [int(value, 16) for value in matches[0]]
    return {"first_ns": values[4], "second_ns": values[5]}


def regression_percent(value, baseline):
    return (value / baseline - 1.0) * 100.0


def main():
    parser = argparse.ArgumentParser(
        description="Run the KZT real guest first-binding performance gate."
    )
    parser.add_argument("--latx", required=True, type=existing_file)
    parser.add_argument("--guest-root", required=True, type=existing_directory)
    parser.add_argument("--fixture-dir", required=True, type=existing_directory)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=20260720)
    parser.add_argument("--max-first-regression-percent", type=float,
                        default=3.0)
    parser.add_argument("--max-steady-regression-percent", type=float,
                        default=1.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.iterations < 20 or args.warmup < 0:
        parser.error("iterations must be >= 20 and warmup must be >= 0")

    samples = {mode: {"first_ns": [], "second_ns": []} for mode in MODES}
    rng = random.Random(args.seed)
    for round_index in range(args.warmup + args.iterations):
        order = list(MODES)
        rng.shuffle(order)
        for mode in order:
            sample = run_once(args, mode)
            if round_index >= args.warmup:
                for metric, value in sample.items():
                    samples[mode][metric].append(value)

    medians = {
        mode: {
            metric: statistics.median(values)
            for metric, values in metrics.items()
        }
        for mode, metrics in samples.items()
    }
    regressions = {
        mode: {
            metric: regression_percent(
                medians[mode][metric], medians["legacy"][metric]
            )
            for metric in ("first_ns", "second_ns")
        }
        for mode in ("fail_open", "applied")
    }
    report = {
        "iterations": args.iterations,
        "warmup": args.warmup,
        "seed": args.seed,
        "limits_percent": {
            "first_ns": args.max_first_regression_percent,
            "second_ns": args.max_steady_regression_percent,
        },
        "medians_ns": medians,
        "regressions_percent": regressions,
        "samples_ns": samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n",
                           encoding="utf-8")

    failures = []
    for mode, metrics in regressions.items():
        if metrics["first_ns"] > args.max_first_regression_percent:
            failures.append(f"{mode} first={metrics['first_ns']:.2f}%")
        if metrics["second_ns"] > args.max_steady_regression_percent:
            failures.append(f"{mode} second={metrics['second_ns']:.2f}%")
    print(json.dumps({
        "medians_ns": medians,
        "regressions_percent": regressions,
        "result": "FAIL" if failures else "PASS",
    }, indent=2))
    if failures:
        raise RuntimeError("performance gate exceeded: " + ", ".join(failures))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"KZT real guest performance: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
