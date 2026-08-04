#!/usr/bin/env python3
"""Formal paired performance gate for the real dependency-reopen fixture."""

import argparse
import json
import math
import os
from pathlib import Path
import shutil
import sys

from real_guest_harness import (
    GateResult,
    activate_harness_cpu_isolation,
    analyze_ab_pairs,
    assess_dual_aa,
    classify_gate,
    execute_with_rusage,
    host_load_snapshot,
    randomized_pair_orders,
    restore_harness_cpu_isolation,
)


LIFECYCLE_MARKER = "WI600_GUEST_LOADER_PASS dependency-reopen"
METRIC = "dlopen_lifecycle_process_total_ns"
DEFAULT_SEED = 20260729
SANITIZED_VARIABLES = (
    "LAT_DFILTER", "LAT_GDB", "LAT_LOG", "LAT_LOG_FILENAME",
    "LAT_SINGLESTEP", "LAT_STRACE", "LAT_STRACE_ERROR", "LAT_TRACE",
    "LD_AUDIT", "LD_BIND_NOW", "LD_DEBUG", "LD_DEBUG_OUTPUT",
    "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_PROFILE", "QEMU_LOG",
    "QEMU_STRACE",
)


class GuestLifecycleError(RuntimeError):
    pass


def lifecycle_command(latx, guest_root, fixture_dir, cpu):
    return [
        "taskset", "-c", str(cpu), str(latx), "-L", str(guest_root),
        str(Path(fixture_dir) / "dependency-reopen"),
    ]


def lifecycle_environment(role, fixture_dir):
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT") or name in SANITIZED_VARIABLES:
            environment.pop(name, None)
    environment.update({
        "LATX_AOT": "0",
        "LATX_KZT": "2",
        "LATX_KZT_LAZY_DIAGNOSTICS": "0",
        "LATX_KZT_REGISTRY_DIAGNOSTICS": "0",
        "LD_LIBRARY_PATH": str(fixture_dir),
    })
    if role == "candidate":
        environment.update({
            "LATX_KZT_PATCH_SPIKE": "1",
            "LATX_KZT_PATCH_SPIKE_WRITE": "1",
            "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
        })
    return environment


def validate_lifecycle_execution(execution):
    if execution.get("timed_out"):
        raise GuestLifecycleError("dependency-reopen timed out")
    if execution.get("returncode") != 0:
        raise GuestLifecycleError(
            "dependency-reopen exited with "
            f"{execution.get('returncode')}"
        )
    if LIFECYCLE_MARKER not in execution.get("output", "").splitlines():
        raise GuestLifecycleError("dependency-reopen did not emit its PASS marker")
    elapsed = execution.get("process_total_ns", 0)
    if not isinstance(elapsed, int) or elapsed <= 0:
        raise GuestLifecycleError("dependency-reopen has no positive process time")
    return {METRIC: elapsed}


def run_lifecycle_sample(args, role):
    latx = args.baseline_latx if role == "baseline" else args.candidate_latx
    command = lifecycle_command(latx, args.guest_root, args.fixture_dir, args.cpu)
    execution = execute_with_rusage(
        command, lifecycle_environment(role, args.fixture_dir), args.timeout
    )
    metrics = validate_lifecycle_execution(execution)
    return {
        **metrics,
        "role": role,
        "command": command,
        "rusage": execution["rusage"],
        "wait_method": execution["wait_method"],
        "output": execution["output"],
    }


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def _run_pair(args, output, phase, pair_index, order, labels):
    pair = {"order": list(order)}
    for position, label in enumerate(order):
        role = labels[label]
        sample = run_lifecycle_sample(args, role)
        pair[label] = sample
        output.write(json.dumps({
            "phase": phase,
            "pair_index": pair_index,
            "position": position,
            "label": label,
            "pair_order": list(order),
            "sample": sample,
        }, sort_keys=True) + "\n")
        output.flush()
    return pair


def _run_aa(args, output, role):
    labels = {"a": role, "b": role}
    orders = randomized_pair_orders(
        args.aa_pairs, args.seed + (0 if role == "baseline" else 1),
        ("a", "b"),
    )
    return [
        _run_pair(args, output, role + "-aa", index, order, labels)
        for index, order in enumerate(orders)
    ]


def _issues(args):
    issues = []
    for label, path in (("baseline LATX", args.baseline_latx),
                        ("candidate LATX", args.candidate_latx)):
        if not path.is_file() or not os.access(path, os.X_OK):
            issues.append(f"{label} is not executable: {path}")
    if not args.guest_root.is_dir():
        issues.append(f"guest root does not exist: {args.guest_root}")
    fixture = args.fixture_dir / "dependency-reopen"
    if not fixture.is_file() or not os.access(fixture, os.X_OK):
        issues.append(f"dependency-reopen fixture is not executable: {fixture}")
    if not shutil.which("taskset"):
        issues.append("taskset is unavailable")
    return issues


def run_lifecycle_gate(args):
    issues = _issues(args)
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise GuestLifecycleError(
            f"output directory already contains evidence: {args.output_dir}"
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.output_dir / "raw-samples.jsonl"
    report_path = args.output_dir / "report.json"
    metadata_path = args.output_dir / "run-metadata.json"
    cpu_isolation = activate_harness_cpu_isolation(True, args.cpu)
    if not cpu_isolation["verification"]["passed"]:
        issues.append(
            "physical-core isolation could not be verified: "
            + (cpu_isolation["verification"]["error"] or
               "unknown isolation error")
        )
    report = {
        "artifact_type": "kzt-dlopen-lifecycle-performance-report",
        "metric": METRIC,
        "metric_scope": (
            "end-to-end LATX process time for dependency-reopen; not "
            "guest-internal lazy binding"
        ),
        "config": {
            "baseline_latx": str(args.baseline_latx),
            "candidate_latx": str(args.candidate_latx),
            "guest_root": str(args.guest_root),
            "fixture_dir": str(args.fixture_dir),
            "cpu": args.cpu,
            "aa_pairs": args.aa_pairs,
            "ab_pairs": args.ab_pairs,
            "warmup": args.warmup,
            "seed": args.seed,
            "isolate_harness_cpu": True,
        },
        "harness_cpu_isolation": cpu_isolation,
        "load": {"before": host_load_snapshot()},
        "issues": issues,
        "result": GateResult.INCONCLUSIVE.value,
        "result_scope": "environment_inconclusive",
    }
    try:
        if issues or report["load"]["before"]["oversubscribed"]:
            report["reason"] = (
                "benchmark prerequisites or host load unavailable: "
                + "; ".join(issues)
            )
            return report
        with raw_path.open("w", encoding="utf-8") as output:
            for role in ("baseline", "candidate"):
                for warmup in range(args.warmup):
                    sample = run_lifecycle_sample(args, role)
                    output.write(json.dumps({
                        "phase": "warmup", "role": role,
                        "sample_index": warmup, "sample": sample,
                    }, sort_keys=True) + "\n")
            baseline_aa = _run_aa(args, output, "baseline")
            candidate_aa = _run_aa(args, output, "candidate")
            aa = assess_dual_aa(
                baseline_aa, candidate_aa, seed=args.seed, metrics=(METRIC,)
            )
            report["aa_stability"] = aa
            report["load"]["after_aa"] = host_load_snapshot()
            if not aa["stable"]:
                report["reason"] = "formal A/A lifecycle result is not stable"
                return report
            if report["load"]["after_aa"]["oversubscribed"]:
                report["reason"] = "host load exceeded available capacity during A/A"
                return report
            orders = randomized_pair_orders(
                args.ab_pairs, args.seed + 2, ("baseline", "candidate")
            )
            pairs = [
                _run_pair(
                    args, output, "ab", index, order,
                    {"baseline": "baseline", "candidate": "candidate"},
                )
                for index, order in enumerate(orders)
            ]
        report["load"]["after_ab"] = host_load_snapshot()
        if report["load"]["after_ab"]["oversubscribed"]:
            report["reason"] = "host load exceeded available capacity during A/B"
            return report
        analysis = analyze_ab_pairs(
            pairs, seed=args.seed, formal_stage_count=1,
            metrics=(METRIC,), tail_metrics=(METRIC,)
        )
        decision = classify_gate(
            analysis, pair_count=len(pairs), formal_aa_stable=True
        )
        report["ab"] = analysis
        report["result"] = decision.value
        report["result_scope"] = "performance_conclusion"
        report["reason"] = (
            "paired lifecycle median and paired-index bootstrap marginal "
            "P95-ratio non-inferiority passed"
            if decision == GateResult.PASS else
            "paired lifecycle gate did not establish non-inferiority"
        )
        return report
    except GuestLifecycleError as error:
        report["result"] = GateResult.FAIL.value
        report["result_scope"] = "correctness_failure"
        report["reason"] = str(error)
        return report
    finally:
        report["load"]["after"] = host_load_snapshot()
        restore_harness_cpu_isolation(cpu_isolation)
        report["harness_cpu_isolation"] = cpu_isolation
        metadata = dict(report)
        metadata["artifact_type"] = (
            "kzt-dlopen-lifecycle-performance-run-metadata"
        )
        _write_json(metadata_path, metadata)
        _write_json(report_path, report)


def positive_integer(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-latx", required=True, type=Path)
    parser.add_argument("--candidate-latx", required=True, type=Path)
    parser.add_argument("--guest-root", required=True, type=Path)
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--cpu", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--aa-pairs", type=positive_integer, default=200)
    parser.add_argument("--ab-pairs", type=positive_integer, default=400)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    invalid = (
        args.cpu < 0 or args.warmup < 0 or args.aa_pairs < 200 or
        args.ab_pairs < 400 or not math.isfinite(args.timeout) or
        args.timeout <= 0
    )
    if invalid:
        parser.error("invalid formal sampling configuration")
    for name in ("baseline_latx", "candidate_latx", "guest_root", "fixture_dir"):
        setattr(args, name, getattr(args, name).resolve())
    args.output_dir = args.output_dir.resolve()
    return args


def main():
    args = parse_args()
    report = run_lifecycle_gate(args)
    print(json.dumps({
        "result": report["result"],
        "reason": report.get("reason"),
        "report": str(args.output_dir / "report.json"),
        "raw_samples": str(args.output_dir / "raw-samples.jsonl"),
    }, indent=2, sort_keys=True))
    return 0 if report["result"] == GateResult.PASS.value else 1


if __name__ == "__main__":
    sys.exit(main())
