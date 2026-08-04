#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path
import sys

from real_guest_harness import (
    BASELINE_BINDING_STATES,
    EAGER_FINAL,
    GateResult,
    HarnessConfig,
    run_performance_gate,
)


DEFAULT_SEED = 20260721


def absolute_path(value):
    return Path(value).expanduser().resolve()


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Compare legacy and candidate release LATX KZT performance."
        )
    )
    parser.add_argument(
        "--baseline-latx", required=True, type=absolute_path
    )
    parser.add_argument(
        "--baseline-binding-state",
        choices=BASELINE_BINDING_STATES,
        default=EAGER_FINAL,
        help="expected binding state for the statistical baseline",
    )
    parser.add_argument(
        "--candidate-latx", required=True, type=absolute_path
    )
    parser.add_argument("--guest-root", required=True, type=absolute_path)
    parser.add_argument("--fixture-dir", required=True, type=absolute_path)
    parser.add_argument("--cpu", required=True, type=int)
    parser.add_argument("--isolate-harness-cpu", action="store_true")
    parser.add_argument("--aa-only", action="store_true")
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--samples", type=int, default=80)
    parser.add_argument("--max-samples", type=int, default=800)
    parser.add_argument("--aa-samples", type=int, default=200)
    parser.add_argument("--steady-calls", type=int, default=100000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output-dir", required=True, type=absolute_path)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    if args.cpu < 0:
        parser.error("--cpu must be non-negative")
    if args.warmup < 0:
        parser.error("--warmup must be non-negative")
    if args.samples not in (80, 400, 800, 1600):
        parser.error("--samples must be one of 80, 400, 800, or 1600")
    if args.max_samples < args.samples:
        parser.error("--max-samples must be at least --samples")
    if args.max_samples not in (80, 400, 800, 1600):
        parser.error("--max-samples must be one of 80, 400, 800, or 1600")
    if args.aa_samples != 50 and args.aa_samples < 200:
        parser.error("--aa-samples must be 50 for screening or at least 200")
    if args.aa_samples == 50 and args.max_samples != 80:
        parser.error("--aa-samples 50 requires --max-samples 80")
    if args.steady_calls < 100000:
        parser.error("--steady-calls must be at least 100000")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    return args


def main():
    args = parse_args()
    config = HarnessConfig(
        baseline_latx=args.baseline_latx,
        baseline_binding_state=args.baseline_binding_state,
        candidate_latx=args.candidate_latx,
        guest_root=args.guest_root,
        fixture_dir=args.fixture_dir,
        cpu=args.cpu,
        warmup=args.warmup,
        samples=args.samples,
        max_samples=args.max_samples,
        aa_samples=args.aa_samples,
        steady_calls=args.steady_calls,
        seed=args.seed,
        output_dir=args.output_dir,
        timeout=args.timeout,
        isolate_harness_cpu=args.isolate_harness_cpu,
        aa_only=args.aa_only,
    )
    report = run_performance_gate(config)
    print(json.dumps({
        "result": report["result"],
        "reason": report["reason"],
        "report": str(args.output_dir / "report.json"),
        "raw_samples": report["raw_samples"],
    }, indent=2, sort_keys=True))
    if report["result"] == GateResult.PASS.value:
        return 0
    if report["result"] == GateResult.FAIL.value:
        return 1
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("KZT real guest performance: INCONCLUSIVE: interrupted",
              file=sys.stderr)
        sys.exit(2)
