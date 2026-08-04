#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


SCENARIOS = (
    {
        "id": "dependency-reopen",
        "description": "dependency, duplicate handles, close, and reopen",
    },
    {
        "id": "visibility-noload",
        "description": "RTLD_LOCAL, RTLD_GLOBAL, and RTLD_NOLOAD",
    },
    {
        "id": "namespace-isolation",
        "description": "dlmopen namespace identity and isolation",
    },
    {
        "id": "symbol-versions-errors",
        "description": "dlsym, dlvsym, missing objects, and dlerror",
    },
    {
        "id": "wrapped-library-handle",
        "description": "wrapped library guest handle, duplicate open, and NOLOAD",
    },
)

LOADER_PATHS = (
    "lib64/ld-linux-x86-64.so.2",
    "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
)

EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "INCONCLUSIVE": 2,
}

SANITIZED_LOADER_VARIABLES = (
    "LD_AUDIT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_PROFILE",
)


def path_issue(path, label, executable=False, directory=False):
    if directory:
        if not path.is_dir():
            return f"{label} directory not found: {path}"
        return None
    if not path.is_file():
        return f"{label} not found: {path}"
    if executable and not os.access(str(path), os.X_OK):
        return f"{label} is not executable: {path}"
    return None


def guest_root_issue(guest_root):
    issue = path_issue(guest_root, "guest root", directory=True)
    if issue:
        return issue
    if not any((guest_root / relative).is_file() for relative in LOADER_PATHS):
        return f"x86-64 guest loader not found under guest root: {guest_root}"
    return None


def normalise_output(output):
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def write_log(log_path, command, output, reason):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["command: " + " ".join(command), "result: " + reason, ""]
    if output:
        lines.append(output.rstrip())
        lines.append("")
    log_path.write_text("\n".join(lines), encoding="utf-8")


def result(status, reason, command, log_path, duration=0.0,
           returncode=None):
    return {
        "status": status,
        "reason": reason,
        "returncode": returncode,
        "duration_seconds": round(duration, 6),
        "command": command,
        "log": str(log_path),
    }


def run_scenario(label, latx, scenario, args, infrastructure_issue=None):
    scenario_id = scenario["id"]
    executable = args.fixture_dir / scenario_id
    log_path = args.log_dir / f"{label}-{scenario_id}.log"
    command = [
        str(latx),
        "-L",
        str(args.guest_root),
        str(executable),
    ]

    issue = infrastructure_issue
    if issue is None:
        issue = path_issue(
            executable, f"fixture for {scenario_id}", executable=True
        )
    if issue:
        reason = "infrastructure unavailable: " + issue
        write_log(log_path, command, "", reason)
        return result("INCONCLUSIVE", reason, command, log_path)

    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT"):
            environment.pop(name)
    for name in SANITIZED_LOADER_VARIABLES:
        environment.pop(name, None)
    environment.update({
        "LATX_KZT": "2",
        "LATX_KZT_LAZY_DIAGNOSTICS": "0",
        "LATX_KZT_REGISTRY_DIAGNOSTICS": "0",
        "LD_LIBRARY_PATH": str(args.fixture_dir),
    })
    if label == "candidate":
        environment.update({
            "LATX_KZT_PATCH_SPIKE": "1",
            "LATX_KZT_PATCH_SPIKE_WRITE": "1",
            "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
        })

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(args.fixture_dir),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        duration = time.monotonic() - started
        output = normalise_output(error.stdout)
        reason = f"guest run timed out after {args.timeout:g} seconds"
        write_log(log_path, command, output, reason)
        return result(
            "INCONCLUSIVE", reason, command, log_path, duration=duration
        )
    except OSError as error:
        duration = time.monotonic() - started
        reason = f"could not execute LATX: {error}"
        write_log(log_path, command, "", reason)
        return result(
            "INCONCLUSIVE", reason, command, log_path, duration=duration
        )

    duration = time.monotonic() - started
    output = completed.stdout
    if completed.returncode == 77:
        reason = "guest run reported skip (exit 77)"
        status = "INCONCLUSIVE"
    elif completed.returncode != 0:
        reason = f"guest exited with status {completed.returncode}"
        status = "FAIL"
    else:
        expected_marker = f"WI600_GUEST_LOADER_PASS {scenario_id}"
        marker_found = any(
            line.strip() == expected_marker for line in output.splitlines()
        )
        if marker_found:
            reason = "guest scenario passed"
            status = "PASS"
        else:
            reason = f"guest exited successfully without pass marker: {expected_marker}"
            status = "FAIL"

    write_log(log_path, command, output, reason)
    return result(
        status,
        reason,
        command,
        log_path,
        duration=duration,
        returncode=completed.returncode,
    )


def compare_results(baseline, candidate):
    regression = baseline["status"] == "PASS" and \
        candidate["status"] == "FAIL"
    if candidate["status"] == "FAIL":
        if regression:
            reason = "candidate failed after baseline passed"
        else:
            reason = "candidate P0 scenario failed"
        return "FAIL", regression, reason
    if candidate["status"] == "INCONCLUSIVE":
        return "INCONCLUSIVE", False, \
            "candidate result is inconclusive"
    if baseline["status"] == "INCONCLUSIVE":
        return "INCONCLUSIVE", False, \
            "baseline comparison is inconclusive"
    if baseline["status"] == "FAIL":
        return "PASS", False, "candidate passed while baseline failed"
    return "PASS", False, "baseline and candidate passed"


def overall_status(scenarios):
    statuses = {scenario["status"] for scenario in scenarios}
    if "FAIL" in statuses:
        return "FAIL"
    if "INCONCLUSIVE" in statuses:
        return "INCONCLUSIVE"
    return "PASS"


def render_table(report):
    headings = ("SCENARIO", "BASELINE", "CANDIDATE", "GATE", "REGRESSION")
    rows = [headings]
    for scenario in report["scenarios"]:
        rows.append((
            scenario["id"],
            scenario["baseline"]["status"],
            scenario["candidate"]["status"],
            scenario["status"],
            "yes" if scenario["regression"] else "no",
        ))
    widths = [max(len(row[index]) for row in rows) for index in range(5)]
    rendered = []
    for row_index, row in enumerate(rows):
        rendered.append("  ".join(
            value.ljust(widths[index])
            for index, value in enumerate(row)
        ).rstrip())
        if row_index == 0:
            rendered.append("  ".join("-" * width for width in widths))
    rendered.append(f"OVERALL: {report['status']}")
    return "\n".join(rendered)


def run_gate(args):
    args.baseline_latx = args.baseline_latx.resolve()
    args.candidate_latx = args.candidate_latx.resolve()
    args.guest_root = args.guest_root.resolve()
    args.fixture_dir = args.fixture_dir.resolve()
    args.log_dir = args.log_dir.resolve()
    args.json_output = args.json_output.resolve()

    shared_issue = guest_root_issue(args.guest_root)
    if shared_issue is None:
        shared_issue = path_issue(
            args.fixture_dir, "fixture", directory=True
        )
    baseline_issue = shared_issue or path_issue(
        args.baseline_latx, "baseline LATX", executable=True
    )
    candidate_issue = shared_issue or path_issue(
        args.candidate_latx, "candidate LATX", executable=True
    )

    scenario_reports = []
    for scenario in SCENARIOS:
        baseline = run_scenario(
            "baseline", args.baseline_latx, scenario, args, baseline_issue
        )
        candidate = run_scenario(
            "candidate", args.candidate_latx, scenario, args, candidate_issue
        )
        status, regression, reason = compare_results(baseline, candidate)
        scenario_reports.append({
            "id": scenario["id"],
            "description": scenario["description"],
            "p0": True,
            "status": status,
            "regression": regression,
            "reason": reason,
            "baseline": baseline,
            "candidate": candidate,
        })

    status = overall_status(scenario_reports)
    counts = {
        name: sum(item["status"] == name for item in scenario_reports)
        for name in ("PASS", "FAIL", "INCONCLUSIVE")
    }
    return {
        "schema_version": 1,
        "gate": "WI-600-real-guest-loader",
        "status": status,
        "exit_code": EXIT_CODES[status],
        "inputs": {
            "baseline_latx": str(args.baseline_latx),
            "candidate_latx": str(args.candidate_latx),
            "guest_root": str(args.guest_root),
            "fixture_dir": str(args.fixture_dir),
            "timeout_seconds": args.timeout,
        },
        "counts": counts,
        "scenarios": scenario_reports,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare WI-600 real guest loader behavior across LATX builds."
    )
    parser.add_argument("--baseline-latx", required=True, type=Path)
    parser.add_argument("--candidate-latx", required=True, type=Path)
    parser.add_argument("--guest-root", required=True, type=Path)
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.log_dir is None:
        args.log_dir = args.fixture_dir / "logs" / "wi600-loader-gate"
    if args.json_output is None:
        args.json_output = args.log_dir / "report.json"
    return args


def main(argv=None):
    args = parse_args(argv)
    report = run_gate(args)
    print(render_table(report))
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"JSON report: {args.json_output.resolve()}")
    return report["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        print(f"WI-600 guest loader gate: INCONCLUSIVE: {error}", file=sys.stderr)
        sys.exit(EXIT_CODES["INCONCLUSIVE"])
