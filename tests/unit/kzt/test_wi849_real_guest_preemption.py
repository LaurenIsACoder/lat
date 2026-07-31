#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


TARGET_SYMBOL = "dlerror"
SUCCESS_PATTERN = re.compile(
    r"KZT_GUEST_E2E_OK calls=2 slot=(0x[0-9a-f]+) "
    r"before=(0x[0-9a-f]+) after_first=(0x[0-9a-f]+) "
    r"after_second=(0x[0-9a-f]+) first_ns=(0x[0-9a-f]+) "
    r"second_ns=(0x[0-9a-f]+)"
)
SCENARIOS = (
    {
        "name": "unique",
        "executable": "kzt_guest_main",
        "marker": None,
        "candidate_count": 1,
        "direct": True,
        "reason": "SELECTED_PROVIDER",
    },
    {
        "name": "strong-one",
        "executable": "kzt_guest_preempt_a_main",
        "marker": "KZT_PREEMPT_PROVIDER_A",
        "candidate_count": 2,
        "direct": False,
        "reason": "SELECTED_PROVIDER",
    },
    {
        "name": "strong-two",
        "executable": "kzt_guest_preempt_ab_main",
        "marker": "KZT_PREEMPT_PROVIDER_A",
        "candidate_count": 3,
        "direct": False,
        "reason": "SELECTED_PROVIDER",
    },
    {
        "name": "weak-first",
        "executable": "kzt_guest_preempt_weak_main",
        "marker": "KZT_PREEMPT_PROVIDER_WEAK",
        "candidate_count": 2,
        "direct": False,
        "reason": "UNSUPPORTED_PROVIDER_BINDING",
    },
    {
        "name": "rtld-local-isolation",
        "executable": "kzt_guest_local_scope_main",
        "marker": "KZT_PREEMPT_PROVIDER_A",
        "candidate_count": 2,
        "direct": False,
        "reason": "SELECTED_PROVIDER",
        "scope_ready_marker": "KZT_LOCAL_GROUP_READY",
    },
)


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
        if marker < 0:
            continue
        record = parse_record(line[marker:])
        if record.get("symbol") == TARGET_SYMBOL:
            records.append(record)
    return records


def require(condition, message, output):
    if condition:
        return
    raise RuntimeError(f"{message}\n--- guest output ---\n{output.rstrip()}")


def scenario_environment(fixture_dir):
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT"):
            environment.pop(name)
    for name in (
        "LD_AUDIT",
        "LD_BIND_NOW",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_PROFILE",
    ):
        environment.pop(name, None)
    environment.update({
        "LD_LIBRARY_PATH": str(fixture_dir),
        "LATX_AOT": "0",
        "LATX_KZT": "1",
        "LATX_KZT_REGISTRY_DIAGNOSTICS": "1",
        "LATX_KZT_LAZY_DIAGNOSTICS": "1",
        "LATX_KZT_PATCH_SPIKE": "1",
        "LATX_KZT_PATCH_SPIKE_WRITE": "1",
        "LATX_KZT_PATCH_SPIKE_BUDGET": "1",
    })
    return environment


def run_scenario(args, scenario):
    command = [
        str(args.latx),
        "-L",
        str(args.guest_root),
        str(args.fixture_dir / scenario["executable"]),
    ]
    completed = subprocess.run(
        command,
        env=scenario_environment(args.fixture_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    output = completed.stdout
    log_path = args.log_dir / f"wi849-{scenario['name']}.log"
    log_path.write_text(output, encoding="utf-8")

    require(completed.returncode == 0,
            f"{scenario['name']} exited with {completed.returncode}.", output)
    success_matches = SUCCESS_PATTERN.findall(output)
    require(len(success_matches) == 1,
            f"{scenario['name']} did not finish the guest probe.", output)
    slot, before, after_first, after_second, _, _ = (
        int(value, 16) for value in success_matches[0]
    )
    publication_records = [
        parse_record(line[line.find("kzt_lazy_prebind_publish "):])
        for line in output.splitlines()
        if "kzt_lazy_prebind_publish " in line
    ]
    prebound = scenario["direct"] and any(
        record.get("result") == "APPLIED" for record in publication_records
    )
    if prebound:
        require(slot != 0 and before != 0 and after_first == before,
                "The unique provider did not retain its prebound GOT slot.",
                output)
    else:
        require(slot != 0 and before != 0 and after_first != before,
                f"{scenario['name']} did not resolve the lazy GOT slot.", output)
    require(after_second == after_first,
            f"{scenario['name']} changed the GOT slot on the second call.",
            output)

    if scenario.get("scope_ready_marker"):
        lines = output.splitlines()
        ready_lines = [
            index for index, line in enumerate(lines)
            if line == scenario["scope_ready_marker"]
        ]
        decision_lines = [
            index for index, line in enumerate(lines)
            if "kzt_lazy_preemption " in line and
            "symbol=dlerror" in line
        ]
        require(len(ready_lines) == 1 and len(decision_lines) == 1 and
                ready_lines[0] < decision_lines[0],
                "KZT decision was not made after the RTLD_LOCAL group load.",
                output)

    resolver_entries = symbol_records(output, "kzt_lazy_resolver_entry ")
    path_records = symbol_records(output, "kzt_lazy_path ")
    preemption_records = symbol_records(output, "kzt_lazy_preemption ")
    direct_records = symbol_records(output, "kzt_lazy_direct ")
    if prebound:
        require(not resolver_entries and not path_records and
                not preemption_records and not direct_records,
                "The prebound unique provider re-entered lazy resolution.",
                output)
    else:
        require(len(resolver_entries) == 1,
                f"{scenario['name']} must enter the resolver exactly once.", output)
        require(len(path_records) == 1,
                f"{scenario['name']} must emit exactly one lazy path.", output)
        path = path_records[0]
        require(path.get("legacy_lookup") == "0",
                f"{scenario['name']} used the removed legacy host lookup.", output)
        require(path.get("legacy_write") == "0",
                f"{scenario['name']} used the removed legacy GOT writer.", output)
        require(len(preemption_records) == 1,
                f"{scenario['name']} must emit one preemption decision.", output)
        decision = preemption_records[0]
        require(decision.get("scope_complete") == "1",
                f"{scenario['name']} has incomplete lookup scope evidence.", output)
        require(decision.get("lookup_order_known") == "1",
                f"{scenario['name']} has unknown lookup order.", output)
        require(int(decision.get("candidate_count", "0"), 0) ==
                scenario["candidate_count"],
                f"{scenario['name']} reported the wrong visible definition count.",
                output)

    if scenario["direct"] and not prebound:
        require(path.get("route") == "NEW_DIRECT",
                "The unique provider reported the wrong lazy path.", output)
        require(path.get("guest_handoff") == "0",
                "The unique provider unexpectedly entered guest ld.so.", output)
        require(len(direct_records) == 1,
                "The unique provider must use native direct apply.", output)
        require(decision.get("reason") == scenario["reason"],
                f"{scenario['name']} lacks an approval reason.", output)
    elif not prebound:
        require(path.get("route") == "GUEST_LD_SO",
                f"{scenario['name']} did not report guest ld.so handoff.",
                output)
        require(path.get("guest_handoff") == "1",
                f"{scenario['name']} must hand off exactly once to guest ld.so.",
                output)
        require(not direct_records,
                f"{scenario['name']} must not use native direct apply.", output)
        require(decision.get("reason") == scenario["reason"],
                f"{scenario['name']} lacks a fail-open reason.", output)
        require(output.count(scenario["marker"] + "\n") == 2,
                f"{scenario['name']} did not execute the selected guest "
                "provider twice.", output)
        other_markers = {
            "KZT_PREEMPT_PROVIDER_A",
            "KZT_PREEMPT_PROVIDER_B",
            "KZT_PREEMPT_PROVIDER_WEAK",
            "KZT_LOCAL_PREEMPT_PROVIDER",
        } - {scenario["marker"]}
        require(all(marker not in output for marker in other_markers),
                f"{scenario['name']} executed an unselected provider.", output)
        lazy_records = symbol_records(output, "kzt_lazy_diagnostic ")
        require(len(lazy_records) == 1,
                f"{scenario['name']} must complete one guest fallback.", output)

    require("KZT_LOCAL_PREEMPT_PROVIDER" not in output,
            f"{scenario['name']} executed the unrelated RTLD_LOCAL provider.",
            output)

    return log_path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run KZT first-bind symbol preemption scenarios."
    )
    parser.add_argument("--latx", required=True, type=existing_file)
    parser.add_argument("--guest-root", required=True, type=existing_directory)
    parser.add_argument("--fixture-dir", required=True, type=existing_directory)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    args.log_dir = (
        args.log_dir.resolve() if args.log_dir
        else args.fixture_dir / "wi849-logs"
    )
    args.log_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "kzt_guest_main",
        "kzt_guest_preempt_a_main",
        "kzt_guest_preempt_ab_main",
        "kzt_guest_preempt_weak_main",
        "kzt_guest_local_scope_main",
        "libkzt_preempt_a.so",
        "libkzt_preempt_b.so",
        "libkzt_preempt_weak.so",
        "libkzt_local_preempt.so",
    ):
        if not (args.fixture_dir / name).is_file():
            parser.error(f"Fixture is missing {name}.")
    return args


def main():
    args = parse_args()
    logs = [run_scenario(args, scenario) for scenario in SCENARIOS]
    print("KZT WI-849 real guest preemption: PASS")
    for log in logs:
        print(f"log: {log}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"KZT WI-849 real guest preemption: FAIL: {error}",
              file=sys.stderr)
        sys.exit(1)
