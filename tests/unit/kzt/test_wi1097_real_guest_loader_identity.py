#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


SCENARIOS = ("dependency-reopen", "namespace-isolation")
UNLOAD_RE = re.compile(
    r"phase=unload link_map=0x([0-9a-f]+) generation=([0-9]+) "
    r"namespace=0x([0-9a-f]+) result=(-?[0-9]+)"
)


def existing_file(value):
    path = Path(value).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"file not found: {path}")
    return path


def existing_directory(value):
    path = Path(value).resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"directory not found: {path}")
    return path


def run_scenario(args, scenario):
    executable = args.fixture_dir / scenario
    if not executable.is_file():
        raise RuntimeError(f"fixture not found: {executable}")

    command = [
        str(args.latx),
        "-L",
        str(args.guest_root),
        str(executable),
    ]
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("LATX_KZT"):
            environment.pop(name)
    environment.update({
        "LATX_KZT": "2",
        "LATX_KZT_REGISTRY_DIAGNOSTICS": "1",
        "LATX_KZT_LAZY_DIAGNOSTICS": "0",
        "LD_LIBRARY_PATH": str(args.fixture_dir),
    })
    completed = subprocess.run(
        command,
        cwd=args.fixture_dir,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.timeout,
        check=False,
    )
    args.log_dir.mkdir(parents=True, exist_ok=True)
    log_path = args.log_dir / f"{scenario}.log"
    log_path.write_text(
        "command: " + " ".join(command) + "\n\n" + completed.stdout,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"{scenario}: guest exited {completed.returncode}; log={log_path}"
        )
    marker = f"WI600_GUEST_LOADER_PASS {scenario}"
    if marker not in completed.stdout.splitlines():
        raise AssertionError(f"{scenario}: missing pass marker; log={log_path}")
    unloads = [
        tuple(int(value, 16 if index in (0, 2) else 10)
              for index, value in enumerate(match.groups()))
        for match in UNLOAD_RE.finditer(completed.stdout)
    ]
    if any(result != 0 for _, _, _, result in unloads):
        raise AssertionError(f"{scenario}: unload retire failed; log={log_path}")
    return unloads, completed.stdout, log_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--latx", required=True, type=existing_file)
    parser.add_argument("--guest-root", required=True, type=existing_directory)
    parser.add_argument("--fixture-dir", required=True, type=existing_directory)
    parser.add_argument("--log-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    dependency, dependency_output, dependency_log = run_scenario(
        args, "dependency-reopen"
    )
    if "registry_result=3" in dependency_output:
        raise AssertionError(
            f"dependency-reopen: Registry conflict after reopen; "
            f"log={dependency_log}"
        )
    main_unloads = [entry for entry in dependency if entry[2] == 0]
    generations = {entry[1] for entry in main_unloads}
    if len(main_unloads) < 4 or len(generations) < 4:
        raise AssertionError(
            f"dependency-reopen: expected two exact unload rounds; "
            f"log={dependency_log}"
        )

    namespace, _, namespace_log = run_scenario(args, "namespace-isolation")
    namespace_unloads = [entry for entry in namespace if entry[2] != 0]
    if not namespace_unloads:
        raise AssertionError(
            f"namespace-isolation: missing non-main unload; log={namespace_log}"
        )

    print(
        "WI-1097 real guest loader identity: PASS "
        f"dependency_unloads={len(main_unloads)} "
        f"namespace_unloads={len(namespace_unloads)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
