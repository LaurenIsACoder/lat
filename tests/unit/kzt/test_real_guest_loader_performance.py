#!/usr/bin/env python3
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from real_guest_loader_performance import (
    LIFECYCLE_MARKER,
    GuestLifecycleError,
    lifecycle_command,
    run_lifecycle_gate,
    validate_lifecycle_execution,
)


class GuestLoaderPerformanceTest(unittest.TestCase):
    def test_accepts_dependency_reopen_pass_marker(self):
        result = validate_lifecycle_execution({
            "returncode": 0,
            "timed_out": False,
            "process_total_ns": 1234,
            "output": LIFECYCLE_MARKER + "\n",
        })

        self.assertEqual(result["dlopen_lifecycle_process_total_ns"], 1234)

    def test_rejects_non_passing_lifecycle_execution(self):
        for execution in (
            {"returncode": 1, "timed_out": False,
             "process_total_ns": 1234, "output": ""},
            {"returncode": 0, "timed_out": True,
             "process_total_ns": 1234, "output": LIFECYCLE_MARKER},
            {"returncode": 0, "timed_out": False,
             "process_total_ns": 1234, "output": "missing marker\n"},
        ):
            with self.assertRaises(GuestLifecycleError):
                validate_lifecycle_execution(execution)

    def test_command_pins_existing_dependency_reopen_fixture(self):
        command = lifecycle_command(
            "/candidate/latx", "/guest-root", "/fixture", 3
        )

        self.assertEqual(command[:2], ["taskset", "-c"])
        self.assertEqual(command[2], "3")
        self.assertEqual(command[3], "/candidate/latx")
        self.assertEqual(
            command[4:],
            ["-L", "/guest-root", "/fixture/dependency-reopen"],
        )

    def test_unverified_core_isolation_blocks_formal_lifecycle_samples(self):
        failed_isolation = {
            "requested": True,
            "applied": False,
            "guest_cpu": 37,
            "topology_source": "/synthetic/thread_siblings_list",
            "thread_siblings": None,
            "initial_affinity": [4, 12, 37, 55],
            "active_affinity": [4, 12, 37, 55],
            "parent_cpus": {
                "initial": [4, 12, 37, 55],
                "expected": [4, 12, 37, 55],
                "active": [4, 12, 37, 55],
            },
            "excluded_cpus": [],
            "verification": {
                "passed": False,
                "siblings_excluded": None,
                "active_matches_expected": None,
                "error": "synthetic topology unavailable",
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "lifecycle"
            args = SimpleNamespace(
                baseline_latx=Path("/baseline"),
                candidate_latx=Path("/candidate"),
                guest_root=Path("/guest"),
                fixture_dir=Path("/fixture"),
                cpu=37,
                output_dir=output_dir,
                aa_pairs=200,
                ab_pairs=400,
                warmup=20,
                seed=7,
                timeout=60.0,
            )
            with mock.patch("real_guest_loader_performance._issues",
                            return_value=[]), \
                 mock.patch(
                    "real_guest_loader_performance.activate_harness_cpu_isolation",
                    return_value=failed_isolation,
                    create=True,
                 ), \
                 mock.patch("real_guest_loader_performance.host_load_snapshot",
                            return_value={"oversubscribed": False}), \
                 mock.patch(
                    "real_guest_loader_performance.run_lifecycle_sample",
                    side_effect=AssertionError("sample must not run"),
                 ):
                report = run_lifecycle_gate(args)

            metadata = json.loads(
                (output_dir / "run-metadata.json").read_text()
            )
        self.assertEqual(report["result"], "INCONCLUSIVE")
        self.assertIn("synthetic topology unavailable", report["reason"])
        self.assertEqual(report["harness_cpu_isolation"], failed_isolation)
        self.assertEqual(metadata["harness_cpu_isolation"], failed_isolation)


if __name__ == "__main__":
    unittest.main()
