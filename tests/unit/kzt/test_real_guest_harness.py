#!/usr/bin/env python3
import os
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import real_guest_harness

from real_guest_harness import (
    AAResult,
    EAGER_FINAL,
    GateResult,
    GUEST_FIRST_BINDING_METRIC,
    GUEST_LAZY_COMPARISON_METRICS,
    GuestCorrectnessError,
    HarnessConfig,
    PrerequisiteError,
    PERFORMANCE_MODES,
    PRIMARY_TIME_METRICS,
    LAZY_TO_GUEST_FINAL,
    LAZY_TO_NATIVE_FINAL,
    PREBOUND_NATIVE_FINAL,
    analyze_ab_pairs,
    assess_dual_aa,
    assess_aa_pairs,
    benchmark_environment,
    benchmark_command,
    classify_gate,
    comparison_metrics_for_baseline_state,
    activate_harness_cpu_isolation,
    _preflight_address,
    _checkpoint_targets,
    _acquire_output_ownership,
    _formal_stage_count,
    _inconclusive_details,
    _one_sided_quantile_bounds,
    _order_statistic_interval,
    _statistics_record,
    parse_guest_record,
    randomized_pair_orders,
    run_performance_gate,
    run_guest_mode,
    runtime_environment_snapshot,
    run_guest_sample,
    validate_role_mode_record,
    verify_guest_preserved_preflight,
    verify_role_modes_preflight,
    verify_native_apply_preflight,
)
from test_real_guest_performance import parse_args


def timed_sample(value):
    sample = {metric: value for metric in PRIMARY_TIME_METRICS}
    sample[GUEST_FIRST_BINDING_METRIC] = value
    return sample


def ab_pairs(baseline_values, candidate_values):
    return [
        {
            "baseline": timed_sample(baseline),
            "candidate": timed_sample(candidate),
            "order": ["baseline", "candidate"],
        }
        for baseline, candidate in zip(baseline_values, candidate_values)
    ]


def aa_pairs(values):
    return [
        {
            "a": timed_sample(value),
            "b": timed_sample(value),
            "order": ["a", "b"],
        }
        for value in values
    ]


class GuestRecordTests(unittest.TestCase):
    def test_parses_three_performance_modes_and_null_result_counts(self):
        startup = (
            "KZT_GUEST_PERF_OK mode=startup steady_calls=0 slot=0 before=0 "
            "after_first=0 after_steady=0 first_ns=0 steady_total_ns=0 "
            "steady_per_call_ns=0 checksum=0\n"
        )
        first = (
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            "before=0x200 after_first=0x300 after_steady=0x300 "
            "first_ns=0x64 steady_total_ns=0 steady_per_call_ns=0 checksum=1\n"
        )
        steady = (
            "KZT_GUEST_PERF_OK mode=steady steady_calls=100000 slot=0x100 "
            "before=0x200 after_first=0x300 after_steady=0x300 "
            "first_ns=0x64 steady_total_ns=0xf4240 steady_per_call_ns=0xa "
            "checksum=100001\n"
        )

        self.assertEqual(
            parse_guest_record(startup, 100000, expected_mode="startup")["mode"],
            "startup",
        )
        self.assertEqual(
            parse_guest_record(first, 100000, expected_mode="first")["checksum"],
            1,
        )
        self.assertEqual(
            parse_guest_record(steady, 100000, expected_mode="steady")[
                "checksum"
            ],
            100001,
        )

    def test_parses_performance_record(self):
        output = (
            "KZT_GUEST_PERF_OK steady_calls=10000 slot=0x100 before=0x200 "
            "after_first=0x300 after_steady=0x300 first_ns=0x64 "
            "steady_total_ns=0x186a0 steady_per_call_ns=0xa checksum=0x1\n"
        )

        record = parse_guest_record(output, expected_steady_calls=10000)

        self.assertEqual(record["first_binding_ns"], 100)
        self.assertEqual(record["steady_total_ns"], 100000)
        self.assertEqual(record["steady_per_call_ns"], 10)
        self.assertEqual(record["steady_calls"], 10000)

    def test_rejects_duplicate_records(self):
        line = (
            "KZT_GUEST_PERF_OK steady_calls=10000 slot=0x100 before=0x200 "
            "after_first=0x300 after_steady=0x300 first_ns=0x64 "
            "steady_total_ns=0x186a0 steady_per_call_ns=0xa checksum=0x1\n"
        )

        with self.assertRaises(GuestCorrectnessError):
            parse_guest_record(line + line, expected_steady_calls=10000)

    def test_rejects_changed_steady_slot(self):
        output = (
            "KZT_GUEST_PERF_OK steady_calls=10000 slot=0x100 before=0x200 "
            "after_first=0x300 after_steady=0x301 first_ns=0x64 "
            "steady_total_ns=0x186a0 steady_per_call_ns=0xa checksum=0x1\n"
        )

        with self.assertRaises(GuestCorrectnessError):
            parse_guest_record(output, expected_steady_calls=10000)


class PairOrderTests(unittest.TestCase):
    def test_orders_are_seeded_random_and_balanced(self):
        first = randomized_pair_orders(11, seed=1234, labels=("old", "new"))
        second = randomized_pair_orders(11, seed=1234, labels=("old", "new"))

        self.assertEqual(first, second)
        self.assertNotEqual(first, randomized_pair_orders(
            11, seed=1235, labels=("old", "new")
        ))
        self.assertTrue(all(set(order) == {"old", "new"} for order in first))
        old_first = sum(order[0] == "old" for order in first)
        self.assertLessEqual(abs(old_first - (len(first) - old_first)), 1)


class HarnessCpuIsolationTests(unittest.TestCase):
    def test_parses_kernel_cpu_lists_without_machine_specific_numbering(self):
        self.assertEqual(
            real_guest_harness._parse_cpu_list("4,12-14,37,55-56\n"),
            [4, 12, 13, 14, 37, 55, 56],
        )

    def test_excludes_guest_thread_siblings_from_parent_harness(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            topology_root = Path(temporary_directory)
            sibling_path = (
                topology_root / "cpu37" / "topology" /
                "thread_siblings_list"
            )
            sibling_path.parent.mkdir(parents=True)
            sibling_path.write_text("12,37\n", encoding="ascii")
            with mock.patch.object(
                    real_guest_harness, "CPU_SYSFS_ROOT", topology_root,
                    create=True), \
                 mock.patch(
                    "real_guest_harness.os.sched_getaffinity",
                    side_effect=[{4, 12, 37, 55}, {4, 55}],
                 ), \
                 mock.patch(
                    "real_guest_harness.os.sched_setaffinity"
                 ) as set_affinity:
                isolation = activate_harness_cpu_isolation(True, 37)

        set_affinity.assert_called_once_with(0, {4, 55})
        self.assertEqual(isolation["guest_cpu"], 37)
        self.assertEqual(isolation["thread_siblings"], [12, 37])
        self.assertEqual(isolation["initial_affinity"], [4, 12, 37, 55])
        self.assertEqual(isolation["active_affinity"], [4, 55])
        self.assertTrue(isolation["verification"]["passed"])
        self.assertTrue(isolation["applied"])

    def test_missing_or_malformed_topology_never_falls_back_to_guest_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            topology_root = Path(temporary_directory)
            sibling_path = (
                topology_root / "cpu37" / "topology" /
                "thread_siblings_list"
            )
            for value in (None, "", "12-4", "cpu12,37"):
                with self.subTest(value=value):
                    if sibling_path.exists():
                        sibling_path.unlink()
                    if value is not None:
                        sibling_path.parent.mkdir(parents=True, exist_ok=True)
                        sibling_path.write_text(value, encoding="ascii")
                    with mock.patch.object(
                            real_guest_harness, "CPU_SYSFS_ROOT",
                            topology_root), \
                         mock.patch(
                            "real_guest_harness.os.sched_getaffinity",
                            return_value={4, 12, 37, 55},
                         ), \
                         mock.patch(
                            "real_guest_harness.os.sched_setaffinity"
                         ) as set_affinity:
                        isolation = activate_harness_cpu_isolation(True, 37)

                    set_affinity.assert_not_called()
                    self.assertFalse(isolation["applied"])
                    self.assertFalse(isolation["verification"]["passed"])
                    self.assertIsNotNone(isolation["verification"]["error"])
                    self.assertEqual(
                        isolation["topology_source"], str(sibling_path)
                    )


class ModeContractTests(unittest.TestCase):
    def config(self):
        return HarnessConfig(
            baseline_latx=Path("/baseline-latx"),
            candidate_latx=Path("/candidate-latx"),
            guest_root=Path("/guest-root"),
            fixture_dir=Path("/fixture"),
            cpu=6,
            warmup=0,
            samples=80,
            max_samples=800,
            aa_samples=50,
            steady_calls=100000,
            seed=7,
            output_dir=Path("/output"),
        )

    def test_declares_three_endpoint_to_endpoint_modes_and_primary_metrics(self):
        self.assertEqual(PERFORMANCE_MODES, ("startup", "first", "steady"))
        self.assertEqual(PRIMARY_TIME_METRICS, (
            "startup_process_total_ns",
            "launch_to_first_result_ns",
            "steady_total_ns",
        ))
        self.assertEqual(
            comparison_metrics_for_baseline_state(LAZY_TO_GUEST_FINAL),
            GUEST_LAZY_COMPARISON_METRICS,
        )
        self.assertNotIn(
            "steady_total_ns", GUEST_LAZY_COMPARISON_METRICS
        )

    def test_mode_commands_preserve_role_and_steady_count(self):
        config = self.config()
        startup = benchmark_command(config, "baseline", "startup", "/taskset")
        first = benchmark_command(config, "candidate", "first", "/taskset")
        steady = benchmark_command(config, "candidate", "steady", "/taskset")

        self.assertEqual(startup[-1:], ["startup"])
        self.assertEqual(first[-1:], ["first"])
        self.assertEqual(steady[-2:], ["steady", "100000"])
        self.assertIn("/baseline-latx", startup)
        self.assertIn("/candidate-latx", first)

    def test_role_binding_states_are_distinct_and_fail_closed(self):
        eager = {
            "before": 0x300,
            "after_first": 0x300,
            "after_steady": 0x300,
        }
        lazy = {
            "before": 0x200,
            "after_first": 0x300,
            "after_steady": 0x300,
        }

        self.assertEqual(
            validate_role_mode_record("baseline", "first", eager),
            "EAGER_FINAL",
        )
        self.assertEqual(
            validate_role_mode_record("candidate", "steady", lazy),
            "LAZY_TO_NATIVE_FINAL",
        )
        with self.assertRaisesRegex(GuestCorrectnessError, "EAGER_FINAL"):
            validate_role_mode_record("baseline", "first", lazy)
        self.assertEqual(
            validate_role_mode_record("candidate", "steady", eager),
            PREBOUND_NATIVE_FINAL,
        )

    def test_baseline_binding_state_can_explicitly_require_lazy(self):
        eager = {
            "before": 0x300,
            "after_first": 0x300,
            "after_steady": 0x300,
        }
        lazy = {
            "before": 0x200,
            "after_first": 0x300,
            "after_steady": 0x300,
        }

        self.assertEqual(
            validate_role_mode_record(
                "baseline",
                "first",
                lazy,
                baseline_binding_state=LAZY_TO_NATIVE_FINAL,
            ),
            LAZY_TO_NATIVE_FINAL,
        )
        with self.assertRaisesRegex(
                GuestCorrectnessError, "LAZY_TO_NATIVE_FINAL"):
            validate_role_mode_record(
                "baseline",
                "first",
                eager,
                baseline_binding_state=LAZY_TO_NATIVE_FINAL,
            )

    def test_baseline_can_require_guest_preserved_lazy_binding(self):
        lazy = {
            "before": 0x200,
            "after_first": 0x300,
            "after_steady": 0x300,
        }

        self.assertEqual(
            validate_role_mode_record(
                "baseline",
                "first",
                lazy,
                baseline_binding_state=LAZY_TO_GUEST_FINAL,
            ),
            LAZY_TO_GUEST_FINAL,
        )

    def test_candidate_ignores_baseline_binding_state(self):
        eager = {
            "before": 0x300,
            "after_first": 0x300,
            "after_steady": 0x300,
        }
        self.assertEqual(
            validate_role_mode_record(
                "candidate",
                "first",
                eager,
                baseline_binding_state=LAZY_TO_NATIVE_FINAL,
            ),
            PREBOUND_NATIVE_FINAL,
        )

    def test_run_guest_mode_uses_configured_baseline_binding_state_only(self):
        lazy_output = (
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            "before=0x200 after_first=0x300 after_steady=0x300 "
            "first_ns=0x10 steady_total_ns=0 steady_per_call_ns=0 "
            "checksum=1\n"
        )
        eager_output = lazy_output.replace(
            "before=0x200", "before=0x300"
        )
        config = HarnessConfig(
            **{**self.config().__dict__,
               "baseline_binding_state": LAZY_TO_NATIVE_FINAL}
        )
        execution = {
            "returncode": 0,
            "timed_out": False,
            "process_total_ns": 1,
            "rusage": None,
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value={**execution, "output": lazy_output}):
            baseline = run_guest_mode(config, "baseline", "first", "/taskset")
        self.assertEqual(baseline["binding_state"], LAZY_TO_NATIVE_FINAL)
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value={**execution, "output": eager_output}):
            candidate = run_guest_mode(config, "candidate", "first", "/taskset")
        self.assertEqual(candidate["binding_state"], PREBOUND_NATIVE_FINAL)

    def test_sample_combines_three_modes_without_using_diagnostic_metrics(self):
        outputs = (
            "KZT_GUEST_PERF_OK mode=startup steady_calls=0 slot=0 before=0 "
            "after_first=0 after_steady=0 first_ns=0 steady_total_ns=0 "
            "steady_per_call_ns=0 checksum=0\n",
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            "before=0x300 after_first=0x300 after_steady=0x300 "
            "first_ns=0x10 steady_total_ns=0 steady_per_call_ns=0 checksum=1\n",
            "KZT_GUEST_PERF_OK mode=steady steady_calls=100000 slot=0x100 "
            "before=0x300 after_first=0x300 after_steady=0x300 "
            "first_ns=0x10 steady_total_ns=0xf4240 steady_per_call_ns=0xa "
            "checksum=100001\n",
        )
        executions = [
            {"returncode": 0, "timed_out": False, "output": output,
             "process_total_ns": process_total, "rusage": None}
            for output, process_total in zip(outputs, (11, 22, 33))
        ]
        with mock.patch("real_guest_harness.execute_with_rusage",
                        side_effect=executions):
            sample = run_guest_sample(self.config(), "baseline", "/taskset")

        self.assertEqual(sample["startup_process_total_ns"], 11)
        self.assertEqual(sample["launch_to_first_result_ns"], 22)
        self.assertEqual(sample["steady_total_ns"], 0xf4240)
        self.assertEqual(sample["binding_state"], "EAGER_FINAL")
        self.assertNotIn("steady_per_call_ns", PRIMARY_TIME_METRICS)

    def test_role_preflight_runs_all_three_modes(self):
        outputs = (
            "KZT_GUEST_PERF_OK mode=startup steady_calls=0 slot=0 before=0 "
            "after_first=0 after_steady=0 first_ns=0 steady_total_ns=0 "
            "steady_per_call_ns=0 checksum=0\n",
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            "before=0x300 after_first=0x300 after_steady=0x300 "
            "first_ns=0x10 steady_total_ns=0 steady_per_call_ns=0 checksum=1\n",
            "KZT_GUEST_PERF_OK mode=steady steady_calls=100000 slot=0x100 "
            "before=0x300 after_first=0x300 after_steady=0x300 "
            "first_ns=0x10 steady_total_ns=0xf4240 steady_per_call_ns=0xa "
            "checksum=100001\n",
        )
        executions = [
            {"returncode": 0, "timed_out": False, "output": output,
             "process_total_ns": 1, "rusage": None}
            for output in outputs
        ]
        with mock.patch("real_guest_harness.execute_with_rusage",
                        side_effect=executions):
            result = verify_role_modes_preflight(
                self.config(), "baseline", "/taskset"
            )

        self.assertEqual(tuple(result), ("startup", "first", "steady"))
        self.assertEqual(result["steady"]["binding_state"], "EAGER_FINAL")


class EnvironmentTests(unittest.TestCase):
    def config(self, baseline_binding_state=EAGER_FINAL):
        return HarnessConfig(
            baseline_latx=Path("/baseline-latx"),
            candidate_latx=Path("/candidate-latx"),
            guest_root=Path("/guest-root"),
            fixture_dir=Path("/fixture"),
            cpu=6,
            warmup=0,
            samples=80,
            max_samples=80,
            aa_samples=50,
            steady_calls=100000,
            seed=7,
            output_dir=Path("/output"),
            baseline_binding_state=baseline_binding_state,
        )

    def test_forces_legacy_kzt_and_only_enables_writer_for_candidate(self):
        inherited = {
            "LAT_LOG": "exec",
            "LATX_AOT": "1",
            "LATX_KZT": "0",
            "LATX_KZT_LAZY_DIAGNOSTICS": "1",
            "LATX_KZT_PATCH_SPIKE": "9",
        }
        with mock.patch.dict(os.environ, inherited, clear=False):
            baseline = benchmark_environment(
                self.config(), "baseline", "/tmp/fixture"
            )
            candidate = benchmark_environment(
                self.config(), "candidate", "/tmp/fixture"
            )

        self.assertEqual(baseline["LATX_KZT"], "2")
        self.assertEqual(baseline["LATX_KZT_LAZY_DIAGNOSTICS"], "0")
        self.assertEqual(baseline["LATX_KZT_REGISTRY_DIAGNOSTICS"], "0")
        self.assertEqual(baseline["LATX_AOT"], "0")
        self.assertNotIn("LAT_LOG", baseline)
        self.assertNotIn("LATX_KZT_PATCH_SPIKE", baseline)
        self.assertEqual(baseline["LD_LIBRARY_PATH"], "/tmp/fixture")
        self.assertEqual(candidate["LATX_KZT"], "2")
        self.assertEqual(candidate["LD_LIBRARY_PATH"], "/tmp/fixture")
        self.assertEqual(candidate["LATX_KZT_PATCH_SPIKE"], "1")
        self.assertEqual(candidate["LATX_KZT_PATCH_SPIKE_WRITE"], "1")
        self.assertEqual(candidate["LATX_KZT_PATCH_SPIKE_BUDGET"], "1")
        self.assertEqual(candidate["LATX_AOT"], "0")

    def test_lazy_baseline_uses_candidate_profile_but_baseline_binary(self):
        config = self.config(LAZY_TO_NATIVE_FINAL)
        baseline = benchmark_environment(config, "baseline", "/tmp/fixture")
        candidate = benchmark_environment(config, "candidate", "/tmp/fixture")
        command = benchmark_command(config, "baseline", "first", "/taskset")

        self.assertEqual(baseline["LATX_KZT_PATCH_SPIKE"], "1")
        self.assertEqual(baseline["LATX_KZT_PATCH_SPIKE_WRITE"], "1")
        self.assertEqual(baseline["LATX_KZT_PATCH_SPIKE_BUDGET"], "1")
        self.assertEqual(
            runtime_environment_snapshot(config, "baseline"),
            runtime_environment_snapshot(config, "candidate"),
        )
        self.assertIn("/baseline-latx", command)
        self.assertNotIn("/candidate-latx", command)

    def test_guest_lazy_baseline_keeps_writer_disabled(self):
        config = self.config(LAZY_TO_GUEST_FINAL)
        baseline = benchmark_environment(config, "baseline", "/tmp/fixture")
        candidate = benchmark_environment(config, "candidate", "/tmp/fixture")

        self.assertNotIn("LATX_KZT_PATCH_SPIKE", baseline)
        self.assertNotIn("LATX_KZT_PATCH_SPIKE_WRITE", baseline)
        self.assertEqual(candidate["LATX_KZT_PATCH_SPIKE"], "1")
        self.assertEqual(candidate["LATX_KZT_PATCH_SPIKE_WRITE"], "1")

    def test_environment_profile_rejects_invalid_baseline_binding_state(self):
        with self.assertRaisesRegex(ValueError, "baseline binding state"):
            real_guest_harness.benchmark_environment_profile(
                "baseline", "invalid"
            )


class NativeApplyPreflightTests(unittest.TestCase):
    def config(self):
        return HarnessConfig(
            baseline_latx=Path("/baseline-latx"),
            candidate_latx=Path("/candidate-latx"),
            guest_root=Path("/guest-root"),
            fixture_dir=Path("/fixture"),
            cpu=6,
            warmup=0,
            samples=50,
            max_samples=400,
            aa_samples=50,
            steady_calls=10000,
            seed=7,
            output_dir=Path("/output"),
        )

    def native_apply_output(self, *, before="0x200", after_first="0x300",
                            after_steady="0x300", lazy_target="0x300",
                            bridge_target="0x300"):
        return (
            "kzt_lazy_diagnostic schema=1 symbol=dlerror "
            "completion_route_status=NATIVE_APPLIED "
            f"selected_second_target={lazy_target}\n"
            "kzt_rela_diagnostic symbol=dlerror decision=APPROVED "
            "writer_result=APPLIED legacy_fallback=0 "
            f"bridge_target={bridge_target}\n"
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            f"before={before} "
            f"after_first={after_first} after_steady={after_steady} "
            "first_ns=0x64 steady_total_ns=0 steady_per_call_ns=0 "
            "checksum=0x1\n"
        )

    def direct_apply_output(self, *, before="0x200", after_first="0x300",
                            after_steady="0x300", slot_before="0x200",
                            slot_after="0x300", selected_target="0x300",
                            writer_result="APPLIED"):
        return (
            "kzt_lazy_direct schema=1 symbol=dlerror "
            "route_status=NATIVE_APPLIED "
            f"writer_result={writer_result} "
            f"slot_before={slot_before} slot_after={slot_after} "
            f"selected_target={selected_target}\n"
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            f"before={before} "
            f"after_first={after_first} after_steady={after_steady} "
            "first_ns=0x64 steady_total_ns=0 steady_per_call_ns=0 "
            "checksum=0x1\n"
        )

    def test_accepts_only_applied_native_lazy_route(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.native_apply_output(),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            result = verify_native_apply_preflight(
                self.config(), "/usr/bin/taskset"
            )

        self.assertEqual(result["lazy"]["completion_route_status"],
                         "NATIVE_APPLIED")
        self.assertEqual(result["rela"]["writer_result"], "APPLIED")
        self.assertEqual(result["guest"]["after_first"], 0x300)

    def test_accepts_evidence_backed_direct_native_route(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.direct_apply_output(),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            result = verify_native_apply_preflight(
                self.config(), "/usr/bin/taskset"
            )

        self.assertEqual(result["path"], "direct")
        self.assertEqual(result["direct"]["writer_result"], "APPLIED")
        self.assertEqual(result["guest"]["after_first"], 0x300)

    def test_rejects_mixed_guest_first_and_direct_records(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.native_apply_output() + self.direct_apply_output(),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaisesRegex(
                    GuestCorrectnessError, "exactly one native route"):
                verify_native_apply_preflight(
                    self.config(), "/usr/bin/taskset"
                )

    def test_rejects_direct_route_with_inconsistent_slot_evidence(self):
        for field in ("slot_before", "slot_after", "selected_target"):
            with self.subTest(field=field):
                value = "0x201" if field == "slot_before" else "0x301"
                execution = {
                    "returncode": 0,
                    "timed_out": False,
                    "output": self.direct_apply_output(**{field: value}),
                }
                with mock.patch("real_guest_harness.execute_with_rusage",
                                return_value=execution):
                    with self.assertRaisesRegex(
                            GuestCorrectnessError, "slot evidence mismatch"):
                        verify_native_apply_preflight(
                            self.config(), "/usr/bin/taskset"
                        )

    def test_rejects_direct_route_without_applied_cas(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.direct_apply_output(writer_result="CONFLICT"),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaisesRegex(
                    GuestCorrectnessError, "did not apply"):
                verify_native_apply_preflight(
                    self.config(), "/usr/bin/taskset"
                )

    def test_lazy_baseline_preflight_uses_baseline_binary_and_writer_profile(self):
        config = HarnessConfig(
            **{**self.config().__dict__,
               "baseline_binding_state": LAZY_TO_NATIVE_FINAL}
        )
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.native_apply_output(),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution) as execute:
            result = verify_native_apply_preflight(
                config, "/usr/bin/taskset", role="baseline"
            )

        command, environment, _ = execute.call_args.args
        self.assertEqual(result["role"], "baseline")
        self.assertIn("/baseline-latx", command)
        self.assertNotIn("/candidate-latx", command)
        self.assertEqual(environment["LATX_KZT_PATCH_SPIKE"], "1")
        self.assertEqual(environment["LATX_KZT_PATCH_SPIKE_WRITE"], "1")
        self.assertEqual(environment["LATX_KZT_LAZY_DIAGNOSTICS"], "1")
        self.assertEqual(environment["LATX_KZT_REGISTRY_DIAGNOSTICS"], "1")

    def test_rejects_applied_labels_with_mismatched_slot_evidence(self):
        for field in ("after_first", "after_steady"):
            with self.subTest(field=field):
                output = self.native_apply_output(**{field: "0x400"})
                execution = {
                    "returncode": 0,
                    "timed_out": False,
                    "output": output,
                }
                with mock.patch("real_guest_harness.execute_with_rusage",
                                return_value=execution):
                    with self.assertRaisesRegex(
                            GuestCorrectnessError, "slot evidence"):
                        verify_native_apply_preflight(
                            self.config(), "/usr/bin/taskset"
                        )

    def test_rejects_stable_guest_slot_that_differs_from_bridges(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.native_apply_output(
                after_first="0x400", after_steady="0x400"
            ),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaisesRegex(
                    GuestCorrectnessError, "slot evidence mismatch"):
                verify_native_apply_preflight(
                    self.config(), "/usr/bin/taskset"
                )

    def test_rejects_mismatched_lazy_or_rela_bridge_target(self):
        for field in ("lazy_target", "bridge_target"):
            with self.subTest(field=field):
                execution = {
                    "returncode": 0,
                    "timed_out": False,
                    "output": self.native_apply_output(**{field: "0x301"}),
                }
                with mock.patch("real_guest_harness.execute_with_rusage",
                                return_value=execution):
                    with self.assertRaisesRegex(
                            GuestCorrectnessError, "slot evidence mismatch"):
                        verify_native_apply_preflight(
                            self.config(), "/usr/bin/taskset"
                        )

    def test_rejects_zero_or_negative_preflight_address(self):
        for value in ("0", "-1"):
            with self.subTest(value=value):
                with self.assertRaises(GuestCorrectnessError):
                    _preflight_address(
                        {"bridge_target": value}, "rela", "bridge_target",
                        {"output": "diagnostic"},
                    )

    def test_rejects_applied_labels_without_lazy_slot_update(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.native_apply_output(before="0x300"),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaisesRegex(
                    GuestCorrectnessError, "before=0x300 after_first=0x300"):
                verify_native_apply_preflight(
                    self.config(), "/usr/bin/taskset"
                )

    def test_rejects_guest_preserved_lazy_route(self):
        output = (
            "kzt_lazy_diagnostic schema=1 symbol=dlerror "
            "completion_route_status=GUEST_PRESERVED\n"
            "kzt_rela_diagnostic symbol=dlerror decision=APPROVED "
            "writer_result=APPLIED legacy_fallback=0\n"
        )
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": output,
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaises(GuestCorrectnessError):
                verify_native_apply_preflight(self.config(), "/usr/bin/taskset")


class GuestPreservedPreflightTests(unittest.TestCase):
    def config(self):
        return HarnessConfig(
            baseline_latx=Path("/baseline-latx"),
            candidate_latx=Path("/candidate-latx"),
            guest_root=Path("/guest-root"),
            fixture_dir=Path("/fixture"),
            cpu=6,
            warmup=0,
            samples=80,
            max_samples=80,
            aa_samples=50,
            steady_calls=100000,
            seed=7,
            output_dir=Path("/output"),
            baseline_binding_state=LAZY_TO_GUEST_FINAL,
        )

    def guest_preserved_output(self, writer_result="DISABLED",
                               lazy_target="0x300", after_first="0x300",
                               after_steady="0x300"):
        return (
            "kzt_lazy_diagnostic schema=1 symbol=dlerror "
            "completion_route_status=GUEST_PRESERVED "
            f"slot_after_guest={lazy_target} "
            f"selected_second_target={lazy_target}\n"
            "kzt_rela_diagnostic symbol=dlerror decision=APPROVED "
            f"writer_result={writer_result} legacy_fallback=0 "
            "bridge_target=0x400\n"
            "KZT_GUEST_PERF_OK mode=first steady_calls=0 slot=0x100 "
            "before=0x200 "
            f"after_first={after_first} after_steady={after_steady} "
            "first_ns=0x64 steady_total_ns=0 steady_per_call_ns=0 "
            "checksum=0x1\n"
        )

    def test_accepts_guest_preserved_lazy_baseline_with_writer_disabled(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.guest_preserved_output(),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution) as execute:
            result = verify_guest_preserved_preflight(
                self.config(), "/usr/bin/taskset"
            )

        command, environment, _ = execute.call_args.args
        self.assertEqual(result["lazy"]["completion_route_status"],
                         "GUEST_PRESERVED")
        self.assertEqual(result["rela"]["writer_result"], "DISABLED")
        self.assertEqual(result["guest"]["after_first"], 0x300)
        self.assertIn("/baseline-latx", command)
        self.assertNotIn("LATX_KZT_PATCH_SPIKE_WRITE", environment)

    def test_rejects_guest_baseline_when_writer_applied(self):
        execution = {
            "returncode": 0,
            "timed_out": False,
            "output": self.guest_preserved_output(writer_result="APPLIED"),
        }
        with mock.patch("real_guest_harness.execute_with_rusage",
                        return_value=execution):
            with self.assertRaisesRegex(
                    GuestCorrectnessError, "Guest-preserved"):
                verify_guest_preserved_preflight(
                    self.config(), "/usr/bin/taskset"
                )


class OrderStatisticTests(unittest.TestCase):
    def test_guest_lazy_analysis_excludes_semantically_different_steady_state(
            self):
        analysis = analyze_ab_pairs(
            ab_pairs([100] * 80, [100] * 80),
            seed=7,
            formal_stage_count=0,
            analysis_look_count=1,
            metrics=GUEST_LAZY_COMPARISON_METRICS,
        )

        self.assertEqual(
            tuple(analysis["metrics"]), GUEST_LAZY_COMPARISON_METRICS
        )
        self.assertEqual(analysis["comparison_count"], 4)

    def test_bonferroni_interval_has_99_percent_family_confidence(self):
        interval = _order_statistic_interval(
            [math.log(1.2)] * 200,
            quantile=0.5,
            alpha=0.01 / 18,
            confidence=1 - 0.01 / 18,
            method="exact binomial median order-statistic interval",
        )

        self.assertGreater(interval["lower"], 0.0)
        self.assertAlmostEqual(interval["confidence"], 1 - 0.01 / 18)
        self.assertNotEqual(interval["confidence"], 0.98)

    def test_one_sided_quantile_bound_scales_to_sixteen_hundred_samples(self):
        bounds = _one_sided_quantile_bounds(
            list(range(1600)), quantile=0.95, alpha=0.001,
            log_scale=False,
        )

        self.assertIsNotNone(bounds["lower"])
        self.assertIsNotNone(bounds["upper"])
        self.assertLess(bounds["lower"], bounds["upper"])

    def test_point_estimate_uses_the_requested_quantile(self):
        interval = _order_statistic_interval(
            [1, 2, 3, 4, 5],
            quantile=0.95,
            alpha=0.1,
            confidence=0.9,
            method="test",
        )

        self.assertEqual(interval["estimate"], 4.8)


class StabilityTests(unittest.TestCase):
    def test_wide_aa_interval_is_inconclusive_not_stable(self):
        pairs = [
            {
                "a": timed_sample(100),
                "b": timed_sample(value),
                "order": ["a", "b"],
            }
            for value in [99.7, 101.5] * 100
        ]

        assessment = assess_aa_pairs(pairs, seed=19)

        self.assertEqual(assessment["result"], AAResult.INCONCLUSIVE.value)
        self.assertFalse(assessment["stable"])
        self.assertEqual(assessment["family_confidence"], 0.99)
        self.assertEqual(assessment["comparison_count"], 18)
        self.assertAlmostEqual(
            assessment["per_interval_confidence"], 1 - 0.01 / 18
        )

    def test_label_stability_uses_each_pair_log_ratio(self):
        pairs = []
        for a, b in ((100, 100), (200, 400), (300, 150)) * 2:
            pairs.append({
                "a": timed_sample(a),
                "b": timed_sample(b),
                "order": ["a", "b"],
            })

        assessment = assess_aa_pairs(pairs, seed=19)

        self.assertAlmostEqual(
            assessment["metrics"]["steady_total_ns"]["label"]["estimate"],
            0.0,
        )

    def test_accepts_stable_aa_pairs(self):
        assessment = assess_aa_pairs(
            aa_pairs([100] * 200), seed=19
        )

        self.assertTrue(assessment["stable"])
        self.assertEqual(assessment["result"], AAResult.STABLE.value)
        self.assertEqual(assessment["reasons"], [])

    def test_accepts_aa_control_difference_at_half_percent_limit(self):
        pairs = [
            {"a": timed_sample(100), "b": timed_sample(100.5),
             "order": ["a", "b"]}
            for _ in range(200)
        ]

        assessment = assess_aa_pairs(pairs, seed=19)

        self.assertTrue(assessment["stable"])

    def test_fifty_pair_aa_screen_cannot_claim_stable(self):
        assessment = assess_aa_pairs(
            aa_pairs([100] * 50), seed=19
        )

        self.assertEqual(assessment["mode"], "screening")
        self.assertEqual(assessment["result"], AAResult.INCONCLUSIVE.value)
        self.assertFalse(assessment["stable"])

    def test_rejects_aa_control_difference_over_one_percent(self):
        pairs = [
            {"a": timed_sample(100), "b": timed_sample(102),
             "order": ["a", "b"]}
            for _ in range(200)
        ]

        assessment = assess_aa_pairs(pairs, seed=19)

        self.assertFalse(assessment["stable"])

    def test_rejects_temporal_aa_drift(self):
        assessment = assess_aa_pairs(
            aa_pairs([100] * 100 + [140] * 100),
            seed=19,
        )

        self.assertFalse(assessment["stable"])
        self.assertTrue(any("temporal" in reason for reason in assessment["reasons"]))

    def test_requires_both_baseline_and_candidate_aa_stability(self):
        assessment = assess_dual_aa(
            aa_pairs([100] * 200),
            aa_pairs([100] * 100 + [140] * 100),
            seed=23,
        )

        self.assertTrue(assessment["baseline"]["stable"])
        self.assertFalse(assessment["candidate"]["stable"])
        self.assertFalse(assessment["stable"])


class GateDecisionTests(unittest.TestCase):
    def analyze(self, baseline_values, candidate_values, *, stages=1):
        return analyze_ab_pairs(
            ab_pairs(baseline_values, candidate_values),
            seed=31,
            formal_stage_count=stages,
        )

    def test_pass_requires_at_least_400_pairs(self):
        analysis = self.analyze([100] * 400, [100] * 400)

        self.assertEqual(
            classify_gate(analysis, pair_count=200, formal_aa_stable=True), GateResult.INCONCLUSIVE
        )
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True), GateResult.PASS
        )

    def test_screening_aa_cannot_formally_pass_ab(self):
        analysis = self.analyze([100] * 400, [100] * 400)

        self.assertEqual(
            classify_gate(
                analysis, pair_count=400, formal_aa_stable=False
            ),
            GateResult.INCONCLUSIVE,
        )

    def test_analysis_uses_per_pair_log_ratios(self):
        analysis = self.analyze([100, 100], [50, 200])
        estimate = analysis["metrics"]["startup_process_total_ns"][
            "paired_log_ratio"
        ]["median"]["estimate"]

        self.assertAlmostEqual(estimate, 0.0)

    def test_paired_log_ratio_contains_only_the_median(self):
        analysis = self.analyze([100] * 400, [100] * 400)
        metric = analysis["metrics"]["startup_process_total_ns"]

        self.assertEqual(set(metric["paired_log_ratio"]), {"median"})
        self.assertIn("paired_index_bootstrap_p95_log_ratio", metric)
        self.assertNotIn("paired_p95_log_ratio", metric)

    def test_p95_resamples_pair_indices_then_compares_marginal_tails(self):
        analysis = self.analyze(
            [100, 130] * 200,
            [130, 100] * 200,
        )
        interval = analysis["metrics"]["startup_process_total_ns"][
            "paired_index_bootstrap_p95_log_ratio"
        ]["p95"]

        self.assertEqual(
            analysis["metrics"]["startup_process_total_ns"]["baseline"]["p95"],
            analysis["metrics"]["startup_process_total_ns"]["candidate"]["p95"],
        )
        self.assertAlmostEqual(interval["estimate"], 0.0)
        self.assertAlmostEqual(interval["ratio"], 1.0)

    def test_p95_paired_index_bounds_accept_nanosecond_scale_samples(self):
        analysis = self.analyze([30_000_000] * 400, [30_000_000] * 400)
        interval = analysis["metrics"]["startup_process_total_ns"][
            "paired_index_bootstrap_p95_log_ratio"
        ]["p95"]

        self.assertAlmostEqual(interval["ratio"], 1.0)

    def test_ab_uses_six_simultaneous_one_sided_bounds(self):
        analysis = self.analyze([100] * 400, [100] * 400)
        interval = analysis["metrics"]["startup_process_total_ns"][
            "paired_log_ratio"
        ]["median"]
        p95 = analysis["metrics"]["startup_process_total_ns"][
            "paired_index_bootstrap_p95_log_ratio"
        ]["p95"]

        self.assertEqual(analysis["comparison_count"], 6)
        self.assertEqual(analysis["pass_upper_family_confidence"], 0.99)
        self.assertEqual(analysis["fail_lower_family_confidence"], 0.99)
        self.assertAlmostEqual(analysis["per_ratio_bound_alpha"], 0.01 / 6)
        self.assertAlmostEqual(
            interval["one_sided_confidence"], 1 - 0.01 / 6
        )
        self.assertEqual(
            p95["method"],
            "paired-index percentile bootstrap P95 log-ratio bounds",
        )
        self.assertEqual(p95["bootstrap_resamples"], 20000)
        self.assertEqual(p95["bootstrap_seed"], 31)
        self.assertEqual(p95["resampling_unit"], "paired sample index")
        self.assertEqual(interval["method"], "exact binomial quantile order-statistic bounds")
        self.assertIn("lower", interval)
        self.assertIn("upper", interval)

    def test_eight_hundred_pair_plan_allocates_across_two_formal_stages(self):
        analysis = self.analyze([100] * 400, [100] * 400, stages=2)
        p95 = analysis["metrics"]["startup_process_total_ns"][
            "paired_index_bootstrap_p95_log_ratio"
        ]["p95"]

        self.assertEqual(analysis["formal_stage_count"], 2)
        self.assertAlmostEqual(analysis["per_ratio_bound_alpha"], 0.01 / 12)
        self.assertEqual(
            analysis["pass_upper_family_confidence"], 0.99
        )
        self.assertEqual(
            analysis["fail_lower_family_confidence"], 0.99
        )

    def test_one_percent_median_noninferiority_threshold_is_accepted(self):
        analysis = self.analyze([100] * 400, [100.9] * 400)

        self.assertLess(math.log(1.009), math.log(1.01))
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True), GateResult.PASS
        )

    def test_fail_requires_at_least_400_pairs(self):
        analysis = self.analyze([100] * 400, [120] * 400)

        self.assertEqual(
            classify_gate(analysis, pair_count=399, formal_aa_stable=True), GateResult.INCONCLUSIVE
        )
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True), GateResult.FAIL
        )

    def test_clear_median_slowdown_fails_despite_better_raw_p95(self):
        analysis = self.analyze(
            [100] * 360 + [200] * 40,
            [120] * 400,
        )

        self.assertLess(
            analysis["metrics"]["startup_process_total_ns"]["candidate"]["p95"],
            analysis["metrics"]["startup_process_total_ns"]["baseline"]["p95"],
        )
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True), GateResult.FAIL
        )

    def test_clear_p95_slowdown_fails_despite_better_median(self):
        analysis = self.analyze(
            [100] * 400,
            [90] * 360 + [150] * 40,
        )

        self.assertLess(
            analysis["metrics"]["startup_process_total_ns"]["candidate"]["median"],
            analysis["metrics"]["startup_process_total_ns"]["baseline"]["median"],
        )
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True), GateResult.FAIL
        )

    def test_ambiguous_result_remains_inconclusive_at_800_pairs(self):
        analysis = self.analyze(
            [100] * 800,
            [103] * 40 + [99] * 760,
        )

        self.assertEqual(
            classify_gate(analysis, pair_count=800, formal_aa_stable=True), GateResult.INCONCLUSIVE
        )

    def test_inconclusive_reason_names_separate_decision_families(self):
        analysis = self.analyze(
            [100] * 800,
            [103] * 40 + [99] * 760,
            stages=2,
        )

        self.assertIn(
            "Separate 99% PASS-upper and FAIL-lower decision-family bounds",
            _inconclusive_details(analysis),
        )

    def test_direction_and_formal_checkpoints_are_80_400_800_1600(self):
        self.assertEqual(_checkpoint_targets(80, 1600), [80, 400, 800, 1600])

    def test_formal_stage_count_uses_actual_formal_checkpoints(self):
        self.assertEqual(_formal_stage_count(80, 80), 0)
        self.assertEqual(_formal_stage_count(80, 400), 1)
        self.assertEqual(_formal_stage_count(400, 400), 1)
        self.assertEqual(_formal_stage_count(80, 800), 2)
        self.assertEqual(_formal_stage_count(400, 800), 2)
        self.assertEqual(_formal_stage_count(800, 800), 1)
        self.assertEqual(_formal_stage_count(80, 1600), 3)

    def test_guest_first_binding_is_a_median_only_noninferiority_gate(self):
        pairs = []
        for _ in range(400):
            baseline = timed_sample(100)
            candidate = timed_sample(100)
            baseline[GUEST_FIRST_BINDING_METRIC] = 100
            candidate[GUEST_FIRST_BINDING_METRIC] = 99
            pairs.append({
                "baseline": baseline,
                "candidate": candidate,
                "order": ["baseline", "candidate"],
            })
        analysis = analyze_ab_pairs(
            pairs,
            seed=31,
            metrics=(*PRIMARY_TIME_METRICS, GUEST_FIRST_BINDING_METRIC),
            tail_metrics=PRIMARY_TIME_METRICS,
        )
        guest_first = analysis["metrics"][GUEST_FIRST_BINDING_METRIC]

        self.assertEqual(guest_first["required_statistics"], ("median",))
        self.assertNotIn("paired_index_bootstrap_p95_log_ratio", guest_first)
        self.assertEqual(
            classify_gate(analysis, pair_count=400, formal_aa_stable=True),
            GateResult.PASS,
        )

    def test_gate_requires_explicit_formal_aa_stability(self):
        analysis = self.analyze([100] * 400, [100] * 400)

        with self.assertRaises(TypeError):
            classify_gate(analysis, pair_count=400)


class StatisticsReportTests(unittest.TestCase):
    def test_report_states_formal_simultaneous_inference_contract(self):
        statistics_record = _statistics_record()

        self.assertEqual(statistics_record["aa"]["comparison_count"], 18)
        self.assertEqual(statistics_record["aa"]["family_confidence"], 0.99)
        self.assertEqual(statistics_record["aa"]["formal_min_pairs_per_role"], 200)
        self.assertEqual(statistics_record["aa"]["stability_percent_limit"], 0.5)
        self.assertEqual(
            statistics_record["aa"]["temporal_independence_assumption"],
            "time-ordered early/late paired contrasts are independent across pair indices",
        )
        self.assertEqual(statistics_record["ab"]["comparison_count"], 6)
        self.assertAlmostEqual(
            statistics_record["ab"]["per_ratio_bound_alpha"], 0.01 / 12
        )
        self.assertEqual(statistics_record["ab"]["min_formal_pairs"], 400)
        self.assertEqual(statistics_record["ab"]["max_formal_pairs"], 800)
        self.assertEqual(
            statistics_record["method"],
            "paired log-ratio median exact-binomial bounds and paired-index "
            "bootstrap marginal P95-ratio bounds",
        )

    def test_eight_hundred_pair_report_declares_separate_decision_families(self):
        statistics_record = _statistics_record(max_samples=800)
        ab = statistics_record["ab"]

        self.assertEqual(ab["formal_stage_count"], 2)
        self.assertAlmostEqual(ab["per_ratio_bound_alpha"], 0.01 / 12)
        self.assertEqual(ab["pass_upper_family"]["confidence"], 0.99)
        self.assertEqual(ab["fail_lower_family"]["confidence"], 0.99)
        self.assertNotIn("all_twelve_bounds_confidence", ab)

    def test_directional_eighty_pair_report_has_no_formal_stage(self):
        ab = _statistics_record(max_samples=80)["ab"]
        self.assertEqual(ab["formal_stage_count"], 0)
        self.assertEqual(ab["analysis_look_count"], 1)
        self.assertAlmostEqual(ab["per_ratio_bound_alpha"], 0.01 / 6)

    def test_report_describes_paired_index_p95_and_family_adjustment(self):
        method = _statistics_record()["ab"]["p95_method"]

        self.assertIn("paired-index", method)
        self.assertIn("P95(candidate) / P95(baseline)", method)
        self.assertIn("family-and-look-adjusted", method)
        self.assertEqual(
            _statistics_record()["ab"]["p95_bootstrap_resamples"], 20000
        )

    def test_non_median_quantile_estimate_is_explicitly_interpolated(self):
        bounds = real_guest_harness._one_sided_quantile_bounds(
            [1, 2, 3, 4, 5], quantile=0.95, alpha=0.1
        )
        self.assertEqual(bounds["estimate_method"],
                         "linear interpolated sample quantile")
        self.assertAlmostEqual(bounds["estimate"], 4.8)


class CommandLineContractTests(unittest.TestCase):
    def arguments(self, *extra):
        return [
            "test_real_guest_performance.py",
            "--baseline-latx", "/baseline",
            "--candidate-latx", "/candidate",
            "--guest-root", "/guest",
            "--fixture-dir", "/fixture",
            "--cpu", "0",
            "--output-dir", "/output",
            *extra,
        ]

    def test_formal_aa_default_is_two_hundred_pairs(self):
        with mock.patch.object(sys, "argv", self.arguments()):
            self.assertEqual(parse_args().aa_samples, 200)

    def test_aa_only_flag_requests_independent_aa(self):
        with mock.patch.object(
                sys, "argv", self.arguments("--aa-only")):
            self.assertTrue(parse_args().aa_only)

    def test_baseline_binding_state_defaults_to_eager_and_accepts_lazy(self):
        with mock.patch.object(sys, "argv", self.arguments()):
            self.assertEqual(parse_args().baseline_binding_state, EAGER_FINAL)
        with mock.patch.object(sys, "argv", self.arguments(
                "--baseline-binding-state", LAZY_TO_GUEST_FINAL)):
            self.assertEqual(parse_args().baseline_binding_state,
                             LAZY_TO_GUEST_FINAL)
        with mock.patch.object(sys, "argv", self.arguments(
                "--baseline-binding-state", LAZY_TO_NATIVE_FINAL)):
            self.assertEqual(parse_args().baseline_binding_state,
                             LAZY_TO_NATIVE_FINAL)

    def test_aa_rejects_non_screening_sample_count_below_two_hundred(self):
        with mock.patch.object(sys, "argv", self.arguments(
                "--aa-samples", "199")):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_aa_screening_requires_directional_ab_limit(self):
        with mock.patch.object(sys, "argv", self.arguments(
                "--aa-samples", "50", "--max-samples", "400")):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_samples_and_max_samples_are_checkpoint_values(self):
        for option, value in (("--samples", "81"), ("--max-samples", "81")):
            with self.subTest(option=option):
                with mock.patch.object(sys, "argv", self.arguments(option, value)):
                    with self.assertRaises(SystemExit):
                        parse_args()

    def test_samples_must_not_exceed_max_samples(self):
        with mock.patch.object(sys, "argv", self.arguments(
                "--samples", "400", "--max-samples", "80")):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_timeout_must_be_finite_and_positive(self):
        for value in ("nan", "inf", "-inf", "0"):
            timeout_arguments = (
                (f"--timeout={value}",)
                if value.startswith("-") else ("--timeout", value)
            )
            with self.subTest(value=value), mock.patch.object(
                    sys, "argv", self.arguments(*timeout_arguments)):
                with self.assertRaises(SystemExit):
                    parse_args()

    def test_sixteen_hundred_is_an_allowed_formal_checkpoint(self):
        with mock.patch.object(sys, "argv", self.arguments(
                "--samples", "400", "--max-samples", "1600")):
            self.assertEqual(parse_args().max_samples, 1600)


class OutputDirectoryContractTests(unittest.TestCase):
    def config(self, output_dir, **changes):
        values = {
            "baseline_latx": Path("/baseline-latx"),
            "candidate_latx": Path("/candidate-latx"),
            "guest_root": Path("/guest-root"),
            "fixture_dir": Path("/fixture"),
            "cpu": 0,
            "warmup": 0,
            "samples": 80,
            "max_samples": 80,
            "aa_samples": 50,
            "steady_calls": 100000,
            "seed": 7,
            "output_dir": output_dir,
            "timeout": 60.0,
        }
        values.update(changes)
        return HarnessConfig(**values)

    def test_output_ownership_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "run"
            output_dir.mkdir()
            descriptor = _acquire_output_ownership(output_dir)
            try:
                with self.assertRaises(PrerequisiteError):
                    _acquire_output_ownership(output_dir)
            finally:
                os.close(descriptor)

    def test_existing_output_evidence_is_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "existing-evidence"
            output_dir.mkdir()
            evidence = output_dir / "raw-samples.jsonl"
            evidence.write_text("original evidence\n", encoding="utf-8")
            config = HarnessConfig(
                baseline_latx=Path("/baseline-latx"),
                candidate_latx=Path("/candidate-latx"),
                guest_root=Path("/guest-root"),
                fixture_dir=Path("/fixture"),
                cpu=0,
                warmup=0,
                samples=80,
                max_samples=400,
                aa_samples=200,
                steady_calls=100000,
                seed=7,
                output_dir=output_dir,
            )

            with self.assertRaises(PrerequisiteError):
                run_performance_gate(config)

            self.assertEqual(
                evidence.read_text(encoding="utf-8"), "original evidence\n"
            )
            self.assertEqual(list(output_dir.iterdir()), [evidence])

    def test_internal_screening_config_cannot_request_formal_ab(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "new-output"
            config = HarnessConfig(
                baseline_latx=Path("/baseline-latx"),
                candidate_latx=Path("/candidate-latx"),
                guest_root=Path("/guest-root"),
                fixture_dir=Path("/fixture"),
                cpu=0,
                warmup=0,
                samples=80,
                max_samples=400,
                aa_samples=50,
                steady_calls=100000,
                seed=7,
                output_dir=output_dir,
            )

            with self.assertRaises(PrerequisiteError):
                run_performance_gate(config)

            self.assertFalse(output_dir.exists())

    def test_aa_only_screening_never_runs_ab_and_stays_inconclusive(self):
        phases = []

        def fake_pair(config, taskset, raw_samples, phase, pair_index, order,
                      roles):
            phases.append(phase)
            raw_samples.write({
                "phase": phase,
                "pair_index": pair_index,
                "pair_order": list(order),
            })
            return {
                "order": list(order),
                **{label: timed_sample(100) for label in order},
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "aa-only"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], "/taskset")), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_role_modes_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_native_apply_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness._run_pair",
                            side_effect=fake_pair), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(
                    output_dir, aa_only=True,
                ))

            metadata = json.loads(
                (output_dir / "run-metadata.json").read_text()
            )
            raw_records = [
                json.loads(line)
                for line in (output_dir / "raw-samples.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]

        self.assertEqual(
            set(phases), {"baseline-aa", "candidate-aa"}
        )
        self.assertFalse(any(record["phase"] == "ab"
                             for record in raw_records))
        self.assertNotIn("ab_checkpoints", report)
        self.assertEqual(report["result"], GateResult.INCONCLUSIVE.value)
        self.assertEqual(report["result_scope"], "aa_screening")
        self.assertIn("A/A-only", report["reason"])
        self.assertTrue(report["configuration"]["aa_only"])
        self.assertTrue(metadata["configuration"]["aa_only"])

    def test_invalid_sampling_configuration_does_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "new-output"
            config = HarnessConfig(
                baseline_latx=Path("/baseline-latx"),
                candidate_latx=Path("/candidate-latx"),
                guest_root=Path("/guest-root"),
                fixture_dir=Path("/fixture"),
                cpu=0,
                warmup=0,
                samples=80,
                max_samples=400,
                aa_samples=50,
                steady_calls=100000,
                seed=7,
                output_dir=output_dir,
            )

            with self.assertRaises(PrerequisiteError):
                run_performance_gate(config)

            self.assertFalse(output_dir.exists())

    def test_invalid_runtime_configuration_does_not_create_output_directory(self):
        invalid = {
            "cpu": -1,
            "warmup": -1,
            "steady_calls": 99999,
            "timeout": 0,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            for field, value in invalid.items():
                with self.subTest(field=field):
                    output_dir = Path(temporary_directory) / field
                    with self.assertRaises(PrerequisiteError):
                        run_performance_gate(self.config(output_dir,
                                                         **{field: value}))
                    self.assertFalse(output_dir.exists())

    def test_non_finite_timeout_does_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            for value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(value=value):
                    output_dir = Path(temporary_directory) / str(value)
                    with self.assertRaises(PrerequisiteError):
                        run_performance_gate(self.config(output_dir,
                                                         timeout=value))
                    self.assertFalse(output_dir.exists())

    def test_invalid_baseline_binding_state_does_not_create_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "invalid-binding-state"
            with self.assertRaises(PrerequisiteError):
                run_performance_gate(self.config(
                    output_dir, baseline_binding_state="invalid"
                ))
            self.assertFalse(output_dir.exists())

    def test_report_and_metadata_record_baseline_binding_state(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "lazy-baseline"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=(["mock prerequisite"], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(
                    output_dir,
                    baseline_binding_state=LAZY_TO_NATIVE_FINAL,
                ))
            metadata = json.loads((output_dir / "run-metadata.json").read_text())
            for artifact in (report, metadata):
                self.assertEqual(artifact["configuration"][
                    "baseline_binding_state"
                ], LAZY_TO_NATIVE_FINAL)
                self.assertEqual(artifact["environment"]["baseline"][
                    "LATX_KZT_PATCH_SPIKE"
                ], "1")

    def test_unverified_core_isolation_is_environment_inconclusive(self):
        failed_isolation = {
            "requested": True,
            "applied": False,
            "guest_cpu": 37,
            "topology_source": "/synthetic/cpu37/thread_siblings_list",
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
            output_dir = Path(temporary_directory) / "topology-inconclusive"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], "/taskset")), \
                 mock.patch(
                    "real_guest_harness.activate_harness_cpu_isolation",
                    return_value=failed_isolation,
                 ), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}), \
                 mock.patch(
                    "real_guest_harness.verify_role_modes_preflight",
                    side_effect=AssertionError("guest preflight must not run"),
                 ):
                report = run_performance_gate(self.config(
                    output_dir, cpu=37, isolate_harness_cpu=True,
                ))

            metadata = json.loads(
                (output_dir / "run-metadata.json").read_text()
            )
        self.assertEqual(report["result"], GateResult.INCONCLUSIVE.value)
        self.assertEqual(report["result_scope"], "environment_inconclusive")
        self.assertIn("synthetic topology unavailable", report["reason"])
        self.assertEqual(report["harness_cpu_isolation"], failed_isolation)
        self.assertEqual(metadata["harness_cpu_isolation"], failed_isolation)

    def test_formal_gate_requires_verified_core_isolation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "formal-without-isolation"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], "/taskset")), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}), \
                 mock.patch(
                    "real_guest_harness.verify_role_modes_preflight",
                    side_effect=AssertionError("guest preflight must not run"),
                 ):
                report = run_performance_gate(self.config(
                    output_dir,
                    samples=400,
                    max_samples=400,
                    aa_samples=200,
                    isolate_harness_cpu=False,
                ))

        self.assertEqual(report["result"], GateResult.INCONCLUSIVE.value)
        self.assertEqual(report["result_scope"], "environment_inconclusive")
        self.assertIn("physical-core isolation", report["reason"])
        isolation = report["harness_cpu_isolation"]
        self.assertEqual(isolation["guest_cpu"], 0)
        self.assertIsNone(isolation["thread_siblings"])
        self.assertIn("cpu0/topology/thread_siblings_list",
                      isolation["topology_source"])
        self.assertFalse(isolation["verification"]["passed"])

    def test_native_apply_preflight_scope_follows_baseline_binding_state(self):
        def run_with_binding_state(baseline_binding_state):
            with tempfile.TemporaryDirectory() as temporary_directory:
                output_dir = Path(temporary_directory) / "preflight-scope"
                calls = []

                def preflight(config, taskset, role="candidate"):
                    calls.append(role)
                    if role == "baseline":
                        raise GuestCorrectnessError("baseline preflight stop")
                    return {"role": role}

                with mock.patch("real_guest_harness.prerequisite_issues",
                                return_value=([], "/taskset")), \
                     mock.patch("real_guest_harness.collect_binary_metadata",
                                return_value={}), \
                     mock.patch("real_guest_harness.collect_fixture_metadata",
                                return_value={}), \
                     mock.patch("real_guest_harness.collect_host_metadata",
                                return_value={}), \
                     mock.patch("real_guest_harness.runtime_environment_snapshot",
                                return_value={}), \
                     mock.patch("real_guest_harness.host_load_snapshot",
                                return_value={"oversubscribed": False}), \
                     mock.patch("real_guest_harness.verify_role_modes_preflight",
                                return_value={}), \
                     mock.patch("real_guest_harness.verify_native_apply_preflight",
                                side_effect=preflight):
                    report = run_performance_gate(self.config(
                        output_dir,
                        baseline_binding_state=baseline_binding_state,
                    ))
                return calls, report

        calls, report = run_with_binding_state(EAGER_FINAL)
        self.assertEqual(calls, ["candidate"])
        self.assertIsNone(report["baseline_native_apply_preflight"])

        calls, report = run_with_binding_state(LAZY_TO_NATIVE_FINAL)
        self.assertEqual(calls, ["candidate", "baseline"])
        self.assertEqual(report["native_apply_preflight"], {"role": "candidate"})
        self.assertIsNone(report["baseline_native_apply_preflight"])
        self.assertEqual(report["result_scope"], "correctness_failure")

    def test_lazy_baseline_gate_records_both_native_apply_preflights(self):
        def fake_pair(config, taskset, raw_samples, phase, pair_index, order,
                      roles):
            return {
                "order": list(order),
                **{label: timed_sample(100) for label in order},
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "lazy-preflights"
            calls = []

            def preflight(config, taskset, role="candidate"):
                calls.append(role)
                return {"role": role}

            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], "/taskset")), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_role_modes_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_native_apply_preflight",
                            side_effect=preflight), \
                 mock.patch("real_guest_harness._run_pair",
                            side_effect=fake_pair), \
                 mock.patch("real_guest_harness.assess_dual_aa",
                            return_value={"result": AAResult.INCONCLUSIVE.value}), \
                 mock.patch("real_guest_harness.analyze_ab_pairs",
                            return_value={"metrics": {}}), \
                 mock.patch("real_guest_harness.classify_gate",
                            return_value=GateResult.INCONCLUSIVE), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(
                    output_dir,
                    baseline_binding_state=LAZY_TO_NATIVE_FINAL,
                ))

        self.assertEqual(calls, ["candidate", "baseline"])
        self.assertEqual(report["native_apply_preflight"],
                         {"role": "candidate"})
        self.assertEqual(report["baseline_native_apply_preflight"],
                         {"role": "baseline"})

    def test_guest_lazy_baseline_gate_records_guest_preserved_preflight(self):
        def fake_pair(config, taskset, raw_samples, phase, pair_index, order,
                      roles):
            return {
                "order": list(order),
                **{label: timed_sample(100) for label in order},
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "guest-lazy-preflight"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], "/taskset")), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_role_modes_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_native_apply_preflight",
                            return_value={"role": "candidate"}), \
                 mock.patch(
                     "real_guest_harness.verify_guest_preserved_preflight",
                     return_value={"role": "baseline"},
                 ), \
                 mock.patch("real_guest_harness._run_pair",
                            side_effect=fake_pair), \
                 mock.patch("real_guest_harness.assess_dual_aa",
                            return_value={"result": AAResult.INCONCLUSIVE.value}), \
                 mock.patch("real_guest_harness.analyze_ab_pairs",
                            return_value={"metrics": {}}), \
                 mock.patch("real_guest_harness.classify_gate",
                            return_value=GateResult.INCONCLUSIVE), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(
                    output_dir,
                    baseline_binding_state=LAZY_TO_GUEST_FINAL,
                ))

        self.assertEqual(report["native_apply_preflight"],
                         {"role": "candidate"})
        self.assertIsNone(report["baseline_native_apply_preflight"])
        self.assertEqual(report["baseline_guest_preserved_preflight"],
                         {"role": "baseline"})

    def test_ownership_descriptor_closes_on_metadata_failure(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "early-failure"
            with mock.patch(
                    "real_guest_harness.collect_binary_metadata",
                    side_effect=RuntimeError("metadata failed")):
                with self.assertRaisesRegex(RuntimeError, "metadata failed"):
                    run_performance_gate(self.config(output_dir))
            for artifact in ("report.json", "run-metadata.json"):
                record = json.loads((output_dir / artifact).read_text())
                self.assertEqual(record["result_scope"], "harness_error")
                self.assertEqual(record["harness_error"]["message"],
                                 "metadata failed")
            marker = output_dir / real_guest_harness.OWNERSHIP_MARKER
            marker.unlink()
            descriptor = _acquire_output_ownership(output_dir)
            os.close(descriptor)

    def test_metadata_write_failure_writes_harness_error_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "metadata-write-failure"
            original_write_json = real_guest_harness._write_json
            failed = False

            def fail_first_metadata_write(path, value):
                nonlocal failed
                if path.name == "run-metadata.json" and not failed:
                    failed = True
                    raise OSError("metadata write failed")
                return original_write_json(path, value)

            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=(["mock prerequisite"], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}), \
                 mock.patch("real_guest_harness._write_json",
                            side_effect=fail_first_metadata_write):
                with self.assertRaisesRegex(OSError, "metadata write failed"):
                    run_performance_gate(self.config(output_dir))
            for artifact in ("report.json", "run-metadata.json"):
                record = json.loads((output_dir / artifact).read_text())
                self.assertEqual(record["result_scope"], "harness_error")

    def test_raw_writer_open_failure_writes_harness_error_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "raw-writer-failure"
            writer = mock.MagicMock()
            writer.__enter__.side_effect = OSError("raw writer failed")
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=(["mock prerequisite"], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}), \
                 mock.patch("real_guest_harness.RawSampleWriter",
                            return_value=writer):
                with self.assertRaisesRegex(OSError, "raw writer failed"):
                    run_performance_gate(self.config(output_dir))
            for artifact in ("report.json", "run-metadata.json"):
                record = json.loads((output_dir / artifact).read_text())
                self.assertEqual(record["result_scope"], "harness_error")

    def test_v2_artifacts_and_prerequisite_scope_are_locked(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "prerequisite"
            metadata = {"path": "mock"}
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=(["mock prerequisite"], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value=metadata), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value=metadata), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value=metadata), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value=metadata), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(output_dir))
            run_metadata = json.loads((output_dir / "run-metadata.json").read_text())
            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["artifact_type"],
                             "kzt-real-guest-performance-report")
            self.assertEqual(run_metadata["artifact_type"],
                             "kzt-real-guest-performance-run-metadata")
            self.assertEqual(report["ownership"]["marker"],
                             real_guest_harness.OWNERSHIP_MARKER)
            self.assertEqual(report["result_scope"], "environment_inconclusive",
                             report["reason"])

    def test_harness_and_correctness_scopes_are_not_performance_conclusions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            for error, scope in (
                    (RuntimeError("boom"), "harness_error"),
                    (GuestCorrectnessError("bad guest"), "correctness_failure")):
                with self.subTest(scope=scope):
                    output_dir = Path(temporary_directory) / scope
                    with mock.patch("real_guest_harness.prerequisite_issues",
                                    return_value=([], None)), \
                         mock.patch("real_guest_harness.collect_binary_metadata",
                                    return_value={}), \
                         mock.patch("real_guest_harness.collect_fixture_metadata",
                                    return_value={}), \
                         mock.patch("real_guest_harness.collect_host_metadata",
                                    return_value={}), \
                         mock.patch("real_guest_harness.runtime_environment_snapshot",
                                    return_value={}), \
                         mock.patch("real_guest_harness.host_load_snapshot",
                                    return_value={"oversubscribed": False}), \
                         mock.patch("real_guest_harness.verify_role_modes_preflight",
                                    side_effect=error):
                        report = run_performance_gate(self.config(output_dir))
                    self.assertEqual(report["result_scope"], scope)

    def test_host_load_anomaly_is_environment_inconclusive_with_null_analysis(self):
        def fake_pair(config, taskset, raw_samples, phase, pair_index, order,
                      roles):
            return {
                "order": list(order),
                **{label: timed_sample(100) for label in order},
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "load-anomaly"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_role_modes_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_native_apply_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness._run_pair", side_effect=fake_pair), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            side_effect=[
                                {"oversubscribed": False},
                                {"oversubscribed": False},
                                {"oversubscribed": True},
                                {"oversubscribed": False},
                            ]):
                report = run_performance_gate(self.config(output_dir))
            self.assertEqual(report["result_scope"], "environment_inconclusive",
                             report["reason"])
            self.assertEqual(report["result"], GateResult.INCONCLUSIVE.value)
            checkpoint = report["ab_checkpoints"][0]
            self.assertEqual(checkpoint["mode"], "exploratory")
            self.assertIsNone(checkpoint["analysis"])

    def test_eighty_pair_exploratory_checkpoint_has_one_analysis_look_only(self):
        def fake_pair(config, taskset, raw_samples, phase, pair_index, order,
                      roles):
            return {
                "order": list(order),
                **{label: timed_sample(100) for label in order},
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / "eighty-pair"
            with mock.patch("real_guest_harness.prerequisite_issues",
                            return_value=([], None)), \
                 mock.patch("real_guest_harness.collect_binary_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_fixture_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.collect_host_metadata",
                            return_value={}), \
                 mock.patch("real_guest_harness.runtime_environment_snapshot",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_role_modes_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness.verify_native_apply_preflight",
                            return_value={}), \
                 mock.patch("real_guest_harness._run_pair", side_effect=fake_pair), \
                 mock.patch("real_guest_harness.host_load_snapshot",
                            return_value={"oversubscribed": False}):
                report = run_performance_gate(self.config(output_dir))
            metadata = json.loads((output_dir / "run-metadata.json").read_text())
            checkpoint = report["ab_checkpoints"][-1]
            analysis = checkpoint["analysis"]
            self.assertEqual(report["ab_mode"], "exploratory")
            self.assertEqual(checkpoint["decision"], GateResult.INCONCLUSIVE.value)
            self.assertEqual(report["result"], GateResult.INCONCLUSIVE.value)
            self.assertEqual(analysis["formal_stage_count"], 0)
            self.assertEqual(analysis["analysis_look_count"], 1)
            for artifact in (report, metadata):
                self.assertEqual(artifact["statistics"]["ab"][
                    "formal_stage_count"], 0)
                self.assertEqual(artifact["statistics"]["ab"][
                    "analysis_look_count"], 1)


if __name__ == "__main__":
    unittest.main()
