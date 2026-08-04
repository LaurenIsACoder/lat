#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import test_wi849_real_guest_preemption as runner


SUCCESS = (
    "KZT_GUEST_E2E_OK calls=2 slot=0x1000 before=0x2000 "
    "after_first=0x3000 after_second=0x3000 first_ns=0x1 second_ns=0x1\n"
)


def scenario_output(scenario):
    lines = [
        SUCCESS.rstrip(),
        "kzt_lazy_resolver_entry symbol=dlerror",
        "kzt_lazy_preemption symbol=dlerror version=GLIBC_2.34 "
        f"candidate_count={scenario['candidate_count']} "
        "scope_complete=1 lookup_order_known=1 "
        f"reason={scenario['reason']}",
    ]
    if scenario.get("scope_ready_marker"):
        lines.insert(0, scenario["scope_ready_marker"])
    if scenario["direct"]:
        lines.extend([
            "kzt_lazy_path schema=1 symbol=dlerror route=NEW_DIRECT "
            "guest_handoff=0 legacy_lookup=0 legacy_write=0",
            "kzt_lazy_direct symbol=dlerror route_status=NATIVE_APPLIED",
        ])
    else:
        lines.extend([
            "kzt_lazy_path schema=1 symbol=dlerror route=GUEST_LD_SO "
            "guest_handoff=1 legacy_lookup=0 legacy_write=0",
            scenario["marker"],
            scenario["marker"],
            "kzt_lazy_diagnostic symbol=dlerror",
        ])
    return "\n".join(lines) + "\n"


class WI849RealGuestPreemptionLauncherTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fixture_dir = root / "fixture"
        fixture_dir.mkdir()
        log_dir = root / "logs"
        log_dir.mkdir()
        self.args = SimpleNamespace(
            latx=root / "latx-x86_64",
            guest_root=root / "guest-root",
            fixture_dir=fixture_dir,
            log_dir=log_dir,
            timeout=1.0,
        )

    def test_all_scenarios_use_the_expected_guest_executable(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            executable = Path(command[-1]).name
            scenario = next(
                item for item in runner.SCENARIOS
                if item["executable"] == executable
            )
            return subprocess.CompletedProcess(
                command, 0, scenario_output(scenario)
            )

        with mock.patch.object(runner.subprocess, "run", side_effect=fake_run):
            for scenario in runner.SCENARIOS:
                runner.run_scenario(self.args, scenario)

        self.assertEqual(len(calls), len(runner.SCENARIOS))
        for scenario, (command, kwargs) in zip(runner.SCENARIOS, calls):
            self.assertEqual(
                command[-1],
                str(self.args.fixture_dir / scenario["executable"]),
            )
            self.assertEqual(
                kwargs["env"]["LD_LIBRARY_PATH"],
                str(self.args.fixture_dir),
            )
            self.assertNotIn("LD_DYNAMIC_WEAK", kwargs["env"])
            self.assertNotIn("LD_PRELOAD", kwargs["env"])

    def test_rejects_unstable_got_and_wrong_provider(self):
        strong = runner.SCENARIOS[1]
        unstable = scenario_output(strong).replace(
            "after_second=0x3000", "after_second=0x4000"
        )
        wrong_provider = scenario_output(strong).replace(
            "KZT_PREEMPT_PROVIDER_A", "KZT_PREEMPT_PROVIDER_B"
        )
        outputs = iter((unstable, wrong_provider))

        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, next(outputs))

        with mock.patch.object(runner.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(
                RuntimeError, "changed the GOT slot"
            ):
                runner.run_scenario(self.args, strong)
            with self.assertRaisesRegex(
                RuntimeError, "did not execute the selected guest provider"
            ):
                runner.run_scenario(self.args, strong)

    def test_unique_provider_requires_one_direct_record(self):
        unique = runner.SCENARIOS[0]
        missing_direct = scenario_output(unique).replace(
            "kzt_lazy_direct symbol=dlerror route_status=NATIVE_APPLIED\n", ""
        )

        with mock.patch.object(
            runner.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, missing_direct),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "unique provider must use native direct apply"
            ):
                runner.run_scenario(self.args, unique)

    def test_rejects_missing_or_duplicate_lazy_path(self):
        strong = runner.SCENARIOS[1]
        path = (
            "kzt_lazy_path schema=1 symbol=dlerror route=GUEST_LD_SO "
            "guest_handoff=1 legacy_lookup=0 legacy_write=0\n"
        )
        missing = scenario_output(strong).replace(path, "")
        duplicate = scenario_output(strong).replace(path, path + path)
        outputs = iter((missing, duplicate))

        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, next(outputs))

        with mock.patch.object(runner.subprocess, "run", side_effect=fake_run):
            for expected in ("exactly one lazy path", "exactly one lazy path"):
                with self.assertRaisesRegex(RuntimeError, expected):
                    runner.run_scenario(self.args, strong)

    def test_rejects_legacy_activity_and_wrong_guest_handoff(self):
        strong = runner.SCENARIOS[1]
        legacy_lookup = scenario_output(strong).replace(
            "legacy_lookup=0", "legacy_lookup=1"
        )
        wrong_handoff = scenario_output(strong).replace(
            "guest_handoff=1", "guest_handoff=0"
        )
        outputs = iter((legacy_lookup, wrong_handoff))

        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, next(outputs))

        with mock.patch.object(runner.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "legacy host lookup"):
                runner.run_scenario(self.args, strong)
            with self.assertRaisesRegex(RuntimeError, "hand off exactly once"):
                runner.run_scenario(self.args, strong)


if __name__ == "__main__":
    unittest.main()
