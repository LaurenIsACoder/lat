#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import test_real_guest_e2e as runner


SUCCESS = (
    "KZT_GUEST_E2E_OK calls=2 slot=0x1000 before=0x2000 "
    "after_first=0x3000 after_second=0x3000 first_ns=0x1 second_ns=0x1\n"
)


def scenario_output(scenario):
    lines = [
        SUCCESS.rstrip(),
        "kzt_lazy_resolver_entry symbol=dlerror",
        "kzt_lazy_preemption schema=1 symbol=dlerror version=GLIBC_2.34 "
        f"candidate_count={scenario['candidate_count']} "
        "scope_complete=1 lookup_order_known=1 "
        f"reason={scenario['reason']}",
    ]
    if scenario["direct"]:
        lines.extend(
            [
                "kzt_lazy_direct schema=1 symbol=dlerror "
                "route_status=NATIVE_APPLIED writer_result=APPLIED",
                "kzt_lazy_path schema=1 symbol=dlerror route=NEW_DIRECT "
                "guest_handoff=0 legacy_lookup=0 legacy_write=0",
            ]
        )
    else:
        lines.extend(
            [
                "kzt_lazy_path schema=1 symbol=dlerror route=GUEST_LD_SO "
                "guest_handoff=1 legacy_lookup=0 legacy_write=0",
                scenario["marker"],
                scenario["marker"],
                "kzt_lazy_diagnostic symbol=dlerror",
            ]
        )
    return "\n".join(lines) + "\n"


class WI601RealGuestE2ELauncherTest(unittest.TestCase):
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

    def test_direct_and_guest_handoff_use_real_scenario_commands(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            executable = Path(command[-1]).name
            scenario = next(
                item
                for item in runner.SCENARIOS
                if item["executable"] == executable
            )
            return subprocess.CompletedProcess(
                command, 0, scenario_output(scenario)
            )

        with mock.patch.object(
            runner.preemption.subprocess, "run", side_effect=fake_run
        ):
            for scenario in runner.SCENARIOS:
                runner.run_scenario(self.args, scenario)

        self.assertEqual(len(calls), 2)
        for scenario, (command, kwargs) in zip(runner.SCENARIOS, calls):
            self.assertEqual(
                command,
                [
                    str(self.args.latx),
                    "-L",
                    str(self.args.guest_root),
                    str(self.args.fixture_dir / scenario["executable"]),
                ],
            )
            self.assertEqual(
                kwargs["env"]["LD_LIBRARY_PATH"],
                str(self.args.fixture_dir),
            )

    def test_direct_requires_one_new_path_and_zero_legacy_activity(self):
        direct = runner.SCENARIOS[0]
        output = scenario_output(direct)
        invalid_outputs = (
            output.replace("kzt_lazy_direct schema=1", "missing_direct"),
            output.replace("legacy_lookup=0", "legacy_lookup=1"),
            output.replace("legacy_write=0", "legacy_write=1"),
        )

        with mock.patch.object(
            runner.preemption.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, item)
                for item in invalid_outputs
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "native direct apply"):
                runner.run_scenario(self.args, direct)
            with self.assertRaisesRegex(RuntimeError, "legacy host lookup"):
                runner.run_scenario(self.args, direct)
            with self.assertRaisesRegex(RuntimeError, "legacy GOT writer"):
                runner.run_scenario(self.args, direct)

    def test_guest_fallback_hands_off_once_to_selected_provider(self):
        fallback = runner.SCENARIOS[1]
        output = scenario_output(fallback)
        invalid_outputs = (
            output.replace("guest_handoff=1", "guest_handoff=0"),
            output.replace(
                "KZT_PREEMPT_PROVIDER_A", "KZT_PREEMPT_PROVIDER_B"
            ),
        )

        with mock.patch.object(
            runner.preemption.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, item)
                for item in invalid_outputs
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "hand off exactly once"):
                runner.run_scenario(self.args, fallback)
            with self.assertRaisesRegex(
                RuntimeError, "selected guest provider"
            ):
                runner.run_scenario(self.args, fallback)


if __name__ == "__main__":
    unittest.main()
