#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER = SCRIPT_DIR / "test_real_guest_loader_gate.py"
SCENARIOS = (
    "dependency-reopen",
    "visibility-noload",
    "namespace-isolation",
    "symbol-versions-errors",
    "wrapped-library-handle",
)


class GuestLoaderGateHarnessTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.fixture_dir = self.root / "fixture"
        self.fixture_dir.mkdir()
        for scenario in SCENARIOS:
            executable = self.fixture_dir / scenario
            executable.write_text("fake guest fixture\n", encoding="utf-8")
            executable.chmod(0o755)

        self.guest_root = self.root / "guest-root"
        loader = self.guest_root / "lib64" / "ld-linux-x86-64.so.2"
        loader.parent.mkdir(parents=True)
        loader.write_text("fake guest loader\n", encoding="utf-8")

    def write_fake_latx(self, name, actions=None):
        path = self.root / name
        action_map = repr(actions or {})
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "import time\n"
            f"actions = {action_map}\n"
            "scenario = Path(sys.argv[-1]).name\n"
            "fixture = str(Path(sys.argv[-1]).parent)\n"
            "if '-E' in sys.argv:\n"
            "    print('release-incompatible -E option used')\n"
            "    raise SystemExit(78)\n"
            "if os.environ.get('LD_LIBRARY_PATH') != fixture:\n"
            "    print('guest LD_LIBRARY_PATH was not inherited')\n"
            "    raise SystemExit(79)\n"
            "if os.environ.get('LATX_KZT') != '2':\n"
            "    print('KZT was not forced for the gate')\n"
            "    raise SystemExit(80)\n"
            "candidate = 'candidate' in Path(sys.argv[0]).name\n"
            "writer = os.environ.get('LATX_KZT_PATCH_SPIKE')\n"
            "if candidate != (writer == '1'):\n"
            "    print('candidate writer environment mismatch')\n"
            "    raise SystemExit(81)\n"
            "action = actions.get(scenario, 'pass')\n"
            "if action == 'timeout':\n"
            "    time.sleep(10)\n"
            "elif action == 'skip':\n"
            "    print('fake LATX skipped scenario')\n"
            "    raise SystemExit(77)\n"
            "elif action == 'fail':\n"
            "    print('fake guest assertion failed')\n"
            "    raise SystemExit(42)\n"
            "elif action == 'no-marker':\n"
            "    raise SystemExit(0)\n"
            "print('WI600_GUEST_LOADER_PASS ' + scenario)\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def run_gate(self, baseline_actions=None, candidate_actions=None,
                 candidate_path=None, timeout="8"):
        baseline = self.write_fake_latx("baseline-latx", baseline_actions)
        if candidate_path is None:
            candidate = self.write_fake_latx(
                "candidate-latx", candidate_actions
            )
        else:
            candidate = candidate_path
        report_path = self.root / "report.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--baseline-latx", str(baseline),
                "--candidate-latx", str(candidate),
                "--guest-root", str(self.guest_root),
                "--fixture-dir", str(self.fixture_dir),
                "--timeout", timeout,
                "--json-output", str(report_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )
        report = None
        if report_path.is_file():
            report = json.loads(report_path.read_text(encoding="utf-8"))
        return completed, report

    def scenario(self, report, scenario_id):
        return next(
            item for item in report["scenarios"]
            if item["id"] == scenario_id
        )

    def test_all_p0_scenarios_pass_with_table_and_json(self):
        completed, report = self.run_gate()

        self.assertEqual(
            completed.returncode, 0, f"{completed.stderr}\n{report}"
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["scenarios"]), len(SCENARIOS))
        for scenario in SCENARIOS:
            self.assertIn(scenario, completed.stdout)
            result = self.scenario(report, scenario)
            self.assertEqual(result["baseline"]["status"], "PASS")
            self.assertEqual(result["candidate"]["status"], "PASS")
            self.assertEqual(result["status"], "PASS")

    def test_baseline_pass_candidate_failure_is_a_regression(self):
        completed, report = self.run_gate(
            candidate_actions={"dependency-reopen": "fail"}
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        result = self.scenario(report, "dependency-reopen")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["regression"])
        self.assertIn("baseline passed", result["reason"])

    def test_candidate_failure_is_fail_when_baseline_also_fails(self):
        actions = {"visibility-noload": "fail"}
        completed, report = self.run_gate(
            baseline_actions=actions,
            candidate_actions=actions,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(report["status"], "FAIL")
        result = self.scenario(report, "visibility-noload")
        self.assertEqual(result["candidate"]["status"], "FAIL")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["regression"])

    def test_zero_exit_without_guest_pass_marker_is_fail(self):
        completed, report = self.run_gate(
            candidate_actions={"namespace-isolation": "no-marker"}
        )

        self.assertEqual(completed.returncode, 1)
        result = self.scenario(report, "namespace-isolation")
        self.assertEqual(result["candidate"]["status"], "FAIL")
        self.assertIn("pass marker", result["candidate"]["reason"])

    def test_timeout_is_inconclusive_and_cannot_pass(self):
        completed, report = self.run_gate(
            candidate_actions={"symbol-versions-errors": "timeout"},
            timeout="0.05",
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        result = self.scenario(report, "symbol-versions-errors")
        self.assertEqual(result["candidate"]["status"], "INCONCLUSIVE")
        self.assertIn("timed out", result["candidate"]["reason"])

    def test_skip_is_inconclusive_and_cannot_pass(self):
        completed, report = self.run_gate(
            candidate_actions={"dependency-reopen": "skip"}
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        result = self.scenario(report, "dependency-reopen")
        self.assertEqual(result["candidate"]["status"], "INCONCLUSIVE")
        self.assertIn("skip", result["candidate"]["reason"])

    def test_missing_latx_is_inconclusive_and_still_writes_report(self):
        completed, report = self.run_gate(
            candidate_path=self.root / "missing-candidate-latx"
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        for result in report["scenarios"]:
            self.assertEqual(
                result["candidate"]["status"], "INCONCLUSIVE"
            )
            self.assertIn("not found", result["candidate"]["reason"])

    def test_missing_guest_root_is_inconclusive(self):
        self.guest_root = self.root / "missing-guest-root"

        completed, report = self.run_gate()

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "INCONCLUSIVE")
        for result in report["scenarios"]:
            self.assertEqual(result["baseline"]["status"], "INCONCLUSIVE")
            self.assertEqual(result["candidate"]["status"], "INCONCLUSIVE")
            self.assertIn(
                "guest root directory not found",
                result["candidate"]["reason"],
            )


if __name__ == "__main__":
    unittest.main()
