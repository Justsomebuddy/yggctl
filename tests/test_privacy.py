"""Opt-in privacy posture: profiles, cost estimate, guard and posture file."""

import argparse
import contextlib
import io
import json
import stat

from core import Failure
import main
import privacy
from test_support import ConsoleFixture


class Privacy(ConsoleFixture):
    def setUp(self):
        super().setUp()
        self.stdout = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.stdout))

    def args(self, values=(), force=False):
        return argparse.Namespace(
            command="privacy",
            args=list(values),
            apply=False,
            force=force,
            full=False,
            recipient=None,
        )

    def run_cli(self, values=(), force=False):
        main.dispatch(self.ctx, self.args(values, force))
        return json.loads(self.stdout.getvalue())

    def test_status_defaults_to_disabled(self):
        self.assertEqual(self.run_cli(["status"]), privacy.DEFAULTS)

    def test_on_refuses_a_small_anonymity_set(self):
        with self.assertRaisesRegex(Failure, "privacy_refused"):
            self.run_cli(["on", "balanced", "7", "87", "1280"])
        verdict = json.loads(self.stdout.getvalue())
        self.assertTrue(verdict["refused"])
        self.assertEqual(verdict["gate"]["reason"], "anonymity_set_too_small")
        self.assertEqual(privacy.load(self.ctx)["enabled"], False)

    def test_on_refuses_a_profile_that_does_not_fit_its_budget(self):
        with self.assertRaisesRegex(Failure, "privacy_refused"):
            self.run_cli(["on", "balanced", "60", "87", "1280"])
        self.assertIn("fits_budget", json.loads(self.stdout.getvalue())["cost"])

    def test_on_succeeds_and_persists_owner_only_state(self):
        saved = self.run_cli(["on", "balanced", "60", "87", "4088"])
        self.assertTrue(saved["enabled"])
        self.assertEqual(saved["profile"], "balanced")
        path = self.paths.state / privacy.STATE
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text())["enabled"], True)
        self.stdout.seek(0)
        self.stdout.truncate(0)
        self.assertEqual(self.run_cli(["off"])["enabled"], False)

    def test_force_overrides_the_guard_and_the_budget(self):
        saved = self.run_cli(["on", "paranoid", "3", "87", "1280"], force=True)
        self.assertTrue(saved["enabled"])
        self.assertEqual(saved["profile"], "paranoid")

    def test_estimate_uses_the_given_measurements(self):
        cost = self.run_cli(["estimate", "paranoid", "1280", "87", "56"])
        self.assertEqual(cost["cover_kbps"], 81.92)
        self.assertAlmostEqual(cost["added_delay_ms"], 17.33, places=2)
        self.assertGreater(cost["overhead_pct"], 0)

    def test_cli_rejects_bad_actions_and_profiles(self):
        for values, message in (
            ([], "privacy_action_required"),
            (["run"], "unknown_privacy_action"),
            (["estimate"], "privacy_profile_required"),
            (["on"], "privacy_profile_required"),
            (["on", "stealth", "60", "87", "4088"], "unknown_privacy_profile"),
            (["on", "off", "60", "87", "4088"], "privacy_off_cannot_be_enabled"),
            (["estimate", "balanced", "0", "87", "56"], "numeric_argument_out_of_range"),
        ):
            with self.assertRaisesRegex(Failure, message):
                self.run_cli(values)

    def test_module_level_rules(self):
        with self.assertRaisesRegex(Failure, "privacy_chunk_must_be_positive"):
            privacy.overhead(privacy.PROFILES["balanced"], 0)
        with self.assertRaisesRegex(Failure, "privacy_measurements_must_be_positive"):
            privacy.estimate("balanced", 1280, -1, 56)
        self.assertEqual(privacy.estimate("off", 1280, 87, 56)["profile"], "off")
        with self.assertRaisesRegex(Failure, "privacy_participants_must_be_non_negative"):
            privacy.anonymity_gate(-1)
        self.assertTrue(privacy.anonymity_gate(50)["allowed"])
        for values, message in (
            ([], "privacy_config_not_an_object"),
            ({"nope": 1}, "unknown_privacy_keys"),
            ({"enabled": 1}, "privacy_flags_must_be_boolean"),
            ({"log_private_flows": "no"}, "privacy_flags_must_be_boolean"),
            ({"profile": 3}, "privacy_profile_must_be_string"),
            ({"enabled": True, "profile": "off"}, "privacy_enabled_profile_required"),
            (
                {"enabled": True, "log_private_flows": True},
                "privacy_flows_must_not_be_logged",
            ),
        ):
            with self.assertRaisesRegex(Failure, message):
                privacy.validate(values)

    def test_load_fails_closed_on_corrupt_state(self):
        (self.paths.state / privacy.STATE).write_text("{")
        with self.assertRaisesRegex(Failure, "privacy_config_not_json"):
            privacy.load(self.ctx)
        (self.paths.state / privacy.STATE).write_text(
            json.dumps({"enabled": True, "profile": "off"})
        )
        with self.assertRaisesRegex(Failure, "privacy_enabled_profile_required"):
            privacy.load(self.ctx)
