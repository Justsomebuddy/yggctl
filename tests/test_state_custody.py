"""Existing privileged state is admitted without chmod/chown or content writes."""

import errno
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import checks
import core
from core import Failure, logged
from test_support import ConsoleFixture


class StateCustodyTests(ConsoleFixture):
    @logged
    def test_health_guard_checks_custody_before_external_configuration(self):
        self.ctx.require_root = True
        with (
            patch.object(
                checks, "state_custody", side_effect=Failure("fixture_refusal")
            ) as custody,
            patch.object(self.ctx, "config") as config,
            self.assertRaisesRegex(Failure, "fixture_refusal"),
        ):
            checks.guard(self.ctx)
        custody.assert_called_once_with(self.ctx)
        config.assert_not_called()

    @logged
    def info(self, mode=stat.S_IFREG | 0o600, uid=0, links=1):
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)

    @logged
    def test_safe_members_and_missing_optional_state(self):
        for directory, mode in ((True, 0o755), (False, 0o600), (False, 0o640)):
            with (
                self.subTest(directory=directory, mode=mode),
                patch.object(
                    Path,
                    "lstat",
                    return_value=self.info((stat.S_IFDIR if directory else stat.S_IFREG) | mode),
                ),
                patch.object(
                    checks.os, "getxattr", side_effect=OSError(errno.ENODATA, "absent")
                ) as acl,
            ):
                checks.state_member(
                    Path("/state"), directory=directory, mode=None if directory else mode
                )
                self.assertEqual(acl.call_count, 2 if directory else 1)
                self.assertTrue(
                    all(call.kwargs == {"follow_symlinks": False} for call in acl.call_args_list)
                )
        with patch.object(Path, "lstat", side_effect=FileNotFoundError()):
            self.assertIsNone(checks.state_member(Path("/missing"), optional=True))
            with self.assertRaises(FileNotFoundError):
                checks.state_member(Path("/missing"), directory=True)

    @logged
    def test_unsafe_types_owners_permissions_and_hardlinks_refused(self):
        cases = (
            (self.info(stat.S_IFLNK | 0o600), False, 0o600),
            (self.info(stat.S_IFIFO | 0o600), False, 0o600),
            (self.info(stat.S_IFREG | 0o600), True, None),
            (self.info(uid=1000), False, 0o600),
            (self.info(stat.S_IFDIR | 0o775), True, None),
            (self.info(stat.S_IFDIR | 0o757), True, None),
            (self.info(links=2), False, 0o600),
            (self.info(stat.S_IFREG | 0o644), False, 0o600),
        )
        for info, directory, mode in cases:
            with (
                self.subTest(info=info, directory=directory),
                patch.object(Path, "lstat", return_value=info),
                patch.object(checks.os, "getxattr") as acl,
                self.assertRaisesRegex(Failure, "untrusted_state_custody"),
            ):
                checks.state_member(Path("/state"), directory=directory, mode=mode)
            acl.assert_not_called()

    @logged
    def test_access_default_acl_and_unavailable_acl_are_not_accepted(self):
        for answers, reason in (
            ([b"synthetic-acl"], "state_extended_acl_requires_review"),
            (
                [OSError(errno.ENODATA, "absent"), b"synthetic-default"],
                "state_extended_acl_requires_review",
            ),
            ([OSError(errno.EACCES, "unavailable")], "state_acl_unavailable"),
            ([OSError(errno.ENOTSUP, "unsupported")], "state_acl_unavailable"),
        ):
            with (
                self.subTest(reason=reason, count=len(answers)),
                patch.object(Path, "lstat", return_value=self.info(stat.S_IFDIR | 0o755)),
                patch.object(checks.os, "getxattr", side_effect=answers),
                self.assertRaisesRegex(Failure, reason),
            ):
                checks.state_member(Path("/state"), directory=True)

    @logged
    def test_inventory_covers_ancestors_and_only_protected_root_state(self):
        with patch.object(checks, "state_member") as member:
            checks.state_custody(self.ctx)
        directories = [
            call.args[0] for call in member.call_args_list if call.kwargs.get("directory")
        ]
        self.assertEqual(directories, [self.paths.state, *self.paths.state.parents])
        leaves = {
            call.args[0].name: call.kwargs
            for call in member.call_args_list
            if not call.kwargs.get("directory")
        }
        self.assertEqual(
            set(leaves),
            {
                ".console.lock",
                ".worker.lock",
                "alert-state.json",
                "alerts-forwarded.json",
                "simplex-attempts.json",
                "alerts.jsonl",
                "metrics.jsonl",
                "notify.state",
                "privacy.json",
            },
        )
        self.assertEqual(leaves["alerts.jsonl"], {"mode": 0o640, "optional": True})
        self.assertEqual(leaves["alert-state.json"], {"mode": 0o600, "optional": True})
        self.assertEqual(leaves["privacy.json"], {"mode": 0o600, "optional": True})
        self.assertNotIn("research", leaves)
        self.assertNotIn("atlas", leaves)

    @logged
    def test_root_lock_checks_before_creation_and_after_acquisition(self):
        self.ctx.require_root = True
        with (
            patch.object(self.ctx, "root"),
            patch.object(checks, "state_custody") as custody,
            patch.object(core.os, "fstat", return_value=self.info()),
        ):
            with self.ctx.locked():
                self.assertEqual(custody.call_count, 2)
                with self.ctx.locked():
                    self.assertEqual(custody.call_count, 2)
            self.assertEqual(self.ctx.lock_depth, 0)

    @logged
    def test_custody_failure_prevents_lock_creation_and_recheck_unwinds(self):
        self.ctx.require_root = True
        lock = self.paths.state / ".console.lock"
        for outcomes, created in (
            ([Failure("fixture_refusal")], False),
            ([None, Failure("fixture_refusal")], True),
        ):
            with (
                self.subTest(created=created),
                patch.object(self.ctx, "root"),
                patch.object(checks, "state_custody", side_effect=outcomes),
                patch.object(core.os, "fstat", return_value=self.info()),
                self.assertRaisesRegex(Failure, "fixture_refusal"),
                self.ctx.locked(),
            ):
                self.fail("unsafe state admitted")
            self.assertEqual(lock.exists(), created)
            self.assertEqual(self.ctx.lock_depth, 0)
