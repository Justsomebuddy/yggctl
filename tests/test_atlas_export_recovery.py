"""Atlas export crash custody and process concurrency in synthetic local state."""

import contextlib
import io
import os
from pathlib import Path
import select
import stat
from unittest.mock import patch

from core import Failure, atomic, logged
from atlas import analysis
from atlas.store import Store
from observed_fixture import ObservedFixture


class AtlasExportRecovery(ObservedFixture):
    @logged
    def setUp(self):
        super().setUp()
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        with Store(self.ctx, True):
            pass
        self.root = self.paths.state / "atlas"

    @logged
    def report(self):
        with Store(self.ctx) as store:
            return analysis.report(self.ctx, store)

    @logged
    def test_crash_before_replace_recovers_on_next_report(self):
        baseline = self.report()
        preserved = {key: Path(baseline[key]).read_bytes() for key in ("json", "md", "dot", "html")}
        with Store(self.ctx, True) as writer:
            writer.meta("checkpoint", "unchanged")
        for _ in range(2):
            # The child exits inside the real atomic write, so its finally block cannot run.
            child = os.fork()
            if child == 0:
                import core

                def crash_before_replace(_source, _target):
                    os._exit(23)

                try:
                    with patch.object(core.os, "replace", side_effect=crash_before_replace):
                        self.report()
                except BaseException:
                    os._exit(25)
                os._exit(24)
            self.assertEqual(os.waitpid(child, 0)[1], 23 << 8)
            temporary = list(self.root.glob(".yggctl-*"))
            self.assertEqual(len(temporary), 1)
            self.assertEqual(stat.S_IMODE(temporary[0].lstat().st_mode), 0o600)
            self.assertEqual(
                {key: Path(baseline[key]).read_bytes() for key in preserved}, preserved
            )
            with Store(self.ctx) as reader:
                self.assertEqual(reader.meta("checkpoint"), "unchanged")
            result = self.report()
            self.assertFalse(temporary[0].exists())
            self.assertTrue(
                all(Path(result[key]).is_file() for key in ("json", "md", "dot", "html"))
            )

    @logged
    def test_parallel_reports_busy_then_safe_retry(self):
        entered_r, entered_w = os.pipe()
        release_r, release_w = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(entered_r)
            os.close(release_w)
            import core

            real_replace = core.os.replace
            waiting = True

            def hold_first_replace(source, target):
                nonlocal waiting
                if waiting:
                    waiting = False
                    os.write(entered_w, b"1")
                    if os.read(release_r, 1) != b"1":
                        os._exit(25)
                return real_replace(source, target)

            try:
                with patch.object(core.os, "replace", side_effect=hold_first_replace):
                    self.report()
            except BaseException:
                os._exit(26)
            os._exit(0)
        os.close(entered_w)
        os.close(release_r)
        live = []
        try:
            ready, _, _ = select.select([entered_r], [], [], 10)
            self.assertTrue(ready, "first report did not reach the export barrier")
            self.assertEqual(os.read(entered_r, 1), b"1")
            live = list(self.root.glob(".yggctl-*"))
            self.assertEqual(len(live), 1)
            live_info, live_bytes = live[0].lstat(), live[0].read_bytes()
            with Store(self.ctx, True) as writer:
                writer.meta("during_export", "progressed")
            with self.assertRaisesRegex(Failure, "atlas_export_busy"):
                self.report()
            self.assertEqual(
                (live[0].lstat().st_ino, live[0].read_bytes()),
                (live_info.st_ino, live_bytes),
            )
        finally:
            os.write(release_w, b"1")
            os.close(release_w)
            os.close(entered_r)
            _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0)
        if live:
            self.assertFalse(live[0].exists())
        self.assertEqual(len(list(self.root.glob("atlas-*.json"))), 1)
        self.report()
        self.assertEqual(len(list(self.root.glob("atlas-*.json"))), 2)
        with Store(self.ctx) as reader:
            self.assertEqual(reader.meta("during_export"), "progressed")

    @logged
    def test_writer_can_progress_during_report(self):
        with Store(self.ctx, True) as writer:
            result = self.report()
            writer.meta("export_concurrent_writer", True)
            self.assertTrue(Path(result["json"]).is_file())
            self.assertTrue(writer.meta("export_concurrent_writer"))

    @logged
    def test_normal_exception_releases_lock_and_atomic_temp(self):
        import core

        with (
            patch.object(core.os, "replace", side_effect=OSError("synthetic write failure")),
            self.assertRaises(OSError),
        ):
            self.report()
        self.assertEqual(list(self.root.glob(".yggctl-*")), [])
        self.report()

    @logged
    def test_lock_open_flock_close_failures_trace_lifetime(self):
        for stage in ("open", "flock", "close"):
            with self.subTest(stage=stage):
                events = []
                real_close = os.close

                def close_then_fail(fd):
                    real_close(fd)
                    raise OSError("synthetic close failure")

                action = (
                    patch.object(analysis.os, "open", side_effect=PermissionError())
                    if stage == "open"
                    else patch.object(analysis.fcntl, "flock", side_effect=OSError())
                    if stage == "flock"
                    else patch.object(analysis.os, "close", side_effect=close_then_fail)
                )
                with (
                    patch.object(
                        analysis, "event", side_effect=lambda *parts: events.append(parts)
                    ),
                    action,
                    self.assertRaises(OSError),
                    analysis.export_locked(self.root),
                ):
                    pass
                self.assertIn(("entry", "atlas_export_locked"), events)
                self.assertIn(
                    (
                        "error",
                        "atlas_export_locked",
                        "PermissionError" if stage == "open" else "OSError",
                    ),
                    events,
                )
                self.assertTrue(any(e[0] == "external_error" for e in events))
                self.assertFalse(
                    any(e[0] == "exit" and e[1] == "atlas_export_locked" for e in events)
                )
        self.report()

    @logged
    def test_cleanup_error_keeps_file_and_releases_lock(self):
        temporary = self.root / ".yggctl-abcdefgh"
        atomic(temporary, "abandoned")
        events = []
        real_unlink = Path.unlink

        def fail_temporary_unlink(path, *args, **kwargs):
            if path == temporary:
                raise OSError("synthetic unlink failure")
            return real_unlink(path, *args, **kwargs)

        with (
            patch.object(analysis, "event", side_effect=lambda *parts: events.append(parts)),
            patch.object(Path, "unlink", autospec=True, side_effect=fail_temporary_unlink),
            self.assertRaises(OSError),
        ):
            self.report()
        self.assertTrue(temporary.exists())
        self.assertIn(("error", "atlas_export_locked", "OSError"), events)
        self.assertIn(("state", "atlas_export_lock", "closed"), events)
        self.report()
        self.assertFalse(temporary.exists())

    @logged
    def test_unsafe_abandoned_file_rejected_without_cleanup(self):
        for kind in ("mode", "symlink", "hardlink", "owner"):
            with self.subTest(kind=kind):
                temporary = self.root / ".yggctl-abcdefgh"
                other = self.root / ".yggctl-ijklmnop"
                atomic(other, "abandoned")
                if kind == "symlink":
                    temporary.symlink_to(other)
                else:
                    atomic(temporary, "abandoned")
                    if kind == "mode":
                        temporary.chmod(0o644)
                    elif kind == "hardlink":
                        # Keep the second name outside the scanned export directory.
                        link = self.paths.state / "linked"
                        link.hardlink_to(temporary)
                owner = patch.object(analysis.os, "geteuid", return_value=os.geteuid() + 1)
                with (
                    owner if kind == "owner" else contextlib.nullcontext(),
                    self.assertRaisesRegex(Failure, "atlas_unsafe_temporary_file"),
                ):
                    self.report()
                self.assertTrue(other.exists())
                self.assertTrue(temporary.is_symlink() or temporary.exists())
                temporary.unlink()
                other.unlink()
                if kind == "hardlink":
                    self.assertEqual(link.read_text(), "abandoned")
                    link.unlink()

    @logged
    def test_unknown_entry_and_retention_reject_before_cleanup(self):
        temporary = self.root / ".yggctl-abcdefgh"
        atomic(temporary, "abandoned")
        unknown = self.root / "unexpected"
        atomic(unknown, "not an Atlas export")
        with self.assertRaisesRegex(Failure, "atlas_unsafe_export_entry"):
            self.report()
        self.assertTrue(temporary.exists())
        unknown.unlink()
        generated = []
        for i in range(253):
            path = self.root / ("atlas-" + f"{i:032x}" + ".json")
            atomic(path, "fixture")
            generated.append(path)
        with self.assertRaisesRegex(Failure, "atlas_export_retention_review_required"):
            self.report()
        self.assertTrue(temporary.exists())
        generated[-1].unlink()  # 252 existing + four new exports reaches the 256 limit.
        result = self.report()
        self.assertFalse(temporary.exists())
        self.assertTrue(Path(result["json"]).is_file())

    @logged
    def test_directory_limit_rejects_before_cleanup(self):
        temporary = self.root / ".yggctl-abcdefgh"
        atomic(temporary, "abandoned")
        for i in range(512):
            atomic(self.root / ("atlas-" + f"{i:032x}" + ".md"), "fixture")
        with self.assertRaisesRegex(Failure, "atlas_export_directory_guard"):
            self.report()
        self.assertTrue(temporary.exists())
