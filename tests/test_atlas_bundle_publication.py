"""Atlas reports become visible only as validated four-file bundles."""

import contextlib
import io
import os
from pathlib import Path
import resource
import signal
import time
from types import SimpleNamespace
from unittest.mock import patch

from atlas import analysis
from atlas import viewer
from atlas.store import Store
from core import Failure, atomic, logged
from observed_fixture import ObservedFixture


class AtlasBundlePublication(ObservedFixture):
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
    def wait_child(self, child, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                return status
            time.sleep(0.05)
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        self.fail("Atlas test child exceeded its time bound")

    @logged
    def test_complete_bundle_and_legacy_retention(self):
        legacy = self.root / ("atlas-" + "0" * 32 + ".json")
        atomic(legacy, "old report")
        result = self.report()
        bundle = Path(result["json"]).parent
        self.assertEqual(bundle.parent, self.root)
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            {p.name for p in bundle.iterdir()},
            {"report.json", "report.md", "report.dot", "report.html"},
        )
        self.assertTrue(
            all(
                Path(result[k]).stat().st_mode & 0o777 == 0o600
                for k in ("json", "md", "dot", "html")
            )
        )
        self.assertEqual(legacy.read_text(), "old report")
        self.report()
        self.assertTrue(bundle.exists())
        self.assertEqual(legacy.read_text(), "old report")

    @logged
    def test_repeated_fourth_write_failure_does_not_consume_retention(self):
        real_atomic = analysis.atomic

        def fail_html(path, value):
            if path.name == "report.html":
                raise OSError("synthetic fourth write failure")
            return real_atomic(path, value)

        for _ in range(83):
            with (
                patch.object(analysis, "atomic", side_effect=fail_html),
                self.assertRaises(OSError),
            ):
                self.report()
            self.assertEqual(list(self.root.glob("atlas-[0-9a-f]*")), [])
            self.assertEqual(len(list(self.root.glob(".atlas-stage-*"))), 1)
        result = self.report()
        self.assertTrue(all(Path(result[k]).is_file() for k in ("json", "md", "dot", "html")))
        self.assertEqual(list(self.root.glob(".atlas-stage-*")), [])

    @logged
    def test_real_file_size_limit_retries_and_repair(self):
        child = os.fork()
        if child == 0:
            try:
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (70 * 1024, 70 * 1024))
                with patch.object(viewer, "html", return_value="x" * (80 * 1024)):
                    for _ in range(83):
                        try:
                            self.report()
                        except OSError:
                            pass
                        else:
                            os._exit(24)
            except BaseException:
                os._exit(25)
            os._exit(23)
        self.assertEqual(self.wait_child(child), 23 << 8)
        self.assertEqual(list(self.root.glob("atlas-[0-9a-f]*")), [])
        self.assertEqual(len(list(self.root.glob(".atlas-stage-*"))), 1)
        result = self.report()
        self.assertTrue(Path(result["html"]).is_file())
        self.assertEqual(list(self.root.glob(".atlas-stage-*")), [])

    @logged
    def test_crash_at_each_atomic_replace_recovers(self):
        import core

        for replace_number in (1, 2, 3, 4):
            before = set(self.root.glob("atlas-[0-9a-f]*"))
            child = os.fork()
            if child == 0:
                try:
                    real_replace = core.os.replace
                    seen = 0

                    def crash_after_replace(source, target):
                        nonlocal seen
                        real_replace(source, target)
                        seen += 1
                        if seen == replace_number:
                            os._exit(23)

                    with patch.object(core.os, "replace", side_effect=crash_after_replace):
                        self.report()
                except BaseException:
                    os._exit(25)
                os._exit(24)
            self.assertEqual(self.wait_child(child), 23 << 8)
            self.assertEqual(set(self.root.glob("atlas-[0-9a-f]*")), before)
            stages = list(self.root.glob(".atlas-stage-*"))
            self.assertEqual(len(stages), 1)
            self.assertEqual(len(list(stages[0].iterdir())), replace_number)
            result = self.report()
            self.assertEqual(list(self.root.glob(".atlas-stage-*")), [])
            self.assertTrue(Path(result["html"]).is_file())
            # Completed history remains after every subsequent recovery.
            self.assertEqual(len(list(self.root.glob("atlas-[0-9a-f]*"))), len(before) + 1)

    @logged
    def test_post_rename_failure_preserves_complete_bundle(self):
        real_fsync = analysis.os.fsync
        root_info = self.root.stat()
        events = []

        def fail_root_fsync(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (root_info.st_dev, root_info.st_ino):
                raise OSError("synthetic root fsync failure")
            return real_fsync(fd)

        with (
            patch.object(analysis, "event", side_effect=lambda *parts: events.append(parts)),
            patch.object(analysis.os, "fsync", side_effect=fail_root_fsync),
            self.assertRaises(OSError),
        ):
            self.report()
        self.assertIn(("external_error", "atlas_export_root_fsync", "OSError"), events)
        bundles = list(self.root.glob("atlas-[0-9a-f]*"))
        self.assertEqual(len(bundles), 1)
        self.assertEqual(len(list(bundles[0].iterdir())), 4)
        self.report()
        self.assertTrue(bundles[0].exists())

    @logged
    def test_stage_mkdir_and_rename_errors_are_traced(self):
        for operation in ("mkdir", "rename"):
            with self.subTest(operation=operation):
                before = set(self.root.glob("atlas-[0-9a-f]*"))
                events = []
                action = (
                    patch.object(Path, "mkdir", side_effect=OSError("synthetic mkdir failure"))
                    if operation == "mkdir"
                    else patch.object(
                        Path, "rename", side_effect=OSError("synthetic rename failure")
                    )
                )
                with (
                    patch.object(
                        analysis, "event", side_effect=lambda *parts: events.append(parts)
                    ),
                    action,
                    self.assertRaises(OSError),
                ):
                    self.report()
                label = "atlas_export_stage_" + operation
                self.assertIn(("external_error", label, "OSError"), events)
                self.assertEqual(set(self.root.glob("atlas-[0-9a-f]*")), before)
                self.report()
                self.assertEqual(list(self.root.glob(".atlas-stage-*")), [])

    @logged
    def test_unsafe_stage_rejects_before_other_stage_cleanup(self):
        for kind in ("unknown", "symlink", "hardlink", "mode", "owner", "extra"):
            with self.subTest(kind=kind):
                safe = self.root / (".atlas-stage-" + "1" * 32)
                unsafe = self.root / (".atlas-stage-" + "2" * 32)
                safe.mkdir(mode=0o700)
                unsafe.mkdir(mode=0o700)
                atomic(safe / "report.json", "safe")
                child = unsafe / ("stranger" if kind == "unknown" else "report.json")
                if kind == "symlink":
                    child.symlink_to(safe / "report.json")
                else:
                    atomic(child, "unsafe")
                link = None
                if kind == "hardlink":
                    link = self.paths.state / "linked"
                    link.hardlink_to(child)
                elif kind == "mode":
                    child.chmod(0o644)
                elif kind == "extra":
                    for i in range(5):
                        atomic(unsafe / f"extra{i}", "unsafe")
                owner = patch.object(analysis.os, "geteuid", return_value=os.geteuid() + 1)
                with (
                    owner if kind == "owner" else contextlib.nullcontext(),
                    self.assertRaises(Failure),
                ):
                    self.report()
                self.assertTrue((safe / "report.json").exists())
                for directory in (safe, unsafe):
                    for entry in directory.iterdir():
                        entry.unlink()
                    directory.rmdir()
                if link is not None:
                    link.unlink()

    @logged
    def test_incomplete_completed_directory_rejects_before_cleanup(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        atomic(stage / "report.json", "safe")
        complete = self.root / ("atlas-" + "2" * 32)
        complete.mkdir(mode=0o700)
        atomic(complete / "report.json", "incomplete")
        with self.assertRaisesRegex(Failure, "atlas_unsafe_export_contents"):
            self.report()
        self.assertTrue((stage / "report.json").exists())

    @logged
    def test_cleanup_uses_only_validated_child_paths(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        verified = stage / "report.json"
        atomic(verified, "abandoned")
        unknown = stage / "unknown"
        real_unlink = os.unlink

        def add_entry_before_unlink(path, *args, **kwargs):
            if path == verified.name and kwargs.get("dir_fd") is not None:
                atomic(unknown, "must remain")
            return real_unlink(path, *args, **kwargs)

        with (
            patch.object(analysis.os, "unlink", side_effect=add_entry_before_unlink),
            self.assertRaises(OSError),
        ):
            self.report()
        self.assertEqual(unknown.read_text(), "must remain")
        self.assertFalse(verified.exists())
        with self.assertRaisesRegex(Failure, "atlas_unsafe_export_contents"):
            self.report()

    @logged
    def test_replaced_stage_symlink_cannot_delete_external_file(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        atomic(stage / "report.json", "abandoned")
        moved = self.paths.state / "moved-stage"
        external = self.paths.state / "external"
        external.mkdir(mode=0o700)
        protected = external / "report.json"
        atomic(protected, "must remain")
        real_open = os.open
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == stage and not swapped:
                swapped = True
                stage.rename(moved)
                stage.symlink_to(external, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        with (
            patch.object(analysis.os, "open", side_effect=swap_before_open),
            self.assertRaises(OSError),
        ):
            self.report()
        self.assertTrue(swapped)
        self.assertEqual(protected.read_text(), "must remain")
        self.assertEqual((moved / "report.json").read_text(), "abandoned")

    @logged
    def test_replaced_real_stage_directory_identity_rejected(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        atomic(stage / "report.json", "original")
        moved = self.paths.state / "moved-stage"
        real_open = os.open
        swapped = False

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == stage and not swapped:
                swapped = True
                stage.rename(moved)
                stage.mkdir(mode=0o700)
                atomic(stage / "report.json", "replacement")
            return real_open(path, flags, *args, **kwargs)

        with (
            patch.object(analysis.os, "open", side_effect=swap_before_open),
            self.assertRaisesRegex(Failure, "atlas_unsafe_export_directory"),
        ):
            self.report()
        self.assertTrue(swapped)
        self.assertEqual((stage / "report.json").read_text(), "replacement")
        self.assertEqual((moved / "report.json").read_text(), "original")

    @logged
    def test_stage_path_swap_after_open_preserves_verified_file(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        atomic(stage / "report.json", "original")
        moved = self.paths.state / "moved-stage"
        external = self.paths.state / "external"
        external.mkdir(mode=0o700)
        atomic(external / "report.json", "protected")
        real_fstat = os.fstat
        identity = stage.stat()
        swapped = False

        def swap_before_identity_check(fd):
            nonlocal swapped
            info = real_fstat(fd)
            if not swapped and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                swapped = True
                stage.rename(moved)
                stage.symlink_to(external, target_is_directory=True)
            return info

        with (
            patch.object(analysis.os, "fstat", side_effect=swap_before_identity_check),
            self.assertRaisesRegex(Failure, "atlas_unsafe_export_directory"),
        ):
            self.report()
        self.assertTrue(swapped)
        self.assertEqual((moved / "report.json").read_text(), "original")
        self.assertEqual((external / "report.json").read_text(), "protected")

    @logged
    def test_stage_path_swap_after_verified_unlink_preserves_external_file(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        atomic(stage / "report.json", "abandoned")
        moved = self.paths.state / "moved-stage"
        external = self.paths.state / "external"
        external.mkdir(mode=0o700)
        atomic(external / "report.json", "protected")
        real_unlink = os.unlink
        swapped = False

        def swap_after_unlink(path, *args, **kwargs):
            nonlocal swapped
            result = real_unlink(path, *args, **kwargs)
            if path == "report.json" and kwargs.get("dir_fd") is not None:
                swapped = True
                stage.rename(moved)
                stage.symlink_to(external, target_is_directory=True)
            return result

        with (
            patch.object(analysis.os, "unlink", side_effect=swap_after_unlink),
            self.assertRaisesRegex(Failure, "atlas_unsafe_export_directory"),
        ):
            self.report()
        self.assertTrue(swapped)
        self.assertEqual((external / "report.json").read_text(), "protected")
        self.assertEqual(list(moved.iterdir()), [])

    @logged
    def test_complete_temp_and_two_stage_temps_fail_before_cleanup(self):
        complete = Path(self.report()["json"]).parent
        atomic(complete / ".yggctl-abcdefgh", "unexpected")
        safe = self.root / (".atlas-stage-" + "1" * 32)
        safe.mkdir(mode=0o700)
        atomic(safe / "report.json", "abandoned")
        with self.assertRaisesRegex(Failure, "atlas_unsafe_export_contents"):
            self.report()
        self.assertTrue((safe / "report.json").exists())
        (complete / ".yggctl-abcdefgh").unlink()
        double = self.root / (".atlas-stage-" + "2" * 32)
        double.mkdir(mode=0o700)
        atomic(double / ".yggctl-abcdefgh", "temporary")
        atomic(double / ".yggctl-ijklmnop", "temporary")
        with self.assertRaisesRegex(Failure, "atlas_unsafe_export_contents"):
            self.report()
        self.assertTrue((safe / "report.json").exists())

    @logged
    def test_six_stage_entries_reject_at_bound_before_cleanup(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        stage.mkdir(mode=0o700)
        ordered = []
        for name in (
            "report.json",
            "report.md",
            "report.dot",
            "report.html",
            ".yggctl-abcdefgh",
            "unknown",
        ):
            path = stage / name
            atomic(path, "fixture")
            ordered.append(path)
        safe = self.root / ".yggctl-ijklmnop"
        atomic(safe, "abandoned")
        real_iterdir = Path.iterdir

        def controlled_iterdir(path):
            return iter(ordered) if path == stage else real_iterdir(path)

        with (
            patch.object(Path, "iterdir", autospec=True, side_effect=controlled_iterdir),
            self.assertRaisesRegex(Failure, "atlas_unsafe_export_contents"),
        ):
            self.report()
        self.assertTrue(safe.exists())
        self.assertEqual(len(list(stage.iterdir())), 6)

    @logged
    def test_stage_directory_type_mode_and_child_owner_reject(self):
        stage = self.root / (".atlas-stage-" + "1" * 32)
        safe = self.root / ".yggctl-abcdefgh"
        atomic(safe, "abandoned")
        for kind in ("file", "symlink", "mode", "directory_owner", "child_owner"):
            with self.subTest(kind=kind):
                target = None
                if kind == "file":
                    atomic(stage, "unsafe")
                elif kind == "symlink":
                    target = self.paths.state / "outside"
                    target.mkdir(mode=0o700)
                    stage.symlink_to(target, target_is_directory=True)
                else:
                    stage.mkdir(mode=0o700)
                    atomic(stage / "report.json", "fixture")
                    if kind == "mode":
                        stage.chmod(0o755)
                real_lstat = Path.lstat

                def wrong_owner(path):
                    info = real_lstat(path)
                    if (kind == "directory_owner" and path == stage) or (
                        kind == "child_owner" and path == stage / "report.json"
                    ):
                        fields = list(info)
                        fields[4] = os.geteuid() + 1
                        return os.stat_result(fields)
                    return info

                with (
                    patch.object(Path, "lstat", autospec=True, side_effect=wrong_owner),
                    self.assertRaisesRegex(
                        Failure,
                        "atlas_unsafe_export_contents"
                        if kind == "child_owner"
                        else "atlas_unsafe_export_directory",
                    ),
                ):
                    self.report()
                self.assertTrue(safe.exists())
                if kind == "file" or kind == "symlink":
                    stage.unlink()
                else:
                    (stage / "report.json").unlink()
                    stage.rmdir()
                if target is not None:
                    target.rmdir()

    @logged
    def test_initial_and_late_collision_preserve_destination(self):
        first = self.report()
        destination = Path(first["json"]).parent
        selected = destination.name.removeprefix("atlas-")
        marker = Path(first["json"]).read_bytes()
        with (
            patch.object(analysis.uuid, "uuid4", return_value=SimpleNamespace(hex=selected)),
            self.assertRaisesRegex(Failure, "atlas_export_collision"),
        ):
            self.report()
        self.assertEqual(Path(first["json"]).read_bytes(), marker)

        late_id = "f" * 32
        late_destination = self.root / ("atlas-" + late_id)
        real_atomic = analysis.atomic

        def introduce_collision(path, value):
            real_atomic(path, value)
            if path.name == "report.html":
                late_destination.mkdir(mode=0o700)
                for extension in ("json", "md", "dot", "html"):
                    real_atomic(late_destination / ("report." + extension), "collision")

        with (
            patch.object(analysis.uuid, "uuid4", return_value=SimpleNamespace(hex=late_id)),
            patch.object(analysis, "atomic", side_effect=introduce_collision),
            self.assertRaisesRegex(Failure, "atlas_export_collision"),
        ):
            self.report()
        self.assertEqual((late_destination / "report.html").read_text(), "collision")
        self.assertEqual(len(list(self.root.glob(".atlas-stage-*"))), 1)

    @logged
    def test_mixed_retention_counts_completed_bundle_as_four(self):
        self.report()
        first = next(self.root.glob("atlas-[0-9a-f]*"))
        for i in range(249):
            atomic(self.root / ("atlas-" + f"{i:032x}" + ".md"), "legacy")
        with self.assertRaisesRegex(Failure, "atlas_export_retention_review_required"):
            self.report()
        self.assertTrue(first.is_dir())
        self.assertEqual(len(list(self.root.glob("atlas-*.md"))), 249)
