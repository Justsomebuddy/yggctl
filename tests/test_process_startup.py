"""Fault-injected startup cleanup; the real kernel-limit experiment is separate."""

import errno
from pathlib import Path
import selectors
import subprocess  # nosec B404 # Owned synthetic children only.
import sys
import tempfile
from typing import BinaryIO, cast
import unittest
from unittest.mock import patch

import core
from core import logged


class ProcessStartup(unittest.TestCase):
    @logged
    def test_selector_error_reaps_started_child(self):
        children: list[subprocess.Popen[bytes]] = []
        real_spawn = subprocess.Popen

        @logged
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child

        try:
            with (
                patch.object(
                    core.selectors, "DefaultSelector", side_effect=OSError(errno.EMFILE, "fd")
                ),
                patch.object(core.subprocess, "Popen", side_effect=spawn),
                self.assertRaises(OSError) as caught,
            ):
                core.bounded_process([sys.executable, "-I", "-c", "import time;time.sleep(6)"])
            self.assertEqual(caught.exception.errno, errno.EMFILE)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()

    @logged
    def test_failed_spawn_does_not_allocate_a_selector(self):
        with tempfile.TemporaryDirectory(prefix="startup-") as directory:
            missing = str(Path(directory) / "missing-executable")
            with (
                patch.object(core.selectors, "DefaultSelector") as selector,
                patch.object(core.os, "killpg") as kill,
                self.assertRaises(FileNotFoundError),
            ):
                core.bounded_process([missing])
        kill.assert_not_called()
        selector.assert_not_called()

    @logged
    def test_post_spawn_setup_errors_kill_and_reap_owned_child(self):
        for stage in ("memory", "pipe"):
            with self.subTest(stage=stage):
                children: list[subprocess.Popen[bytes]] = []
                monitors: list[selectors.BaseSelector] = []
                real_spawn = subprocess.Popen
                real_selector = selectors.DefaultSelector

                @logged
                def spawn(*args, **kwargs):
                    proc = real_spawn(*args, **kwargs)
                    children.append(proc)
                    return proc

                @logged
                def monitor():
                    selector = real_selector()
                    monitors.append(selector)
                    return selector

                failure = (
                    patch.object(core, "memoryview", side_effect=MemoryError(), create=True)
                    if stage == "memory"
                    else patch.object(core.os, "set_blocking", side_effect=OSError(errno.EIO, "io"))
                )
                expected = MemoryError if stage == "memory" else OSError
                try:
                    with (
                        patch.object(core.subprocess, "Popen", side_effect=spawn),
                        patch.object(core.selectors, "DefaultSelector", side_effect=monitor),
                        failure,
                        self.assertRaises(expected),
                    ):
                        core.bounded_process(
                            [sys.executable, "-I", "-c", "import time;time.sleep(6)"], timeout=2
                        )
                    self.assertEqual(len(children), 1)
                    child = children[0]
                    self.assertIsNotNone(child.returncode)
                    self.assertLess(cast(int, child.returncode), 0)
                    self.assertTrue(cast(BinaryIO, child.stdout).closed)
                    self.assertTrue(cast(BinaryIO, child.stderr).closed)
                    self.assertIsNone(monitors[0].get_map())
                finally:
                    for child in children:
                        if child.poll() is None:
                            child.kill()
                        child.wait(timeout=3)
                        for stream in (child.stdin, child.stdout, child.stderr):
                            if stream is not None:
                                stream.close()
                    for selector in monitors:
                        selector.close()
