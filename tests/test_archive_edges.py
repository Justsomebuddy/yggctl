"""Hostile archive manifests remain data; no extraction or selected target writes."""

import io
import json
import tarfile
from unittest.mock import Mock, patch

from core import Failure, digest, logged
import recovery
from test_support import ConsoleFixture


class ArchiveEdges(ConsoleFixture):
    @logged
    def raw_archive(self, files, manifest):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, value in dict(
                files, **{"manifest.json": json.dumps(manifest).encode()}
            ).items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        return output.getvalue()

    @logged
    def test_archive_caps_missing_hashes_and_key_flag(self):
        files = recovery.members(self.ctx)
        manifest = {
            "schema": 1,
            "keys": False,
            "sha256": {name: digest(data) for name, data in files.items()},
        }
        with self.assertRaisesRegex(Failure, "backup_size_limit"):
            recovery.inspect_archive(b"x" * (4 * 1024 * 1024 + 1))
        for data, label in (
            (dict(manifest, schema=True), "invalid_backup_manifest_schema"),
            (
                dict(manifest, sha256={name: "0" * 64 for name in files}),
                "backup_member_hash_mismatch",
            ),
        ):
            with self.assertRaisesRegex(Failure, label):
                recovery.inspect_archive(self.raw_archive(files, data))
        subset = dict(files)
        subset.pop(next(iter(subset)))
        with self.assertRaisesRegex(Failure, "backup_members_missing"):
            recovery.inspect_archive(
                self.raw_archive(
                    subset,
                    dict(manifest, sha256={name: digest(value) for name, value in subset.items()}),
                )
            )
        with self.assertRaisesRegex(Failure, "backup_key_flag_mismatch"):
            recovery.inspect_archive(self.raw_archive(files, dict(manifest, keys=True)))
        full = recovery.members(self.ctx, True)
        recovered, keys = recovery.inspect_archive(recovery.archive(full, True))
        self.assertTrue(keys)
        self.assertEqual(recovered, full)

    @logged
    def test_unreadable_archive_member_fails_closed(self):
        archive = Mock()
        archive.__enter__ = Mock(return_value=archive)
        archive.__exit__ = Mock(return_value=False)
        archive.__iter__ = Mock(return_value=iter([tarfile.TarInfo("manifest.json")]))
        archive.extractfile.return_value = None
        data = recovery.archive(recovery.members(self.ctx))
        with (
            patch.object(recovery.tarfile, "open", return_value=archive),
            self.assertRaisesRegex(Failure, "unreadable_archive_member"),
        ):
            recovery.inspect_archive(data)

    @logged
    def test_manifest_version_and_corrupt_archive(self):
        files = recovery.members(self.ctx)
        manifest = {"schema": 2, "keys": False, "sha256": {k: digest(v) for k, v in files.items()}}
        with self.assertRaisesRegex(Failure, "backup_manifest_mismatch"):
            recovery.inspect_archive(self.raw_archive(files, manifest))
        with self.assertRaisesRegex(Failure, "invalid_backup_archive"):
            recovery.inspect_archive(b"not gzip tar")
