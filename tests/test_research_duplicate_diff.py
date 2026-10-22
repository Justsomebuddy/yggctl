"""Peer tuple multiset diffs, never fabricated stable identities for links."""

import copy
import itertools
import unittest
from unittest.mock import patch

from core import logged
from research import model

A = "a" * 64
B = "b" * 64
C = "c" * 64


class ResearchDuplicateDiff(unittest.TestCase):
    @logged
    def row(self, key=B, up=True, port=7, inbound=False, latency=1):
        return {"key": key, "up": up, "port": port, "inbound": inbound, "latency_ms": latency}

    @logged
    def snapshot(self, rows, after=False):
        return {
            "schema": 1,
            "id": ("2" if after else "1") * 32,
            "instance": "node",
            "started": "2026-10-22T10:01:00+00:00" if after else "2026-10-22T10:00:00+00:00",
            "finished": "2026-10-22T10:01:01+00:00" if after else "2026-10-22T10:00:01+00:00",
            "identity_stable": True,
            "sources": {name: "ok" for name in model.SOURCES},
            "observations": {
                "self": {"key": A, "routing_entries": 1},
                "peers": model.project("peers", {"peers": rows}, stored=True),
                "tree": [],
                "paths": [],
            },
        }

    @logged
    def compare(self, before_rows, after_rows):
        before, after = self.snapshot(before_rows), self.snapshot(after_rows, after=True)
        originals = copy.deepcopy((before, after))
        result = model.difference(before, after)
        self.assertEqual((before, after), originals)
        return result["sources"]["peers"]

    @logged
    def test_duplicate_multiplicity_change_is_visible_without_fake_link_ids(self):
        token = B + ":7:False"
        for old, new in ((2, 1), (1, 2), (3, 1)):
            with self.subTest(old=old, new=new):
                result = self.compare([self.row()] * old, [self.row()] * new)
                self.assertEqual(result["added"], [])
                self.assertEqual(result["removed"], [])
                self.assertEqual(result["changed"], [token])
                self.assertEqual(result["unidentified_before"], 0)
                self.assertEqual(result["unidentified_after"], 0)
        before = self.snapshot([self.row(), self.row()])
        after = self.snapshot([self.row()], after=True)
        self.assertEqual(model.graph(before)["edges"][0]["links"], 2)
        self.assertEqual(model.graph(after)["edges"][0]["links"], 1)

    @logged
    def test_reordered_duplicate_multiset_is_stable_for_all_permutations(self):
        rows = [self.row(), self.row(up=False), self.row(latency=20)]
        for order in itertools.permutations(rows):
            with self.subTest(order=[row["up"] for row in order]):
                result = self.compare(rows, list(order))
                self.assertEqual(result["changed"], [])
                self.assertEqual(result["added"], [])
                self.assertEqual(result["removed"], [])

    @logged
    def test_nonlast_duplicate_state_change_is_not_hidden(self):
        result = self.compare(
            [self.row(), self.row(up=False)],
            [self.row(up=False), self.row(up=False)],
        )
        self.assertEqual(result["changed"], [B + ":7:False"])
        # Latency changes were never topology changes, including single-link input.
        self.assertEqual(self.compare([self.row()], [self.row(latency=50)])["changed"], [])

    @logged
    def test_single_link_and_tuple_add_remove_semantics_are_preserved(self):
        result = self.compare([self.row()], [self.row(up=False)])
        self.assertEqual(
            result,
            {
                "known": True,
                "added": [],
                "removed": [],
                "changed": [B + ":7:False"],
                "unidentified_before": 0,
                "unidentified_after": 0,
            },
        )
        result = self.compare([self.row(port=7)], [self.row(port=8), self.row(key=C, inbound=True)])
        self.assertEqual(result["removed"], [B + ":7:False"])
        self.assertEqual(result["added"], [B + ":8:False", C + ":7:True"])
        self.assertEqual(result["changed"], [])
        result = self.compare([], [self.row(), self.row()])
        self.assertEqual(result["added"], [B + ":7:False"])
        self.assertEqual(result["changed"], [])
        self.assertEqual(self.compare([self.row(), self.row()], [])["removed"], [B + ":7:False"])

    @logged
    def test_unidentified_and_unavailable_sources_are_not_invented_link_identities(self):
        result = self.compare([self.row(key=None)] * 2, [self.row(key=None)])
        self.assertEqual(result["changed"], [])
        self.assertEqual(result["unidentified_before"], 2)
        self.assertEqual(result["unidentified_after"], 1)
        before, after = self.snapshot([self.row()] * 2), self.snapshot([], after=True)
        after["sources"]["peers"] = "unavailable"
        after["observations"]["peers"] = None
        result = model.difference(before, after)
        self.assertEqual(
            result["sources"]["peers"],
            {
                "known": False,
                "added": None,
                "removed": None,
                "changed": None,
            },
        )

    @logged
    def test_aggregation_has_secret_safe_entry_and_exit_logging(self):
        with patch("core.event") as event:
            result = model.peer_link_groups([self.row(), self.row(up=False), self.row(key=None)])
        self.assertEqual(result, {B + ":7:False": {"links": 2, "up_links": 1}})
        event.assert_any_call("entry", "peer_link_groups")
        event.assert_any_call("exit", "peer_link_groups", "success")
        self.assertNotIn(B, repr(event.call_args_list))
