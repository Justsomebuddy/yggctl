"""Independent finite counterexample controls for stored-observation adjacency."""

import contextlib
import datetime as dt
import io
import unittest
from unittest.mock import patch

import telemetry as tm

URI = "ws://192.0.2.8:443/first"
AT = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def peer(rx=0, tx=0, uri=URI):
    return {"r": uri, "rx": rx, "tx": tx}


def observations(*rows):
    return [(AT + dt.timedelta(seconds=i * 60), {"peers": row}) for i, row in enumerate(rows)]


class ObservationBoundaries(unittest.TestCase):
    def render(self, values, invalid=0):
        out = io.StringIO()
        with (
            patch.object(tm, "window", return_value=(values, invalid)),
            contextlib.redirect_stdout(out),
        ):
            tm.throughput(object(), 24)
        text = out.getvalue()
        return text

    def test_generated_output_declares_writable_history_provenance(self):
        text = self.render(observations([peer()], [peer(1, 1)]))
        self.assertIn("history_provenance=unverified_role_writable_history", text)
        self.assertIn("authenticated=false immutable_since_capture=false", text)

    def test_invalid_middle_cannot_be_removed_to_invent_a_rate(self):
        for rx, tx in ((None, None), (None, 0), (0, None), (True, 1), (1, float("nan"))):
            with self.subTest(rx=rx, tx=tx):
                text = self.render(
                    observations([peer()], [peer(rx, tx)], [peer(15_000_000, 15_000_000)])
                )
                self.assertNotIn("sent=", text)
                self.assertIn("no_usable_intervals", text)

    def test_missing_or_unassignable_middle_breaks_continuity(self):
        for middle in ([], None, "invalid", [None], [peer(uri="invalid")]):
            with self.subTest(middle=middle):
                text = self.render(observations([peer()], middle, [peer(15_000_000, 15_000_000)]))
                self.assertNotIn("sent=", text)

    def test_unassignable_identity_does_not_leave_other_series_connected(self):
        middle = [peer(7_500_000, 7_500_000), peer(uri="not-a-uri")]
        text = self.render(observations([peer()], middle, [peer(15_000_000, 15_000_000)]))
        self.assertNotIn("sent=", text)
        self.assertIn("invalid_identities=1", text)

    def test_conflicting_duplicates_break_both_neighbours_permutation_invariant(self):
        for middle in (
            [peer(2, 2), peer(3, 3)],
            [peer(3, 3), peer(2, 2)],
            [peer(2, 2), peer(3, 3), peer(2, 2)],
        ):
            text = self.render(observations([peer()], middle, [peer(15_000_000, 15_000_000)]))
            self.assertNotIn("sent=", text)
            self.assertIn("no_usable_intervals", text)

    def test_duplicate_timestamps_cannot_bridge_unknown_counter_epoch(self):
        values = observations([peer()], [peer(1, 1)], [peer(2, 2)], [peer(15_000_000, 15_000_000)])
        values[2] = (values[1][0], values[2][1])
        self.assertNotIn("sent=", self.render(values))

    def test_invalid_counters_still_register_a_colliding_identity(self):
        text = self.render(
            observations([peer()], [peer(None, None, "ws://192.0.2.8:443/second")], [peer(15, 15)])
        )
        self.assertIn("ambiguous_labels=1", text)
        self.assertIn("ambiguous_peer_label series=2", text)
        self.assertNotIn("sent=", text)

    def test_unknown_positions_of_invalid_records_withhold_all_rates(self):
        text = self.render(observations([peer()], [peer(7_500_000, 7_500_000)]), invalid=1)
        self.assertIn("history_record_boundaries_unknown: rates withheld", text)
        self.assertNotIn("sent=", text)

    def test_rates_resume_only_after_two_new_valid_adjacent_observations(self):
        text = self.render(
            observations([peer()], [peer(None, None)], [peer()], [peer(3_750_000, 7_500_000)])
        )
        self.assertIn("sent=1.00Mbit/s peak=1.00 recv=0.50Mbit/s peak=0.50 intervals=1", text)

    def test_identical_duplicate_deduplication_preserves_single_interval(self):
        text = self.render(observations([peer(), peer()], [peer(7_500_000, 7_500_000)]))
        self.assertIn("sent=1.00Mbit/s", text)
        self.assertIn("intervals=1", text)

    def test_track_refuses_nonpositive_elapsed_even_with_adjacent_positions(self):
        for at in (AT, AT - dt.timedelta(seconds=1)):
            result = tm.throughput_track([(0, AT, 0, 0), (1, at, 100, 100)])
            self.assertEqual(result["intervals"], 0)
