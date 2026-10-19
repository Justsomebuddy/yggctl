"""Explicit bounded numeric contract used by CLI and focused mutation checks."""

import unittest

from core import Failure, bounded_number, logged


class NumericContract(unittest.TestCase):
    @logged
    def test_closed_interval_integers_and_decimal_strings(self):
        for value in range(1, 61):
            self.assertEqual(bounded_number(value, 1, 60), value)
            self.assertEqual(bounded_number(str(value), 1, 60), value)
        for invalid in (0, 61, -1, "", "1.5", "word", "+1", " 1", "1 ", "1_0", True, None):
            with (
                self.subTest(value=invalid),
                self.assertRaisesRegex(Failure, "numeric_argument_out_of_range"),
            ):
                bounded_number(invalid, 1, 60)

    @logged
    def test_non_decimal_digits_and_overlong_numeric_input_fail_closed(self):
        for invalid in ("²", "①", "1" * 5000):
            with self.assertRaisesRegex(Failure, "numeric_argument_out_of_range"):
                bounded_number(invalid, 1, 60)
        self.assertEqual(bounded_number("١٢", 1, 60), 12)
