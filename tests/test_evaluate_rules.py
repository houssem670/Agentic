"""Tests minimaux du découpage et des métriques d'évaluation."""

import unittest

from scripts.evaluate_rules import (
    calculate_metrics,
    generate_evaluation_windows,
    split_windows,
)
from tools.traffic_simulator.simulator import CanRecord


class TestRulesEvaluation(unittest.TestCase):
    def test_split_windows_sets_attack_truth_and_majority_type(self):
        records = [
            CanRecord(0.1, 0x100, 8, b"\x00" * 8, "normal"),
            CanRecord(0.2, 0x300, 8, b"\x01" * 8, "spoofing"),
            CanRecord(0.3, 0x300, 8, b"\x02" * 8, "spoofing"),
            CanRecord(1.0, 0x100, 8, b"\x03" * 8, "normal"),
        ]

        windows = split_windows(records, duration=2.0)

        self.assertEqual(len(windows), 2)
        self.assertTrue(windows[0].is_attack)
        self.assertEqual(windows[0].attack_type, "spoofing")
        self.assertFalse(windows[1].is_attack)
        self.assertIsNone(windows[1].attack_type)

    def test_metrics_match_known_confusion_counts(self):
        metrics = calculate_metrics(
            truth=[True, True, False, False],
            predictions=[True, False, True, False],
        )

        self.assertEqual(
            (
                metrics.true_positive,
                metrics.false_positive,
                metrics.true_negative,
                metrics.false_negative,
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(metrics.precision, 0.5)
        self.assertEqual(metrics.recall, 0.5)
        self.assertEqual(metrics.f1, 0.5)
        self.assertEqual(metrics.false_positive_rate, 0.5)

    def test_false_positive_rate_is_undefined_without_normal_windows(self):
        metrics = calculate_metrics(truth=[True], predictions=[True])

        self.assertIsNone(metrics.false_positive_rate)

    def test_evaluation_scenario_contains_normal_windows(self):
        windows = generate_evaluation_windows()

        self.assertGreater(sum(not window.is_attack for window in windows), 0)


if __name__ == "__main__":
    unittest.main()
