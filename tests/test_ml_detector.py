"""Tests minimaux des features et de l'entraînement ML."""

import math
import unittest
from unittest.mock import patch

from tools.anomaly_detector.ml_detector import (
    FEATURE_NAMES,
    MLAnomalyDetector,
    extract_features,
)
from tools.traffic_simulator.simulator import CanRecord


class TestMLAnomalyDetector(unittest.TestCase):
    def test_features_match_a_known_window(self):
        records = [
            CanRecord(0.0, 0x123, 2, bytes((0, 10)), "normal"),
            CanRecord(0.5, 0x123, 2, bytes((2, 12)), "normal"),
            CanRecord(1.5, 0x123, 2, bytes((4, 14)), "normal"),
        ]

        sample = extract_features(records, window_seconds=2.0)[0]
        values = dict(zip(FEATURE_NAMES, sample.values))

        self.assertEqual(values["frame_count"], 3.0)
        self.assertAlmostEqual(values["interval_mean"], 0.75)
        self.assertAlmostEqual(values["interval_std"], 0.25)
        self.assertEqual(values["distinct_payloads"], 3.0)
        self.assertAlmostEqual(values["payload_entropy"], math.log2(6))
        self.assertAlmostEqual(values["byte_0_mean"], 2.0)
        self.assertAlmostEqual(values["byte_0_std"], math.sqrt(8 / 3))
        self.assertAlmostEqual(values["byte_1_mean"], 12.0)
        self.assertAlmostEqual(values["byte_1_std"], math.sqrt(8 / 3))
        self.assertEqual(values["byte_2_mean"], 0.0)

    def test_fit_uses_only_normal_records(self):
        records = [
            CanRecord(0.0, 0x100, 8, b"\x00" * 8, "normal"),
            CanRecord(1.0, 0x100, 8, b"\x01" * 8, "normal"),
            CanRecord(2.0, 0x100, 8, b"\xff" * 8, "flooding"),
            CanRecord(0.0, 0x000, 8, b"\xff" * 8, "flooding"),
        ]
        fitted_rows: list[list[tuple[float, ...]]] = []

        class RecordingForest:
            def __init__(self, **kwargs: object) -> None:
                self.options = kwargs

            def fit(
                self, samples: list[tuple[float, ...]]
            ) -> object:
                fitted_rows.append(samples)
                return self

        with patch(
            "tools.anomaly_detector.ml_detector.IsolationForest",
            RecordingForest,
        ):
            detector = MLAnomalyDetector().fit(records)

        self.assertEqual(len(fitted_rows), 1)
        self.assertEqual(len(fitted_rows[0]), 2)
        self.assertEqual(set(detector._models), {0x100})


if __name__ == "__main__":
    unittest.main()
