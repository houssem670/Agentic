"""Tests minimaux des features et de l'entraînement ML."""

import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib

from tools.anomaly_detector.ml_detector import (
    FEATURE_NAMES,
    MLAnomalyDetector,
    WindowFeatures,
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

    def test_batched_predictions_match_record_predictions(self):
        training_records = [
            CanRecord(0.0, 0x100, 2, bytes((0, 1)), "normal"),
            CanRecord(1.0, 0x100, 2, bytes((1, 2)), "normal"),
            CanRecord(0.0, 0x200, 2, bytes((2, 3)), "normal"),
            CanRecord(1.0, 0x200, 2, bytes((3, 4)), "normal"),
        ]
        test_records = [
            CanRecord(2.0, 0x100, 2, bytes((4, 5)), "normal"),
            CanRecord(2.1, 0x700, 2, bytes((6, 7)), "fuzzing"),
            CanRecord(3.0, 0x200, 2, bytes((4, 5)), "normal"),
        ]
        detector = MLAnomalyDetector().fit(training_records)

        record_predictions = detector.predict(test_records)
        feature_predictions = detector.predict_features(
            extract_features(test_records)
        )

        self.assertEqual(record_predictions, feature_predictions)
        self.assertNotIn(0x700, record_predictions[0].anomalous_can_ids)
        self.assertIn(0x700, record_predictions[0].unseen_can_ids)

    def test_unseen_only_window_is_novelty_not_an_isolation_forest_anomaly(self):
        training_samples = [
            WindowFeatures(
                index,
                0x100,
                tuple(float(index + value) for value in range(21)),
            )
            for index in range(4)
        ]
        detector = MLAnomalyDetector(n_estimators=20).fit_features(
            training_samples,
            training_capture_id="synthetic-training",
        )

        prediction = detector.predict_features(
            [WindowFeatures(7, 0x700, tuple(float(value) for value in range(21)))]
        )[0]

        self.assertFalse(prediction.is_anomaly)
        self.assertEqual(prediction.anomaly_score, 0.0)
        self.assertEqual(prediction.anomalous_can_ids, ())
        self.assertEqual(prediction.unseen_can_ids, (0x700,))

    def test_zero_variance_feature_deviation_is_described_without_huge_score(self):
        training_records = [
            CanRecord(float(index), 0x100, 1, bytes((index,)), "normal")
            for index in range(4)
        ]
        detector = MLAnomalyDetector(n_estimators=20).fit(training_records)
        test_records = [
            CanRecord(4.0, 0x100, 8, bytes((4, 0, 0, 0, 0, 0, 0, 7)), "normal")
        ]

        descriptions = detector.most_deviant_features(test_records, 0x100)

        self.assertTrue(
            any(
                "byte_7_mean" in item and "variance nulle" in item
                for item in descriptions
            )
        )
        self.assertFalse(any("1e+09" in item for item in descriptions))

    def test_independent_normal_calibration_is_explicit_and_per_id(self):
        training_samples = [
            WindowFeatures(
                index,
                0x100,
                tuple(float(index * (value + 1)) for value in range(21)),
            )
            for index in range(12)
        ]
        validation_samples = [
            WindowFeatures(
                index,
                0x100,
                tuple(float((index + 20) * (value + 1)) for value in range(21)),
            )
            for index in range(10)
        ]
        detector = MLAnomalyDetector(n_estimators=20).fit_features(
            training_samples,
            training_capture_id="synthetic-training",
        )
        self.assertEqual(detector._calibration_status, "not_independently_calibrated")
        self.assertEqual(detector._calibrated_thresholds, {})

        scores = sorted(
            -float(score)
            for score in detector._models[0x100].decision_function(
                [sample.values for sample in validation_samples]
            )
        )
        detector.calibrate_thresholds(
            validation_samples,
            0.2,
            validation_capture_id="synthetic-validation",
        )

        self.assertEqual(
            detector._calibrated_thresholds[0x100],
            scores[8],
        )
        self.assertEqual(
            detector._calibration_status,
            "calibrated_from_independent_normal_data",
        )
        self.assertEqual(detector._calibration_sample_counts, {0x100: 10})
        probe = WindowFeatures(
            100,
            0x100,
            tuple(float(1000 * (value + 1)) for value in range(21)),
        )
        probe_score = -float(
            detector._models[0x100].decision_function([probe.values])[0]
        )
        prediction = detector.predict_features([probe])[0]
        self.assertEqual(
            prediction.is_anomaly,
            probe_score > detector._calibrated_thresholds[0x100],
        )
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "calibrated.joblib"
            joblib.dump(detector, model_path)
            loaded = joblib.load(model_path)

        self.assertEqual(loaded._calibrated_thresholds, detector._calibrated_thresholds)
        self.assertEqual(loaded._calibration_status, detector._calibration_status)

    def test_calibration_rejects_insufficient_samples_and_unseen_ids(self):
        training_samples = [
            WindowFeatures(index, 0x100, tuple(float(index) for _ in FEATURE_NAMES))
            for index in range(5)
        ]
        detector = MLAnomalyDetector(n_estimators=20).fit_features(
            training_samples,
            training_capture_id="training-capture",
        )

        with self.assertRaisesRegex(ValueError, "Au moins 9 fenêtres"):
            detector.calibrate_thresholds(
                training_samples[:5],
                0.1,
                validation_capture_id="validation-capture",
            )
        with self.assertRaisesRegex(ValueError, "absent des modèles entraînés"):
            detector.calibrate_thresholds(
                training_samples
                + [WindowFeatures(6, 0x700, tuple(float(0) for _ in FEATURE_NAMES))],
                0.2,
                validation_capture_id="validation-capture",
            )
        with self.assertRaisesRegex(ValueError, "capture indépendante"):
            detector.calibrate_thresholds(
                training_samples,
                0.2,
                validation_capture_id="training-capture",
            )
        with self.assertRaisesRegex(ValueError, "Fenêtre de calibration dupliquée"):
            detector.calibrate_thresholds(
                [training_samples[0], training_samples[0]],
                0.5,
                validation_capture_id="validation-capture",
            )
        without_capture_id = MLAnomalyDetector(n_estimators=20).fit_features(
            training_samples
        )
        with self.assertRaisesRegex(ValueError, "capture d'entraînement est requis"):
            without_capture_id.calibrate_thresholds(
                training_samples,
                0.2,
                validation_capture_id="validation-capture",
            )


if __name__ == "__main__":
    unittest.main()
