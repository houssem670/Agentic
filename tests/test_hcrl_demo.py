import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts import demo_hcrl_pipeline as demo
from tools.anomaly_detector.ml_detector import WindowPrediction


class _DeterministicHcrlDetector:
    window_seconds = 1.0
    _models = {0x100: object()}
    _calibration_status = "not_independently_calibrated"
    _training_capture_id = "normal_run_data.txt"

    def predict_features(self, samples):
        self.assert_feature_only_input(samples)
        grouped = {}
        for sample in samples:
            grouped.setdefault(sample.window_index, []).append(sample)

        predictions = []
        for window_index, window_samples in sorted(grouped.items()):
            known_ids = tuple(
                sorted(
                    sample.can_id
                    for sample in window_samples
                    if sample.can_id in self._models
                )
            )
            anomalous_ids = known_ids if window_index == 2 else ()
            unseen_ids = tuple(
                sorted(
                    sample.can_id
                    for sample in window_samples
                    if sample.can_id not in self._models
                )
            )
            predictions.append(
                WindowPrediction(
                    window_index=window_index,
                    start=float(window_index),
                    end=float(window_index + 1),
                    is_anomaly=bool(anomalous_ids),
                    anomaly_score=0.42 if anomalous_ids else 0.0,
                    anomalous_can_ids=anomalous_ids,
                    unseen_can_ids=unseen_ids,
                )
            )
        return predictions

    @staticmethod
    def assert_feature_only_input(samples):
        if any(hasattr(sample, "label") for sample in samples):
            raise AssertionError("Labels must not reach detector inference.")

    @staticmethod
    def most_deviant_features(records, can_id):
        return ("frame_count", "byte_0_mean")


class TestHcrlDemo(unittest.TestCase):
    @staticmethod
    def _write_fixture(data_dir):
        data_dir.mkdir(parents=True)
        normal_rows = [
            f"Timestamp: {1000 + second:.1f} ID: 0100 000 DLC: 2 "
            f"{second:02x} {(second + 1):02x}\n"
            for second in range(10)
        ]
        (data_dir / "normal_run_data.txt").write_text(
            "".join(normal_rows),
            encoding="utf-8",
        )
        (data_dir / "gear_dataset.csv").write_text(
            "200.0,0100,2,01,00,R\n"
            "202.3,0100,2,fe,ff,T\n"
            "202.5,0700,2,aa,bb,T\n",
            encoding="utf-8",
        )
        (data_dir / "DoS_dataset.csv").write_text(
            "500.0,000,2,00,00,T\n"
            "501.0,000,2,00,01,T\n",
            encoding="utf-8",
        )

    def test_runs_normal_gear_and_unseen_dos_scenarios_offline(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_dir = root / "hcrl"
            self._write_fixture(data_dir)
            detector = _DeterministicHcrlDetector()

            with patch.object(
                demo,
                "_load_hcrl_ml_detector",
                return_value=detector,
            ):
                result = demo.run_hcrl_demo(
                    data_dir=data_dir,
                    report_path=root / "benchmark" / "report.md",
                    results_path=root / "benchmark" / "results.json",
                )

            self.assertEqual(result.normal_evaluation.known_windows, 4)
            self.assertEqual(
                result.normal_evaluation.metrics.false_positive,
                0,
            )
            self.assertEqual(result.gear_evaluation.known_attack_windows, 1)
            self.assertEqual(result.gear_evaluation.stats.gaps_over_one_second, 1)
            self.assertAlmostEqual(
                result.gear_evaluation.stats.max_gap_seconds,
                2.3,
            )
            self.assertEqual(result.dos_evaluation.known_windows, 0)
            self.assertEqual(result.dos_evaluation.unseen_attack_records, 2)

            event = result.selected_event
            self.assertIsNotNone(event)
            self.assertEqual(event.detection_rule, "ISOLATION_FOREST")
            self.assertEqual(event.metadata["anomalous_can_ids"], [0x100])
            self.assertEqual(event.metadata["unseen_can_ids"], [0x700])
            self.assertEqual(event.metadata["data_provenance"], "HCRL_BENCHMARK")
            self.assertEqual(event.message_count, 2)
            self.assertEqual(
                event.timestamp,
                datetime.fromtimestamp(202.0, timezone.utc),
            )
            self.assertEqual(result.selected_event_truth_ids, (0x100,))

            self.assertEqual(result.dos_novelty_example["status"], "unseen / requires review")
            self.assertEqual(result.dos_novelty_example["unseen_injected_ids"], ["0x000"])
            self.assertFalse(result.dos_novelty_example["sent_to_agents"])
            self.assertIsNotNone(result.workflow)
            self.assertEqual(
                [entry["agent"] for entry in result.workflow["agent_trace"]],
                ["Security Agent", "Diagnostic Agent", "Report Agent"],
            )
            report = result.report_path.read_text(encoding="utf-8")
            self.assertIn("HCRL_BENCHMARK", report)
            self.assertIn("0.420000", report)
            self.assertIn("not_independently_calibrated", report)
            self.assertIn("0x100", report)
            self.assertIn("frame_count", report)
            self.assertIn("unseen / requires review", report)
            self.assertIn("Known-ID events sent to LangGraph: 1", report)
            self.assertTrue(result.results_path.is_file())

    def test_model_loading_failure_does_not_create_outputs(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_dir = root / "hcrl"
            self._write_fixture(data_dir)
            report_path = root / "benchmark" / "report.md"
            results_path = root / "benchmark" / "results.json"

            with patch.object(
                demo,
                "_load_hcrl_ml_detector",
                side_effect=FileNotFoundError("missing HCRL model"),
            ):
                with self.assertRaisesRegex(
                    FileNotFoundError,
                    "missing HCRL model",
                ):
                    demo.run_hcrl_demo(
                        data_dir=data_dir,
                        report_path=report_path,
                        results_path=results_path,
                    )

            self.assertFalse(report_path.exists())
            self.assertFalse(results_path.exists())


if __name__ == "__main__":
    unittest.main()
