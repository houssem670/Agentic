import tempfile
import unittest
from pathlib import Path

from scripts.train_evaluate_hcrl import (
    CaptureStats,
    _iter_attack_records,
    run_pipeline,
)


class TestHcrlTraining(unittest.TestCase):
    def test_attack_parser_maps_labels_and_variable_dlc(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Fuzzy_dataset.csv"
            path.write_text(
                "1478195721.0,0316,2,05,21,R\n"
                "1478195722.0,043f,5,00,40,60,ff,7e,T\n",
                encoding="utf-8",
            )
            stats = CaptureStats()
            records = list(_iter_attack_records(path, "Fuzzy", stats))

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].timestamp, 0.0)
        self.assertEqual(records[0].label, "normal")
        self.assertEqual(records[0].data, bytes((0x05, 0x21)))
        self.assertEqual(records[1].timestamp, 1.0)
        self.assertEqual(records[1].label, "Fuzzy")
        self.assertEqual(records[1].data, bytes((0x00, 0x40, 0x60, 0xFF, 0x7E)))

    def test_training_and_evaluation_stream_and_exclude_unseen_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "datasets" / "hcrl"
            data_dir.mkdir(parents=True)
            normal_rows = [
                f"Timestamp: {1000 + second:.6f} ID: 0100 000 DLC: 2 "
                f"{second:02x} {(second + 1):02x}\n"
                for second in range(6)
            ]
            (data_dir / "normal_run_data.txt").write_text(
                "".join(normal_rows) + "Timestamp: 1006.0     ",
                encoding="utf-8",
            )

            attack_rows = (
                "100.0,0100,2,00,00,R\n"
                "100.5,0100,2,00,01,T\n"
                "101.2,0700,2,02,03,T\n"
                "102.2,0100,2,00,02,R\n"
            )
            for filename in (
                "DoS_dataset.csv",
                "Fuzzy_dataset.csv",
                "gear_dataset.csv",
                "RPM_dataset.csv",
            ):
                (data_dir / filename).write_text(attack_rows, encoding="utf-8")

            model_path = root / "models" / "hcrl_ml_detector.joblib"
            report_path = root / "reports" / "hcrl_ml_evaluation.md"
            run = run_pipeline(
                data_dir=data_dir,
                model_path=model_path,
                report_path=report_path,
                train_fraction=0.5,
            )

            self.assertTrue(model_path.is_file())
            self.assertTrue(report_path.is_file())
            self.assertEqual(run.normal_stats.record_count, 6)
            self.assertEqual(run.normal_stats.skipped_incomplete_final_lines, 1)
            self.assertEqual(run.training_time_windows, 2)
            self.assertEqual(run.training_feature_count, 2)
            self.assertEqual(run.training_windows_by_id, {0x100: 2})

            for evaluation in run.evaluations[1:]:
                self.assertEqual(evaluation.known_windows, 2)
                self.assertEqual(evaluation.known_attack_windows, 1)
                self.assertEqual(evaluation.unseen_id_records, 1)
                self.assertEqual(evaluation.unseen_attack_records, 1)
                self.assertEqual(evaluation.unseen_windows, 1)
                self.assertEqual(evaluation.unseen_only_windows, 1)
                self.assertEqual(
                    evaluation.metrics.true_positive
                    + evaluation.metrics.false_positive
                    + evaluation.metrics.true_negative
                    + evaluation.metrics.false_negative,
                    2,
                )
                self.assertEqual(evaluation.tested_windows, 3)
                self.assertEqual(evaluation.unseen_metrics.true_positive, 1)
                self.assertEqual(evaluation.unseen_metrics.false_positive, 0)
                self.assertEqual(evaluation.unseen_metrics.false_negative, 0)
                self.assertEqual(evaluation.unseen_metrics.true_negative, 2)
                self.assertIn(0x100, evaluation.per_id_evaluations)
                self.assertEqual(
                    evaluation.per_id_evaluations[0x100].windows,
                    2,
                )

            report = report_path.read_text(encoding="utf-8")
            self.assertIn("unseen-ID-only windows are excluded", report)
            self.assertIn("R` is a normal message and `T` is an injected", report)
            self.assertIn("Known-ID metrics by CAN ID", report)
            self.assertIn("False-positive feature diagnostics", report)
            self.assertIn("Unseen-ID novelty status (separate from ML)", report)
            self.assertIn("not_independently_calibrated", report)
            self.assertIn(
                "DoS `T` frames: 1 on trained IDs and 1 on unseen IDs", report
            )


if __name__ == "__main__":
    unittest.main()
