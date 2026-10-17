import unittest

from tools.anomaly_detector.benchmark import run_benchmark


class TestSyntheticCanBenchmark(unittest.TestCase):
    def test_scenarios_match_expected_labels_and_report_metrics(self):
        result = run_benchmark()

        self.assertEqual(result["dataset_id"], "autosentinel-can-synthetic-v1")
        self.assertEqual(result["provenance"], "SYNTHETIC_TEST_FIXTURE")
        self.assertTrue(all(case["passed"] for case in result["scenarios"]))
        self.assertEqual(len(result["scenarios"]), 8)
        self.assertEqual(
            result["scenarios"][0]["scenario_id"],
            "FREQ-NORMAL-BELOW",
        )
        self.assertEqual(
            result["confusion_matrix"],
            {
                "true_positive": 4,
                "false_positive": 0,
                "true_negative": 4,
                "false_negative": 0,
            },
        )
        self.assertEqual(
            result["metrics"],
            {
                "precision": 1.0,
                "recall": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
            },
        )
        self.assertEqual(len(result["invalid_inputs"]), 5)
        self.assertTrue(all(case["passed"] for case in result["invalid_inputs"]))


if __name__ == "__main__":
    unittest.main()