from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from models.diagnostic_report import DiagnosticReport
from models.security_assessment import SecurityAssessment
from tools.anomaly_detector.ml_detector import (
    MLAnomalyDetector,
    WindowPrediction,
)
from tools.traffic_simulator.simulator import CanRecord, TrafficSimulator


class TestMainML(unittest.TestCase):
    def setUp(self):
        self.detector = MLAnomalyDetector().fit(
            TrafficSimulator(duration=12.0, seed=7).generate(attacks=())
        )

    def test_ml_window_converts_to_security_event_with_evidence(self):
        records = [
            CanRecord(
                timestamp=5.1 + index * 0.1,
                can_id=0x100,
                dlc=8,
                data=bytes((index, 255, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)),
                label="spoofing",
            )
            for index in range(5)
        ]
        prediction = WindowPrediction(
            window_index=5,
            start=5.0,
            end=6.0,
            is_anomaly=True,
            anomaly_score=0.375,
            anomalous_can_ids=(0x100,),
        )

        event = main.ml_prediction_to_event(
            prediction,
            records,
            self.detector,
            "simulated",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        self.assertEqual(event.detection_rule, "ISOLATION_FOREST")
        self.assertEqual(event.can_id, "0x100")
        self.assertEqual(event.metadata["anomaly_score"], 0.375)
        self.assertTrue(event.anomaly)
        self.assertIsNone(event.attack_type)
        self.assertTrue(any("CAN ID : 0x100" in item for item in event.evidence))
        self.assertTrue(
            any("Caractéristique éloignée de la normale" in item
                for item in event.evidence)
        )

    def test_simulated_ml_mode_runs_with_mocked_agents(self):
        args = main._parse_args(["--source", "simulated", "--detector", "ml"])
        self.assertEqual((args.source, args.detector), ("simulated", "ml"))

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(main, "MODEL_PATH", Path(directory) / "ml_detector.joblib"),
                patch.object(
                    main,
                    "capture_can_messages",
                    side_effect=AssertionError("simulated mode must not open vcan0"),
                ),
                patch(
                    "agents.orchestrator.orchestrator.security_agent",
                    return_value=SecurityAssessment(
                        risk_level="UNKNOWN",
                        summary="Mocked security assessment.",
                    ),
                ) as mock_security,
                patch(
                    "agents.orchestrator.orchestrator.diagnostic_agent",
                    return_value=DiagnosticReport(
                        diagnostic_summary="Mocked diagnosis.",
                        analysis_method="MOCK",
                    ),
                ) as mock_diagnostic,
                patch(
                    "agents.orchestrator.orchestrator.generate_security_report",
                    return_value="# Mocked report",
                ) as mock_report,
                patch.object(
                    main,
                    "save_security_report",
                    return_value="reports/security_report.md",
                ) as mock_save,
                redirect_stdout(StringIO()),
            ):
                main.main(detector=args.detector, source=args.source)

        self.assertGreater(mock_security.call_count, 0)
        self.assertEqual(mock_security.call_count, mock_diagnostic.call_count)
        self.assertEqual(mock_security.call_count, mock_report.call_count)
        mock_save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
