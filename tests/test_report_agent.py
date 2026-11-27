import unittest
from dataclasses import replace
from datetime import datetime, timezone

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)


class TestReportAgent(unittest.TestCase):

    def setUp(self):
        self.event = SecurityEvent(
            event_id="TEST-001",
            timestamp=datetime.now(timezone.utc),
            event_type="CAN_ANOMALY",
            can_id="0x123",
            channel="vcan0",
            message_count=6,
            window_seconds=0.05,
            observed_rate=120.0,
            detection_rule="CONSECUTIVE_FRAME_REPETITION",
            threshold=5.0,
            anomaly=True,
            attack_type="REPLAY_SUSPECTED",
            evidence=["Six identical consecutive frames"],
        )

        self.assessment = SecurityAssessment(
            threat_type="Replay suspicion",
            risk_level="MEDIUM",
            summary="Repeated CAN frames detected.",
            confidence=0.8,
        )

        self.diagnostic = DiagnosticReport(
            event_id="TEST-001",
            diagnostic_summary="Further investigation is required.",
            confidence=0.7,
            root_cause_confirmed=False,
        )

    def test_report_contains_key_information(self):
        self.event.metadata["scenario_id"] = "REPLAY-SYNTH-001"
        report = generate_security_report(
            self.event, self.assessment, self.diagnostic
        )

        self.assertIn("Automotive CAN Security Report", report)
        self.assertIn("TEST-001", report)
        self.assertIn("0x123", report)
        self.assertIn("REPLAY_SUSPECTED", report)
        self.assertIn("MEDIUM", report)
        self.assertIn("| Scenario ID | REPLAY-SYNTH-001 |", report)

    def test_hcrl_ml_report_contains_score_provenance_ids_and_features(self):
        event = replace(
            self.event,
            can_id="0x2B0",
            detection_rule="ISOLATION_FOREST",
            attack_type=None,
            evidence=[
                "Isolation Forest score (relative, not probabilistic): 0.123456",
                "Model provenance: HCRL Car-Hacking Dataset",
                "Calibration status: not_independently_calibrated",
                "Known anomalous CAN ID: 0x2B0",
                "Unseen CAN ID: 0x700 (unseen / requires review)",
                "Feature deviation: byte_0_mean=250.000",
            ],
            metadata={
                "anomaly_score": 0.123456,
                "model_provenance": "HCRL Car-Hacking Dataset",
                "calibration_status": "not_independently_calibrated",
                "anomalous_can_ids": [0x2B0],
                "unseen_can_ids": [0x700],
                "data_provenance": "HCRL_BENCHMARK",
            },
        )
        diagnostic = replace(self.diagnostic, analysis_method="MOCK")

        report = generate_security_report(
            event,
            self.assessment,
            diagnostic,
            security_provider="OpenRouter",
        )

        self.assertIn("| Data provenance | HCRL_BENCHMARK |", report)
        self.assertIn("| Provider | OpenRouter |", report)
        self.assertIn("0.123456", report)
        self.assertIn("HCRL Car-Hacking Dataset", report)
        self.assertIn("not_independently_calibrated", report)
        self.assertIn("0x2B0", report)
        self.assertIn("0x700", report)
        self.assertIn("byte_0_mean=250.000", report)
        self.assertIn("unseen / requires review", report)

    def test_report_handles_missing_information(self):
        assessment = SecurityAssessment()
        diagnostic = DiagnosticReport()

        report = generate_security_report(
            self.event,
            assessment,
            diagnostic,
            security_provider="unverified provider",
        )

        self.assertIn("No security summary provided.", report)
        self.assertIn("| Provider | Unknown |", report)
        self.assertIn("Not available", report)

    def test_save_report_creates_file(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        report = generate_security_report(
            self.event, self.assessment, self.diagnostic
        )

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "security_report.md"
            saved_path = save_security_report(report, path)

            self.assertTrue(path.exists())
            self.assertEqual(Path(saved_path).read_text(encoding="utf-8"), report)

    def test_empty_report_is_rejected(self):
        with self.assertRaises(ValueError):
            save_security_report("   ", "reports/empty_test.md")


if __name__ == "__main__":
    unittest.main()
