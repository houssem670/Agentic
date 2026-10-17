import tempfile
import unittest
from pathlib import Path

from backend.app.dashboard import create_app, parse_report


SAMPLE_REPORT = """# Automotive CAN Security Report

## 1. Report Information
| Field | Value |
|---|---|
| Generated at | 2026-10-11 12:42:04 UTC |
| Event ID | TEST-CAN-001 |
| Event timestamp | 2026-10-11T12:42:04.738683+00:00 |
| CAN interface | vcan0 |
| CAN ID | 0x123 |
| Detection rule | CONSECUTIVE_FRAME_REPETITION |

## 2. Executive Summary
Repeated frames require investigation.

## 3. Detection Evidence
| Metric | Value |
|---|---|
| Event type | CAN_ANOMALY |
| Detector attack label | REPLAY_SUSPECTED |
| Anomaly flagged | True |
| Message count | 6 |
| Observation duration | 0.050000 seconds |
| Observed rate | 120.00 messages/second |
| Detector threshold | 5.0 |

### Evidence recorded by the detector
- Six repeated frames

## 4. Security Assessment
| Field | Value |
|---|---|
| Threat classification | REPLAY_SUSPECTED |
| Assessed risk level | MEDIUM |
| Assessment confidence | Not available |

### Observed facts
- Six frames observed

### Unknowns and limitations
- Malicious intent is unconfirmed

## 5. Diagnostic Analysis
| Field | Value |
|---|---|
| Diagnostic event ID | TEST-CAN-001 |
| Diagnostic confidence | 50% |
| Analysis method | MOCK_TEST |
| Root cause confirmed | False |

### Diagnostic summary
Compare with normal traffic.

### Diagnostic unknowns
- Root cause not confirmed

### Recommended diagnostic checks
- Compare a trusted baseline
"""


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_path = Path(self.temp_dir.name) / "security_report.md"
        self.app = create_app(self.report_path)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dashboard_page_exposes_existing_sections_and_event_pagination(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Agent", response.data)
        self.assertIn(b"Diagnostic Agent", response.data)
        self.assertIn(b"Report Agent", response.data)
        self.assertIn(b"events-pagination", response.data)
        self.assertIn(b"href=\"#traffic\"", response.data)
        self.assertIn(b"href=\"#threats\"", response.data)
        self.assertIn(b"href=\"#workflow\"", response.data)
        self.assertIn(b"href=\"#diagnostics\"", response.data)
        self.assertIn(b"Report history", response.data)
        self.assertIn(b"Not persisted", response.data)
        self.assertIn(b"data-provenance", response.data)
        self.assertIn(b"AutoSentinel", response.data)
        self.assertIn(b"Frames analyzed", response.data)
        self.assertIn(b"No alert lifecycle is implemented", response.data)
        self.assertNotIn(b"stat-latest", response.data)
        self.assertNotIn(b'id="settings"', response.data)
        self.assertNotIn(b"Agentic AI-powered", response.data)
        self.assertNotIn(b"brand-mark svg", response.data)

    def test_parse_report_extracts_only_recorded_values(self):
        records, errors = parse_report(SAMPLE_REPORT)
        self.assertEqual(errors, [])
        self.assertEqual(len(records), 1)
        event = records[0]
        self.assertEqual(event["event_id"], "TEST-CAN-001")
        self.assertEqual(event["data_provenance"], "SYNTHETIC_TEST_FIXTURE")
        self.assertEqual(event["message_count"], 6)
        self.assertEqual(event["security"]["risk_level"], "MEDIUM")
        self.assertIsNone(event["security"]["confidence"])
        self.assertFalse(event["diagnostic"]["root_cause_confirmed"])

    def test_api_exposes_report_scenario_id_and_recorded_agent_trace(self):
        report = SAMPLE_REPORT.replace(
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |",
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |\n"
            "| Scenario ID | REPLAY-SYNTH-001 |",
        ) + """

## 7. Agent Execution Trace
| Agent | Status | Duration (ms) | Error type |
|---|---|---:|---|
| Security Agent | completed | 12.500 | Not recorded |
| Diagnostic Agent | fallback | 35.250 | TimeoutError |
| Report Agent | completed | 1.000 | Not recorded |
"""
        self.report_path.write_text(report, encoding="utf-8")

        event = self.client.get("/api/events").get_json()["events"][0]

        self.assertEqual(event["scenario_id"], "REPLAY-SYNTH-001")
        self.assertEqual(
            event["workflow_provenance"],
            "LangGraph workflow (recorded execution trace)",
        )
        self.assertEqual(
            event["agent_trace"][1],
            {
                "agent": "Diagnostic Agent",
                "status": "fallback",
                "duration_ms": 35.25,
                "error_type": "TimeoutError",
            },
        )

    def test_api_reports_actual_summary_and_report_preview(self):
        self.report_path.write_text(SAMPLE_REPORT, encoding="utf-8")
        summary = self.client.get("/api/summary").get_json()
        self.assertEqual(summary["total_security_events"], 1)
        self.assertEqual(summary["replay_suspicions"], 1)
        self.assertEqual(summary["frequency_anomalies"], 0)
        self.assertEqual(summary["risk_levels"], {"MEDIUM": 1})
        report = self.client.get("/api/reports/latest").get_json()
        self.assertTrue(report["available"])
        self.assertIn("Automotive CAN Security Report", report["html"])
        self.assertEqual(report["freshness"]["state"], "stale")
        self.assertEqual(report["data_provenance"], "SYNTHETIC_TEST_FIXTURE")
        self.assertEqual(
            self.client.get("/api/health").get_json()["data_provenance"],
            "SYNTHETIC_TEST_FIXTURE",
        )
        self.assertFalse(summary["history_available"])

    def test_explicit_live_and_unknown_provenance_are_distinguished(self):
        live_report = SAMPLE_REPORT.replace(
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |",
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |\n"
            "| Data provenance | LIVE_CAPTURE |",
        ).replace("TEST-CAN-001", "EVENT-LIVE-001").replace("MOCK_TEST", "Gemini")
        live_report = live_report.replace(
            "Test synthétique de suspicion de replay.",
            "Replay suspicion requires investigation.",
        )
        self.report_path.write_text(live_report, encoding="utf-8")
        live_payload = self.client.get("/api/reports/latest").get_json()
        self.assertEqual(live_payload["data_provenance"], "LIVE_CAPTURE")

        contradictory_report = SAMPLE_REPORT.replace(
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |",
            "| Detection rule | CONSECUTIVE_FRAME_REPETITION |\n"
            "| Data provenance | LIVE_CAPTURE |",
        )
        self.report_path.write_text(contradictory_report, encoding="utf-8")
        contradictory_payload = self.client.get("/api/reports/latest").get_json()
        self.assertEqual(
            contradictory_payload["data_provenance"],
            "SYNTHETIC_TEST_FIXTURE",
        )

        unknown_report = (
            SAMPLE_REPORT.replace("TEST-CAN-001", "EVENT-001")
            .replace("MOCK_TEST", "LLM")
            .replace(
                "Test synthétique de suspicion de replay.",
                "Replay suspicion.",
            )
        )
        self.report_path.write_text(unknown_report, encoding="utf-8")
        unknown_payload = self.client.get("/api/reports/latest").get_json()
        self.assertEqual(unknown_payload["data_provenance"], "UNSPECIFIED")

    def test_recorded_orchestrator_errors_are_exposed(self):
        report = SAMPLE_REPORT + "\n## Orchestrator Errors and Limitations\n- Diagnostic Agent failed: RuntimeError\n"
        records, errors = parse_report(report)
        self.assertEqual(errors, [])
        self.assertEqual(records[0]["execution_errors"], ["Diagnostic Agent failed: RuntimeError"])
        self.assertEqual(records[0]["workflow_provenance"], "LangGraph orchestrator (recorded error section)")

    def test_missing_report_is_empty_and_download_is_not_found(self):
        report = self.client.get("/api/reports/latest").get_json()
        self.assertFalse(report["available"])
        self.assertEqual(report["freshness"]["state"], "unknown")
        self.assertEqual(report["data_provenance"], "UNSPECIFIED")
        self.assertEqual(self.client.get("/api/events").get_json(), {"events": []})
        self.assertEqual(self.client.get("/api/reports/latest/download").status_code, 404)

    def test_malformed_report_blocks_are_omitted(self):
        self.report_path.write_text(
            "# Automotive CAN Security Report\n\n## 1. Report Information\nNo event table.",
            encoding="utf-8",
        )
        health = self.client.get("/api/health").get_json()
        self.assertEqual(health["invalid_report_blocks"], 1)
        self.assertEqual(self.client.get("/api/summary").get_json()["total_security_events"], 0)

    def test_unparseable_timestamps_do_not_break_report_endpoints(self):
        report = SAMPLE_REPORT.replace("2026-10-11 12:42:04 UTC", "Unknown")
        report = report.replace("2026-10-11T12:42:04.738683+00:00", "Unknown")
        self.report_path.write_text(report, encoding="utf-8")
        summary = self.client.get("/api/summary").get_json()
        latest = self.client.get("/api/reports/latest").get_json()
        self.assertIsNone(summary["latest_analysis_timestamp"])
        self.assertIsNone(summary["latest_report_timestamp"])
        self.assertIsNone(latest["generated_at"])

    def test_report_html_escapes_raw_html(self):
        self.report_path.write_text(SAMPLE_REPORT + "\n<script>alert(1)</script>\n", encoding="utf-8")
        html = self.client.get("/api/reports/latest").get_json()["html"]
        self.assertNotIn("<script>", html)


if __name__ == "__main__":
    unittest.main()