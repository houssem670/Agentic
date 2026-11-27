import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import requests

from agents.orchestrator.orchestrator import run_workflow
from models.diagnostic_report import DiagnosticReport
from models.security_event import SecurityEvent
from agents.security_agent.security_agent import security_agent


class TestSecurityAgent(unittest.TestCase):

    def setUp(self):
        self.event = SecurityEvent(
            event_id="TEST-SEC-001",
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
            evidence=["Six trames identiques"],
            metadata={"test": True},
        )

        self.valid_response = {
            "threat_type": "OTHER_VALUE",
            "risk_level": "MEDIUM",
            "summary": "Suspicion de répétition de trames.",
            "observed_facts": ["Six trames identiques observées"],
            "security_interpretation": "Une investigation est nécessaire.",
            "unknowns": ["L'intention malveillante n'est pas établie"],
            "investigation_steps": ["Comparer au trafic normal"],
            "mitigation_actions": ["Continuer la surveillance"],
            "confidence": 0.7,
        }

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_valid_gemini_response(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        response = MagicMock()
        response.text = json.dumps(self.valid_response)
        gemini.models.generate_content.return_value = response

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.risk_level, "MEDIUM")
        self.assertEqual(result.confidence, 0.7)
        self.assertEqual(result.provider, "Gemini")
        openrouter.assert_not_called()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_gemini_failure_uses_openrouter(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        gemini.models.generate_content.side_effect = RuntimeError("Test failure")
        openrouter.return_value = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.provider, "OpenRouter")
        openrouter.assert_called_once()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_gemini_timeout_uses_openrouter(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        gemini.models.generate_content.side_effect = TimeoutError("Gemini timed out")
        openrouter.return_value = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.provider, "OpenRouter")
        gemini.models.generate_content.assert_called_once()
        openrouter.assert_called_once()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_gemini_quota_error_uses_openrouter(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        gemini.models.generate_content.side_effect = RuntimeError(
            "429 RESOURCE_EXHAUSTED"
        )
        openrouter.return_value = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.provider, "OpenRouter")
        openrouter.assert_called_once()

    def test_provider_timeouts_use_orchestrator_safe_assessment(self):
        with (
            patch(
                "agents.security_agent.security_agent.build_rag_context",
                return_value={"results": [], "context": "Test RAG"},
            ),
            patch("agents.security_agent.security_agent.gemini_client") as gemini,
            patch(
                "agents.security_agent.security_agent.openrouter_chat_completion"
            ) as openrouter,
            patch(
                "agents.orchestrator.orchestrator.diagnostic_agent",
                return_value=DiagnosticReport(
                    event_id=self.event.event_id,
                    diagnostic_summary="Mock diagnostic result.",
                ),
            ),
        ):
            gemini.models.generate_content.side_effect = TimeoutError(
                "Gemini timed out"
            )
            openrouter.side_effect = TimeoutError("OpenRouter timed out")

            workflow = run_workflow(self.event, persist_report=False)

        gemini.models.generate_content.assert_called_once()
        openrouter.assert_called_once()
        self.assertEqual(workflow["assessment"].risk_level, "UNKNOWN")
        self.assertEqual(workflow["assessment"].provider, "Safe fallback")
        self.assertEqual(workflow["security_provider"], "Safe fallback")
        self.assertIn("assessment unavailable", workflow["assessment"].summary)
        self.assertIn("Security Agent failed: RuntimeError", workflow["errors"])
        self.assertEqual(workflow["agent_trace"][0]["status"], "fallback")
        self.assertIn("| Provider | Safe fallback |", workflow["report"])

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_invalid_gemini_json_uses_openrouter(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}

        response = MagicMock()
        response.text = "{invalid json"
        gemini.models.generate_content.return_value = response
        openrouter.return_value = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.risk_level, "MEDIUM")
        self.assertEqual(result.provider, "OpenRouter")
        openrouter.assert_called_once()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_openrouter_invalid_json_is_rejected(self, gemini, openrouter, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        gemini.models.generate_content.side_effect = TimeoutError()
        openrouter.return_value = "{invalid json"

        with self.assertRaisesRegex(RuntimeError, "Gemini and OpenRouter failed"):
            security_agent(self.event)

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.openrouter_chat_completion")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_isolation_forest_prompt_preserves_hcrl_context(
        self,
        gemini,
        openrouter,
        rag,
    ):
        rag.return_value = {"results": [], "context": "Test RAG"}
        response = MagicMock()
        response.text = json.dumps(self.valid_response)
        gemini.models.generate_content.return_value = response
        event = replace(
            self.event,
            detection_rule="ISOLATION_FOREST",
            attack_type=None,
            evidence=[
                "Isolation Forest anomaly score is relative, not a probability.",
                "Feature deviation: byte_0_mean=250.0",
            ],
            metadata={
                "anomaly_score": 0.42,
                "model_provenance": "HCRL Car-Hacking Dataset",
                "calibration_status": "not_independently_calibrated",
                "unseen_can_ids": [0x700],
            },
        )

        security_agent(event)

        prompt = gemini.models.generate_content.call_args.kwargs["contents"]
        self.assertIn("Isolation Forest anomaly score: 0.42", prompt)
        self.assertIn("HCRL Car-Hacking Dataset", prompt)
        self.assertIn("not_independently_calibrated", prompt)
        self.assertIn("Feature deviation: byte_0_mean=250.0", prompt)
        self.assertIn("not a probability that an attack occurred", prompt)
        self.assertIn("does not prove an attack or malicious intent", prompt)
        openrouter.assert_not_called()

    def test_missing_openrouter_key_uses_safe_fallback_without_request(self):
        with (
            patch(
                "agents.security_agent.security_agent.build_rag_context",
                return_value={"results": [], "context": "Test RAG"},
            ),
            patch("agents.security_agent.security_agent.gemini_client") as gemini,
            patch(
                "agents.security_agent.security_agent.OPENROUTER_API_KEY",
                None,
            ),
            patch("agents.openrouter_provider.requests.post") as post,
            patch(
                "agents.orchestrator.orchestrator.diagnostic_agent",
                return_value=DiagnosticReport(
                    event_id=self.event.event_id,
                    diagnostic_summary="Mock diagnostic result.",
                ),
            ),
        ):
            gemini.models.generate_content.side_effect = TimeoutError()

            workflow = run_workflow(self.event, persist_report=False)

        post.assert_not_called()
        self.assertEqual(workflow["assessment"].provider, "Safe fallback")
        self.assertEqual(workflow["security_provider"], "Safe fallback")

    def test_openrouter_429_keeps_langgraph_pipeline_running(self):
        with (
            patch(
                "agents.security_agent.security_agent.build_rag_context",
                return_value={"results": [], "context": "Test RAG"},
            ),
            patch(
                "agents.diagnostic_agent.diagnostic_agent.build_rag_context",
                return_value={"results": [], "context": "Test RAG"},
            ),
            patch("agents.security_agent.security_agent.gemini_client") as security_gemini,
            patch(
                "agents.diagnostic_agent.diagnostic_agent.gemini_client"
            ) as diagnostic_gemini,
            patch("agents.openrouter_provider.requests.post") as post,
        ):
            security_gemini.models.generate_content.side_effect = TimeoutError()
            diagnostic_gemini.models.generate_content.side_effect = TimeoutError()
            response = MagicMock()
            response.status_code = 429
            response.raise_for_status.side_effect = requests.HTTPError(
                "429 Too Many Requests",
                response=response,
            )
            post.return_value = response

            workflow = run_workflow(self.event, persist_report=False)

        self.assertEqual(post.call_count, 2)
        self.assertEqual(workflow["security_provider"], "Safe fallback")
        self.assertEqual(workflow["assessment"].provider, "Safe fallback")
        self.assertEqual(workflow["diagnostic"].analysis_method, "FALLBACK")
        self.assertEqual(
            workflow["diagnostic"].provider_errors,
            ["Gemini: TimeoutError", "OpenRouter: HTTPError"],
        )
        self.assertIn("| Provider | Safe fallback |", workflow["report"])
        self.assertIn("| Analysis method | FALLBACK |", workflow["report"])
        self.assertEqual(
            [entry["agent"] for entry in workflow["agent_trace"]],
            ["Security Agent", "Diagnostic Agent", "Report Agent"],
        )
        self.assertEqual(
            [entry["status"] for entry in workflow["agent_trace"]],
            ["fallback", "fallback", "completed"],
        )


if __name__ == "__main__":
    unittest.main()
