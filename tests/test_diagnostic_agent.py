import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from agents.diagnostic_agent.diagnostic_agent import diagnostic_agent
from models.security_event import SecurityEvent


class TestDiagnosticAgent(unittest.TestCase):
    def setUp(self):
        self.event = SecurityEvent(
            event_id="TEST-DIAG-001",
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
            evidence=["Six identical frames observed"],
            metadata={},
        )
        self.valid_response = {
            "diagnostic_summary": "Further investigation is required.",
            "probable_causes": ["Periodic traffic remains possible."],
            "supporting_evidence": ["Six identical frames observed"],
            "unknowns": ["The transmitting ECU is unknown."],
            "recommended_checks": ["Compare a trusted baseline."],
            "confidence": 0.6,
        }

    def _rag_patch(self):
        patcher = patch(
            "agents.diagnostic_agent.diagnostic_agent.build_rag_context",
            return_value={"results": [], "context": "No test retrieval."},
        )
        self.addCleanup(patcher.stop)
        patcher.start()

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_valid_gemini_output_is_structured(self, gemini, ollama):
        self._rag_patch()
        gemini.models.generate_content.return_value.text = json.dumps(
            self.valid_response
        )

        result = diagnostic_agent(self.event)

        self.assertEqual(result.event_id, self.event.event_id)
        self.assertEqual(result.analysis_method, "Gemini")
        self.assertEqual(result.confidence, 0.6)
        self.assertFalse(result.root_cause_confirmed)
        ollama.invoke.assert_not_called()

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_invalid_gemini_json_falls_back_to_ollama(self, gemini, ollama):
        self._rag_patch()
        gemini.models.generate_content.return_value.text = "{invalid"
        ollama.invoke.return_value.content = json.dumps(self.valid_response)

        result = diagnostic_agent(self.event)

        self.assertEqual(result.analysis_method, "Ollama")
        self.assertEqual(result.provider_errors, ["Gemini: ValueError"])
        ollama.invoke.assert_called_once()

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_missing_optional_fields_default_without_inventing_causes(
        self, gemini, ollama
    ):
        self._rag_patch()
        gemini.models.generate_content.return_value.text = json.dumps(
            {"diagnostic_summary": "Insufficient data for diagnosis."}
        )

        result = diagnostic_agent(self.event)

        self.assertEqual(result.probable_causes, [])
        self.assertEqual(result.supporting_evidence, [])
        self.assertEqual(result.confidence, 0.0)
        self.assertFalse(result.root_cause_confirmed)
        ollama.invoke.assert_not_called()

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_missing_summary_tries_ollama(self, gemini, ollama):
        self._rag_patch()
        gemini.models.generate_content.return_value.text = json.dumps(
            {"probable_causes": ["Unverified claim"]}
        )
        ollama.invoke.return_value.content = json.dumps(self.valid_response)

        result = diagnostic_agent(self.event)

        self.assertEqual(result.analysis_method, "Ollama")
        self.assertEqual(result.probable_causes, self.valid_response["probable_causes"])

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_invalid_confidence_uses_safe_fallback(self, gemini, ollama):
        self._rag_patch()
        invalid = {**self.valid_response, "confidence": float("nan")}
        gemini.models.generate_content.return_value.text = json.dumps(invalid)
        ollama.invoke.return_value.content = "not json"

        result = diagnostic_agent(self.event)

        self.assertEqual(result.analysis_method, "FALLBACK")
        self.assertEqual(result.probable_causes, [])
        self.assertEqual(result.supporting_evidence, self.event.evidence)
        self.assertEqual(result.confidence, 0.0)
        self.assertFalse(result.root_cause_confirmed)
        self.assertIn("No validated LLM diagnostic result is available.", result.unknowns)

    @patch("agents.diagnostic_agent.diagnostic_agent.ollama_llm")
    @patch("agents.diagnostic_agent.diagnostic_agent.gemini_client")
    def test_provider_failures_return_safe_fallback(self, gemini, ollama):
        self._rag_patch()
        gemini.models.generate_content.side_effect = TimeoutError()
        ollama.invoke.side_effect = TimeoutError()

        result = diagnostic_agent(self.event)

        self.assertEqual(result.analysis_method, "FALLBACK")
        self.assertEqual(result.probable_causes, [])
        self.assertFalse(result.root_cause_confirmed)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(
            result.provider_errors,
            ["Gemini: TimeoutError", "Ollama: TimeoutError"],
        )


if __name__ == "__main__":
    unittest.main()