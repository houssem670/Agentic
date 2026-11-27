import unittest
from unittest.mock import patch

import requests

from agents.openrouter_provider import (
    OPENROUTER_CHAT_COMPLETIONS_URL,
    OPENROUTER_TIMEOUT_SECONDS,
    openrouter_chat_completion,
)


class TestOpenRouterProvider(unittest.TestCase):
    @patch("agents.openrouter_provider.requests.post")
    def test_chat_completion_uses_openrouter_endpoint_and_timeout(self, post):
        response = post.return_value
        response.json.return_value = {
            "choices": [{"message": {"content": "  valid response  "}}]
        }

        result = openrouter_chat_completion(
            "test prompt",
            api_key="unit-test-placeholder",
            model="test-model",
        )

        self.assertEqual(result, "valid response")
        args, kwargs = post.call_args
        self.assertEqual(args[0], OPENROUTER_CHAT_COMPLETIONS_URL)
        self.assertEqual(
            OPENROUTER_CHAT_COMPLETIONS_URL,
            "https://openrouter.ai/api/v1/chat/completions",
        )
        self.assertEqual(kwargs["timeout"], OPENROUTER_TIMEOUT_SECONDS)
        self.assertEqual(OPENROUTER_TIMEOUT_SECONDS, 30)
        self.assertEqual(kwargs["json"]["model"], "test-model")
        self.assertEqual(
            kwargs["json"]["messages"],
            [{"role": "user", "content": "test prompt"}],
        )
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Bearer "))

    @patch("agents.openrouter_provider.requests.post")
    def test_missing_configuration_does_not_make_a_request(self, post):
        with self.assertRaisesRegex(ValueError, "OPENROUTER_API_KEY"):
            openrouter_chat_completion(
                "test prompt",
                api_key=None,
                model="test-model",
            )

        post.assert_not_called()

    @patch("agents.openrouter_provider.requests.post")
    def test_missing_completion_content_is_rejected(self, post):
        post.return_value.json.return_value = {"choices": []}

        with self.assertRaisesRegex(ValueError, "no completion choices"):
            openrouter_chat_completion(
                "test prompt",
                api_key="unit-test-placeholder",
                model="test-model",
            )

    @patch("agents.openrouter_provider.requests.post")
    def test_http_429_is_propagated_without_retry(self, post):
        response = post.return_value
        response.status_code = 429
        response.raise_for_status.side_effect = requests.HTTPError(
            "429 Too Many Requests",
            response=response,
        )

        with self.assertRaises(requests.HTTPError) as raised:
            openrouter_chat_completion(
                "test prompt",
                api_key="unit-test-placeholder",
                model="test-model",
            )

        self.assertEqual(raised.exception.response.status_code, 429)
        post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
