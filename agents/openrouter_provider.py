"""Minimal client for the OpenRouter OpenAI-compatible chat completions API."""

from __future__ import annotations

import requests


OPENROUTER_CHAT_COMPLETIONS_URL = (
    "https://openrouter.ai/api/v1/chat/completions"
)
OPENROUTER_TIMEOUT_SECONDS = 30


def openrouter_chat_completion(
    prompt: str,
    api_key: str | None,
    model: str | None,
) -> str:
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("OPENROUTER_API_KEY is not configured.")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("OPENROUTER_MODEL is not configured.")

    response = requests.post(
        OPENROUTER_CHAT_COMPLETIONS_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        },
        timeout=OPENROUTER_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("OpenRouter response must be a JSON object.")

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("OpenRouter response contains no completion choices.")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise ValueError("OpenRouter response contains no message content.")
    return content.strip()
