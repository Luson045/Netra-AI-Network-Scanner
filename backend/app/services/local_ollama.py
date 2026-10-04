"""Shared, loopback-only Ollama client for local model tasks."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from app.core.config import settings
from app.core.errors import ExplanationServiceError
from app.core.logging import get_logger

logger = get_logger("app.local_ollama")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


async def generate_local_text(
    prompt: str, *, max_tokens: int = 256, json_mode: bool = False
) -> tuple[str, str]:
    base_url = settings.ollama_base_url.rstrip("/")
    parsed_url = urlsplit(base_url)
    if (
        parsed_url.scheme != "http"
        or parsed_url.hostname not in _LOCAL_HOSTS
        or parsed_url.username
        or parsed_url.password
    ):
        raise ExplanationServiceError(
            "Ollama must use an HTTP endpoint bound to this device (localhost)."
        )

    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": max_tokens},
    }
    if json_mode:
        payload["format"] = "json"
    try:
        async with httpx.AsyncClient(timeout=settings.ollama_timeout_secs) as client:
            response = await client.post(f"{base_url}/api/generate", json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Local Ollama request failed: %s", exc)
        raise ExplanationServiceError(
            "Could not reach local Ollama. Start Ollama and confirm the configured model is available."
        ) from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise ExplanationServiceError("Local Ollama returned an invalid response.") from exc
    text = body.get("response") if isinstance(body, dict) else None
    if not isinstance(text, str) or not text.strip():
        raise ExplanationServiceError(
            "Local Ollama returned no response. Confirm the configured model is available."
        )
    return text.strip(), settings.ollama_model
