"""Tests for the optional local Ollama explanation service."""

import pytest

from app.core.config import settings
from app.core.errors import ExplanationServiceError
from app.services.explanations import generate_local_ai_explanation


class _FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"response": "This service was observed open. Restrict access if unnecessary."}


class _FakeAsyncClient:
    requested_url = None
    requested_payload = None

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def post(self, url, json):
        self.requested_url = url
        self.requested_payload = json
        return _FakeResponse()


@pytest.mark.asyncio
async def test_generate_local_ai_explanation_uses_configured_ollama(monkeypatch):
    monkeypatch.setattr(settings, "ollama_base_url", "http://127.0.0.1:11434/")
    monkeypatch.setattr(settings, "ollama_model", "unit-test-model")
    monkeypatch.setattr("app.services.explanations.httpx.AsyncClient", _FakeAsyncClient)

    explanation, model = await generate_local_ai_explanation(
        {
            "title": "Redis exposed on TCP/6379",
            "severity": "high",
            "description": "Redis is listening.",
            "evidence": "TCP/6379 accepted a connection",
            "recommendation": "Restrict access.",
            "asset_ip": "127.0.0.1",
            "asset_risk_score": 40,
        }
    )

    assert "observed open" in explanation
    assert model == "unit-test-model"


@pytest.mark.asyncio
async def test_generate_local_ai_explanation_rejects_nonlocal_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "ollama_base_url", "http://model-server.example:11434")

    with pytest.raises(ExplanationServiceError, match="bound to this device"):
        await generate_local_ai_explanation(
            {
                "title": "Finding",
                "severity": "low",
                "description": "Description",
                "recommendation": "Recommendation",
            }
        )
