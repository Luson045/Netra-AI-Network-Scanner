"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
import os

import pytest


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def _test_env(monkeypatch):
    """Force safe test settings; never touch real databases."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./data/test.db")
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("ALLOW_LOCALHOST", "true")
    # isolate settings cache per test
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
