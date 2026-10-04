"""Tests for safe TCP checks against a real local listener."""

import asyncio
import socket

import pytest

from app.services.scanner.checks import check_host, check_port


@pytest.fixture()
async def local_server():
    """Start a tiny TCP server on an ephemeral localhost port."""
    async def close_connection(reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(close_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


async def test_open_port(local_server):
    result = await check_port("127.0.0.1", local_server)
    assert result.state == "open"
    assert result.latency_ms is not None


async def test_closed_port():
    # Bind then close: nothing listens on that port anymore
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = await check_port("127.0.0.1", port)
    assert result.state == "closed"


async def test_check_host_mixed(local_server):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    results = await check_host("127.0.0.1", [local_server, closed_port])
    by_port = {r.port: r.state for r in results}
    assert by_port[local_server] == "open"
    assert by_port[closed_port] == "closed"
