import asyncio
import queue

import pytest
from starlette.websockets import WebSocketDisconnect

from tests.conftest import AUTH


class Writer:
    def __init__(self):
        self.data = queue.Queue()
        self.closed = False

    def write(self, data):
        self.data.put(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def test_bidirectional_bytes_and_slot_cleanup(client_factory, monkeypatch):
    client = client_factory()
    writer = Writer()

    async def connect(host, port):
        assert host == "gateway.discord.gg" and port == 443
        reader = asyncio.StreamReader()
        reader.feed_data(b"TLS ciphertext from upstream")
        return reader, writer

    monkeypatch.setattr(client.app.state.policy, "open_tcp", connect)
    with client.websocket_connect(
        "wss://testserver/tunnel?host=gateway.discord.gg", headers=AUTH
    ) as ws:
        assert ws.receive_bytes() == b"TLS ciphertext from upstream"
        ws.send_bytes(b"TLS ciphertext from bot")
        assert writer.data.get(timeout=2) == b"TLS ciphertext from bot"
        assert client.app.state.access.total == 1
    # Synchronize with the server task finishing cleanup.
    client.get("/health")
    assert writer.closed
    assert client.app.state.access.total == 0


@pytest.mark.parametrize(
    "url,headers",
    [
        ("wss://testserver/tunnel?host=discord.com", {}),
        ("ws://testserver/tunnel?host=discord.com", AUTH),
        ("wss://testserver/tunnel?host=127.0.0.1", AUTH),
        ("wss://testserver/tunnel?host=discord.com&port=80", AUTH),
        ("wss://testserver/tunnel?host=discord.com&token=secret", AUTH),
        ("wss://testserver/tunnel?host=discord.com&host=api.telegram.org", AUTH),
    ],
)
def test_tunnel_rejected_before_connect(client_factory, monkeypatch, url, headers):
    client = client_factory()

    async def never(*args):
        pytest.fail("Rejected tunnel attempted TCP connection")

    monkeypatch.setattr(client.app.state.policy, "open_tcp", never)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(url, headers=headers):
            pass
    assert client.app.state.access.total == 0


def test_binary_frames_only(client_factory, monkeypatch):
    client = client_factory()
    writer = Writer()

    async def connect(host, port):
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(client.app.state.policy, "open_tcp", connect)
    with client.websocket_connect("wss://testserver/tunnel?host=discord.com", headers=AUTH) as ws:
        ws.send_text("no text")
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_bytes()
        assert exc.value.code == 1003
    assert writer.closed


def test_oversized_frame(client_factory, monkeypatch):
    client = client_factory(max_frame_bytes=32)
    writer = Writer()

    async def connect(host, port):
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(client.app.state.policy, "open_tcp", connect)
    with client.websocket_connect("wss://testserver/tunnel?host=discord.com", headers=AUTH) as ws:
        ws.send_bytes(b"x" * 33)
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_bytes()
        assert exc.value.code == 1009
    assert writer.closed


def test_idle_cleanup(client_factory, monkeypatch):
    client = client_factory(tunnel_idle_seconds=0.05)
    writer = Writer()

    async def connect(host, port):
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(client.app.state.policy, "open_tcp", connect)
    with client.websocket_connect("wss://testserver/tunnel?host=discord.com", headers=AUTH) as ws:
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_bytes()
        assert exc.value.code == 1000
    assert writer.closed
