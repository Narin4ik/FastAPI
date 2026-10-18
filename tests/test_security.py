import asyncio
from contextlib import ExitStack
from dataclasses import replace

import httpcore
import pytest
from fastapi import HTTPException
from starlette.datastructures import Headers

from relay.network import PinnedBackend, TargetPolicy
from relay.security import AccessControl
from relay.settings import Settings
from tests.conftest import AUTH


def test_startup_requires_external_secret(monkeypatch):
    monkeypatch.delenv("RELAY_KEYS_JSON", raising=False)
    monkeypatch.delenv("PROXY_SECRET_128", raising=False)
    with pytest.raises(ValueError, match="Set RELAY_KEYS"):
        Settings.from_env()
    monkeypatch.setenv("PROXY_SECRET_128", "a" * 128)
    assert Settings.from_env().keys == {"default": "a" * 128}
    monkeypatch.setenv("PROXY_SECRET_128", "short")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.parametrize(
    "keys", [{}, {"bad id": "a" * 64}, {"bot": "short"}, {"bot": "я" * 64}, {"bot": 32}]
)
def test_invalid_settings(keys):
    with pytest.raises(ValueError):
        Settings(keys=keys)


def test_expiring_auth_blocks_and_bounded_memory(settings, monkeypatch):
    now = [0.0]
    monkeypatch.setattr("relay.security.time.monotonic", lambda: now[0])
    access = AccessControl(replace(settings, max_tracking_entries=2, failed_threshold=2))
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            access.authenticate(Headers(), "ip")
        assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        access.authenticate(Headers(AUTH), "ip")
    assert exc.value.status_code == 429
    now[0] = settings.block_seconds + 1
    assert access.authenticate(Headers(AUTH), "ip") == "bot"
    for ip in ("a", "b", "c"):
        with pytest.raises(HTTPException):
            access.authenticate(Headers(), ip)
    assert len(access.failures) == 2


def test_zero_disables_request_limits(settings):
    unlimited = replace(
        settings,
        max_concurrent=0,
        max_per_key=0,
        requests_per_minute=0,
        max_request_bytes=0,
        max_response_bytes=0,
    )
    access = AccessControl(unlimited)
    for _ in range(130):
        assert access.authenticate(Headers(AUTH), "ip") == "bot"
    assert not access.rates
    with ExitStack() as stack:
        for _ in range(80):
            stack.enter_context(access.slot("bot"))
        assert access.total == 80
    assert access.total == 0


@pytest.mark.parametrize(
    "field",
    [
        "max_concurrent",
        "max_per_key",
        "requests_per_minute",
        "max_request_bytes",
        "max_response_bytes",
    ],
)
def test_negative_limits_rejected(field):
    with pytest.raises(ValueError):
        Settings(keys={"bot": "a" * 64}, **{field: -1})


def test_slots_released_after_error(settings):
    access = AccessControl(replace(settings, max_per_key=1))
    with access.slot("bot"):
        with pytest.raises(HTTPException):
            with access.slot("bot"):
                pass
        assert access.total == 1
    assert access.total == 0
    assert not access.active


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2001::1",
    ],
)
def test_non_public_ips_blocked(ip):
    assert not TargetPolicy.is_public(ip)


async def test_dns_mixed_answers_rejected(settings, monkeypatch):
    async def resolve(*args, **kwargs):
        return [(2, 1, 6, "", ("1.1.1.1", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    with pytest.raises(HTTPException, match="non-public"):
        await TargetPolicy(settings).resolve("discord.com")


async def test_pinned_backend_dials_validated_ip(settings, monkeypatch):
    policy = TargetPolicy(settings)
    calls = []

    async def resolve(host, port):
        calls.append((host, port))
        return ["1.1.1.1"]

    backend = PinnedBackend(policy)

    async def connect(host, port, **kwargs):
        assert host == "1.1.1.1"
        assert port == 443
        return httpcore.AsyncMockStream([])

    monkeypatch.setattr(policy, "resolve", resolve)
    monkeypatch.setattr(backend.backend, "connect_tcp", connect)
    await backend.connect_tcp("discord.com", 443)
    assert calls == [("discord.com", 443)]


async def test_tcp_tunnel_uses_validated_ip(settings, monkeypatch):
    policy = TargetPolicy(settings)

    async def resolve(host, port):
        return ["1.1.1.1"]

    async def connect(host, port):
        assert host == "1.1.1.1"
        return "reader", "writer"

    monkeypatch.setattr(policy, "resolve", resolve)
    monkeypatch.setattr(asyncio, "open_connection", connect)
    assert await policy.open_tcp("discord.com") == ("reader", "writer")
