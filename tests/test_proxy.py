import asyncio
import base64
import json

import httpcore
import httpx
import pytest

from tests.conftest import AUTH

URL = "https://discord.com/api/v10/gateway"


def test_health_and_private_schema(client_factory):
    client = client_factory()
    assert client.get("/health").json() == {"ok": True}
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_auth_before_json_parsing(client_factory):
    client = client_factory()
    assert client.post("/proxy", content=b"bad JSON").status_code == 401
    assert client.post("/proxy", content=b"bad JSON", headers=AUTH).status_code == 422


def test_secure_transport_required(client_factory):
    client = client_factory()
    assert (
        client.post("http://testserver/proxy", headers=AUTH, json={"url": URL}).status_code == 400
    )
    assert (
        client.post(
            "http://testserver/proxy",
            headers={**AUTH, "X-Forwarded-Proto": "https"},
            json={"url": URL},
        ).status_code
        == 400
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://discord.com/api",
        "https://127.0.0.1/",
        "https://169.254.169.254/",
        "https://localhost/",
        "https://discord.com:8443/",
        "https://discord.com.evil.test/",
        "https://evilgateway.discord.gg/",
        "https://a.gateway.discord.gg.evil.test/",
        "https://user:password@discord.com/",
        "https://discord.com/#fragment",
        "https://[::1]/",
        "file:///etc/passwd",
    ],
)
def test_reject_targets(client_factory, url):
    def never(req):
        pytest.fail("Invalid target reached transport")

    client = client_factory(never)
    assert client.post("/proxy", headers=AUTH, json={"url": url}).status_code == 400


def test_header_filter_and_rate_limits(client_factory):
    def handler(req):
        assert req.headers["host"] == "discord.com"
        assert req.headers["authorization"] == "Bot upstream-token"
        assert "x-proxy-secret" not in req.headers
        assert "x-proxy-key" not in req.headers
        assert "x-custom-hop" not in req.headers
        assert "forwarded" not in req.headers
        assert "x-forwarded-for" not in req.headers
        assert req.headers["accept-encoding"] == "identity"
        return httpx.Response(
            429,
            stream=httpx.ByteStream(b'{"retry_after":1}'),
            headers={
                "content-type": "application/json",
                "retry-after": "1",
                "x-ratelimit-reset": "2",
                "set-cookie": "bot=private",
                "connection": "close",
            },
        )

    client = client_factory(handler)
    response = client.post(
        "/proxy",
        headers=AUTH,
        json={
            "url": URL,
            "headers": {
                "HOST": "internal",
                "Authorization": "Bot upstream-token",
                "X-Proxy-Secret": "do-not-leak",
                "X-Proxy-Key": "bot",
                "CoNnEcTiOn": "X-Custom-Hop",
                "X-Custom-Hop": "hidden",
                "Forwarded": "for=private",
                "X-Forwarded-For": "127.0.0.1",
            },
        },
    )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "1"
    assert response.headers["x-ratelimit-reset"] == "2"
    assert "set-cookie" not in response.headers
    assert "connection" not in response.headers


def test_cookies_do_not_cross_bot_keys(client_factory):
    seen = []

    def handler(req):
        seen.append(req.headers.get("cookie"))
        return httpx.Response(
            200, stream=httpx.ByteStream(b"ok"), headers={"set-cookie": "private=token"}
        )

    client = client_factory(handler, keys={"bot": "a" * 64, "other": "b" * 64})
    client.post("/proxy", headers=AUTH, json={"url": URL})
    client.post(
        "/proxy", headers={"X-Proxy-Key": "other", "X-Proxy-Secret": "b" * 64}, json={"url": URL}
    )
    assert seen == [None, None]


@pytest.mark.parametrize(
    "payload",
    [
        {"json": {"hello": "world"}},
        {"data": "raw ✓"},
        {"data": {"hello": "world"}},
        {"body_base64": base64.b64encode(b"\x00\xff").decode()},
        {"json": None},
    ],
)
def test_body_forwarding(client_factory, payload):
    def handler(req):
        if payload.get("body_base64"):
            assert req.content == b"\x00\xff"
        elif isinstance(payload.get("data"), str):
            assert req.content == "raw ✓".encode()
        elif isinstance(payload.get("data"), dict):
            assert req.content == b"hello=world"
        else:
            assert json.loads(req.content) == payload["json"]
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    client = client_factory(handler)
    assert (
        client.post(
            "/proxy", headers=AUTH, json={"url": URL, "method": "POST", **payload}
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"json": {}, "data": "also"},
        {"body_base64": "%%%"},
        {"headers": {"Authorization": "token\r\nX: bad"}},
        {"headers": {"Bad Header": "x"}},
        {"timeout": 121},
        {"surprise": "bot-token"},
    ],
)
def test_invalid_payload_redacted(client_factory, payload):
    client = client_factory()
    response = client.post("/proxy", headers=AUTH, json={"url": URL, **payload})
    assert response.status_code == 422
    assert "bot-token" not in response.text
    assert "input" not in response.text


def test_auth_duplicate_and_unicode_secret(client_factory):
    client = client_factory()
    headers = [("X-Proxy-Key", "bot"), ("X-Proxy-Secret", "a" * 64), ("X-Proxy-Secret", "a" * 64)]
    assert client.post("/proxy", headers=headers, json={"url": URL}).status_code == 401


def test_request_limit_and_chunked_body(client_factory):
    client = client_factory(max_request_bytes=128)
    assert client.post("/proxy", headers=AUTH, content=b"x" * 129).status_code == 413
    assert (
        client.post("/proxy", headers=AUTH, content=iter([b"x" * 64, b"x" * 65])).status_code == 413
    )


class Chunks(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"x" * 65
        yield b"x" * 64


def test_response_limit(client_factory):
    client = client_factory(
        lambda req: httpx.Response(200, stream=Chunks()), max_response_bytes=128
    )
    assert client.post("/proxy", headers=AUTH, json={"url": URL}).status_code == 502


def test_unlimited_request_and_response_bytes(client_factory):
    sent = b"z" * 8192
    returned = b"x" * 8192

    def handler(req):
        assert req.content == sent
        return httpx.Response(200, stream=httpx.ByteStream(returned))

    client = client_factory(
        handler, max_request_bytes=0, max_response_bytes=0, requests_per_minute=0
    )
    for _ in range(3):
        response = client.post(
            "/proxy",
            headers=AUTH,
            json={"url": URL, "method": "POST", "body_base64": base64.b64encode(sent).decode()},
        )
        assert response.status_code == 200
        assert response.content == returned


def test_no_automatic_redirects(client_factory):
    seen = []

    def handler(req):
        seen.append(req.url.host)
        return httpx.Response(
            302, stream=httpx.ByteStream(b""), headers={"location": "http://169.254.169.254/"}
        )

    client = client_factory(handler)
    response = client.post("/proxy", headers=AUTH, json={"url": URL})
    assert response.status_code == 302
    assert "location" not in response.headers
    assert seen == ["discord.com"]


@pytest.mark.parametrize(
    "error,status",
    [
        (httpcore.ConnectError("https://api.telegram.org/botSECRET"), 502),
        (httpx.ReadTimeout("token"), 504),
    ],
)
def test_upstream_errors_redacted(client_factory, error, status):
    def handler(req):
        raise error

    client = client_factory(handler)
    response = client.post("/proxy", headers=AUTH, json={"url": URL})
    assert response.status_code == status
    assert "SECRET" not in response.text
    assert "telegram" not in response.text


def test_total_timeout(client_factory):
    async def slow(req):
        await asyncio.sleep(1)
        return httpx.Response(200)

    client = client_factory(slow)
    assert client.post("/proxy", headers=AUTH, json={"url": URL, "timeout": 0.1}).status_code == 504


def test_per_key_rate_limit(client_factory):
    client = client_factory(requests_per_minute=1)
    assert client.post("/proxy", headers=AUTH, json={"url": URL}).status_code == 200
    response = client.post("/proxy", headers=AUTH, json={"url": URL})
    assert response.status_code == 429
    assert "retry-after" in response.headers
