import hmac
import logging
import time
from collections import OrderedDict
from contextlib import contextmanager

from fastapi import HTTPException

from .settings import Settings

# Credentials for Discord/Telegram are allowed; relay and routing headers are not.
HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "x-proxy-key",
    "x-proxy-secret",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "accept-encoding",
}


def clean_headers(headers: dict[str, str]) -> dict[str, str]:
    connection_tokens = set()
    for name, value in headers.items():
        if name.lower() == "connection":
            connection_tokens.update(part.strip().lower() for part in value.split(","))
    return {
        name.lower(): value
        for name, value in headers.items()
        if name.lower() not in HOP_HEADERS | connection_tokens
        and not name.lower().startswith("x-forwarded-")
    }


class AccessControl:
    """Bounded, expiring state. All methods run on the application's event loop."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.failures: OrderedDict[str, tuple[int, float, float]] = OrderedDict()
        self.rates: OrderedDict[str, tuple[int, float]] = OrderedDict()
        self.active: dict[str, int] = {}
        self.total = 0

    def _put(self, mapping, key, value):
        mapping[key] = value
        mapping.move_to_end(key)
        while len(mapping) > self.settings.max_tracking_entries:
            mapping.popitem(last=False)

    def authenticate(self, headers, ip: str) -> str:
        now = time.monotonic()
        count, started, blocked_until = self.failures.get(ip, (0, now, 0))
        if blocked_until > now:
            raise HTTPException(
                429,
                "Too many authentication failures",
                headers={"Retry-After": str(max(1, int(blocked_until - now)))},
            )
        key_id = headers.get("x-proxy-key", "default")
        values = headers.getlist("x-proxy-secret")
        ids = headers.getlist("x-proxy-key")
        secret = values[0] if len(values) == 1 else ""
        expected = self.settings.keys.get(key_id)
        valid = (
            len(ids) <= 1
            and expected is not None
            and len(secret) <= 256
            and secret.isascii()
            and hmac.compare_digest(secret, expected)
        )
        if not valid:
            if now - started >= self.settings.failed_window_seconds or blocked_until:
                count, started = 0, now
            count += 1
            blocked_until = (
                now + self.settings.block_seconds
                if (count >= self.settings.failed_threshold)
                else 0
            )
            self._put(self.failures, ip, (count, started, blocked_until))
            raise HTTPException(401, "Invalid or missing relay credentials")
        self.failures.pop(ip, None)
        count, started = self.rates.get(key_id, (0, now))
        if now - started >= 60:
            count, started = 0, now
        if count >= self.settings.requests_per_minute:
            raise HTTPException(
                429,
                "Rate limit exceeded",
                headers={"Retry-After": str(max(1, int(60 - now + started)))},
            )
        self._put(self.rates, key_id, (count + 1, started))
        return key_id

    @contextmanager
    def slot(self, key_id: str):
        if self.total >= self.settings.max_concurrent or (
            self.active.get(key_id, 0) >= self.settings.max_per_key
        ):
            raise HTTPException(429, "Connection limit exceeded", headers={"Retry-After": "5"})
        self.total += 1
        self.active[key_id] = self.active.get(key_id, 0) + 1
        try:
            yield
        finally:
            self.total -= 1
            self.active[key_id] -= 1
            if not self.active[key_id]:
                del self.active[key_id]


class QuietWebSocketLogs(logging.Filter):
    """Uvicorn logs WS target query strings even with access_log=False."""

    def filter(self, record):
        return "WebSocket" not in str(record.msg)
