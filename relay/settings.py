import json
import os
import re
from dataclasses import dataclass, field

DEFAULT_HOSTS = (
    "discord.com",
    "gateway.discord.gg",
    "*.gateway.discord.gg",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "api.telegram.org",
)


def canonical_host(host: str) -> str:
    host = host.rstrip(".").lower()
    if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("Invalid host")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in host.split(".")
    ):
        raise ValueError("Invalid host")
    return host


@dataclass(frozen=True)
class Settings:
    keys: dict[str, str]
    allowed_hosts: tuple[str, ...] = DEFAULT_HOSTS
    require_tls: bool = True
    max_request_bytes: int = 2 * 1024 * 1024
    max_response_bytes: int = 8 * 1024 * 1024
    max_concurrent: int = 64
    max_per_key: int = 16
    requests_per_minute: int = 120
    max_tracking_entries: int = 4096
    failed_threshold: int = 5
    failed_window_seconds: int = 600
    block_seconds: int = 600
    connect_timeout: float = 10
    request_timeout: float = 120
    tunnel_idle_seconds: float = 180
    tunnel_max_seconds: float = 86400
    max_frame_bytes: int = 65536
    trusted_proxy_ips: str = "127.0.0.1"
    port: int = 8280
    host: str = "0.0.0.0"
    _patterns: tuple[tuple[str, bool], ...] = field(init=False, repr=False)

    def __post_init__(self):
        if not self.keys:
            raise ValueError("Set RELAY_KEYS_JSON or PROXY_SECRET_128 before starting")
        for key_id, secret in self.keys.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id):
                raise ValueError("Key IDs must contain 1-64 letters, digits, '_' or '-'")
            if not isinstance(secret, str) or not 32 <= len(secret) <= 256:
                raise ValueError("Relay secrets must contain 32-256 ASCII characters")
            if not secret.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in secret):
                raise ValueError("Relay secrets must be printable ASCII without spaces")
        if not self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS cannot be empty")
        patterns = []
        for pattern in self.allowed_hosts:
            wildcard = pattern.startswith("*.")
            host = canonical_host(pattern[2:] if wildcard else pattern)
            if wildcard and "." not in host:
                raise ValueError("Wildcards must be scoped to a domain")
            patterns.append((host, wildcard))
        object.__setattr__(self, "_patterns", tuple(patterns))
        for name in (
            "max_request_bytes",
            "max_response_bytes",
            "max_concurrent",
            "max_per_key",
            "requests_per_minute",
            "max_tracking_entries",
            "failed_threshold",
            "failed_window_seconds",
            "block_seconds",
            "connect_timeout",
            "request_timeout",
            "tunnel_idle_seconds",
            "tunnel_max_seconds",
            "max_frame_bytes",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_frame_bytes > 65536:
            raise ValueError("max_frame_bytes cannot exceed 65536")
        if not 1 <= self.port <= 65535:
            raise ValueError("PORT must be between 1 and 65535")

    def allows_host(self, host: str) -> bool:
        return any(
            host == domain if not wildcard else host.endswith("." + domain)
            for domain, wildcard in self._patterns
        )

    @classmethod
    def from_env(cls):
        raw = os.getenv("RELAY_KEYS_JSON", "{}")
        try:
            keys = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("RELAY_KEYS_JSON must be a JSON object") from None
        if not isinstance(keys, dict):
            raise ValueError("RELAY_KEYS_JSON must be a JSON object")
        legacy = os.getenv("PROXY_SECRET_128")
        if legacy:
            if len(legacy) != 128:
                raise ValueError("PROXY_SECRET_128 must contain exactly 128 characters")
            if "default" in keys and keys["default"] != legacy:
                raise ValueError("Conflicting default relay keys")
            keys["default"] = legacy
        insecure = os.getenv("ALLOW_INSECURE_TRANSPORT", "false").lower()
        if insecure not in {"true", "false"}:
            raise ValueError("ALLOW_INSECURE_TRANSPORT must be true or false")
        kwargs = {}
        for name in (
            "max_request_bytes",
            "max_response_bytes",
            "max_concurrent",
            "max_per_key",
            "requests_per_minute",
            "max_tracking_entries",
            "failed_threshold",
            "failed_window_seconds",
            "block_seconds",
            "max_frame_bytes",
            "port",
        ):
            if os.getenv(name.upper()) is not None:
                kwargs[name] = int(os.environ[name.upper()])
        for name in (
            "connect_timeout",
            "request_timeout",
            "tunnel_idle_seconds",
            "tunnel_max_seconds",
        ):
            if os.getenv(name.upper()) is not None:
                kwargs[name] = float(os.environ[name.upper()])
        return cls(
            keys=keys,
            require_tls=insecure != "true",
            allowed_hosts=tuple(
                h.strip()
                for h in os.getenv("ALLOWED_HOSTS", ",".join(DEFAULT_HOSTS)).split(",")
                if h.strip()
            ),
            trusted_proxy_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
            host=os.getenv("HOST", "0.0.0.0"),
            **kwargs,
        )
