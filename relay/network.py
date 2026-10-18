import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import httpcore
import httpx
from fastapi import HTTPException

from .settings import Settings, canonical_host


class TargetPolicy:
    def __init__(self, settings: Settings):
        self.settings = settings

    def check_host(self, host: str, port: int = 443) -> str:
        try:
            host = canonical_host(host)
        except ValueError:
            raise HTTPException(400, "Invalid target host") from None
        if port != 443 or not self.settings.allows_host(host):
            raise HTTPException(400, "Target is not allowed")
        # Numeric targets are never needed for API endpoints; even explicitly
        # allowlisted private IPs cannot pass the DNS policy below.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        raise HTTPException(400, "IP literal targets are not allowed")

    def check_url(self, url: str) -> str:
        try:
            parts = urlsplit(url)
            if parts.scheme != "https" or parts.username is not None or parts.password is not None:
                raise ValueError
            if parts.fragment:
                raise ValueError
            return self.check_host(parts.hostname or "", 443 if parts.port is None else parts.port)
        except ValueError:
            raise HTTPException(
                400, "Only HTTPS URLs without userinfo or fragments are allowed"
            ) from None

    async def resolve(self, host: str, port: int = 443) -> list[str]:
        host = self.check_host(host, port)
        try:
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                self.settings.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError):
            raise HTTPException(502, "Target DNS lookup failed") from None
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses or any(not self.is_public(address) for address in addresses):
            raise HTTPException(400, "Target resolves to a non-public address")
        return addresses

    @staticmethod
    def is_public(address: str) -> bool:
        ip = ipaddress.ip_address(address)
        # Block transition mechanisms too; embedded IPv4 must not bypass checks.
        if isinstance(ip, ipaddress.IPv6Address) and (
            ip.ipv4_mapped is not None
            or ip.sixtofour is not None
            or ip.teredo is not None
            or ip in ipaddress.ip_network("64:ff9b::/96")
            or ip in ipaddress.ip_network("64:ff9b:1::/48")
        ):
            return False
        return ip.is_global and not ip.is_multicast and not ip.is_reserved

    async def open_tcp(self, host: str, port: int = 443):
        addresses = await self.resolve(host, port)

        async def connect():
            for address in addresses:
                try:
                    # Use the validated numeric address, never resolve the name a second time.
                    return await asyncio.open_connection(address, port)
                except OSError:
                    continue
            raise HTTPException(502, "Target connection failed")

        try:
            return await asyncio.wait_for(connect(), self.settings.connect_timeout)
        except asyncio.TimeoutError:
            raise HTTPException(504, "Target connection timed out") from None


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Resolve once, reject non-public answers and dial only verified addresses.

    HTTPcore retains the original Host header and TLS SNI/certificate hostname.
    """

    def __init__(self, policy: TargetPolicy):
        self.policy = policy
        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = await self.policy.resolve(host, port)

        async def connect():
            last_error = None
            for address in addresses:
                try:
                    return await self.backend.connect_tcp(
                        address,
                        port,
                        timeout=timeout,
                        local_address=local_address,
                        socket_options=socket_options,
                    )
                except httpcore.ConnectError as exc:
                    last_error = exc
            raise last_error or httpcore.ConnectError("No usable addresses")

        try:
            return await asyncio.wait_for(
                connect(), timeout or self.policy.settings.connect_timeout
            )
        except asyncio.TimeoutError:
            raise httpcore.ConnectTimeout("Connection timed out") from None

    async def connect_unix_socket(self, *args, **kwargs):
        raise httpcore.ConnectError("Unix sockets are not allowed")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


class CoreStream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, policy: TargetPolicy):
        self.backend = PinnedBackend(policy)
        self.pool = httpcore.AsyncConnectionPool(
            network_backend=self.backend,
            max_connections=policy.settings.max_concurrent or None,
            max_keepalive_connections=(min(20, policy.settings.max_concurrent) if policy.settings.max_concurrent > 0 else 20),
        )

    async def handle_async_request(self, request):
        response = await self.pool.handle_async_request(
            httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
        )
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=CoreStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self):
        await self.pool.aclose()
