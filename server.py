import asyncio
import base64
import binascii
import contextlib
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpcore
import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.datastructures import Headers

from relay.network import PinnedTransport, TargetPolicy
from relay.security import AccessControl, QuietWebSocketLogs, clean_headers
from relay.settings import Settings

logger = logging.getLogger("relay")


class ProxyRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: str = Field(min_length=1, max_length=8192)
    params: dict[str, str | int | float | bool | None] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: Any = Field(default=None, alias="json")
    data: str | dict[str, str] | None = None
    body_base64: str | None = None
    timeout: float = Field(default=60, ge=0.1, le=120, allow_inf_nan=False)

    @model_validator(mode="after")
    def check_payload(self):
        if sum(value is not None for value in (self.json_body, self.data, self.body_base64)) > 1:
            raise ValueError("Use only one of json, data or body_base64")
        if len(self.headers) > 100 or sum(len(k) + len(v) for k, v in self.headers.items()) > 16384:
            raise ValueError("Too many headers")
        for name, value in self.headers.items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError("Invalid header name")
            if any(ord(c) < 32 and c != "\t" or ord(c) == 127 or ord(c) > 126 for c in value):
                raise ValueError("Invalid header value")
        return self


class RequestGuard:
    """Authenticate before reading JSON, bound upload size/time, and count slots."""

    def __init__(self, app, state):
        self.app, self.state = app, state

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/proxy":
            return await self.app(scope, receive, send)
        settings = self.state.settings
        try:
            if settings.require_tls and scope["scheme"] != "https":
                raise HTTPException(400, "HTTPS is required")
            headers = Headers(scope=scope)
            ip = scope.get("client", ("unknown", 0))[0]
            key_id = self.state.access.authenticate(headers, ip)
            scope.setdefault("state", {})["key_id"] = key_id
            with self.state.access.slot(key_id):
                length = headers.get("content-length")
                if length is not None:
                    try:
                        if int(length) < 0:
                            raise ValueError
                        too_large = (
                            settings.max_request_bytes > 0
                            and int(length) > settings.max_request_bytes
                        )
                    except ValueError:
                        raise HTTPException(400, "Invalid content length") from None
                    if too_large:
                        raise HTTPException(413, "Request body too large")
                body = bytearray()

                async def read_body():
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return False
                        body.extend(message.get("body", b""))
                        if (
                            settings.max_request_bytes > 0
                            and len(body) > settings.max_request_bytes
                        ):
                            raise HTTPException(413, "Request body too large")
                        if not message.get("more_body", False):
                            return True

                try:
                    complete = await asyncio.wait_for(read_body(), 15)
                except asyncio.TimeoutError:
                    raise HTTPException(408, "Request upload timed out") from None
                if not complete:
                    return
                delivered = False

                async def replay_body():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                await self.app(scope, replay_body, send)
        except HTTPException as exc:
            await JSONResponse(
                {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
            )(scope, receive, send)


async def pump_tunnel(websocket, reader, writer, settings):
    started = last_activity = time.monotonic()
    to_target_bytes = to_client_bytes = 0

    async def to_target():
        nonlocal last_activity, to_target_bytes
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return "client_disconnect"
            data = message.get("bytes")
            if data is None:
                await websocket.close(1003, "Binary frames required")
                return "text_frame"
            if len(data) > settings.max_frame_bytes:
                await websocket.close(1009, "Frame too large")
                return "frame_too_large"
            if data:
                last_activity = time.monotonic()
                to_target_bytes += len(data)
                writer.write(data)
                await writer.drain()

    async def to_client():
        nonlocal last_activity, to_client_bytes
        while True:
            data = await reader.read(settings.max_frame_bytes)
            if not data:
                return "target_eof"
            last_activity = time.monotonic()
            to_client_bytes += len(data)
            await websocket.send_bytes(data)

    async def watchdog():
        # WebSocket pings alone don't keep an unused upstream TCP connection alive.
        while True:
            await asyncio.sleep(min(5, settings.tunnel_idle_seconds))
            if time.monotonic() - last_activity >= settings.tunnel_idle_seconds:
                await websocket.close(1000, "Idle timeout")
                return "idle_timeout"

    tasks = [asyncio.create_task(coro()) for coro in (to_target, to_client, watchdog)]
    reason = "max_lifetime"
    try:
        done, _ = await asyncio.wait(
            tasks, timeout=settings.tunnel_max_seconds, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            try:
                reason = task.result()
            except (WebSocketDisconnect, OSError, RuntimeError) as error:
                reason = type(error).__name__
                raise
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.getLogger("uvicorn.error").info(
            "Tunnel closed: reason=%s duration=%.1fs to_target=%d to_client=%d",
            reason,
            time.monotonic() - started,
            to_target_bytes,
            to_client_bytes,
        )


def create_app(settings: Settings | None = None, *, transport=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings.from_env()
        ws_logger = logging.getLogger("uvicorn.error")
        log_filter = QuietWebSocketLogs()
        ws_logger.addFilter(log_filter)
        app.state.policy = TargetPolicy(app.state.settings)
        app.state.access = AccessControl(app.state.settings)
        async with httpx.AsyncClient(
            transport=transport or PinnedTransport(app.state.policy),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            app.state.client = client
            try:
                yield
            finally:
                ws_logger.removeFilter(log_filter)

    app = FastAPI(
        title="Private API Relay",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
    )
    app.add_middleware(RequestGuard, state=app.state)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's normal response may include the user's bot token/body.
        return JSONResponse({"detail": "Invalid proxy request"}, status_code=422)

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.post("/proxy")
    async def proxy(payload: ProxyRequest, request: Request):
        cfg = app.state.settings
        app.state.policy.check_url(payload.url)
        headers = clean_headers(payload.headers)
        headers["accept-encoding"] = "identity"
        kwargs = {}
        if payload.body_base64 is not None:
            try:
                kwargs["content"] = base64.b64decode(payload.body_base64, validate=True)
            except (ValueError, binascii.Error):
                raise HTTPException(422, "Invalid base64 body") from None
        elif isinstance(payload.data, str):
            kwargs["content"] = payload.data.encode("utf-8")
        elif payload.data is not None:
            kwargs["data"] = payload.data
        elif "json_body" in payload.model_fields_set:
            if payload.json_body is None:
                kwargs["content"] = b"null"
                headers.setdefault("content-type", "application/json")
            else:
                kwargs["json"] = payload.json_body
        timeout = min(payload.timeout, cfg.request_timeout)
        # Build a standalone Request so pooled HTTPX cookies cannot cross key IDs.
        upstream = httpx.Request(
            payload.method, payload.url, params=payload.params, headers=headers, **kwargs
        )
        if cfg.max_request_bytes > 0 and len(upstream.content) > cfg.max_request_bytes:
            raise HTTPException(413, "Upstream request body too large")
        upstream.extensions["timeout"] = {
            name: timeout for name in ("connect", "read", "write", "pool")
        }
        upstream.extensions["timeout"]["connect"] = min(timeout, cfg.connect_timeout)
        try:

            async def forward():
                response = await app.state.client.send(upstream, stream=True)
                try:
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk)
                        if cfg.max_response_bytes > 0 and len(body) > cfg.max_response_bytes:
                            raise HTTPException(502, "Upstream response too large")
                    # Preserve rate limits and file metadata; no cookies or redirect following.
                    allowed = {
                        "content-type",
                        "content-encoding",
                        "content-disposition",
                        "retry-after",
                        "etag",
                        "last-modified",
                    }
                    result_headers = {
                        k: v
                        for k, v in response.headers.items()
                        if k in allowed or k.startswith("x-ratelimit-")
                    }
                    return Response(
                        bytes(body), status_code=response.status_code, headers=result_headers
                    )
                finally:
                    await response.aclose()

            return await asyncio.wait_for(forward(), timeout)
        except (httpcore.TimeoutException, httpx.TimeoutException, asyncio.TimeoutError):
            raise HTTPException(504, "Upstream request timed out") from None
        except (httpcore.NetworkError, httpcore.ProtocolError, httpx.RequestError, OSError):
            # Never log exception text: Telegram tokens can occur in URL paths.
            logger.warning("Upstream request failed")
            raise HTTPException(502, "Upstream request failed") from None

    @app.websocket("/tunnel")
    async def tunnel(websocket: WebSocket):
        writer = None
        accepted = False
        try:
            cfg = app.state.settings
            if cfg.require_tls and websocket.scope["scheme"] != "wss":
                raise HTTPException(400, "WSS is required")
            ip = websocket.client.host if websocket.client else "unknown"
            key_id = app.state.access.authenticate(websocket.headers, ip)
            # Parse only after authentication. There are no credentials in URLs.
            if set(websocket.query_params) - {"host", "port"}:
                raise HTTPException(400, "Invalid tunnel parameters")
            if (
                len(websocket.query_params.getlist("host")) != 1
                or len(websocket.query_params.getlist("port")) > 1
            ):
                raise HTTPException(400, "Invalid tunnel parameters")
            try:
                port = int(websocket.query_params.get("port", "443"))
            except ValueError:
                raise HTTPException(400, "Invalid target port") from None
            host = app.state.policy.check_host(websocket.query_params.get("host", ""), port)
            with app.state.access.slot(key_id):
                reader, writer = await app.state.policy.open_tcp(host, port)
                # Successful upgrade means the target socket is already connected.
                await websocket.accept()
                accepted = True
                await pump_tunnel(websocket, reader, writer, cfg)
        except HTTPException as error:
            if error.status_code >= 500:
                logging.getLogger("uvicorn.error").warning(
                    "Tunnel target unavailable: status=%d reason=%s",
                    error.status_code,
                    error.detail,
                )
            with contextlib.suppress(RuntimeError, OSError, WebSocketDisconnect):
                await websocket.close(1008, "Tunnel rejected")
        except (WebSocketDisconnect, OSError, RuntimeError):
            if accepted:
                logger.info("Tunnel disconnected")
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 3)
            if accepted:
                with contextlib.suppress(RuntimeError, OSError, WebSocketDisconnect):
                    await websocket.close()

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Validate before binding a socket; never embed a credential in source code.
    config = Settings.from_env()
    uvicorn.run(
        "server:app",
        host=config.host,
        port=config.port,
        proxy_headers=True,
        forwarded_allow_ips=config.trusted_proxy_ips,
        access_log=False,
        ws="websockets-sansio",
        ws_max_size=config.max_frame_bytes,
        ws_max_queue=4,
        ws_per_message_deflate=False,
        limit_concurrency=config.max_concurrent + 16 if config.max_concurrent > 0 else None,
        ssl_certfile=os.getenv("TLS_CERT_FILE"),
        ssl_keyfile=os.getenv("TLS_KEY_FILE"),
    )
