"""CI-only local targets: never deploy this test application."""

import asyncio
import json
import os
import ssl
from contextlib import asynccontextmanager

import httpcore
from fastapi import WebSocket

from relay.network import PinnedTransport, TargetPolicy
from relay.settings import Settings
from server import create_app

port = int(os.environ["RELAY_TEST_PORT"])
settings = Settings(keys={"ci": "s" * 64}, port=port)
policy = TargetPolicy(settings)
transport = PinnedTransport(policy)
transport.pool = httpcore.AsyncConnectionPool(
    network_backend=transport.backend,
    ssl_context=ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"]),
)
app = create_app(settings, transport=transport)
original_lifespan = app.router.lifespan_context


@asynccontextmanager
async def local_targets(app):
    async with original_lifespan(app):

        async def local_dns(host, port):
            app.state.policy.check_host(host, port)
            return ["127.0.0.1"]

        async def local_tcp(host, target_port):
            app.state.policy.check_host(host, target_port)
            return await asyncio.open_connection("127.0.0.1", port)

        # DNS/connection injection belongs exclusively to the fixture, not production settings.
        app.state.policy = policy
        app.state.policy.resolve = local_dns
        app.state.policy.open_tcp = local_tcp
        real_connect = transport.backend.backend.connect_tcp

        async def target_connect(host, target_port, **kwargs):
            assert host == "127.0.0.1" and target_port == 443
            return await real_connect(host, port, **kwargs)

        transport.backend.backend.connect_tcp = target_connect
        yield


app.router.lifespan_context = local_targets


@app.get("/api/v10/gateway")
async def target_api():
    return {"marker": "https-through-tunnel", "payload": "x" * 70000}


@app.websocket("/")
async def target_gateway(socket: WebSocket):
    await socket.accept()
    await socket.send_text(json.dumps({"op": 10, "d": {"heartbeat_interval": 45000}}))
    try:
        await socket.receive()
    finally:
        await socket.close()
