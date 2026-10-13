from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from relay.settings import Settings
from server import create_app

SECRET = "a" * 64
AUTH = {"X-Proxy-Key": "bot", "X-Proxy-Secret": SECRET}


@pytest.fixture
def settings():
    return Settings(keys={"bot": SECRET})


@pytest.fixture
def client_factory(settings):
    clients = []

    def make(handler=None, **overrides):
        cfg = replace(settings, **overrides)
        handler = handler or (lambda req: httpx.Response(200, stream=httpx.ByteStream(b"ok")))
        app = create_app(cfg, transport=httpx.MockTransport(handler))
        client = TestClient(app, base_url="https://testserver")
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in reversed(clients):
        client.__exit__(None, None, None)
