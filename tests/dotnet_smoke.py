"""Real TLS + C# HTTP/WebSocket integration, using only local test endpoints."""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def main():
    dotnet = shutil.which("dotnet")
    if not dotnet:
        raise RuntimeError(".NET 8 SDK is required for the integration smoke test")
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        cert, key = root / "ca.pem", root / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,DNS:discord.com,DNS:gateway.discord.gg",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(
            RELAY_TEST_PORT=str(port),
            SSL_CERT_FILE=str(cert),
            RELAY_ENDPOINT=f"wss://localhost:{port}/tunnel",
            RELAY_KEY_ID="ci",
            RELAY_SECRET="s" * 64,
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "tests.tls_fixture:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--ssl-certfile",
                str(cert),
                "--ssl-keyfile",
                str(key),
                "--no-access-log",
                "--ws",
                "websockets-sansio",
                "--ws-max-size",
                "65536",
                "--ws-max-queue",
                "4",
                "--ws-per-message-deflate",
                "false",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
        )
        try:
            url = f"https://localhost:{port}"
            context = ssl.create_default_context(cafile=str(cert))
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError("TLS fixture exited before readiness")
                try:
                    with urlopen(url + "/health", context=context, timeout=1):
                        break
                except (URLError, OSError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("TLS fixture not ready")
            # Exercise the real HTTPcore connection/TLS transport too.
            payload = json.dumps({"url": "https://discord.com/api/v10/gateway"}).encode()
            request = Request(
                url + "/proxy",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Proxy-Key": "ci",
                    "X-Proxy-Secret": "s" * 64,
                },
            )
            with urlopen(request, context=context, timeout=5) as response:
                assert json.load(response)["marker"] == "https-through-tunnel"
            print("Real pinned HTTP transport with target TLS passed")
            for mode, marker in (
                ("api", "https-through-tunnel"),
                ("websocket", "Gateway received"),
            ):
                result = subprocess.run(
                    [dotnet, "examples/dotnet/bin/Release/net8.0/RelayClient.dll", mode],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode or marker not in result.stdout:
                    raise RuntimeError(f"C# {mode} test failed: {result.stderr[:2000]}")
                print(f"C# {mode} over certificate-verified WSS passed")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
