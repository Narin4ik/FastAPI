"""Launch the production entrypoint; no bot tokens or external API calls needed."""

import json
import os
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env.pop("PROXY_SECRET_128", None)
    env.update(
        RELAY_KEYS_JSON=json.dumps({"ci": "s" * 64}),
        HOST="127.0.0.1",
        PORT=str(port),
        ALLOW_INSECURE_TRANSPORT="true",
    )
    proc = subprocess.Popen([sys.executable, "server.py"], env=env, stdout=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Server exited before readiness")
            try:
                with urlopen(url + "/health", timeout=1) as response:
                    assert json.load(response) == {"ok": True}
                break
            except (URLError, OSError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Server did not become ready")
        request = Request(url + "/proxy", data=b"{}", headers={"Content-Type": "application/json"})
        try:
            urlopen(request, timeout=2)
            raise AssertionError("Unauthenticated request was allowed")
        except HTTPError as exc:
            assert exc.code == 401
        print("Startup, readiness and authentication smoke checks passed")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    env.pop("RELAY_KEYS_JSON")
    result = subprocess.run([sys.executable, "server.py"], env=env, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert b"Set RELAY_KEYS_JSON" in result.stderr
    print("Startup without a secret is rejected")


if __name__ == "__main__":
    main()
