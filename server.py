import os
import hmac
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, AnyHttpUrl, Field, ConfigDict

app = FastAPI(title="Simple API Proxy with IP Blacklist")

# ====== СЕКРЕТНЫЙ КЛЮЧ ПОДКЛЮЧЕНИЯ (нужно заменить ниже) ======
SECRET_IN_CODE = "CHANGE_ME"

if len(SECRET_IN_CODE) != 128:
    raise RuntimeError("SECRET_IN_CODE must be exactly 128 characters long.")

PROXY_SECRET = os.getenv("PROXY_SECRET_128", SECRET_IN_CODE)

FAILED_THRESHOLD = int(os.getenv("FAILED_THRESHOLD", "5"))
FAILED_WINDOW_SECONDS = int(os.getenv("FAILED_WINDOW_SECONDS", "600"))
_attempts_lock = threading.Lock()
_failed_attempts: Dict[str, tuple[int, float]] = {}

HERE = Path(__file__).resolve().parent
BLACKLIST_FILE = HERE / "blacklist.txt"
BLACKLIST_FILE.touch(exist_ok=True)

_blacklist_lock = threading.Lock()
_blacklist_cache: set[str] = set()
_blacklist_mtime: float = 0.0


def _refresh_blacklist_cache() -> None:
    """Ленивая подгрузка blacklist.txt (подхватывает ручные правки файла)."""
    global _blacklist_mtime, _blacklist_cache
    try:
        mtime = BLACKLIST_FILE.stat().st_mtime
    except FileNotFoundError:
        BLACKLIST_FILE.touch(exist_ok=True)
        mtime = BLACKLIST_FILE.stat().st_mtime
    if mtime != _blacklist_mtime:
        _blacklist_mtime = mtime
        with BLACKLIST_FILE.open("r", encoding="utf-8", errors="ignore") as f:
            _blacklist_cache = {line.strip() for line in f if line.strip()}


def _add_to_blacklist(ip: str) -> None:
    with _blacklist_lock:
        _refresh_blacklist_cache()
        if ip not in _blacklist_cache:
            with BLACKLIST_FILE.open("a", encoding="utf-8") as f:
                f.write(ip + "\n")
            _blacklist_cache.add(ip)


def _is_blacklisted(ip: str) -> bool:
    _refresh_blacklist_cache()
    return ip in _blacklist_cache


class ProxyRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    url: AnyHttpUrl
    params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None

    json_body: Optional[Any] = Field(default=None, alias="json")
    data: Optional[Any] = None        # form/bytes/str
    timeout: float = Field(default=15, ge=0.1, le=120)


def _check_secret(token: Optional[str]) -> bool:
    return token is not None and len(token) == 128 and hmac.compare_digest(token, PROXY_SECRET)


def _register_failure_and_maybe_blacklist(ip: str) -> None:
    now = time.time()
    with _attempts_lock:
        cnt, first_ts = _failed_attempts.get(ip, (0, now))
        if now - first_ts > FAILED_WINDOW_SECONDS:
            cnt, first_ts = 0, now
        cnt += 1
        _failed_attempts[ip] = (cnt, first_ts)
        if cnt >= FAILED_THRESHOLD:
            _add_to_blacklist(ip)


def _client_ip(request: Request) -> str:
    """
    Получаем IP клиента. Если запускаете за обратным прокси и включили
    проксируемые заголовки (uvicorn --proxy-headers), значение request.client.host
    будет уже корректным.
    """
    return request.client.host


ALLOWED_HOSTS = {
    h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()
}
DISALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _check_target(url: str) -> None:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if host in DISALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Target host not allowed")
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Target host not in allowlist")


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/proxy")
async def proxy(
    req: ProxyRequest,
    request: Request,
    x_proxy_secret: Optional[str] = Header(default=None, alias="X-Proxy-Secret"),
):
    ip = _client_ip(request)

    if _is_blacklisted(ip):
        raise HTTPException(status_code=403, detail="This IP is blacklisted")

    if not _check_secret(x_proxy_secret):
        _register_failure_and_maybe_blacklist(ip)
        if _is_blacklisted(ip):
            raise HTTPException(status_code=403, detail="This IP is blacklisted")
        raise HTTPException(status_code=401, detail="Invalid or missing secret")

    _check_target(str(req.url))

    fwd_headers = dict(req.headers or {})
    for h in [
        "host", "content-length", "connection", "keep-alive",
        "proxy-authenticate", "proxy-authorization", "te",
        "trailers", "transfer-encoding", "upgrade",
    ]:
        fwd_headers.pop(h, None)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        resp = await client.request(
            req.method,
            str(req.url),
            params=req.params,
            headers=fwd_headers,
            json=req.json_body if req.data is None else None,
            data=req.data if req.json_body is None else None,
            timeout=req.timeout,
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={"content-type": resp.headers.get("content-type", "application/octet-stream")},
    )

if __name__ == "__main__":
    import os, uvicorn
    uvicorn.run("server:app", host=os.getenv("HOST", "0.0.0.0"),
                port=int(os.getenv("PORT", "8280")))
