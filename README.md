# Simple API Proxy (FastAPI) — with IP Blacklist & Allowlist

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API%20framework-009688.svg)](https://fastapi.tiangolo.com/)
[![httpx](https://img.shields.io/badge/httpx-async%20client-4F5B93.svg)](https://www.python-httpx.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A minimal, security-minded HTTP proxy built with **FastAPI** and **httpx**.  
It forwards requests to a specified target URL **only if** the caller supplies a valid **128-character secret** and passes host checks. The app also **auto-blacklists** IPs after repeated failed attempts and supports a simple **allowlist** for target hosts.

## ✨ Features

- **Header secret check**: Requests must include a 128-char `X-Proxy-Secret` (constant or env).
- **Automatic IP blacklisting**: After *N* failed secret checks within a time window, the client IP is written to `blacklist.txt`.
- **Allowlist & disallowlist**:
  - Blocks `localhost`, `127.0.0.1`, `::1` by default.
  - Optional allowlist via `ALLOWED_HOSTS`.
- **Safe header forwarding**: Strips hop-by-hop & sensitive headers (`host`, `content-length`, `connection`, etc.).
- **Flexible payloads**: Supports JSON or form/bytes via `json` or `data`.
- **Per-request timeout**: Default `15s`, adjustable per call.
- **Endpoints**: `/health`, `/proxy`.

## 🧩 Request Model (JSON body)

```json
{
  "method": "GET | POST | PUT | PATCH | DELETE | HEAD | OPTIONS",
  "url": "https://example.com/api",
  "params": { "q": "value" },
  "headers": { "Accept": "application/json" },

  "json": { "any": "json-payload" },
  "data": "optional-raw-or-form-data (use only one of json/data)",
  "timeout": 15.0
}
```
