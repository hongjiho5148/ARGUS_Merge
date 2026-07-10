"""Shared HTTP transport for diagnosis probes (httpx direct or ZAP sendRequest)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.services.zap_util import zap_send_raw_request_full
from inventory.probe_build import format_raw_http_request


@dataclass(frozen=True)
class ProbeResponse:
    status: int | None
    body: bytes
    headers: dict[str, str]
    error: str | None = None


class ProbeTransport(Protocol):
    name: str

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        *,
        follow_redirects: bool = True,
        timeout: float = 10.0,
    ) -> ProbeResponse: ...


class HttpxTransport:
    name = "httpx"

    def __init__(self, *, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout, follow_redirects=False)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        *,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> ProbeResponse:
        _ = follow_redirects
        # Remove Content-Length to avoid mismatch with body bytes
        safe_headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
        
        # httpx handles body=b"" with None better when no body is actually intended
        actual_body = body if body and len(body) > 0 else None

        try:
            resp = self._client.request(
                method,
                url,
                headers=safe_headers,
                content=actual_body,
                timeout=timeout if timeout is not None else self._timeout,
            )
            return ProbeResponse(
                status=resp.status_code,
                body=bytes(resp.content or b""),
                headers={str(k): str(v) for k, v in resp.headers.items()},
            )
        except (httpx.HTTPError, httpx.InvalidURL, UnicodeEncodeError, ValueError, TypeError) as exc:
            return ProbeResponse(status=None, body=b"", headers={}, error=str(exc)[:200])

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpxTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class ZapTransport:
    name = "zap"

    def __init__(self, zap: Any) -> None:
        self._zap = zap

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        *,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> ProbeResponse:
        _ = follow_redirects, timeout
        try:
            body_str = body.decode("utf-8", errors="replace") if body else ""
            if isinstance(body, bytes) and body and body_str == "":
                body_str = body.decode("latin-1", errors="replace")
            probe = {
                "method": method.upper(),
                "url": url,
                "headers": headers,
                "body": body_str,
            }
            raw = format_raw_http_request(probe)
            full = zap_send_raw_request_full(self._zap, raw)
        except (ValueError, UnicodeEncodeError, TypeError) as exc:
            return ProbeResponse(status=None, body=b"", headers={}, error=str(exc)[:200])
        if full is None:
            return ProbeResponse(status=None, body=b"", headers={}, error="zap_send_failed")
        return ProbeResponse(
            status=full.status,
            body=full.body,
            headers={str(k): str(v) for k, v in full.headers.items()},
        )
