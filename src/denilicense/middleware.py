from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import math
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("denilicense.http")


class ClientSourceResolver:
    def __init__(
        self,
        trusted_proxies: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
        hash_key: bytes,
    ) -> None:
        self._trusted = tuple(trusted_proxies)
        self._hash_key = bytes(hash_key)

    def _is_trusted(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(address in network for network in self._trusted)

    def address(self, request: Request) -> str:
        raw_peer = request.client.host if request.client else ""
        try:
            peer = ipaddress.ip_address(raw_peer.split("%", 1)[0])
        except ValueError:
            return "unknown"
        if not self._is_trusted(peer):
            return str(peer)
        values = request.headers.getlist("x-forwarded-for")
        if not values:
            return str(peer)
        forwarded = [part.strip() for part in ",".join(values).split(",")]
        candidate = peer
        for value in reversed(forwarded):
            if not self._is_trusted(candidate):
                break
            try:
                candidate = ipaddress.ip_address(value)
            except ValueError:
                return str(peer)
        return str(candidate)

    def source_hash(self, request: Request) -> str:
        digest = hmac.new(
            self._hash_key,
            b"DeniLicense/request-source/v1\x00" + self.address(request).encode(),
            hashlib.sha256,
        ).digest()
        import base64

        return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@dataclass(slots=True)
class _Bucket:
    tokens: float
    last: float


class RateLimiter:
    def __init__(self, capacity: int, window_seconds: float, resolver: ClientSourceResolver) -> None:
        self._capacity = float(capacity)
        self._refill = capacity / window_seconds
        self._resolver = resolver
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._last_gc = time.monotonic()

    def _allow(self, key: str, now: float) -> tuple[bool, int]:
        with self._lock:
            bucket = self._buckets.get(key, _Bucket(self._capacity, now))
            bucket.tokens = min(self._capacity, bucket.tokens + (now - bucket.last) * self._refill)
            bucket.last = now
            allowed = bucket.tokens >= 1
            if allowed:
                bucket.tokens -= 1
            self._buckets[key] = bucket
            if now - self._last_gc > 600:
                self._buckets = {
                    candidate: entry for candidate, entry in self._buckets.items() if now - entry.last <= 3600
                }
                self._last_gc = now
            retry_after = max(1, math.ceil((1 - bucket.tokens) / self._refill)) if not allowed else 0
            return allowed, retry_after

    def enforce(self, request: Request) -> None:
        allowed, retry_after = self._allow(self._resolver.address(request), time.monotonic())
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Wait before trying again.",
                headers={"Retry-After": str(retry_after)},
            )


class RequestMiddleware:
    def __init__(self, app: ASGIApp, resolver: ClientSourceResolver, *, production: bool) -> None:
        self.app = app
        self.resolver = resolver
        self.production = production

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = secrets.token_hex(16)
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status = 500
        bytes_written = 0
        path = scope.get("path", "")
        is_ui = path == "/ui" or path.startswith("/ui/")

        async def wrapped_send(message: Message) -> None:
            nonlocal status, bytes_written
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                content_security_policy = (
                    b"default-src 'none'; script-src 'self'; style-src 'self'; "
                    b"connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                    b"manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                    b"form-action 'self'; object-src 'none'"
                    if is_ui
                    else b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
                )
                security = {
                    b"x-request-id": request_id.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"content-security-policy": content_security_policy,
                    b"cross-origin-resource-policy": b"same-origin",
                }
                if self.production:
                    security[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                existing = {name.lower() for name, _ in headers}
                headers.extend((name, value) for name, value in security.items() if name not in existing)
                message["headers"] = headers
            elif message["type"] == "http.response.body":
                bytes_written += len(message.get("body", b""))
            await send(message)

        request = Request(scope, receive=receive)
        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            logger.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "bytes": bytes_written,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "source_hash": self.resolver.source_hash(request),
                },
            )


Handler = Callable[[Request], Awaitable[Any]]
