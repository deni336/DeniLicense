import ipaddress
from types import SimpleNamespace

from starlette.requests import Request

from denilicense.middleware import ClientSourceResolver, RateLimiter


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": (peer, 1234),
        "server": ("test", 80),
        "scheme": "http",
        "query_string": b"",
    }
    return Request(scope)


def test_forwarding_chain_is_used_only_for_trusted_peer() -> None:
    resolver = ClientSourceResolver([ipaddress.ip_network("10.0.0.0/8")], b"p" * 32)
    assert resolver.address(_request("192.0.2.1", "198.51.100.2")) == "192.0.2.1"
    assert resolver.address(_request("10.0.0.1", "198.51.100.2, 10.1.1.1")) == "198.51.100.2"


def test_rate_limiter_returns_dynamic_retry() -> None:
    resolver = SimpleNamespace(address=lambda _request: "source")
    limiter = RateLimiter(1, 60, resolver)  # type: ignore[arg-type]
    allowed, _ = limiter._allow("source", 100.0)
    denied, retry = limiter._allow("source", 100.0)
    assert allowed is True
    assert denied is False
    assert retry == 60
