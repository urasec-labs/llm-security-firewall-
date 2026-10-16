"""API key auth + sliding-window rate limiter."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque

from fastapi import HTTPException, Request


class InMemoryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: float, max_keys: int) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self.max_keys = max_keys
        self._buckets: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > self.max_keys and key not in self._buckets:
                # simple eviction of oldest key
                oldest = next(iter(self._buckets))
                del self._buckets[oldest]
            q = self._buckets[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True


def request_identity(request: Request) -> str:
    # Prefer API key, fallback to client IP
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return f"key:{auth[7:15]}..."
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return f"ip:{forwarded.split(',')[0].strip()}"
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


def enforce_access(
    request: Request,
    auth_required: bool,
    client_api_key: str | None,
    limiter: InMemoryRateLimiter,
) -> str:
    identity = request_identity(request)

    if auth_required and client_api_key:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer token")
        token = auth[7:].strip()
        if token != client_api_key:
            raise HTTPException(status_code=403, detail="Invalid API key")

    if not limiter.allow(identity):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    return identity
