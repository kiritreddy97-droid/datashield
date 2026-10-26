"""Fixed-window in-memory rate limiter. Per process: with several instances, move the counters to Redis."""

import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self):
        self._hits: dict[tuple[str, str], tuple[float, int]] = defaultdict(lambda: (0.0, 0))
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def check(self, scope: str, key: str, limit: int, window: float, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            start, count = self._hits[(scope, key)]
            if now - start >= window:
                start, count = now, 0
            count += 1
            self._hits[(scope, key)] = (start, count)
            retry = int(window - (now - start)) + 1
        if count > limit:
            raise HTTPException(429, "too many requests", headers={"Retry-After": str(retry)})


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def limit(scope: str, limit_: int, window: float = 60.0):
    """Route dependency: at most `limit_` calls per `window` seconds per client IP."""

    def dep(request: Request) -> None:
        limiter.check(scope, client_ip(request), limit_, window)

    return dep
