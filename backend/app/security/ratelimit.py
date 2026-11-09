"""In-process sliding-window rate limiter (per key). Sufficient for a single API container;
login lockout is additionally persisted on the admin row."""
import threading
import time
from collections import deque

SWEEP_EVERY = 300.0  # seconds: keys with no hit inside their window are dropped, so memory follows active keys only


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._windows: dict[str, float] = {}
        self._lock = threading.Lock()
        self._swept = time.monotonic()

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        """Record a hit; return False when the key exceeded `limit` within the window."""
        now = time.monotonic()
        with self._lock:
            if now - self._swept > SWEEP_EVERY:
                self._sweep(now)
            q = self._hits.setdefault(key, deque())
            self._windows[key] = window_seconds
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def _sweep(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] > self._windows.get(k, 60.0)]:
            self._hits.pop(key, None)
            self._windows.pop(key, None)
        self._swept = now


limiter = RateLimiter()
