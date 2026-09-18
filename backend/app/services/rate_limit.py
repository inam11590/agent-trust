"""Local and Redis-backed request rate limiters."""

import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Hashable


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[Hashable, deque[datetime]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key_id: Hashable, limit: int, now: datetime | None = None) -> bool:
        checked_at = now or datetime.now(timezone.utc)
        cutoff = checked_at - timedelta(minutes=1)
        with self._lock:
            events = self._events[key_id]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(checked_at)
            return True

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


developer_rate_limiter = RateLimiter()


class RedisRateLimiter:
    """Fixed-window distributed limiter. Redis data is disposable security state."""

    def __init__(self, redis_url: str, namespace: str = "agenttrust:rate"):
        try:
            from redis import Redis
            self.client = Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
        except (ImportError, ValueError) as exc:
            raise RuntimeError("Redis rate limiting is unavailable") from exc
        self.namespace = namespace
    def allow(self, key_id: Hashable, limit: int, now: datetime | None = None) -> bool:
        checked_at = now or datetime.now(timezone.utc)
        window = int(checked_at.timestamp()) // 60
        digest = hashlib.sha256(str(key_id).encode()).hexdigest()[:32]
        key = f"{self.namespace}:{window}:{digest}"
        try:
            with self.client.pipeline() as pipe:
                pipe.incr(key)
                pipe.expire(key, 120, nx=True)
                count, _ = pipe.execute()
            return int(count) <= limit
        except Exception:
            # Fail closed: a limiter outage must not remove authentication protection.
            return False
    def clear(self) -> None:
        return None


def create_rate_limiter(settings, namespace: str):
    if settings.rate_limit_backend == "redis":
        return RedisRateLimiter(settings.redis_url.get_secret_value(), namespace)
    return RateLimiter()
