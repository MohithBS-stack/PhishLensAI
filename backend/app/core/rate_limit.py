"""In-memory sliding window rate limiter for authentication endpoints.

Note:
This implementation is process-local. In a multi-worker or multi-instance deployment
(such as multiple horizontal Render instances), limits are enforced per-process.
For distributed enforcement across multiple stateless workers, a shared store like Redis
can be plugged in.
"""
from collections import OrderedDict
import math
import threading
import time
from typing import Dict, List, Optional, Tuple
from fastapi import Request

from app.core.config import settings
from app.core.errors import AppException


class InMemorySlidingWindowLimiter:
    """Thread-safe in-memory sliding window rate limiter with bounded memory and LRU eviction.

    Note:
        This limiter is strictly process-local. In a multi-worker or multi-instance deployment
        (e.g., multiple horizontal Render instances), limits are tracked per process.
        A shared distributed store such as Redis is required for global cross-instance enforcement.
    """

    def __init__(self, max_buckets: int = 10000, cleanup_interval: float = 300.0) -> None:
        self._lock = threading.Lock()
        self._max_buckets = max_buckets
        self._cleanup_interval = cleanup_interval
        # OrderedDict maintains insertion/access order to bound memory via LRU eviction
        self._buckets: OrderedDict[str, List[float]] = OrderedDict()
        self._last_cleanup = time.time()

    def check_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """Checks if an event for `key` exceeds `max_requests` in `window_seconds`.

        Returns:
            Tuple[bool, int]: (allowed, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            # Periodic cleanup of empty or stale buckets
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup_stale_buckets(now)

            cutoff = now - window_seconds
            timestamps = self._buckets.get(key)
            if timestamps is None:
                # Memory capacity guard: evict oldest entries if at or over max_buckets
                if len(self._buckets) >= self._max_buckets:
                    self._cleanup_stale_buckets(now)
                    while len(self._buckets) >= self._max_buckets:
                        self._buckets.popitem(last=False)
                timestamps = []
                self._buckets[key] = timestamps
            else:
                # Mark as recently used
                self._buckets.move_to_end(key)

            # Remove timestamps outside the sliding window
            while timestamps and timestamps[0] <= cutoff:
                timestamps.pop(0)

            if len(timestamps) >= max_requests:
                earliest = timestamps[0]
                # Use math.ceil to guarantee clients waiting retry_after seconds do not retry prematurely
                retry_after = max(1, math.ceil(earliest + window_seconds - now))
                return False, retry_after

            timestamps.append(now)
            return True, 0

    def reset_key(self, key: str) -> None:
        """Clears rate limit records for a specific key (e.g. upon successful login)."""
        with self._lock:
            self._buckets.pop(key, None)

    def reset_all(self) -> None:
        """Clears all rate limit buckets (used in test fixtures)."""
        with self._lock:
            self._buckets.clear()
            self._last_cleanup = time.time()

    def _cleanup_stale_buckets(self, now: float) -> None:
        """Removes buckets that are empty or have had no activity for more than 1 hour."""
        max_retention = 3600
        stale_keys = [
            k for k, v in self._buckets.items()
            if not v or (now - v[-1] > max_retention)
        ]
        for k in stale_keys:
            self._buckets.pop(k, None)
        self._last_cleanup = now


auth_rate_limiter = InMemorySlidingWindowLimiter()


def get_client_ip(request: Request) -> str:
    """Extracts client IP safely without trusting spoofed X-Forwarded-For headers by default.

    Arbitrary client-supplied forwarding headers are ignored unless explicitly configured
    with a trusted proxy topology.
    """
    if getattr(settings, "TRUST_FORWARDED_FOR", False):
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Pick first IP in the chain from reverse proxy
            ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
            if ips:
                return ips[0]

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def enforce_rate_limit(
    request: Request,
    scope: str,
    max_requests: int,
    window_seconds: int,
    extra_identifier: Optional[str] = None,
) -> None:
    """Enforces rate limit for a given scope and client.

    Raises:
        AppException: HTTP 429 RATE_LIMIT_EXCEEDED with retry_after in details.
    """
    ip = get_client_ip(request)
    key_parts = [scope, ip]
    if extra_identifier:
        key_parts.append(extra_identifier.lower().strip())
    key = ":".join(key_parts)

    allowed, retry_after = auth_rate_limiter.check_limit(
        key=key,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    if not allowed:
        raise AppException(
            message=f"Too many requests for {scope}. Please retry in {retry_after} seconds.",
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details={"retry_after": retry_after, "scope": scope},
        )
