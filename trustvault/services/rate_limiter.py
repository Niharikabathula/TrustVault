import time
from threading import Lock
from typing import Dict, List, Optional


class IPRateLimiter:
    """
    Thread-safe, sliding-window in-memory IP rate limiter.
    Provides effective rate limiting across all login attempts,
    including attempts against unknown, non-existent, or random emails.
    """

    def __init__(self, max_requests: int = 20, window_seconds: int = 900):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._records: Dict[str, List[float]] = {}
        self._lock = Lock()

    def is_rate_limited(self, ip_address: str) -> bool:
        """Check if an IP address has exceeded the maximum allowed attempts within the window."""
        if not ip_address:
            return False

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            attempts = self._records.get(ip_address, [])
            # Filter attempts older than cutoff
            valid_attempts = [t for t in attempts if t > cutoff]
            self._records[ip_address] = valid_attempts

            return len(valid_attempts) >= self.max_requests

    def record_attempt(self, ip_address: str) -> None:
        """Record an attempt from the specified IP address."""
        if not ip_address:
            return

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            attempts = self._records.get(ip_address, [])
            valid_attempts = [t for t in attempts if t > cutoff]
            valid_attempts.append(now)
            self._records[ip_address] = valid_attempts

    def reset(self, ip_address: Optional[str] = None) -> None:
        """Reset rate-limiting records (useful for testing or after successful authentication)."""
        with self._lock:
            if ip_address:
                self._records.pop(ip_address, None)
            else:
                self._records.clear()


# Global singleton instance for authentication endpoints
login_rate_limiter = IPRateLimiter(max_requests=20, window_seconds=900)
