"""In-process metrics for dashboard and Prometheus export."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class Metrics:
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    redactions: int = 0
    total_latency_ms: float = 0.0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record(self, blocked: bool, latency_ms: float, redacted: bool = False) -> None:
        with self._lock:
            self.total_requests += 1
            if blocked:
                self.blocked_requests += 1
            else:
                self.allowed_requests += 1
            if redacted:
                self.redactions += 1
            self.total_latency_ms += latency_ms

    def snapshot(self) -> dict:
        with self._lock:
            avg = (
                self.total_latency_ms / self.total_requests
                if self.total_requests
                else 0.0
            )
            rate = (
                self.blocked_requests / self.total_requests
                if self.total_requests
                else 0.0
            )
            return {
                "total_requests": self.total_requests,
                "blocked_requests": self.blocked_requests,
                "allowed_requests": self.allowed_requests,
                "redactions": self.redactions,
                "avg_latency_ms": round(avg, 2),
                "block_rate": round(rate, 4),
            }


_metrics = Metrics()


def get_metrics() -> Metrics:
    return _metrics
