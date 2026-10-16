"""Simple structured audit logger (in-memory + stdout)."""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Deque

logger = logging.getLogger("firewall.audit")


@dataclass
class AuditEvent:
    ts: float
    event: str
    identity: str
    findings: list[str]
    risk_score: float
    latency_ms: float
    blocked: bool


class AuditLogger:
    def __init__(self, max_events: int = 5000) -> None:
        self._events: Deque[AuditEvent] = deque(maxlen=max_events)

    def log(self, event: AuditEvent) -> None:
        self._events.append(event)
        logger.info(
            json.dumps(
                {
                    "ts": event.ts,
                    "event": event.event,
                    "identity": event.identity,
                    "findings": event.findings,
                    "risk_score": round(event.risk_score, 4),
                    "latency_ms": round(event.latency_ms, 2),
                    "blocked": event.blocked,
                },
                ensure_ascii=False,
            )
        )

    def recent(self, n: int = 50) -> list[dict[str, Any]]:
        return [asdict(e) for e in list(self._events)[-n:]]


_audit = AuditLogger()


def get_audit_logger() -> AuditLogger:
    return _audit
