"""Pydantic request/response models."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "developer"]
    content: str | list[Any] | None = None
    name: Optional[str] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = "demo-model"
    messages: list[ChatMessage]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False
    tools: Optional[list[Any]] = None
    tool_choice: Optional[Any] = None


class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)


class ScanResponse(BaseModel):
    blocked: bool
    risk_score: float
    findings: list[str]
    classifier_score: float = 0.0
    semantic_similarity: float = 0.0
    layer_triggered: str = "none"
    redacted_text: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    upstream_mode: str
    semantic_enabled: bool


class MetricsSnapshot(BaseModel):
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    redactions: int
    avg_latency_ms: float
    block_rate: float
EOF

cat > firewall/audit.py << 'PYEOF'
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
