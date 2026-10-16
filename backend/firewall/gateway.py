"""Orchestrates input guard → upstream → output guard."""

from __future__ import annotations

import time
from typing import Any

from firewall.audit import AuditEvent, get_audit_logger
from firewall.config import Settings
from firewall.guards.input_guard import InputGuard, InputDecision
from firewall.guards.output_guard import OutputGuard
from firewall.metrics import get_metrics
from firewall.upstream import build_upstream, UpstreamError


def decision_to_dict(d: InputDecision) -> dict[str, Any]:
    return {
        "blocked": d.blocked,
        "risk_score": round(d.risk_score, 4),
        "findings": list(d.findings),
        "classifier_score": round(d.classifier_score, 4),
        "semantic_similarity": round(d.semantic_similarity, 4),
        "layer_triggered": d.layer_triggered,
    }


class Gateway:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.input_guard = InputGuard(settings)
        self.output_guard = OutputGuard(redact_urls=settings.redact_urls)
        self.upstream = build_upstream(settings)
        self.audit = get_audit_logger()
        self.metrics = get_metrics()

    async def initialize(self) -> None:
        await self.input_guard.initialize()

    async def scan_input(self, text: str) -> InputDecision:
        return await self.input_guard.scan(text)

    def scan_output(self, text: str):
        return self.output_guard.redact(text)

    async def chat_completions(
        self, body: dict[str, Any], identity: str
    ) -> dict[str, Any]:
        start = time.perf_counter()

        # Collect untrusted content (user + tool roles only)
        texts: list[str] = []
        for msg in body.get("messages", []):
            role = msg.get("role")
            if role in ("user", "tool"):
                content = msg.get("content")
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            texts.append(str(part.get("text", "")))

        combined = "\n".join(texts)
        if len(combined) > self.settings.max_prompt_chars:
            raise ValueError("Prompt exceeds maximum allowed characters")

        decision = await self.input_guard.scan(combined)
        latency_ms = (time.perf_counter() - start) * 1000

        if decision.blocked:
            self.metrics.record(blocked=True, latency_ms=latency_ms)
            self.audit.log(
                AuditEvent(
                    ts=time.time(),
                    event="input_blocked",
                    identity=identity,
                    findings=list(decision.findings),
                    risk_score=decision.risk_score,
                    latency_ms=latency_ms,
                    blocked=True,
                )
            )
            return {
                "error": {
                    "message": "Request blocked by LLM Security Firewall",
                    "type": "policy_violation",
                    "code": "blocked",
                    "firewall": decision_to_dict(decision),
                }
            }

        # Forward to upstream
        try:
            upstream_resp = await self.upstream.complete(body)
        except UpstreamError as exc:
            raise

        # Redact output
        choices = upstream_resp.get("choices") or []
        redacted_any = False
        for choice in choices:
            msg = choice.get("message") or {}
            content = msg.get("content")
            if isinstance(content, str) and content:
                result = self.output_guard.redact(content)
                if result.redacted:
                    msg["content"] = result.text
                    redacted_any = True
                    choice["firewall_redactions"] = list(result.findings)

        total_latency = (time.perf_counter() - start) * 1000
        self.metrics.record(
            blocked=False, latency_ms=total_latency, redacted=redacted_any
        )
        self.audit.log(
            AuditEvent(
                ts=time.time(),
                event="allowed",
                identity=identity,
                findings=[],
                risk_score=decision.risk_score,
                latency_ms=total_latency,
                blocked=False,
            )
        )

        upstream_resp["firewall"] = {
            "input": decision_to_dict(decision),
            "output_redacted": redacted_any,
        }
        return upstream_resp
