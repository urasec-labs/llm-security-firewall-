"""Upstream LLM adapters: demo (local) or proxy to OpenAI-compatible endpoint."""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator

import httpx

from firewall.config import Settings


class UpstreamError(Exception):
    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class DemoAdapter:
    """Deterministic local responses – no external network required."""

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        messages = body.get("messages", [])
        last_user = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                content = m.get("content") or ""
                if isinstance(content, list):
                    content = " ".join(
                        p.get("text", "") for p in content if isinstance(p, dict)
                    )
                last_user = str(content)[:500]
                break

        reply = (
            f"[Demo Upstream] Received safe prompt. "
            f"Summary of your message: {last_user[:200] or '(empty)'} "
            f"— This is a simulated response. No external LLM was called."
        )
        return {
            "id": f"chatcmpl-demo-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model", "demo-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }


class ProxyAdapter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = httpx.AsyncClient(
            timeout=settings.upstream_timeout_seconds,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20),
        )

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.settings.upstream_base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.settings.upstream_api_key:
            headers["Authorization"] = f"Bearer {self.settings.upstream_api_key}"

        try:
            resp = await self._client.post(url, json=body, headers=headers)
        except httpx.RequestError as exc:
            raise UpstreamError(f"Upstream connection error: {exc}") from exc

        if resp.status_code >= 400:
            raise UpstreamError(
                f"Upstream returned {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
            )
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def build_upstream(settings: Settings):
    if settings.upstream_mode == "demo":
        return DemoAdapter()
    return ProxyAdapter(settings)
