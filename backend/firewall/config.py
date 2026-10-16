"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "azure": "https://example.openai.azure.com",
    "demo": "http://localhost",
}


@dataclass(frozen=True, slots=True)
class Settings:
    upstream_mode: Literal["demo", "proxy"] = "demo"
    upstream_provider: Literal["openai", "azure", "demo"] = "demo"
    upstream_base_url: str = "http://localhost"
    upstream_api_key: str | None = None
    upstream_timeout_seconds: float = 60.0
    max_upstream_response_bytes: int = 2_000_000
    max_body_bytes: int = 1_000_000
    max_prompt_chars: int = 32_000
    classifier_model_path: str | None = None
    classifier_block_threshold: float = 0.55
    semantic_enabled: bool = False
    semantic_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    semantic_block_threshold: float = 0.75
    redact_urls: bool = True
    auth_required: bool = True
    client_api_key: str | None = None
    rate_limit_requests: int = 60
    rate_limit_window_seconds: float = 60.0
    rate_limit_max_keys: int = 10_000
    port: int = 8080

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.getenv("UPSTREAM_MODE", "demo").lower()
        if mode not in ("demo", "proxy"):
            mode = "demo"
        provider = os.getenv("UPSTREAM_PROVIDER", "demo").lower()
        if provider not in ("openai", "azure", "demo"):
            provider = "demo"

        timeout = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "60"))
        max_upstream = int(os.getenv("MAX_UPSTREAM_RESPONSE_BYTES", "2000000"))
        max_body = int(os.getenv("MAX_BODY_BYTES", "1000000"))
        max_prompt = int(os.getenv("MAX_PROMPT_CHARS", "32000"))
        clf_thr = float(os.getenv("CLASSIFIER_BLOCK_THRESHOLD", "0.55"))
        sem_thr = float(os.getenv("SEMANTIC_BLOCK_THRESHOLD", "0.75"))
        rate_req = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
        rate_win = float(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
        rate_keys = int(os.getenv("RATE_LIMIT_MAX_KEYS", "10000"))

        return cls(
            upstream_mode=mode,  # type: ignore
            upstream_provider=provider,  # type: ignore
            upstream_base_url=os.getenv(
                "UPSTREAM_BASE_URL", PROVIDER_BASE_URLS.get(provider, "http://localhost")
            ),
            upstream_api_key=os.getenv("UPSTREAM_API_KEY") or None,
            upstream_timeout_seconds=timeout,
            max_upstream_response_bytes=max_upstream,
            max_body_bytes=max_body,
            max_prompt_chars=max_prompt,
            classifier_model_path=os.getenv("CLASSIFIER_MODEL_PATH") or None,
            classifier_block_threshold=clf_thr,
            semantic_enabled=_as_bool(os.getenv("SEMANTIC_ENABLED"), False),
            semantic_model=os.getenv(
                "SEMANTIC_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
            ),
            semantic_block_threshold=sem_thr,
            redact_urls=_as_bool(os.getenv("REDACT_URLS"), True),
            auth_required=_as_bool(os.getenv("AUTH_REQUIRED"), False),  # False for demo ease
            client_api_key=os.getenv("CLIENT_API_KEY") or None,
            rate_limit_requests=rate_req,
            rate_limit_window_seconds=rate_win,
            rate_limit_max_keys=rate_keys,
            port=int(os.getenv("PORT", "8080")),
        )
