"""FastAPI entry point – LLM Security Firewall Advanced."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from firewall import __version__
from firewall.access_control import InMemoryRateLimiter, enforce_access
from firewall.audit import get_audit_logger
from firewall.config import Settings
from firewall.gateway import Gateway, decision_to_dict
from firewall.metrics import get_metrics
from firewall.models import (
    ChatCompletionRequest,
    HealthResponse,
    MetricsSnapshot,
    ScanResponse,
    TextScanRequest,
)
from firewall.upstream import UpstreamError

settings = Settings.from_env()
limiter = InMemoryRateLimiter(
    settings.rate_limit_requests,
    settings.rate_limit_window_seconds,
    settings.rate_limit_max_keys,
)
gateway = Gateway(settings)
security = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await gateway.initialize()
    yield
    # cleanup if needed


app = FastAPI(
    title="LLM Security Firewall Advanced",
    description="Multi-layer protection for LLM applications – TÜBİTAK / Teknofest ready",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_identity(request: Request) -> str:
    return enforce_access(
        request,
        settings.auth_required,
        settings.client_api_key,
        limiter,
    )


@app.get("/api/healthz", response_model=HealthResponse)
async def healthz():
    return HealthResponse(
        status="ok",
        version=__version__,
        upstream_mode=settings.upstream_mode,
        semantic_enabled=settings.semantic_enabled,
    )


@app.get("/api/metrics", response_model=MetricsSnapshot)
async def metrics():
    snap = get_metrics().snapshot()
    return MetricsSnapshot(**snap)


@app.get("/api/audit")
async def audit_log(limit: int = 50):
    return {"events": get_audit_logger().recent(min(limit, 200))}


@app.post("/api/scan/input", response_model=ScanResponse)
async def scan_input(body: TextScanRequest, identity: str = Depends(get_identity)):
    decision = await gateway.scan_input(body.text)
    return ScanResponse(
        blocked=decision.blocked,
        risk_score=decision.risk_score,
        findings=list(decision.findings),
        classifier_score=decision.classifier_score,
        semantic_similarity=decision.semantic_similarity,
        layer_triggered=decision.layer_triggered,
    )


@app.post("/api/scan/output", response_model=ScanResponse)
async def scan_output(body: TextScanRequest, identity: str = Depends(get_identity)):
    result = gateway.scan_output(body.text)
    return ScanResponse(
        blocked=False,
        risk_score=1.0 if result.redacted else 0.0,
        findings=list(result.findings),
        redacted_text=result.text,
    )


@app.post("/api/chat/completions")
async def chat_completions(
    request: Request,
    body: ChatCompletionRequest,
    identity: str = Depends(get_identity),
):
    raw = body.model_dump(exclude_none=True)
    try:
        result = await gateway.chat_completions(raw, identity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UpstreamError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    if "error" in result and result["error"].get("code") == "blocked":
        return JSONResponse(status_code=403, content=result)
    return result


@app.get("/")
async def root():
    return {
        "name": "LLM Security Firewall Advanced",
        "version": __version__,
        "docs": "/docs",
        "health": "/api/healthz",
    }
