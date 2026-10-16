"""Composable multi-layer input screening pipeline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from firewall.config import Settings
from firewall.detectors.classifier import PromptClassifier
from firewall.detectors.rules import HeuristicDetector
from firewall.detectors.semantic import MiniLMSimilarityDetector


@dataclass(frozen=True, slots=True)
class InputDecision:
    blocked: bool
    risk_score: float
    findings: tuple[str, ...]
    semantic_similarity: float
    classifier_score: float
    layer_triggered: str  # which layer primarily blocked


class InputGuard:
    """Cheap deterministic checks first → ML → optional semantic."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.heuristics = HeuristicDetector()
        self.classifier = PromptClassifier(settings.classifier_model_path)
        self.semantic = MiniLMSimilarityDetector(
            model_name=settings.semantic_model,
            threshold=settings.semantic_block_threshold,
        )

    async def initialize(self) -> None:
        self.classifier.load_or_train()
        if self.settings.semantic_enabled:
            await self.semantic.initialize()

    async def scan(self, text: str) -> InputDecision:
        # Layer 1: Rules (fastest)
        rule_scan = self.heuristics.scan(text)
        if rule_scan.blocked:
            return InputDecision(
                blocked=True,
                risk_score=1.0,
                findings=rule_scan.findings,
                semantic_similarity=0.0,
                classifier_score=0.0,
                layer_triggered="rules",
            )

        # Layer 2: Classifier
        classifier_score = await asyncio.to_thread(self.classifier.attack_score, text)
        if classifier_score >= self.settings.classifier_block_threshold:
            return InputDecision(
                blocked=True,
                risk_score=classifier_score,
                findings=("classifier:high_risk",),
                semantic_similarity=0.0,
                classifier_score=classifier_score,
                layer_triggered="classifier",
            )

        # Layer 3: Semantic (optional, slower)
        semantic_score = 0.0
        if self.settings.semantic_enabled:
            semantic_score = await self.semantic.score(text)
            if semantic_score >= self.settings.semantic_block_threshold:
                return InputDecision(
                    blocked=True,
                    risk_score=semantic_score,
                    findings=("semantic:high_similarity",),
                    semantic_similarity=semantic_score,
                    classifier_score=classifier_score,
                    layer_triggered="semantic",
                )

        return InputDecision(
            blocked=False,
            risk_score=max(classifier_score, semantic_score),
            findings=(),
            semantic_similarity=semantic_score,
            classifier_score=classifier_score,
            layer_triggered="none",
        )
