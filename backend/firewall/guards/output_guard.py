"""Output scanning and redaction for secrets, PII, tokens and URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass


_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE,
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "api_key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|"
            r"xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|"
            r"AIza[0-9A-Za-z_-]{35})\b"
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key|"
            r"password|client[_ -]?secret|şifre|parola)\b\s*[:=]\s*"
            r"[\"']?[A-Za-z0-9_./+=:-]{8,}"
        ),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
    ),
    (
        "email",
        re.compile(
            r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
        ),
    ),
    (
        "ssn",
        re.compile(r"(?<!\d)(?:\d{3}-\d{2}-\d{4})(?!\d)"),
    ),
    (
        "phone",
        re.compile(r"(?<!\w)\+?\d(?:[\d .()\-]{7,}\d)(?!\w)"),
    ),
    (
        "turkish_id",  # T.C. Kimlik (heuristic)
        re.compile(r"(?<!\d)\d{11}(?!\d)"),
    ),
    (
        "url",
        re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    ),
)

_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str
    findings: tuple[str, ...]

    @property
    def redacted(self) -> bool:
        return bool(self.findings)


def _passes_luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class OutputGuard:
    def __init__(self, redact_urls: bool = True) -> None:
        self.redact_urls = redact_urls

    def redact(self, text: str) -> RedactionResult:
        if not text:
            return RedactionResult(text="", findings=())

        findings: set[str] = set()
        result = text

        # Private keys first (multi-line)
        if _PRIVATE_KEY.search(result):
            result = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", result)
            findings.add("private_key")

        for name, pattern in _SECRET_PATTERNS:
            if name == "url" and not self.redact_urls:
                continue
            if pattern.search(result):
                result = pattern.sub(f"[REDACTED_{name.upper()}]", result)
                findings.add(name)

        # Credit cards (Luhn check)
        def card_replacer(m: re.Match[str]) -> str:
            raw = m.group(0)
            digits_only = re.sub(r"[^\d]", "", raw)
            if _passes_luhn(digits_only):
                findings.add("payment_card")
                return "[REDACTED_CARD]"
            return raw

        result = _CARD_CANDIDATE.sub(card_replacer, result)

        return RedactionResult(text=result, findings=tuple(sorted(findings)))
