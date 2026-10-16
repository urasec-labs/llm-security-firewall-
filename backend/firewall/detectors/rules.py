"""Advanced deterministic rules for prompt injection, jailbreak and exfiltration.

Supports English + Turkish attack patterns. Fast path before ML models.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Attack signature database (English + Turkish)
# ---------------------------------------------------------------------------

ATTACK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # --- Instruction Override ---
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|bypass|override)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|system|safety)\s+"
            r"(?:instructions?|rules?|messages?|prompts?|guidelines?|policies?)\b"
        ),
    ),
    (
        "instruction_override_tr",
        re.compile(
            r"(?i)\b(?:önceki|önceki tüm|sistem|güvenlik)\s+"
            r"(?:talimatları|kuralları|mesajları|yönergeleri)\s+"
            r"(?:yoksay|unut|görmezden gel|devre dışı bırak|geçersiz kıl)\b"
            r"|\b(?:yoksay|unut|görmezden gel)\s+(?:önceki|tüm|sistem)\s+"
            r"(?:talimatları|kuralları)\b"
        ),
    ),
    # --- System / Hidden Prompt Disclosure ---
    (
        "hidden_prompt_disclosure",
        re.compile(
            r"(?i)\b(?:reveal|print|show|repeat|dump|expose|leak|display|output)\s+"
            r"(?:the\s+)?(?:hidden|system|developer|initial|secret|internal)\s+"
            r"(?:prompt|instructions?|message|context|rules?)\b"
        ),
    ),
    (
        "hidden_prompt_disclosure_tr",
        re.compile(
            r"(?i)\b(?:sistem|gizli|geliştirici|iç)\s+"
            r"(?:promptu|talimatı|mesajı|bağlamı)\s+"
            r"(?:göster|yazdır|açıkla|sızdır|ifşa et|tekrar et)\b"
            r"|\b(?:göster|yazdır|ifşa et)\s+(?:sistem|gizli)\s+(?:prompt|talimat)\b"
        ),
    ),
    # --- Jailbreak Personas ---
    (
        "jailbreak_persona",
        re.compile(
            r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+"
            r"(?:an?\s+)?(?:dan|jailbroken|uncensored|unrestricted|evil|unfiltered)\b"
            r"|\b(?:dan|do\s+anything\s+now)\b"
        ),
    ),
    (
        "jailbreak_persona_tr",
        re.compile(
            r"(?i)\b(?:şimdi sen|rol yap|gibi davran)\s+"
            r"(?:sınırsız|sansürsüz|kısıtlamasız|kötü|filtre edilmemiş)\b"
            r"|\b(?:jailbreak|dan\s+modu)\b"
        ),
    ),
    # --- Privileged / Developer Mode ---
    (
        "privileged_mode",
        re.compile(
            r"(?i)\b(?:enable|activate|enter|switch\s+to|turn\s+on)\s+"
            r"(?:developer|god|admin|root|dan|jailbreak|unrestricted)\s+mode\b"
        ),
    ),
    (
        "privileged_mode_tr",
        re.compile(
            r"(?i)\b(?:geliştirici|yönetici|root|tanrı|jailbreak)\s+modu?\s+"
            r"(?:aç|etkinleştir|aktifleştir|geç)\b"
        ),
    ),
    # --- Credential / Data Exfiltration ---
    (
        "credential_exfiltration",
        re.compile(
            r"(?i)\b(?:send|upload|forward|post|exfiltrate|email|transmit|leak|dump)\b"
            r".{0,100}\b(?:api\s*keys?|passwords?|credentials?|access\s*tokens?|"
            r"secrets?|private\s*keys?|ssh\s*keys?|tokens?)\b"
        ),
    ),
    (
        "credential_exfiltration_tr",
        re.compile(
            r"(?i)\b(?:gönder|yükle|iletir|sızdır|email\s+at|aktar)\b"
            r".{0,80}\b(?:api\s*anahtar|şifre|parola|token|gizli\s*anahtar|"
            r"erişim\s*anahtarı|credentials?)\b"
        ),
    ),
    # --- Override Markers / Prompt Injection via tags ---
    (
        "override_marker",
        re.compile(
            r"(?i)(?:\[\s*(?:system|developer|admin)\s*(?:prompt|instructions?)?\s*\]"
            r"|<\s*/?\s*(?:system|developer|admin)\s*>"
            r"|```\s*system\b)"
        ),
    ),
    # --- Role Confusion / New Instructions ---
    (
        "new_instructions",
        re.compile(
            r"(?i)\b(?:new\s+instructions?|from\s+now\s+on|your\s+new\s+role|"
            r"updated\s+system\s+prompt)\b"
        ),
    ),
    # --- Encoding / Obfuscation attempts (heuristic) ---
    (
        "base64_payload_hint",
        re.compile(
            r"(?i)\b(?:decode|base64|decode\s+this|çöz)\b.{0,40}"
            r"(?:ignore|system|prompt|jailbreak|yoksay)"
        ),
    ),
)


_BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{32,}={0,2}(?![A-Za-z0-9_+/-])"
)
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


@dataclass(frozen=True, slots=True)
class RuleScan:
    """Deterministic findings. Original prompt is never returned."""

    findings: tuple[str, ...]

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


def _normalize(text: str) -> str:
    """NFKC + strip control characters except common whitespace."""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(
        ch
        for ch in normalized
        if unicodedata.category(ch) not in {"Cf", "Cc"} or ch in "\n\t\r "
    )


def _decode_unicode_escapes(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    return _UNICODE_ESCAPE.sub(repl, text)


def _decode_hex_escapes(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    return _HEX_ESCAPE.sub(repl, text)


def _try_decode_base64_fragments(text: str) -> list[str]:
    """Attempt to decode long base64-looking substrings."""
    decoded: list[str] = []
    for match in _BASE64_CANDIDATE.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=False)
            if len(raw) > 8:
                try:
                    decoded.append(raw.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        except (binascii.Error, ValueError):
            continue
    return decoded


class HeuristicDetector:
    """Fast multi-stage rule engine with de-obfuscation."""

    def scan(self, text: str) -> RuleScan:
        if not text or not text.strip():
            return RuleScan(findings=())

        normalized = _normalize(text)
        # Multi-pass de-obfuscation
        candidates = [normalized]
        candidates.append(_decode_unicode_escapes(normalized))
        candidates.append(_decode_hex_escapes(normalized))
        for frag in _try_decode_base64_fragments(normalized):
            candidates.append(_normalize(frag))

        findings: set[str] = set()
        for candidate in candidates:
            for name, pattern in ATTACK_RULES:
                if pattern.search(candidate):
                    findings.add(name)

        return RuleScan(findings=tuple(sorted(findings)))
