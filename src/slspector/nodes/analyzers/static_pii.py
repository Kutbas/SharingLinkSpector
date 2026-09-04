"""Static PII family: A-C-1..A-C-5 (identity / sensitive privacy / credentials /
technical info / digital footprint).

Patterns:
- PI-1 email/phone/national-ID (A-C-1)
- PI-2 bank card via Luhn + sensitive lexicon (A-C-2)
- PI-3 secret patterns + high-entropy tokens (A-C-3)
- PI-4 private IPs/MAC/absolute paths/container IDs (A-C-4)
- PI-5 cross-platform handles/profile URLs (A-C-5)
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable

from slspector.models import Finding
from slspector.nodes.analyzers.common import iter_matches, make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_pii"

# PI-1 direct identifiers
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_CN = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_PHONE_INTL = re.compile(r"(?<!\d)\+\d{1,3}[- ]?\(?\d{2,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}(?!\d)")
_CN_ID = re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[\dXx](?!\d)")
_PASSPORT = re.compile(r"(?<![A-Z0-9])[EGe][0-9]{8}(?![0-9])")

# PI-2 sensitive privacy
_BANK_CARD = re.compile(r"(?<!\d)[3-6]\d{15,18}(?!\d)")
_SENSITIVE_LEXICON = re.compile(
    r"诊断|确诊|病历|处方|用药|剂量|抑郁|焦虑|心理咨询|艾滋病|HIV阳性|乙肝携带|"
    r"胎儿|孕周|产检|视力残疾|听力障碍|残疾证|精神病|治疗方案|化疗|放疗|靶向药",
)

# PI-3 credentials
_SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_-]{20,}", "OpenAI-style key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key"),
    (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9+/_-]{16,}['\"]?", ".env style secret"),
]
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# PI-4 technical information
_PRIVATE_IP = re.compile(
    r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)")
_MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_UNIX_PATH = re.compile(r"(?<![\w./])/(?:home|root|var|etc|opt|srv|usr)/(?:[\w.-]+/)*[\w.-]+")
_CONTAINER_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{12,64}(?![0-9a-f])")

# PI-5 digital footprint
_HANDLE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,30}(?![\w@])")
_PROFILE_URL = re.compile(
    r"https?://(?:twitter|x|github|instagram|facebook|tiktok|weibo|zhihu|bilibili|space\.bilibili)"
    r"\.com/[@A-Za-z0-9_.-]{2,40}", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


def _luhn_ok(numstr: str) -> bool:
    digits = [int(d) for d in numstr]
    if len(digits) < 14 or len(digits) > 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum + digits[-1]) % 10 == 0


def _scan(text: str, pattern: str, flags: int, fn: Callable) -> list[Finding]:
    return fn(text, pattern, flags)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []

    def add(tax, pid, conf, msg, match, needs_review=False, evidence=None):
        findings.append(
            make_finding(
                taxonomy_id=tax, pattern_id=pid, confidence=conf, message=msg,
                state=state, pos=match.start(), matched_text=match.group(0),
                needs_review=needs_review, evidence=evidence or {},
            )
        )

    # PI-1 A-C-1
    for m in _EMAIL.finditer(text):
        add("A-C-1", "PI-1", 0.9, "email address exposure", m)
    for m in _PHONE_CN.finditer(text):
        add("A-C-1", "PI-1", 0.9, "mobile phone number exposure", m)
    for m in _PHONE_INTL.finditer(text):
        add("A-C-1", "PI-1", 0.8, "international phone number exposure", m)
    for m in _CN_ID.finditer(text):
        add("A-C-1", "PI-1", 0.95, "CN national ID pattern", m)
    for m in _PASSPORT.finditer(text):
        add("A-C-1", "PI-1", 0.8, "passport number pattern", m, needs_review=True)

    # PI-2 A-C-2
    for m in _BANK_CARD.finditer(text):
        if _luhn_ok(m.group(0)):
            add("A-C-2", "PI-2", 0.9, "bank card number (Luhn valid)", m)
    for m in _SENSITIVE_LEXICON.finditer(text):
        add("A-C-2", "PI-2", 0.5, "health/sensitive-privacy keyword", m)

    # PI-3 A-C-3
    for pat, name in _SECRET_PATTERNS:
        for m in iter_matches(pat, text):
            conf = 0.85 if "BEGIN" in pat else 0.75
            add("A-C-3", "PI-3", conf, f"credential pattern: {name}", m)
    for m in _LONG_TOKEN.finditer(text):
        tok = m.group(0)
        if _shannon_entropy(tok) > 4.5:
            add("A-C-3", "PI-3", 0.5, "high-entropy token (suspected key/encoded payload)",
                m, needs_review=True,
                evidence={"entropy": round(_shannon_entropy(tok), 2), "length": len(tok)})

    # PI-4 A-C-4
    for m in _PRIVATE_IP.finditer(text):
        add("A-C-4", "PI-4", 0.7, "private-network IP", m)
    for m in _MAC.finditer(text):
        add("A-C-4", "PI-4", 0.7, "MAC address", m)
    for m in _UNIX_PATH.finditer(text):
        add("A-C-4", "PI-4", 0.5, "server absolute path", m, needs_review=True)
    for m in _CONTAINER_ID.finditer(text):
        add("A-C-4", "PI-4", 0.4, "suspected container/hash ID", m, needs_review=True)

    # PI-5 A-C-5
    for m in _HANDLE.finditer(text):
        if not text[max(0, m.start() - 200) : m.start()].rstrip().endswith(("://", "www.")):
            add("A-C-5", "PI-5", 0.5, "social handle @handle", m, needs_review=True)
    for m in _PROFILE_URL.finditer(text):
        add("A-C-5", "PI-5", 0.7, "personal profile link", m)

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
