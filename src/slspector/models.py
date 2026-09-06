"""Finding and location models (conversation-level, not file-level)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(slots=True)
class MessageLocation:
    """Finding location within the conversation. message_index=None for record-level
    detections (metadata/attachments)."""

    message_index: int | None = None
    role: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    snippet: str | None = None


@dataclass(slots=True)
class Finding:
    """One risk annotation. Label-only, no scoring: no aggregate risk score is computed."""

    taxonomy_id: str  # A-C-1 / B-CI-8 / ...
    pattern_id: str  # pattern number within family, e.g. PI-1 / LINK-3
    detector: str  # static / llm
    confidence: float  # 0~1
    message: str  # short pattern name (English)
    location: MessageLocation = field(default_factory=MessageLocation)
    matched_text: str | None = None
    context: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    needs_review: bool = False
    reasoning: str | None = None  # LLM-track judgment rationale
    analyzer_id: str = ""

    def fingerprint(self) -> str:
        """Dedup key: same category + pattern + location."""
        loc = f"{self.location.message_index}:{self.location.char_start}:{self.location.char_end}"
        raw = f"{self.taxonomy_id}|{self.pattern_id}|{loc}|{self.matched_text or ''[:64]}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, object]:
        return {
            "taxonomy_id": self.taxonomy_id,
            "pattern_id": self.pattern_id,
            "detector": self.detector,
            "confidence": round(self.confidence, 3),
            "message": self.message,
            "needs_review": self.needs_review,
            "analyzer_id": self.analyzer_id,
            "location": {
                "message_index": self.location.message_index,
                "role": self.location.role,
                "char_start": self.location.char_start,
                "char_end": self.location.char_end,
                "snippet": self.location.snippet,
            },
            "matched_text": (self.matched_text or "")[:200],
            "context": (self.context or "")[:300],
            "evidence": self.evidence,
            "reasoning": self.reasoning,
        }
