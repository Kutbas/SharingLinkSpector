"""Finding 与定位模型（对话级 location，非文件级）。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(slots=True)
class MessageLocation:
    """Finding 在对话中的位置。record 级检测（元数据/附件）时 message_index=None。"""

    message_index: int | None = None
    role: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    snippet: str | None = None


@dataclass(slots=True)
class Finding:
    """一条风险标注。只标注、不打分：severity 为类别固有分级（信息性），无聚合评分。"""

    taxonomy_id: str          # A-C-1 / B-CI-8 / ...
    pattern_id: str           # family 内模式编号，如 PI-1 / LINK-3
    detector: str             # static / llm
    confidence: float         # 0~1
    message: str              # 模式短名（中文）
    location: MessageLocation = field(default_factory=MessageLocation)
    matched_text: str | None = None
    context: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    needs_review: bool = False
    reasoning: str | None = None  # LLM 轨判定理由
    analyzer_id: str = ""

    def fingerprint(self) -> str:
        """去重键：同类别+同模式+同位置。"""
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
