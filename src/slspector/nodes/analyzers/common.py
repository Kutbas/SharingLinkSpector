"""Analyzer family 公共工具：上下文截取、finding 构造。"""

from __future__ import annotations

import re

from slspector.conversation import locate_message
from slspector.models import Finding, MessageLocation
from slspector.state import SlspectorState

CONTEXT_CHARS = 120


def get_context(text: str, pos: int, width: int = CONTEXT_CHARS) -> str:
    lo = max(0, pos - width // 2)
    hi = min(len(text), pos + width // 2)
    return text[lo:hi].replace("\n", "\\n")


def make_finding(
    *,
    taxonomy_id: str,
    pattern_id: str,
    confidence: float,
    message: str,
    state: SlspectorState,
    pos: int,
    matched_text: str | None = None,
    needs_review: bool = False,
    evidence: dict | None = None,
) -> Finding:
    """按全文偏移定位消息并构造 Finding。"""
    idx, role = locate_message(state["message_offsets"], pos)
    return Finding(
        taxonomy_id=taxonomy_id,
        pattern_id=pattern_id,
        detector="static",
        confidence=confidence,
        message=message,
        location=MessageLocation(
            message_index=idx,
            role=role,
            char_start=pos,
            char_end=pos + len(matched_text or ""),
            snippet=get_context(state["full_text"], pos),
        ),
        matched_text=(matched_text or "")[:200],
        context=get_context(state["full_text"], pos),
        needs_review=needs_review,
        evidence=evidence or {},
    )


def make_record_finding(
    *,
    taxonomy_id: str,
    pattern_id: str,
    confidence: float,
    message: str,
    needs_review: bool = False,
    evidence: dict | None = None,
    matched_text: str | None = None,
) -> Finding:
    """记录级 finding（元数据/附件面，无消息定位）。"""
    return Finding(
        taxonomy_id=taxonomy_id,
        pattern_id=pattern_id,
        detector="static",
        confidence=confidence,
        message=message,
        location=MessageLocation(snippet=matched_text),
        matched_text=(matched_text or "")[:200],
        needs_review=needs_review,
        evidence=evidence or {},
    )


def iter_matches(pattern: str, text: str, flags: int = re.IGNORECASE):
    yield from re.finditer(pattern, text, flags)
