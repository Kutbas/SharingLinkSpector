"""LangGraph state schema (adapted from SkillSpector state.py for conversation records)."""

from __future__ import annotations

import operator
from typing import Annotated, NotRequired, TypedDict

from slspector.models import Finding


class RecordMeta(TypedDict):
    share_id: str
    platform: str
    source_url: str | None
    title: str | None
    crawl_time: str | None


class AnalyzerStatus(TypedDict, total=False):
    analyzer_id: str
    status: str  # ok / skipped / error
    detail: str
    duration_ms: int


class SlspectorState(TypedDict, total=False):
    # input
    record: dict[str, object]  # raw JSONL record
    meta: RecordMeta
    use_llm: bool
    provider: str | None
    # build_context products
    messages: list[dict]  # normalized messages (for chunking)
    full_text: str  # "\n\n".join(messages)
    message_offsets: list[tuple[int, int, str]]  # (start, end, role) per message
    links: list[dict[str, object]]  # extracted links/resource refs (url/anchor/kind)
    attachments: list[dict[str, object]]  # normalized attachment_info
    text_stats: dict[str, object]  # length/compression/repetition stats
    # parallel analyzer accumulation
    findings: Annotated[list[Finding], operator.add]
    analyzer_status: Annotated[list[AnalyzerStatus], operator.add]
    # dedup/meta/report
    deduped_findings: list[Finding]
    needs_review_findings: list[Finding]
    coverage: dict[str, object]


class AnalyzerNodeResponse(TypedDict):
    """Incremental analyzer-node update (findings accumulate via reducer)."""

    findings: list[Finding]
    analyzer_status: NotRequired[list[AnalyzerStatus]]
