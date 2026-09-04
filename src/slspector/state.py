"""LangGraph 状态 schema（借鉴 SkillSpector state.py，适配对话记录）。"""

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
    status: str          # ok / skipped / error
    detail: str
    duration_ms: int


class SlspectorState(TypedDict, total=False):
    # 输入
    record: dict[str, object]              # 原始 JSONL 记录
    meta: RecordMeta
    use_llm: bool
    provider: str | None
    # build_context 产物
    full_text: str                          # "\n\n".join(messages) 拼接文本
    message_offsets: list[tuple[int, int, str]]  # (start, end, role) per message
    links: list[dict[str, object]]          # 提取的链接/资源引用（url/anchor/kind）
    attachments: list[dict[str, object]]    # attachment_info 归一化
    text_stats: dict[str, object]           # 长度/压缩比/重复度等
    # analyzers 并行累积
    findings: Annotated[list[Finding], operator.add]
    analyzer_status: Annotated[list[AnalyzerStatus], operator.add]
    # dedup/meta/report
    deduped_findings: list[Finding]
    needs_review_findings: list[Finding]
    coverage: dict[str, object]


class AnalyzerNodeResponse(TypedDict):
    """Analyzer 节点返回的增量更新（findings 由 reducer 累积）。"""

    findings: list[Finding]
    analyzer_status: NotRequired[list[AnalyzerStatus]]
