"""report: 单记录结果 → dict（由 CLI 聚合写盘）。"""

from __future__ import annotations

from slspector.state import SlspectorState


def report(state: SlspectorState) -> dict:
    findings = state.get("deduped_findings", [])
    meta = state.get("meta") or {}
    return {
        "share_id": meta.get("share_id", ""),
        "platform": meta.get("platform", ""),
        "title": meta.get("title"),
        "finding_count": len(findings),
        "needs_review_count": len(state.get("needs_review_findings", [])),
        "findings": [f.to_dict() for f in findings],
    }
