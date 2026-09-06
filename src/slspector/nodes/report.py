"""report: per-record result -> dict (aggregated and written by the CLI)."""

from __future__ import annotations

from slspector.state import SlspectorState


def report(state: SlspectorState) -> dict:
    findings = state.get("deduped_findings", [])
    meta = state.get("meta") or {}
    statuses = state.get("analyzer_status", [])
    llm_statuses = [s for s in statuses if s.get("analyzer_id") == "llm_analyzer"]
    scan_status = (
        "failed"
        if any(s.get("status") == "failed" for s in llm_statuses)
        else ("partial" if any(s.get("status") == "partial" for s in llm_statuses) else "complete")
    )
    return {
        "share_id": meta.get("share_id", ""),
        "platform": meta.get("platform", ""),
        "title": meta.get("title"),
        "scan_status": scan_status,
        "analyzer_status": statuses,
        "finding_count": len(findings),
        "needs_review_count": len(state.get("needs_review_findings", [])),
        "findings": [f.to_dict() for f in findings],
    }
