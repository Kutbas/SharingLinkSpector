"""meta_analyzer: cross-track aggregation (dual-track confidence boost, coverage, needs_review routing)."""

from __future__ import annotations

from collections import Counter, defaultdict

from slspector import taxonomy
from slspector.models import Finding
from slspector.state import SlspectorState


def meta_analyzer(state: SlspectorState) -> dict:
    findings: list[Finding] = state.get("deduped_findings", [])

    by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_cat[f.taxonomy_id].append(f)

    # dual-track co-occurrence: static + llm both hit -> confidence boost (x1.25, cap 0.98)
    for group in by_cat.values():
        detectors = {f.detector for f in group}
        if detectors == {"static", "llm"}:
            for f in group:
                f.confidence = min(0.98, f.confidence * 1.25)

    # category-level needs_review: forced true when taxonomy status=candidate
    for f in findings:
        cat = taxonomy.get(f.taxonomy_id)
        if cat and cat.get("status") == "candidate":
            f.needs_review = True

    needs_review = [f for f in findings if f.needs_review]

    # coverage: declared category-status summary for this scan
    cov = taxonomy.status_counts()
    return {
        "needs_review_findings": needs_review,
        "coverage": {
            "taxonomy_status_counts": cov,
            "categories_hit": dict(Counter(f.taxonomy_id for f in findings)),
            "skipped_categories": [
                cid for cid, c in taxonomy.load_categories().items() if c["status"] == "skipped"
            ],
        },
    }
