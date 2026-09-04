"""meta_analyzer: 跨轨汇总（双轨共现提置信、coverage 标注、needs_review 分流）。"""

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

    # 双轨共现：static + llm 同类别都命中 → 置信上调（×1.25，封顶 0.98）
    for cid, group in by_cat.items():
        detectors = {f.detector for f in group}
        if detectors == {"static", "llm"}:
            for f in group:
                f.confidence = min(0.98, f.confidence * 1.25)

    # 类别级 needs_review：taxonomy status=candidate 的强制 true
    for f in findings:
        cat = taxonomy.get(f.taxonomy_id)
        if cat and cat.get("status") == "candidate":
            f.needs_review = True

    needs_review = [f for f in findings if f.needs_review]

    # coverage：本次扫描"声明覆盖"的类别状态汇总
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
