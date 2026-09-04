"""dedup: fingerprint dedup + keep top-confidence per (category, message, pattern)."""

from __future__ import annotations

from slspector.models import Finding
from slspector.state import SlspectorState


def dedup(state: SlspectorState) -> dict:
    findings: list[Finding] = state.get("findings", [])
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    # keep top-2 confidence per (taxonomy, message_index, pattern) to avoid flooding
    per_key: dict[tuple, list[Finding]] = {}
    for f in out:
        key = (f.taxonomy_id, f.location.message_index, f.pattern_id)
        per_key.setdefault(key, []).append(f)
    kept: list[Finding] = []
    for key, group in per_key.items():
        group.sort(key=lambda x: -x.confidence)
        kept.extend(group[:2])
    kept.sort(key=lambda f: (f.taxonomy_id, f.location.message_index or -1))
    return {"deduped_findings": kept}
