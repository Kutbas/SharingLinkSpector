"""Load data/categories.yaml; category lookup and coverage summaries."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "categories.yaml"


@functools.lru_cache(maxsize=1)
def load_categories() -> dict[str, dict[str, Any]]:
    with DATA_FILE.open(encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    cats: dict[str, dict[str, Any]] = {}
    for c in doc["categories"]:
        cats[c["id"]] = c
    return cats


def get(cid: str) -> dict[str, Any] | None:
    return load_categories().get(cid)


def llm_categories() -> dict[str, dict[str, Any]]:
    """Phase 1 categories with an LLM prompt configured and not skipped."""
    return {
        cid: c
        for cid, c in load_categories().items()
        if c.get("llm") and c["status"] not in ("skipped",)
    }


def status_counts() -> dict[str, int]:
    from collections import Counter

    return dict(Counter(c["status"] for c in load_categories().values()))


def coverage_report() -> list[dict[str, Any]]:
    """Coverage matrix for reports: 49 categories with status + who-can-test notes."""
    rows = []
    for cid, c in load_categories().items():
        rows.append(
            {
                "id": cid,
                "leaf": c["leaf"],
                "leaf_en": c["leaf_en"],
                "tracks": c["tracks"],
                "status": c["status"],
                "note": c.get("note") or "",
                "verdict_note": c.get("verdict_note") or "",
                "who_can_test": _who_can_test(c),
            }
        )
    return rows


def _who_can_test(c: dict[str, Any]) -> str:
    tracks = c["tracks"]
    if "platform" in tracks and not ({"static", "llm"} & set(tracks)):
        return "platform-only (access logs / server-side); not observable by third parties"
    if "dynamic" in tracks and not ({"static", "llm"} & set(tracks)):
        return "requires dynamic capability (sandbox/refetch/redirect-follow); optional for third parties"
    if c["status"] == "future_work":
        return "theoretically testable by third parties but needs external capability (multimodal/decoders/retrieval/corpus-level); future work"
    if c["status"] == "skipped":
        return "not labeled (Kevin's verdict: no detectable feature or payload unavailable)"
    return "testable by third parties (static/LLM)"
