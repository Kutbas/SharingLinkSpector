"""加载 data/categories.yaml；提供类别查询与 coverage 汇总。"""

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
    """Phase 1 配置了 LLM 提示词且未 skipped 的类别。"""
    return {
        cid: c
        for cid, c in load_categories().items()
        if c.get("llm") and c["status"] not in ("skipped",)
    }


def status_counts() -> dict[str, int]:
    from collections import Counter

    return dict(Counter(c["status"] for c in load_categories().values()))


def coverage_report() -> list[dict[str, Any]]:
    """报告用 coverage 矩阵：49 类四态 + 谁才能测说明。"""
    rows = []
    for cid, c in load_categories().items():
        rows.append(
            {
                "id": cid,
                "leaf": c["leaf"],
                "tracks": c["tracks"],
                "status": c["status"],
                "note": c.get("note") or "",
                "kevin_note": c.get("kevin_note") or "",
                "who_can_test": _who_can_test(c),
            }
        )
    return rows


def _who_can_test(c: dict[str, Any]) -> str:
    tracks = c["tracks"]
    if "平台方" in tracks and not ({"静态", "LLM"} & set(tracks)):
        return "仅平台方（访问日志/服务端链路），第三方不可观测"
    if "动态" in tracks and not ({"静态", "LLM"} & set(tracks)):
        return "需动态能力（沙箱/回源/重定向跟随），第三方可选做"
    if c["status"] == "future_work":
        return "第三方理论可测但依赖外部能力（多模态/解码器/检索/语料级），future work"
    if c["status"] == "skipped":
        return "不标注（Kevin 判定：无检测特征或载荷不可得）"
    return "第三方可测（静态/LLM）"
