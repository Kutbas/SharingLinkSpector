"""共享测试夹具。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slspector.graph import create_graph


@pytest.fixture()
def static_graph():
    return create_graph(use_llm=False)


def make_record(*messages: tuple[str, str], platform="test", **extra) -> dict:
    return {
        "share_id": "test-share-001",
        "platform": platform,
        "source_url": f"https://{platform}.com/share/test-share-001",
        "conversation_title": "测试对话",
        "messages": [{"role": r, "content": c} for r, c in messages],
        **extra,
    }


def scan(graph, record: dict) -> list[dict]:
    state = graph.invoke({"record": record, "use_llm": False, "provider": None})
    return [f.to_dict() for f in state["deduped_findings"]]


@pytest.fixture(scope="session")
def subset_first_record() -> dict:
    p = (
        Path(__file__).resolve().parent.parent.parent
        / "Taxonomy_Building"
        / "taxonomy_subset_650.jsonl"
    )
    if not p.exists():
        pytest.skip("subset not available")
    with p.open(encoding="utf-8") as f:
        return json.loads(f.readline())
