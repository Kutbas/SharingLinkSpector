"""LangGraph orchestration (adapted from SkillSpector graph.py for record scanning).

START -> build_context -> [analyzers in parallel] -> dedup -> meta_analyzer -> END
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from slspector.logging_config import get_logger
from slspector.nodes.analyzers import get_analyzers
from slspector.nodes.build_context import build_context
from slspector.nodes.dedup import dedup
from slspector.nodes.meta_analyzer import meta_analyzer
from slspector.state import AnalyzerStatus, SlspectorState

logger = get_logger(__name__)


def _guard(analyzer_id: str, node_func):
    """One analyzer failure must not kill the whole scan (cf. guard_analyzer_node)."""

    def wrapped(state: SlspectorState):
        try:
            return node_func(state)
        except Exception as exc:  # noqa: BLE001
            logger.error("analyzer %s failed: %s", analyzer_id, exc)
            status: AnalyzerStatus = {
                "analyzer_id": analyzer_id,
                "status": "error",
                "detail": str(exc)[:300],
            }
            return {"findings": [], "analyzer_status": [status]}

    return wrapped


def create_graph(use_llm: bool = False, analyzer_filter: set[str] | None = None):
    workflow = StateGraph(SlspectorState)
    workflow.add_node("build_context", build_context)
    workflow.add_node("dedup", dedup)
    workflow.add_node("meta_analyzer", meta_analyzer)

    wired = []
    for analyzer_id, node_func in get_analyzers(use_llm=use_llm):
        if analyzer_filter and analyzer_id not in analyzer_filter:
            continue
        workflow.add_node(analyzer_id, _guard(analyzer_id, node_func))
        workflow.add_edge("build_context", analyzer_id)
        workflow.add_edge(analyzer_id, "dedup")
        wired.append(analyzer_id)

    if not wired:
        logger.warning("no analyzers wired")

    workflow.add_edge(START, "build_context")
    workflow.add_edge("dedup", "meta_analyzer")
    workflow.add_edge("meta_analyzer", END)
    return workflow.compile()
