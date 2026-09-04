"""Analyzer auto-discovery registry (cf. SkillSpector pkgutil pattern).

Each family module must expose:
- ANALYZER_ID: str
- node(state) -> AnalyzerNodeResponse
- optional requires_llm: bool (skipped when True and no LLM configured)
- optional is_available() -> bool
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

ANALYZER_NODE_IDS: list[str] = []
ANALYZER_NODES: dict[str, Any] = {}
ANALYZER_MODULES: dict[str, Any] = {}


def _discover() -> None:
    if ANALYZER_NODE_IDS:
        return
    for _, module_name, is_pkg in pkgutil.iter_modules(__path__):
        if is_pkg or not module_name.startswith(("static_", "llm_")):
            continue
        full = f"{__name__}.{module_name}"
        try:
            mod = importlib.import_module(full)
        except Exception as exc:  # noqa: BLE001
            print(f"[registry] failed to import {module_name}: {exc}")
            continue
        analyzer_id = getattr(mod, "ANALYZER_ID", None)
        node_func = getattr(mod, "node", None)
        if analyzer_id and callable(node_func):
            ANALYZER_NODE_IDS.append(analyzer_id)
            ANALYZER_NODES[analyzer_id] = node_func
            ANALYZER_MODULES[analyzer_id] = mod


def get_analyzers(use_llm: bool) -> list[tuple[str, Any]]:
    """Return [(analyzer_id, node)] filtered by availability."""
    _discover()
    out = []
    for analyzer_id in ANALYZER_NODE_IDS:
        mod = ANALYZER_MODULES[analyzer_id]
        if getattr(mod, "requires_llm", False) and not use_llm:
            continue
        avail = getattr(mod, "is_available", None)
        if callable(avail) and not avail():
            continue
        out.append((analyzer_id, ANALYZER_NODES[analyzer_id]))
    return out
