"""静态供应链 family: B-CIA-9（恶意/仿冒依赖推荐）。

模式:
- SC-1 typosquatting（编辑距离 vs 高频官方包清单）
- SC-2 社工伪装话术 × 包推荐共现
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_supply_chain"

# 高频官方包（py/npm 双生态，离线清单；Phase 2 可接 registry API）
_PY_OFFICIAL = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "httpx", "aiohttp",
    "sqlalchemy", "pydantic", "openai", "anthropic", "langchain", "langgraph",
    "beautifulsoup4", "scrapy", "selenium", "pytest", "cryptography", "jwt",
    "pillow", "opencv-python", "torch", "tensorflow", "transformers", "openpyxl",
}
_NPM_OFFICIAL = {
    "react", "vue", "axios", "express", "lodash", "typescript", "webpack",
    "vite", "next", "eslint", "jest", "chalk", "commander", "openai",
    "@anthropic-ai/sdk", "discord.js", "telegraf", "ws",
}
_OFFICIAL_ALL = _PY_OFFICIAL | _NPM_OFFICIAL

# 包管理/安装语境
_INSTALL_CTX = re.compile(
    r"(?i)(pip\s+install|pip3\s+install|npm\s+install|npm\s+i\s|yarn\s+add|pnpm\s+add|"
    r"uv\s+(add|pip\s+install)|poetry\s+add|conda\s+install|gem\s+install|cargo\s+add)",
)
_PKG_TOKEN = re.compile(r"(?i)(?:install|add|-i)\s+[@\w/.-]{2,60}")
# 社工伪装（SC-2）
_SOCIAL_ENGINEERING = re.compile(
    r"(官方|推荐|最新|修复|official|recommended|fixed|patched|new).{0,30}"
    r"(包|库|package|library|module|sdk)|"
    r"(install|安装).{0,40}(instead of|替代|替换|取代|rather than)",
    re.IGNORECASE,
)


def _edit_distance_within(a: str, b: str, max_d: int) -> bool:
    """带早退的编辑距离 ≤ max_d 判断。"""
    if abs(len(a) - len(b)) > max_d:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            best = min(best, v)
        if best > max_d:
            return False
        prev = cur
    return prev[-1] <= max_d


def _nearest_official(pkg: str) -> tuple[str | None, int]:
    best, best_d = None, 3
    for off in _OFFICIAL_ALL:
        d = 1 if _edit_distance_within(pkg, off, 1) else (2 if _edit_distance_within(pkg, off, 2) else 3)
        if d < best_d:
            best, best_d = off, d
    return best, best_d


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []
    se_hits = _SOCIAL_ENGINEERING.findall(text)

    # 安装语境中的包名提取
    for m in _INSTALL_CTX.finditer(text):
        window = text[m.start() : m.start() + 160]
        for pm in _PKG_TOKEN.finditer(window):
            pkg = pm.group(0).split()[-1].lstrip("@").split("@")[0].strip("`\"'")
            pkg = re.sub(r"[^@\w/.-]", "", pkg)
            if not pkg or len(pkg) < 3 or "/" in pkg and not pkg.startswith("@"):
                continue
            pkg_name = pkg.split("/")[-1]
            if pkg_name in _OFFICIAL_ALL:
                continue
            near, dist = _nearest_official(pkg_name)
            if near and dist <= 2:
                has_se = bool(se_hits)
                findings.append(make_finding(
                    taxonomy_id="B-CIA-9", pattern_id="SC-1",
                    confidence=0.7 if has_se else 0.55,
                    message=f"疑似 typosquatting 包: {pkg_name}（近似 {near}，编辑距离 {dist}）"
                            + ("，伴随社工话术" if has_se else ""),
                    state=state, pos=m.start(), matched_text=m.group(0)[:80],
                    needs_review=not has_se,
                    evidence={"pkg": pkg_name, "nearest_official": near, "distance": dist}))

    # SC-2: 社工话术 + 任意包安装指令共现（不做 typosquat 判定时的兜底候选）
    if len(se_hits) >= 2 and _INSTALL_CTX.search(text):
        first = _INSTALL_CTX.search(text)
        findings.append(make_finding(
            taxonomy_id="B-CIA-9", pattern_id="SC-2", confidence=0.45,
            message=f"安装指令 × 社工伪装话术（×{len(se_hits)}）共现（候选）",
            state=state, pos=first.start(), matched_text=first.group(0),
            needs_review=True, evidence={"se_count": len(se_hits)}))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
