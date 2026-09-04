"""静态 Unicode 隐藏/混淆 family: B-CI-2 + B-I-7。

模式:
- UH-1 零宽/双向控制符（B-CI-2，确定性——静态为主）
- UH-2 混合脚本同形字（B-CI-2 辅助 + B-I-7 混淆规避）
- UH-3 混淆归一化分叉（B-I-7：归一化前后与可见文本语义不一致）
"""

from __future__ import annotations

import re
import unicodedata

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_unicode_hidden"

ZERO_WIDTH = {0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0xFEFF: "BOM/ZWNBSP",
              0x2060: "WJ", 0x180E: "Mongolian VS"}
BIDI_CONTROL = {0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO",
                0x202E: "RLO", 0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI"}
TAG_CHARS = range(0xE0000, 0xE0080)

# 高频拉丁-西里尔/希腊同形字映射（可见相同、码位不同）
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d",
    "ɡ": "g", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
}
# 注入类关键词（UH-3：混淆后的目标语义）
_INJECTION_KEYWORDS = re.compile(
    r"(?i)(ignore|disregard|instruction|prompt|system|执行|忽略|指令|提示词|assistant|api[_ ]?key|secret)",
)


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "?"
    if "CYRILLIC" in name:
        return "cyr"
    if "GREEK" in name:
        return "gre"
    if "CJK" in name or "IDEOGRAPH" in name:
        return "cjk"
    if "LATIN" in name:
        return "lat"
    return "other"


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []

    # UH-1 零宽/双向控制符（逐字符）
    zw_hits: list[tuple[int, str]] = []
    bidi_hits: list[tuple[int, str]] = []
    tag_hits = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in ZERO_WIDTH:
            zw_hits.append((i, ZERO_WIDTH[cp]))
        elif cp in BIDI_CONTROL:
            bidi_hits.append((i, BIDI_CONTROL[cp]))
        elif cp in TAG_CHARS:
            tag_hits += 1

    for pos, name in zw_hits[:50]:  # 上限防刷屏
        findings.append(make_finding(
            taxonomy_id="B-CI-2", pattern_id="UH-1", confidence=0.9,
            message=f"零宽字符 {name}", state=state, pos=pos, matched_text=""))
    for pos, name in bidi_hits[:50]:
        findings.append(make_finding(
            taxonomy_id="B-CI-2", pattern_id="UH-1", confidence=0.9,
            message=f"双向控制符 {name}", state=state, pos=pos, matched_text=""))
    if tag_hits:
        first_tag = next(i for i, ch in enumerate(text) if ord(ch) in TAG_CHARS)
        findings.append(make_finding(
            taxonomy_id="B-CI-2", pattern_id="UH-1", confidence=0.85,
            message=f"Tag 字符 ×{tag_hits}（可隐藏 ASCII 指令）", state=state,
            pos=first_tag, matched_text="", evidence={"count": tag_hits}))

    # UH-2 混合脚本：同一词内混用拉丁与西里尔/希腊
    word_re = re.compile(r"[\w]+")
    mixed_seen = 0
    for m in word_re.finditer(text):
        w = m.group(0)
        scripts = {_script_of(c) for c in w if c.isalpha()}
        if ("lat" in scripts) and (scripts & {"cyr", "gre"}):
            mixed_seen += 1
            if mixed_seen <= 20:
                homo = sum(1 for c in w if c in _HOMOGLYPHS)
                # ≥2 个同形字才高置信；单个/纯混排（俄文技术词常见）→ 低置信候选
                conf = 0.75 if homo >= 2 else 0.5
                findings.append(make_finding(
                    taxonomy_id="B-I-7", pattern_id="UH-2", confidence=conf,
                    message=f"混合脚本词（含 {homo} 个同形字）", state=state,
                    pos=m.start(), matched_text=w[:60],
                    evidence={"scripts": sorted(scripts), "homoglyphs": homo},
                    needs_review=homo < 2))
    if mixed_seen > 20:
        findings.append(make_finding(
            taxonomy_id="B-I-7", pattern_id="UH-2", confidence=0.7,
            message=f"混合脚本词大量出现（×{mixed_seen}）", state=state,
            pos=0, matched_text="", evidence={"count": mixed_seen}))

    # UH-3 归一化分叉：去掉零宽/同形归一后，出现注入关键词而原文肉眼不可见
    cleaned = "".join(
        _HOMOGLYPHS.get(ch, ch) for ch in text
        if ord(ch) not in ZERO_WIDTH and ord(ch) not in TAG_CHARS
    )
    for m in _INJECTION_KEYWORDS.finditer(cleaned):
        # 只报“原文含零宽/同形干扰”的情形——纯英文正常出现 ignore 不报
        orig_window = text[max(0, m.start() - 5) : m.end() + 5]
        has_hidden = any(ord(c) in ZERO_WIDTH or c in _HOMOGLYPHS for c in orig_window)
        if has_hidden:
            findings.append(make_finding(
                taxonomy_id="B-I-7", pattern_id="UH-3", confidence=0.8,
                message=f"归一化后暴露注入关键词: {m.group(0)}", state=state,
                pos=m.start(), matched_text=m.group(0)))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
