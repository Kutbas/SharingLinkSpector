"""静态载荷结构 family: B-C-5（XXE）+ B-CIA-3/4/5/6（XSS/CSV公式/ANSI/SSTI）。

模式:
- PS-1 XXE 原始字节（B-C-5，Kevin 红标: 静态可测）
- PS-2 可执行 HTML/SVG 结构（B-CIA-3，红标: 静态可测）
- PS-3 表格公式前缀（B-CIA-4，确定性）
- PS-4 终端转义序列（B-CIA-5，确定性）
- PS-5 模板注入元语法（B-CIA-6，红标: 候选+人工核验）
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_payload_structures"

# PS-1 B-C-5 XXE（原始字节扫 DOCTYPE/ENTITY/SYSTEM/file://）
_XXE_MARKS = [
    (r"<!DOCTYPE\s+\w+[^>]*>", "DOCTYPE 声明"),
    (r"<!ENTITY\s+\S+\s+(SYSTEM|PUBLIC)\s+[\"'][^\"']+[\"']", "外部实体声明"),
    (r"(?i)file:///(?:etc|proc|dev|windows)", "file 协议引用"),
    (r"&xxe;|%remote;|&SYSTEM;", "实体引用"),
]

# PS-2 B-CIA-3 存储型 XSS 可执行结构
_XSS_MARKS = [
    (r"<script\b[^>]*>", "script 标签"),
    (r"(?i)\bon(?:error|load|click|mouseover|focus|animationstart|toggle)\s*=\s*[\"'`]?[^\"'`>\s]", "事件 handler 属性"),
    (r"(?i)javascript:\s*[a-z(]", "javascript: URI"),
    (r"(?i)<svg\b[^>]*\bon\w+\s*=", "SVG 事件属性"),
    (r"(?i)<img[^>]+src\s*=\s*[\"']?\s*x:", "x: img src"),
    (r"(?i)<iframe\b[^>]*src\s*=", "iframe 引用"),
    (r"(?i)<object\b[^>]*data\s*=|<embed\b[^>]*src\s*=", "object/embed 嵌入"),
    (r"(?i)document\.(cookie|location|write)\s*[=.(]", "DOM 访问"),
    (r"(?i)eval\s*\(\s*(atob|unescape|String\.fromCharCode)", "解码 eval"),
]

# PS-3 B-CIA-4 CSV/表格公式注入（含 Tab/空格前缀变体）
# follower 限定：排除 LaTeX 数学（=\sqrt、,-\frac）与路径分隔符误报
_FORMULA_CELL = re.compile(
    r"(?:^|\n|\t|\||，|,|;|\s)[ \t]*([=+\-@])[ \t]*"
    r"(?=(?:HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTFEED|IMPORTHTML|DDE)\s*\(|"
    r"cmd\b|powershell\b|https?:|file:|[A-Z]{1,2}\$?[0-9]{1,4}\b|R\[)",
)
# 无歧义公式函数（电子表格专属，英文正文不会出现）
_FORMULA_FUNC = re.compile(
    r"\b(HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTFEED|IMPORTHTML|DDE)\s*\(",
)
# 歧义词（image/cmd/exec 英文正文常见）→ 仅表格语境下报告
_FORMULA_AMBIGUOUS = re.compile(
    r"\b(IMAGE|CMD|EXEC)\s*\(",
)
_TABLE_CONTEXT = re.compile(r"(?i)\||\t|csv|excel|sheet|表格|导入|export|导出")

# PS-4 B-CIA-5 ANSI/OSC 转义注入
_ANSI_MARKS = [
    (r"\x1b\[[0-9;?]*[A-Za-z]", "CSI 序列"),
    (r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "OSC 序列（含 OSC 52 剪贴板劫持）"),
    (r"\x1b[()][0-9A-B]", "字符集切换"),
    (r"[\x80-\x9f][\x40-\x7e][\x40-\x7e]", "C1 控制序列（8 位形式）"),
]

# PS-5 B-CIA-6 SSTI 模板元语法（候选）
_SSTI_MARKS = [
    (r"\{\{[^}]{1,120}\}\}", "Jinja2 {{}}"),
    (r"\$\{[^}]{1,120}\}", "EL/模板 ${}"),
    (r"<%[=\-\s][^%]{0,120}%>", "ERB <% %>"),
    (r"#\{[^}]{1,120}\}", "Ruby/Java #{}"),
]
_SSTI_DANGER = re.compile(
    r"(?i)(system|exec|popen|eval|import|os\.|subprocess|__class__|__globals__|__subclasses__|"
    r"request|application|config|self\.)",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []
    # 代码块内的载荷结构置信度降级（展示/教学语境常见），但不跳过——分享页渲染不分代码块
    for pat, name in _XXE_MARKS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(make_finding(
                taxonomy_id="B-C-5", pattern_id="PS-1", confidence=0.7,
                message=f"XXE 结构信号: {name}", state=state,
                pos=m.start(), matched_text=m.group(0)[:120]))

    for pat, name in _XSS_MARKS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(make_finding(
                taxonomy_id="B-CIA-3", pattern_id="PS-2", confidence=0.75,
                message=f"可执行结构: {name}", state=state,
                pos=m.start(), matched_text=m.group(0)[:120]))

    # B-CIA-4: 公式函数签名直接命中；前缀变体需表格语境
    for m in _FORMULA_FUNC.finditer(text):
        findings.append(make_finding(
            taxonomy_id="B-CIA-4", pattern_id="PS-3", confidence=0.8,
            message=f"表格公式函数: {m.group(1)}", state=state,
            pos=m.start(), matched_text=m.group(0)[:100]))
    for m in _FORMULA_AMBIGUOUS.finditer(text, re.IGNORECASE):
        if _TABLE_CONTEXT.search(text[max(0, m.start() - 200) : m.start() + 200]):
            findings.append(make_finding(
                taxonomy_id="B-CIA-4", pattern_id="PS-3", confidence=0.6,
                message=f"疑似表格公式函数: {m.group(1)}", state=state,
                pos=m.start(), matched_text=m.group(0)[:100], needs_review=True))
    for m in _FORMULA_CELL.finditer(text):
        if _TABLE_CONTEXT.search(text[max(0, m.start() - 200) : m.start() + 200]):
            findings.append(make_finding(
                taxonomy_id="B-CIA-4", pattern_id="PS-3", confidence=0.5,
                message="表格单元格公式前缀（=+-@ 变体）", state=state,
                pos=m.start(), matched_text=m.group(0)[:80], needs_review=True))

    for pat, name in _ANSI_MARKS:
        for m in re.finditer(pat, text):
            findings.append(make_finding(
                taxonomy_id="B-CIA-5", pattern_id="PS-4", confidence=0.85,
                message=f"终端转义序列: {name}", state=state,
                pos=m.start(), matched_text=m.group(0)[:60].replace("\x1b", "\\e")))

    for pat, name in _SSTI_MARKS:
        for m in re.finditer(pat, text):
            dangerous = bool(_SSTI_DANGER.search(m.group(0)))
            findings.append(make_finding(
                taxonomy_id="B-CIA-6", pattern_id="PS-5",
                confidence=0.55 if dangerous else 0.35,
                message=f"模板元语法: {name}" + ("（含危险符号）" if dangerous else "（候选，人工核验）"),
                state=state, pos=m.start(), matched_text=m.group(0)[:100],
                needs_review=True))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
