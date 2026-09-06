"""Static payload-structure family: B-C-5 (XXE) + B-CIA-3/4/5/6 (XSS/CSV/ANSI/SSTI).

Patterns:
- PS-1 XXE raw-byte markers (B-C-5, red-flag: statically detectable)
- PS-2 executable HTML/SVG structures (B-CIA-3, red-flag: statically detectable)
- PS-3 table formula prefixes (B-CIA-4, deterministic)
- PS-4 terminal escape sequences (B-CIA-5, deterministic)
- PS-5 template-injection meta-syntax (B-CIA-6, red-flag: candidate + manual review)
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_payload_structures"

# PS-1 B-C-5 XXE (raw-byte scan for DOCTYPE/ENTITY/SYSTEM/file://)
_XXE_MARKS = [
    (r"<!DOCTYPE\s+\w+[^>]*>", "DOCTYPE declaration"),
    (r"<!ENTITY\s+\S+\s+(SYSTEM|PUBLIC)\s+[\"'][^\"']+[\"']", "external entity declaration"),
    (r"(?i)file:///(?:etc|proc|dev|windows)", "file:// scheme reference"),
    (r"&xxe;|%remote;|&SYSTEM;", "entity reference"),
]

# PS-2 B-CIA-3 stored-XSS executable structures
_XSS_MARKS = [
    (r"<script\b[^>]*>", "script tag"),
    (
        r"(?i)\bon(?:error|load|click|mouseover|focus|animationstart|toggle)\s*=\s*[\"'`]?[^\"'`>\s]",
        "event-handler attribute",
    ),
    (r"(?i)javascript:\s*[a-z(]", "javascript: URI"),
    (r"(?i)<svg\b[^>]*\bon\w+\s*=", "SVG event attribute"),
    (r"(?i)<img[^>]+src\s*=\s*[\"']?\s*x:", "x: img src"),
    (r"(?i)<iframe\b[^>]*src\s*=", "iframe reference"),
    (r"(?i)<object\b[^>]*data\s*=|<embed\b[^>]*src\s*=", "object/embed embed"),
    (r"(?i)document\.(cookie|location|write)\s*[=.(]", "DOM access"),
    (r"(?i)eval\s*\(\s*(atob|unescape|String\.fromCharCode)", "decode-eval"),
]

# PS-3 B-CIA-4 CSV/table formula injection (incl. tab/space prefix variants)
# follower whitelist: excludes LaTeX math (=\sqrt, ,-\frac) and path separators
_FORMULA_CELL = re.compile(
    r"(?:^|\n|\t|\||，|,|;|\s)[ \t]*([=+\-@])[ \t]*"
    r"(?=(?:HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTFEED|IMPORTHTML|DDE)\s*\(|"
    r"cmd\b|powershell\b|https?:|file:|[A-Z]{1,2}\$?[0-9]{1,4}\b|R\[)",
)
# unambiguous formula functions (spreadsheet-only, never in English prose)
_FORMULA_FUNC = re.compile(
    r"\b(HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTFEED|IMPORTHTML|DDE)\s*\(",
)
# ambiguous words (image/cmd/exec common in prose) -> report only in table context
_FORMULA_AMBIGUOUS = re.compile(
    r"\b(IMAGE|CMD|EXEC)\s*\(",
)
_TABLE_CONTEXT = re.compile(r"(?i)\||\t|csv|excel|sheet|表格|导入|export|导出")

# PS-4 B-CIA-5 ANSI/OSC escape injection
_ANSI_MARKS = [
    (r"\x1b\[[0-9;?]*[A-Za-z]", "CSI sequence"),
    (r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "OSC sequence (incl. OSC 52 clipboard hijack)"),
    (r"\x1b[()][0-9A-B]", "charset switch"),
    (r"[\x80-\x9f][\x40-\x7e][\x40-\x7e]", "C1 control sequence (8-bit form)"),
]

# PS-5 B-CIA-6 SSTI template meta-syntax (candidate)
_SSTI_MARKS = [
    (r"\{\{[^}]{1,120}\}\}", "Jinja2 {{}}"),
    (r"\$\{[^}]{1,120}\}", "EL/template ${}"),
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
    # note: share-page renderers do not skip code blocks, so we report them (context kept in evidence)
    for pat, name in _XXE_MARKS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    taxonomy_id="B-C-5",
                    pattern_id="PS-1",
                    confidence=0.7,
                    message=f"XXE structure signal: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:120],
                )
            )

    for pat, name in _XSS_MARKS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-3",
                    pattern_id="PS-2",
                    confidence=0.75,
                    message=f"Executable structure: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:120],
                )
            )

    # B-CIA-4: unambiguous formula functions hit directly; prefix variants need table context
    for m in _FORMULA_FUNC.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-CIA-4",
                pattern_id="PS-3",
                confidence=0.8,
                message=f"Spreadsheet formula function: {m.group(1)}",
                state=state,
                pos=m.start(),
                matched_text=m.group(0)[:100],
            )
        )
    for m in _FORMULA_AMBIGUOUS.finditer(text, re.IGNORECASE):
        if _TABLE_CONTEXT.search(text[max(0, m.start() - 200) : m.start() + 200]):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-4",
                    pattern_id="PS-3",
                    confidence=0.6,
                    message=f"Suspected spreadsheet formula function: {m.group(1)}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:100],
                    needs_review=True,
                )
            )
    for m in _FORMULA_CELL.finditer(text):
        if _TABLE_CONTEXT.search(text[max(0, m.start() - 200) : m.start() + 200]):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-4",
                    pattern_id="PS-3",
                    confidence=0.5,
                    message="Table-cell formula prefix (=+-@ variants)",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:80],
                    needs_review=True,
                )
            )

    for pat, name in _ANSI_MARKS:
        for m in re.finditer(pat, text):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-5",
                    pattern_id="PS-4",
                    confidence=0.85,
                    message=f"Terminal escape sequence: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:60].replace("\x1b", "\\e"),
                )
            )

    for pat, name in _SSTI_MARKS:
        for m in re.finditer(pat, text):
            dangerous = bool(_SSTI_DANGER.search(m.group(0)))
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-6",
                    pattern_id="PS-5",
                    confidence=0.55 if dangerous else 0.35,
                    message=f"Template meta-syntax: {name}"
                    + (" (dangerous symbols)" if dangerous else " (candidate, manual review)"),
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:100],
                    needs_review=True,
                )
            )

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
