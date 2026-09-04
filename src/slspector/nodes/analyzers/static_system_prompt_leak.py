"""Static system-prompt-leak family: B-C-1.

Patterns:
- SPL-1 system-prompt fingerprints ("You are..." phrasing / platform templates / tool schemas)
- SPL-2 extraction requests ("repeat the above / print your instructions")
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_system_prompt_leak"

# SPL-1 system-prompt component fingerprints
_SYS_PROMPT_MARKS = [
    (r"(?i)^.{0,40}you are (claude|chatgpt|gpt|gemini|grok|deepseek|qwen|kimi|an? ai|a large language)", "model self-description"),
    (r"(?i)you are (an? )?(helpful|harmless|innocent|expert|assistant)", "persona-setup phrase"),
    (r"(?i)<system>|system prompt\s*[::]|系统提示词\s*[：:]", "explicit system-prompt marker"),
    (r"(?i)(you must|you should always|never reveal|do not disclose).{0,60}(instructions|system prompt|your rules)", "behavior-constraint clause"),
    (r"(?i)知识截止|knowledge cutoff.{0,30}(date|时间)|训练数据(截止|时间)", "platform-template marker"),
    (r"(?i)(可用工具|available tools?)\s*[：:].{0,30}(function|工具|tool)_?", "tool-schema marker"),
    (r"(?i)as an ai (language )?model,? i (can'?t|cannot|don'?t have)", "platform disclaimer phrase"),
]
# SPL-2 extraction requests
_EXTRACTION_ASKS = [
    r"(?i)(repeat|print|output|reveal|show).{0,30}(your|the|以上|上述)?(instructions?|system prompt|initial prompt|规则|指令)",
    r"(?i)what (are|were) your (original |initial )?(instructions|rules|system prompt)",
    r"重复(以上|上面|之前)(的)?(内容|指令|规则|设定)",
    r"(打印|输出|显示)(你的)?(系统提示|初始指令|预设)",
    r"(?i)ignore previous.{0,30}and (print|output|repeat)",
]
_JAILBREAK_CONTEXT = re.compile(
    r"(?i)(ignore|disregard|forget).{0,30}(instructions|rules)|忽略.{0,10}(指令|规则)",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []
    mark_hits = 0

    for pat, name in _SYS_PROMPT_MARKS:
        for m in re.finditer(pat, text, re.IGNORECASE | re.MULTILINE):
            mark_hits += 1
            findings.append(make_finding(
                taxonomy_id="B-C-1", pattern_id="SPL-1", confidence=0.55,
                message=f"System-prompt component: {name}", state=state,
                pos=m.start(), matched_text=m.group(0), needs_review=True))

    for pat in _EXTRACTION_ASKS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            # extraction request + multiple system-prompt components -> more likely a real leak
            conf = 0.75 if mark_hits >= 2 else 0.55
            findings.append(make_finding(
                taxonomy_id="B-C-1", pattern_id="SPL-2", confidence=conf,
                message="System-prompt extraction request", state=state,
                pos=m.start(), matched_text=m.group(0)))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
