"""Static injection-signature family: B-CIA-1/2 + B-CI-8 + B-IA-1/2 + B-CIA-8.

Patterns:
- INJ-1 instruction-hijack imperatives (B-CIA-1)
- INJ-2 dangerous command signatures (B-CIA-2)
- INJ-3 memory-poisoning templates (B-CI-8, red-flag: templates + LLM)
- INJ-4 hidden instructions targeting future retrieval (B-IA-1, red-flag)
- INJ-5 passive state-change resource references (B-IA-2, red-flag)
- INJ-6 assistant-config exfil/privilege logic (B-CIA-8)
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_injection_signatures"

# INJ-1 B-CIA-1 instruction hijack
_HIJACK_PATTERNS = [
    (
        r"(?i)ignore (all|any|the|previous|above|prior) (instructions?|prompts?|rules?|context)",
        "EN instruction override",
    ),
    (
        r"忽略(掉)?(以上|之前|上述|前面|所有)(的)?(指令|提示|规则|设定|内容)",
        "CN instruction override",
    ),
    (
        r"(?i)disregard (all|any|the|previous) (instructions?|guidelines?|rules?)",
        "EN disregard instructions",
    ),
    (
        r"(?i)(please |now )?(go to|visit|browse|open|check) (this|the) (link|url|website|page)",
        "EN visit-link instruction",
    ),
    (
        r"(请|现在|立刻|务必|记得)(去)?(访问|点击|打开|查看|跳转到)(这个|该|上方|下方|以下)?(链接|网址|页面|地址|网站)",
        "CN visit-link instruction",
    ),
    (r"(?i)you are now (in |a )?(new )?(mode|role|persona)|你现在(是|扮演)", "role rewrite"),
    (
        r"(?i)(execute|run|perform) (the )?(following|this) (command|instructions?|code)",
        "EN execute instruction",
    ),
    (
        r"(请|帮我|你)(执行|运行|在终端|跑一下)(以下|下面|这条|上述)?(命令|代码|脚本)",
        "CN execute instruction",
    ),
    (
        r"(?i)new instructions?\s*[::]|新(的)?(指令|指示)\s*[：:]",
        "instruction-override declaration",
    ),
]

# INJ-2 B-CIA-2 dangerous commands
_DANGEROUS_CMD = [
    (r"(?i)curl\s+[^\s|;]+\s*\|\s*(sudo )?(ba)?sh", "curl pipe-to-shell"),
    (r"(?i)wget\s+[^\s|;]+\s*(-[qO][^\s]*\s*)?\|\s*(sudo )?(ba)?sh", "wget pipe-to-shell"),
    (
        r"(?i)(sudo\s+)?(systemctl|service)\s+(stop|disable|mask)\s+(ufw|firewalld|iptables)",
        "disabling firewall",
    ),
    (r"(?i)(ufw|firewall-cmd|iptables)\s+-[ADFZ]\b|iptables\s+-F", "flushing firewall rules"),
    (r"(?i)rm\s+-rf?\s+/(?:etc|usr|var|home|root|boot|\*)", "root-directory delete"),
    (
        r"(?i)(cat|upload|send|post|transfer)\b[^|\n]{0,60}(~/\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b)",
        "key-file exfiltration",
    ),
    (r"(?i)chmod\s+\+x?\s+[^\n]{0,40}&&\s*\.\//", "download-chmod-execute chain"),
    (r"(?i)(eval|exec)\s*\(\s*(base64|atob|bytes\.fromhex)", "decode-and-execute"),
    (r"(?i)(nc|ncat|netcat)\s+-[elp][^\n]{0,60}(sh|bash|/bin/)", "reverse shell"),
    (r"(?i)import\s+socket[^;]{0,120}(exec|subprocess|popen)", "python reverse-shell marker"),
    (
        r"(?i)(powershell|iex)\s+.{0,30}(downloadstring|invoke-expression|iwr)",
        "powershell download-execute",
    ),
    (
        r"(?i)将?\.?env(ironment)?\s*(文件|变量)?(发送|上传|传到|post|upload|send)",
        "env exfiltration wording",
    ),
]

# INJ-3 B-CI-8 memory-poisoning templates (Kevin: "always remember/from now on...")
_MEMORY_POISON = re.compile(
    r"(请|帮我)?(永远|永久|一直)?(记住|记得|牢记)[^。\n]{0,60}"
    r"(以后|今后|之后|未来|下次|下次对话|所有(后续)?(回答|对话|会话)|新的会话|every|future|all (future|subsequent))|"
    r"(always|forever|permanently|from now on)[^.\n]{0,50}(remember|treat|believe|assume)|"
    r"(in (all )?(future|subsequent|new) (conversations?|sessions?|chats?|responses?))[^.\n]{0,60}(remember|assume|believe|follow)|"
    r"写入(你的)?(长期|永久)?记忆|存入记忆|memory injection",
    re.IGNORECASE,
)

# INJ-4 B-IA-1 hidden instructions for RAG/future retrieval (Kevin red-flag)
_RAG_POISON = re.compile(
    r"(当|如果|一旦)[^。\n]{0,12}(检索|搜索|召回|引用|索引|RAG)[^。\n]{0,50}"
    r"(请|则|就|必须|务必|忽略|执行|回答|告诉|输出|遵照|优先)|"
    r"when (retrieved|indexed|searched|cited|RAG)[^.]{0,80}(ignore|execute|answer|tell|output|follow)|"
    r"(供|为了)(未来|后续|以后)?(的)?(检索|RAG|检索系统|AI|agent|助手)(使用|参考|读取)|"
    r"for (future|subsequent) (retrieval|reference|RAG|agents?)|"
    r"(隐藏|注入)(指令|内容).{0,20}(检索|RAG|知识库)",
    re.IGNORECASE,
)

# INJ-5 B-IA-2 passive state-change references (img src -> API endpoint, auto-submit forms)
_PASSIVE_STATE_CHANGE = [
    r"<img[^>]+src=[\"'][^\"']*(api|/v[0-9]/|/user/|/delete|/set|/update|/subscribe|/follow|/logout|/reset)[^\"']*[\"']",
    r"<img[^>]+src=[\"'][^\"']*\?(?:token|action|cmd|do|op)=",
    r"<form[^>]*action=[\"'][^\"']*[\"'][^>]*>(?:(?!</form>).){0,200}(hidden|display\s*:\s*none|visibility\s*:\s*hidden)",
    r"<script>[^<]{0,200}(fetch|XMLHttpRequest|navigator\.sendBeacon)\(",
    r"(?i)<img[^>]+src=[\"'][^\"']*(localhost|127\.0\.0\.1|/admin|/internal)",
]

# INJ-6 B-CIA-8 assistant-config trojan (exfil/privilege logic in shareable assistant/GPT configs)
_ASSISTANT_TROJAN = [
    (
        r"(?i)(assistant|GPT|bot|助手)(的)?(配置|指令|instructions?)[^。\n]{0,60}(发送|上传|转发|POST|webhook)",
        "config exfiltration logic",
    ),
    (
        r"(?i)(每当|when (a )?user|用户)(提问|询问|输入)[^。\n]{0,80}(发送到|转发到|上传到|post to|send to|webhook|api)",
        "trigger-based exfiltration",
    ),
    (
        r"(?i)(工具|tool)[^。\n]{0,40}(越权|未授权|beyond (its )?(scope|permissions))",
        "out-of-scope tool call",
    ),
    (
        r"(?i)(悄悄|静默|silently|secretly|后台)[^。\n]{0,40}(发送|上传|收集|collect|gather|exfiltrat)",
        "covert collection",
    ),
]


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []

    for pat, name in _HIJACK_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-1",
                    pattern_id="INJ-1",
                    confidence=0.7,
                    message=f"Instruction hijack signature: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0),
                )
            )

    for pat, name in _DANGEROUS_CMD:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-2",
                    pattern_id="INJ-2",
                    confidence=0.85,
                    message=f"Dangerous command signature: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0),
                )
            )

    for m in _MEMORY_POISON.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-CI-8",
                pattern_id="INJ-3",
                confidence=0.65,
                message="Memory-poisoning template (LLM re-checks implantation intent)",
                state=state,
                pos=m.start(),
                matched_text=m.group(0),
            )
        )

    for m in _RAG_POISON.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-IA-1",
                pattern_id="INJ-4",
                confidence=0.6,
                message="Hidden-instruction template targeting future retrieval",
                state=state,
                pos=m.start(),
                matched_text=m.group(0),
            )
        )

    for pat in _PASSIVE_STATE_CHANGE:
        for m in re.finditer(pat, text, re.IGNORECASE | re.DOTALL):
            findings.append(
                make_finding(
                    taxonomy_id="B-IA-2",
                    pattern_id="INJ-5",
                    confidence=0.6,
                    message="Passive state-change resource reference",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0)[:150],
                )
            )
            break  # report only the first hit per shape

    for pat, name in _ASSISTANT_TROJAN:
        for m in re.finditer(pat, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    taxonomy_id="B-CIA-8",
                    pattern_id="INJ-6",
                    confidence=0.5,
                    message=f"Suspicious assistant-config logic: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0),
                    needs_review=True,
                )
            )

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
