"""Static harmful-content family: A-C-6 / A-I-1 / B-I-1.

Patterns:
- HJ-1 personal-safety high-risk lexicon (A-C-6, low-recall fallback; LLM primary)
- HJ-2 jailbreak template fingerprints (A-I-1)
- HJ-3 harmful-content keyword/structure signals (B-I-1, fallback)
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_harmful_jailbreak"

# HJ-1 A-C-6 (LLM primary; this is a low-recall fallback)
_HIGH_RISK_LEXICON = re.compile(
    r"家庭住址.{0,20}(泄露|公开)|具体住址|我家地址是|现住址.{0,10}[：:]|"
    r"行踪|定位.{0,10}(跟踪|追踪)| stalking|被跟踪| "
    r"失踪人口|人口贩卖|买卖人口|绑架|勒索赎金| "
    r"证人保护|举报人|线人身份| "
    r"自杀遗书|轻生|自残计划",
)

# HJ-2 A-I-1 jailbreak templates
_JAILBREAK_PATTERNS = [
    (r"\bDAN\b.{0,40}(do anything now|模式|mode)", "DAN mode"),
    (
        r"(?i)ignore (all|previous|above) (instructions|rules|restrictions)",
        "instruction-override jailbreak (EN)",
    ),
    (
        r"忽略(以上|之前|之前所有|上述)(的)?(指令|规则|限制|设定)",
        "instruction-override jailbreak (CN)",
    ),
    (
        r"(?i)(you are|act as|pretend to be).{0,30}(no restrictions|unrestricted|without any (limits|restrictions)|不受限|无限制)",
        "unrestricted roleplay",
    ),
    (r"(?i)jailbreak (prompt|mode)", "explicit jailbreak mention"),
    (r"(?i)developer mode|godmode|admin mode.{0,20}(enabled|开启)", "developer-mode family"),
    (
        r"(?i)hypothetical(ly)?.{0,40}(no rules|anything goes)|思想实验.{0,30}(无限制|没有规则)",
        "hypothetical-scenario jailbreak",
    ),
    (
        r"(?i)(你现在是|扮演)(一个)?(没有|无)(道德|伦理|安全)(限制|约束|审查)",
        "de-constrained roleplay (CN)",
    ),
    (r"(?i)rule bypass|安全绕过|绕过(安全|内容|合规)(策略|审查|过滤)", "safety-bypass wording"),
]
_JB_SUCCESS_MARK = re.compile(
    r"(?i)(成功|done it|worked).{0,40}(绕过|bypass|越狱|jailbreak)|"
    r"看,{0,5}我还是(能|可以).{0,20}(输出|生成|回答)",
)

# HJ-3 B-I-1 (LLM primary; fallback signals)
_HARMFUL_LEXICON = re.compile(
    r"炸弹制造|爆炸物(配方|制作)|制作炸弹|枪支(改造|购买渠道)|消音器 DIY|"
    r"冰毒(制作|合成|配方)|甲基苯丙胺合成|合成大麻|制毒|"
    r"黑客(接单|服务|入侵.{0,10}(收费|接单))|DDoS.{0,10}(出租|接单)|ransomware.{0,20}(source|源码|出售)|"
    r"虚假身份证(办理|制作)|假钞|洗钱(教程|通道|服务)|"
    r"自杀方法|安乐死(药物|方法详情)|购买枪支.{0,10}(渠道|联系方式)",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    findings: list[Finding] = []
    from slspector.nodes.analyzers.common import make_finding

    for m in _HIGH_RISK_LEXICON.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="A-C-6",
                pattern_id="HJ-1",
                confidence=0.5,
                message="High-risk personal-safety signal (fallback; LLM primary)",
                state=state,
                pos=m.start(),
                matched_text=m.group(0),
                needs_review=True,
            )
        )

    for pat, name in _JAILBREAK_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            # boost confidence when a "successful demonstration" appears within 500 chars after
            after = text[m.end() : m.end() + 500]
            conf = 0.8 if _JB_SUCCESS_MARK.search(after) else 0.6
            findings.append(
                make_finding(
                    taxonomy_id="A-I-1",
                    pattern_id="HJ-2",
                    confidence=conf,
                    message=f"Jailbreak template: {name}",
                    state=state,
                    pos=m.start(),
                    matched_text=m.group(0),
                )
            )

    for m in _HARMFUL_LEXICON.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-I-1",
                pattern_id="HJ-3",
                confidence=0.55,
                message="Harmful-content keyword (fallback; LLM primary)",
                state=state,
                pos=m.start(),
                matched_text=m.group(0),
            )
        )

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
