"""静态高危内容 family: A-C-6（高危信息）/ A-I-1（越狱模板）/ B-I-1（有害内容）。

模式:
- HJ-1 人身安危高敏词表（A-C-6，低召回兜底，LLM 为主）
- HJ-2 越狱模板指纹（A-I-1）
- HJ-3 有害内容关键词/结构信号（B-I-1，兜底）
"""

from __future__ import annotations

import re

from slspector.models import Finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_harmful_jailbreak"

# HJ-1 A-C-6（LLM 为主，此为低召回兜底）
_HIGH_RISK_LEXICON = re.compile(
    r"家庭住址.{0,20}(泄露|公开)|具体住址|我家地址是|现住址.{0,10}[：:]|"
    r"行踪|定位.{0,10}(跟踪|追踪)| stalking|被跟踪| "
    r"失踪人口|人口贩卖|买卖人口|绑架|勒索赎金| "
    r"证人保护|举报人|线人身份| "
    r"自杀遗书|轻生|自残计划",
)

# HJ-2 A-I-1 越狱模板
_JAILBREAK_PATTERNS = [
    (r"\bDAN\b.{0,40}(do anything now|模式|mode)", "DAN 模式"),
    (r"(?i)ignore (all|previous|above) (instructions|rules|restrictions)", "忽略指令类越狱(EN)"),
    (r"忽略(以上|之前|之前所有|上述)(的)?(指令|规则|限制|设定)", "忽略指令类越狱(CN)"),
    (r"(?i)(you are|act as|pretend to be).{0,30}(no restrictions|unrestricted|without any (limits|restrictions)|不受限|无限制)", "无限制角色扮演"),
    (r"(?i)jailbreak (prompt|mode)", "jailbreak 显式提及"),
    (r"(?i)developer mode|godmode|admin mode.{0,20}(enabled|开启)", "开发者模式类"),
    (r"(?i)hypothetical(ly)?.{0,40}(no rules|anything goes)|思想实验.{0,30}(无限制|没有规则)", "假想情境越狱"),
    (r"(?i)(你现在是|扮演)(一个)?(没有|无)(道德|伦理|安全)(限制|约束|审查)", "去约束角色扮演(CN)"),
    (r"(?i)rule bypass|安全绕过|绕过(安全|内容|合规)(策略|审查|过滤)", "安全绕过话术"),
]
_JB_SUCCESS_MARK = re.compile(
    r"(?i)(成功|done it|worked).{0,40}(绕过|bypass|越狱|jailbreak)|"
    r"看,{0,5}我还是(能|可以).{0,20}(输出|生成|回答)",
)

# HJ-3 B-I-1（LLM 为主，兜底信号）
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
        findings.append(make_finding(
            taxonomy_id="A-C-6", pattern_id="HJ-1", confidence=0.5,
            message="人身安危高敏信号（兜底，LLM 为主）", state=state,
            pos=m.start(), matched_text=m.group(0), needs_review=True))

    for pat, name in _JAILBREAK_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            # 检查后文 500 字内是否有"成功展示"迹象，提升置信度
            after = text[m.end() : m.end() + 500]
            conf = 0.8 if _JB_SUCCESS_MARK.search(after) else 0.6
            findings.append(make_finding(
                taxonomy_id="A-I-1", pattern_id="HJ-2", confidence=conf,
                message=f"越狱模板: {name}", state=state,
                pos=m.start(), matched_text=m.group(0)))

    for m in _HARMFUL_LEXICON.finditer(text):
        findings.append(make_finding(
            taxonomy_id="B-I-1", pattern_id="HJ-3", confidence=0.55,
            message="有害内容关键词（兜底，LLM 为主）", state=state,
            pos=m.start(), matched_text=m.group(0)))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
