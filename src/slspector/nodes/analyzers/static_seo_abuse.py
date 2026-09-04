"""静态 SEO/权威伪装 family: B-I-2（AI 检索操纵）+ B-I-3（推广注入）。

模式:
- SEO-1 关键词堆砌密度（B-I-2/B-I-3 共用）
- SEO-2 伪造引用结构（B-I-2）
- SEO-3 外链推广密度/锚文本农场（B-I-3）
"""

from __future__ import annotations

import re
from collections import Counter

from slspector.conversation import domain_of
from slspector.models import Finding
from slspector.nodes.analyzers.common import make_record_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_seo_abuse"

_PLATFORM_OWN = (
    "chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "gemini.google.com",
    "grok.com", "deepseek.com", "kimi.com", "chat.qwen.ai", "perplexity.ai",
    "poe.com", "aistudio.google.com", "meta.ai", "copilot.microsoft.com",
)

# 权威伪装高频词（B-I-2）
_AUTHORITY_CLAIMS = re.compile(
    r"(?i)(根据|来源[于:】：]|according to|based on).{0,40}"
    r"(官方|权威|最新|official|authoritative|peer[- ]reviewed|CDC|WHO|FDA|论文|研究显示|studies show)|"
    r"(权威|官方|exclusive|内幕|insider).{0,20}(来源|消息|source|guide|指南)",
    re.IGNORECASE,
)
# 伪造引用编号结构 [1][2] / 【参考1】但无对应来源列表
_FAKE_CITES = re.compile(r"\[(\d{1,2})\]")
_CITE_LIST = re.compile(r"(?i)^(?:参考|references?|来源|sources?)\s*[：:]?$", re.MULTILINE)

# 推广话术（B-I-3）
_PROMO_WORDS = re.compile(
    r"(?i)(限时优惠|特惠|折扣码|promo code|coupon|点击购买|立即咨询|加微信|加V|"
    r"免费领取|零风险|稳赚|包过|代考|代写|官方代理|总代理|一级代理|"
    r"best (price|deal)|discount|limited time offer|buy now|order now|click here)",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    links = state.get("links") or []
    n_chars = max(1, len(text))
    findings: list[Finding] = []

    # SEO-1 关键词堆砌：2-gram 频次异常
    words = re.findall(r"[\w\u4e00-\u9fff]{2,}", text.lower())
    if len(words) > 100:
        bigrams = Counter(zip(words, words[1:]))
        top_bigram, top_n = bigrams.most_common(1)[0]
        density = top_n / len(words)
        if density > 0.02 and top_n > 30:  # 同一二元组占全词 >2%
            tax = "B-I-2"
            findings.append(make_record_finding(
                taxonomy_id=tax, pattern_id="SEO-1", confidence=0.5,
                message=f"关键词堆砌（'{top_bigram[0]} {top_bigram[1]}' ×{top_n}，密度 {density:.1%}）",
                needs_review=True,
                evidence={"bigram": " ".join(top_bigram), "count": top_n, "density": round(density, 4)}))

    # SEO-2 伪造引用
    cites = _FAKE_CITES.findall(text)
    has_ref_list = bool(_CITE_LIST.search(text))
    if len(cites) >= 5 and not has_ref_list:
        findings.append(make_record_finding(
            taxonomy_id="B-I-2", pattern_id="SEO-2", confidence=0.5,
            message=f"引用编号 {len(cites)} 处但无对应参考列表（候选）",
            needs_review=True, evidence={"cite_marks": len(cites)}))
    auth = _AUTHORITY_CLAIMS.findall(text)
    if len(auth) >= 3:
        findings.append(make_record_finding(
            taxonomy_id="B-I-2", pattern_id="SEO-2", confidence=0.45,
            message=f"权威伪装措辞密集（×{len(auth)}，候选，LLM 复核 Phase 2）",
            needs_review=True, evidence={"count": len(auth)}))

    # SEO-3 推广密度
    promo = _PROMO_WORDS.findall(text)
    ext_links = []
    for l in links:
        d = domain_of(l["url"])
        if d and not any(d == p or d.endswith("." + p) for p in _PLATFORM_OWN):
            ext_links.append(l)
    promo_density = len(promo) * 100 / (n_chars / 1000)  # 每千字推广词数
    if len(promo) >= 3 and (promo_density > 1.0 or len(ext_links) >= 5):
        findings.append(make_record_finding(
            taxonomy_id="B-I-3", pattern_id="SEO-3", confidence=0.55,
            message=f"推广话术 ×{len(promo)} 与外链 ×{len(ext_links)} 共现（候选）",
            needs_review=True,
            evidence={"promo_words": len(promo), "ext_links": len(ext_links),
                      "per_1k_chars": round(promo_density, 2)}))
    # 锚文本农场：同一域名被不同锚文本高频引用
    if ext_links:
        dom_counts = Counter(domain_of(l["url"]) for l in ext_links)
        top_dom, top_n = dom_counts.most_common(1)[0]
        if top_n >= 8:
            findings.append(make_record_finding(
                taxonomy_id="B-I-3", pattern_id="SEO-3", confidence=0.5,
                message=f"单域名高频外链（{top_dom} ×{top_n}，候选）",
                needs_review=True, evidence={"domain": top_dom, "count": top_n}))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
