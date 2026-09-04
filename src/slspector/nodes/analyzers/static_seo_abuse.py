"""Static SEO/authority-impersonation family: B-I-2 (AI retrieval manipulation) + B-I-3 (promo injection).

Patterns:
- SEO-1 keyword-stuffing density (shared by B-I-2/B-I-3)
- SEO-2 fake citation structures (B-I-2)
- SEO-3 external-link promo density / anchor farms (B-I-3)
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

# authority-impersonation frequent words (B-I-2)
_AUTHORITY_CLAIMS = re.compile(
    r"(?i)(根据|来源[于:】：]|according to|based on).{0,40}"
    r"(官方|权威|最新|official|authoritative|peer[- ]reviewed|CDC|WHO|FDA|论文|研究显示|studies show)|"
    r"(权威|官方|exclusive|内幕|insider).{0,20}(来源|消息|source|guide|指南)",
    re.IGNORECASE,
)
# fake citation markers [1][2] without a corresponding reference list
_FAKE_CITES = re.compile(r"\[(\d{1,2})\]")
_CITE_LIST = re.compile(r"(?i)^(?:参考|references?|来源|sources?)\s*[：:]?$", re.MULTILINE)

# promo wording (B-I-3)
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

    # SEO-1 keyword stuffing: anomalous 2-gram frequency
    words = re.findall(r"[\w\u4e00-\u9fff]{2,}", text.lower())
    if len(words) > 100:
        bigrams = Counter(zip(words, words[1:]))
        top_bigram, top_n = bigrams.most_common(1)[0]
        density = top_n / len(words)
        if density > 0.02 and top_n > 30:  # one bigram > 2% of all words
            tax = "B-I-2"
            findings.append(make_record_finding(
                taxonomy_id=tax, pattern_id="SEO-1", confidence=0.5,
                message=f"Keyword stuffing ('{top_bigram[0]} {top_bigram[1]}' x{top_n}, density {density:.1%})",
                needs_review=True,
                evidence={"bigram": " ".join(top_bigram), "count": top_n, "density": round(density, 4)}))

    # SEO-2 fake citations
    cites = _FAKE_CITES.findall(text)
    has_ref_list = bool(_CITE_LIST.search(text))
    if len(cites) >= 5 and not has_ref_list:
        findings.append(make_record_finding(
            taxonomy_id="B-I-2", pattern_id="SEO-2", confidence=0.5,
            message=f"Citation markers x{len(cites)} without a reference list (candidate)",
            needs_review=True, evidence={"cite_marks": len(cites)}))
    auth = _AUTHORITY_CLAIMS.findall(text)
    if len(auth) >= 3:
        findings.append(make_record_finding(
            taxonomy_id="B-I-2", pattern_id="SEO-2", confidence=0.45,
            message=f"Dense authority-impersonation wording (x{len(auth)}, candidate; LLM re-check in Phase 2)",
            needs_review=True, evidence={"count": len(auth)}))

    # SEO-3 promo density
    promo = _PROMO_WORDS.findall(text)
    ext_links = []
    for l in links:
        d = domain_of(l["url"])
        if d and not any(d == p or d.endswith("." + p) for p in _PLATFORM_OWN):
            ext_links.append(l)
    promo_density = len(promo) * 100 / (n_chars / 1000)  # promo words per 1k chars
    if len(promo) >= 3 and (promo_density > 1.0 or len(ext_links) >= 5):
        findings.append(make_record_finding(
            taxonomy_id="B-I-3", pattern_id="SEO-3", confidence=0.55,
            message=f"Promo wording x{len(promo)} co-occurring with external links x{len(ext_links)} (candidate)",
            needs_review=True,
            evidence={"promo_words": len(promo), "ext_links": len(ext_links),
                      "per_1k_chars": round(promo_density, 2)}))
    # anchor farm: one domain referenced at high frequency
    if ext_links:
        dom_counts = Counter(domain_of(l["url"]) for l in ext_links)
        top_dom, top_n = dom_counts.most_common(1)[0]
        if top_n >= 8:
            findings.append(make_record_finding(
                taxonomy_id="B-I-3", pattern_id="SEO-3", confidence=0.5,
                message=f"High-frequency external links to one domain ({top_dom} x{top_n}, candidate)",
                needs_review=True, evidence={"domain": top_dom, "count": top_n}))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
