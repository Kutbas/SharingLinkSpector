"""静态链接分析 family: B-CI-3/4/5/6 + B-C-2 + B-C-4。

模式:
- LA-1 锚文本域名与 href 域名不一致（B-CI-4，确定性）
- LA-2 开放重定向参数（B-CI-5）
- LA-3 target=_blank 缺 rel=noopener（B-CI-6，候选）
- LA-4 外部资源引用追踪（B-C-2，候选）
- LA-5 内网/云元数据端点 URL（B-C-4，SSRF 诱导候选）
- LA-6 凭证引导话术 × 外链共现（B-CI-3）
"""

from __future__ import annotations

import re

from slspector.conversation import domain_of
from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_link_analysis"

# LA-2 开放重定向参数（知名平台的跳转参数模式）
_REDIRECT_PARAM = re.compile(
    r"[?&](?:url|next|redirect|redirect_uri|redirect_url|continue|return|returnTo|dest|destination|target|r|u|goto)="
    r"https?[%3A%2F]{0,12}|"
    r"[?&](?:url|next|redirect|continue|dest|goto)=(?:https?%3A|https?://)", re.IGNORECASE)

# LA-5 SSRF 诱导目标
_INTERNAL_URL_MARKS = re.compile(
    r"https?://(?:"
    r"169\.254\.169\.254|metadata\.google\.com|metadata\.azure\.com|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|0177\.0\.0\.1|\[::1\]|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")(?![\w.-])", re.IGNORECASE)
_SSRF_CONTEXT = re.compile(
    r"(访问|请求|fetch|curl|wget|打开|browse to).{0,30}(链接|url|地址|endpoint|端点)|"
    r"(help? ?me |帮我)(访问|请求|fetch).{0,40}(http|内网|internal)",
    re.IGNORECASE,
)

# LA-6 凭证引导话术（与外链/登录词共现）
_CRED_LURE = re.compile(
    r"(登录|login|sign ?in|验证|verify|身份认证|authentication).{0,40}"
    r"(链接|link|url|地址|页面|page|网站|site|二维码|QR)|"
    r"(输入|enter|提供|provide|submit).{0,30}(密码|password|验证码|OTP|credential|凭证|账号)",
    re.IGNORECASE,
)
# 知名平台域名（锚文本伪装时排除：锚文本是知名域不算伪装）
_TRUSTED_ANCHOR_DOMAINS = (
    "github.com", "google.com", "openai.com", "anthropic.com", "microsoft.com",
    "apple.com", "wikipedia.org", "stackoverflow.com", "baidu.com", "zhihu.com",
    "bilibili.com", "weibo.com", "douyin.com", "qq.com", "taobao.com", "jd.com",
    "cn.gov", "edu.cn",
)
# 平台自有域名（B-C-2/B-C-4 白名单用：指向分享平台自身的链接不算外链追踪）
_KNOWN_AI_DOMAINS = (
    "chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "gemini.google.com",
    "grok.com", "x.com", "deepseek.com", "kimi.com", "moonshot.cn", "chat.qwen.ai",
    "qwen.ai", "tongyi.aliyun.com", "perplexity.ai", "poe.com", "aistudio.google.com",
    "doubao.com", "volces.com", "meta.ai", "copilot.microsoft.com", "bing.com",
    "chat.deepseek.com",
)


def _is_trusted_anchor(anchor_domain: str) -> bool:
    return any(anchor_domain == d or anchor_domain.endswith("." + d) for d in _TRUSTED_ANCHOR_DOMAINS)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    links = state.get("links") or []
    platform = (state.get("meta") or {}).get("platform", "")
    findings: list[Finding] = []

    for link in links:
        url: str = link["url"]
        pos: int = link["pos"]
        dom = domain_of(url)
        if not dom:
            continue

        # LA-1 锚文本伪装：anchor 提到某域名但 href 是另一个域名
        # （锚文本自称可信域 + href 指向陌生域正是伪装核心场景，不做锚域豁免）
        if link["kind"] in ("link", "html_link") and link["anchor"]:
            anchor_text = link["anchor"]
            anchor_dom_match = re.search(
                r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", anchor_text, re.IGNORECASE)
            if anchor_dom_match:
                anchor_dom = anchor_dom_match.group(1).lower()
                anchor_root = ".".join(anchor_dom.split(".")[-2:])
                url_root = ".".join(dom.split(".")[-2:])
                if anchor_root != url_root and not _is_trusted_anchor(dom):
                    findings.append(make_finding(
                        taxonomy_id="B-CI-4", pattern_id="LA-1", confidence=0.85,
                        message="锚文本域名与目标域名不一致", state=state,
                        pos=pos, matched_text=f"[{anchor_text[:40]}]({url[:80]})",
                        evidence={"anchor_domain": anchor_dom, "href_domain": dom}))
            # 文本按钮式伪装：anchor 是 URL 样式文本
            elif re.fullmatch(r"https?://\S+|www\.\S+", anchor_text.strip()) and anchor_text.strip() not in url:
                m_anchor = re.search(r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", anchor_text, re.IGNORECASE)
                if m_anchor:
                    a_root = ".".join(m_anchor.group(1).lower().split(".")[-2:])
                    u_root = ".".join(dom.split(".")[-2:])
                    if a_root != u_root:
                        findings.append(make_finding(
                            taxonomy_id="B-CI-4", pattern_id="LA-1", confidence=0.8,
                            message="显示 URL 与真实目标不一致", state=state,
                            pos=pos, matched_text=anchor_text[:80],
                            evidence={"shown": m_anchor.group(1), "actual": dom}))

        # LA-2 开放重定向
        m = _REDIRECT_PARAM.search(url)
        if m:
            findings.append(make_finding(
                taxonomy_id="B-CI-5", pattern_id="LA-2", confidence=0.6,
                message="开放重定向参数模式", state=state,
                pos=pos, matched_text=url[:120], needs_review=True,
                evidence={"param_match": m.group(0)[:60]}))

        # LA-5 SSRF 诱导
        if _INTERNAL_URL_MARKS.search(url):
            ctx_boost = bool(_SSRF_CONTEXT.search(text[max(0, pos - 300) : pos + 300]))
            findings.append(make_finding(
                taxonomy_id="B-C-4", pattern_id="LA-5",
                confidence=0.8 if ctx_boost else 0.6,
                message="内网/云元数据端点 URL" + ("（伴随访问诱导语境）" if ctx_boost else ""),
                state=state, pos=pos, matched_text=url[:120], needs_review=not ctx_boost))

        # LA-4 外部资源追踪（B-C-2）：非平台自有域的资源引用
        if link["kind"] == "resource":
            is_platform_own = any(dom == d or dom.endswith("." + d) for d in _KNOWN_AI_DOMAINS)
            if not is_platform_own:
                findings.append(make_finding(
                    taxonomy_id="B-C-2", pattern_id="LA-4", confidence=0.45,
                    message="外部资源引用（潜在追踪/去匿名化）", state=state,
                    pos=pos, matched_text=url[:120], needs_review=True,
                    evidence={"domain": dom, "platform": platform}))

    # LA-3 tabnabbing（HTML 片段面）
    for m in re.finditer(r"<a\s[^>]*target=[\"']_blank[\"'][^>]*>", text, re.IGNORECASE):
        tag = m.group(0)
        if not re.search(r"rel=[\"'][^\"']*noopener", tag, re.IGNORECASE):
            findings.append(make_finding(
                taxonomy_id="B-CI-6", pattern_id="LA-3", confidence=0.5,
                message="target=_blank 缺 rel=noopener（候选，需人工核验）", state=state,
                pos=m.start(), matched_text=tag[:120], needs_review=True))

    # LA-6 凭证引导 × 外链共现
    ext_links = [l for l in links if domain_of(l["url"]) and not any(
        (domain_of(l["url"]) == d or domain_of(l["url"]).endswith("." + d)) for d in _KNOWN_AI_DOMAINS)]
    for m in _CRED_LURE.finditer(text):
        near = any(abs(l["pos"] - m.start()) < 400 for l in ext_links)
        if near:
            findings.append(make_finding(
                taxonomy_id="B-CI-3", pattern_id="LA-6", confidence=0.55,
                message="凭证引导话术与外链共现（候选）", state=state,
                pos=m.start(), matched_text=m.group(0), needs_review=True))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
