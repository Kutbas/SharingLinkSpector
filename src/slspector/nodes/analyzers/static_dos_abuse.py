"""静态滥用/DoS family: B-A-2/3/4 + B-IA-4 + B-IA-5。

模式:
- AB-1 体量/嵌套深度/表格规模阈值（B-A-2）
- AB-2 病态重复模式（B-A-3 ReDoS 对抗样本）
- AB-3 压缩比异常（B-A-4 zip 炸弹/实体展开类）
- AB-4 base64/hex 解码探针→C2 特征（B-IA-4，Kevin 红标: 候选+人工核验）
- AB-5 归档路径穿越特征（B-IA-5，候选）
"""

from __future__ import annotations

import base64
import binascii
import re

from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding, make_record_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_dos_abuse"

SIZE_WARN_CHARS = 80_000
SIZE_HIGH_CHARS = 300_000
NESTED_DEPTH_WARN = 40
TABLE_COLS_WARN = 60

# AB-2 病态重复：对抗样本结构（嵌套量词正则文本 / 单词连续重复 ≥30 / 超长同字符）
# 注意：不能直接用 (a+)+b 当检测器——它会匹配正文里所有 "ab"；
# 检测对象是攻击载荷本身：字面嵌套量词正则串、超长重复。
_NESTED_QUANTIFIER_TEXT = re.compile(
    r"\([A-Za-z0-9_\[\]{}|]+[+*]\)[+*]"
    r"|\([A-Za-z0-9_|]+\|[A-Za-z0-9_|]+\)[+*]{1}?"
)
_WORD_REPEAT = re.compile(r"\b(\w{1,12})(\s+\1\b){29,}", re.IGNORECASE)
_CHAR_RUN = re.compile(r"(.)\1{999,}")

# AB-4 解码探针
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{60,}(?![0-9a-fA-F])")
_DECODED_SUSPECT = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}"                      # IP
    r"|[A-Za-z0-9-]+\.(?:com|net|org|io|cn|ru|xyz|top|tk|cc|vip|club|online|shop)\b"  # 域名
    r"|(?:/bin/(?:ba)?sh|nc\s+-e|bash\s+-i|powershell|cmd\.exe|curl\s|wget\s)"        # 命令
    r"|(?:https?://[^\s\"']{8,})",                                                    # URL
)

# AB-5 归档穿越
_ARCHIVE_TRAVERSAL = re.compile(
    r"(?:^|[/\\])\.\.(?:[/\\]|$)" r"|(?:^|[\"'/])/(?:etc|usr|var|root|home|tmp)/" r"|\bsymlink\s*->",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    stats = state.get("text_stats") or {}
    attachments = state.get("attachments") or []
    findings: list[Finding] = []

    # AB-1 B-A-2 体量
    chars = int(stats.get("chars") or len(text))
    if chars >= SIZE_HIGH_CHARS:
        findings.append(make_record_finding(
            taxonomy_id="B-A-2", pattern_id="AB-1", confidence=0.7,
            message=f"超大内容体量（{chars:,} 字符）", evidence={"chars": chars}))
    elif chars >= SIZE_WARN_CHARS:
        findings.append(make_record_finding(
            taxonomy_id="B-A-2", pattern_id="AB-1", confidence=0.4,
            message=f"大内容体量（{chars:,} 字符）", needs_review=True,
            evidence={"chars": chars}))
    # 嵌套深度（markdown 引用/列表嵌套）
    depth = max_line_depth = 0
    for ln in text.splitlines():
        d = len(ln) - len(ln.lstrip(" >\t"))
        max_line_depth = max(max_line_depth, d)
    if max_line_depth >= NESTED_DEPTH_WARN:
        findings.append(make_record_finding(
            taxonomy_id="B-A-2", pattern_id="AB-1", confidence=0.5,
            message=f"深层嵌套结构（depth={max_line_depth}）", needs_review=True,
            evidence={"depth": max_line_depth}))
    # 表格列数
    for ln in text.splitlines():
        if ln.count("|") >= TABLE_COLS_WARN:
            findings.append(make_record_finding(
                taxonomy_id="B-A-2", pattern_id="AB-1", confidence=0.5,
                message=f"超宽表格行（{ln.count('|')} 列）", needs_review=True))
            break

    # AB-2 B-A-3 病态重复
    for m in _NESTED_QUANTIFIER_TEXT.finditer(text):
        findings.append(make_finding(
            taxonomy_id="B-A-3", pattern_id="AB-2", confidence=0.75,
            message="嵌套量词正则对抗样本特征", state=state,
            pos=m.start(), matched_text=m.group(0)[:80]))
        break
    for m in _WORD_REPEAT.finditer(text):
        findings.append(make_finding(
            taxonomy_id="B-A-3", pattern_id="AB-2", confidence=0.5,
            message=f"单词连续重复 ≥30 次（{m.group(1)!r}）", state=state,
            pos=m.start(), matched_text=m.group(0)[:80], needs_review=True,
            evidence={"word": m.group(1)}))
        break
    for m in _CHAR_RUN.finditer(text):
        findings.append(make_finding(
            taxonomy_id="B-A-3", pattern_id="AB-2", confidence=0.75,
            message=f"单字符超长连续（{len(m.group(0)):,}）", state=state,
            pos=m.start(), matched_text=m.group(0)[:20] + "…",
            evidence={"run_len": len(m.group(0))}))
        break
    longest_repeat = int(stats.get("longest_repeat") or 0)
    if longest_repeat >= 20_000:
        findings.append(make_record_finding(
            taxonomy_id="B-A-3", pattern_id="AB-2", confidence=0.7,
            message=f"超长前缀重复（≈{longest_repeat:,} 字符）",
            evidence={"longest_repeat": longest_repeat}))

    # AB-3 B-A-4 压缩比
    ratio = float(stats.get("compression_ratio") or 1.0)
    if chars > 10_000 and ratio < 0.01:
        findings.append(make_record_finding(
            taxonomy_id="B-A-4", pattern_id="AB-3", confidence=0.75,
            message=f"极端低压缩比（{ratio}，疑似压缩炸弹结构）",
            evidence={"compression_ratio": ratio, "chars": chars}))
    elif chars > 10_000 and ratio < 0.05:
        findings.append(make_record_finding(
            taxonomy_id="B-A-4", pattern_id="AB-3", confidence=0.45,
            message=f"低压缩比（{ratio}，候选）", needs_review=True,
            evidence={"compression_ratio": ratio, "chars": chars}))
    # 实体展开比：&xxe; 重复 × 千次级
    entity_refs = re.findall(r"&\w+;", text)
    if len(entity_refs) > 2_000 and len(set(entity_refs)) < 10:
        findings.append(make_record_finding(
            taxonomy_id="B-A-4", pattern_id="AB-3", confidence=0.6,
            message=f"实体引用海量重复（{len(entity_refs):,} 次）",
            evidence={"distinct": len(set(entity_refs)), "total": len(entity_refs)}))
    # 附件面：attachment_info 的 file_type/大小线索
    for a in attachments:
        ft = str(a.get("file_type") or "")
        if any(k in ft.lower() for k in ("zip", "gzip", "rar", "7z", "tar")):
            findings.append(make_record_finding(
                taxonomy_id="B-A-4", pattern_id="AB-3", confidence=0.4,
                message=f"归档附件（{a.get('file_name') or ft}，需人工核验大小）",
                needs_review=True, evidence={"attachment": a}))

    # AB-4 B-IA-4 解码探针（候选+人工核验）
    decoded_hits = 0
    for m in list(_B64_CANDIDATE.finditer(text))[:30]:
        tok = m.group(0)
        try:
            pad = tok + "=" * (-len(tok) % 4)
            raw = base64.b64decode(pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for dm in _DECODED_SUSPECT.finditer(decoded):
            decoded_hits += 1
            findings.append(make_finding(
                taxonomy_id="B-IA-4", pattern_id="AB-4", confidence=0.5,
                message=f"base64 解码后含可疑特征: {dm.group(0)[:50]}", state=state,
                pos=m.start(), matched_text=tok[:60] + "…", needs_review=True,
                evidence={"decoded_hit": dm.group(0)[:80]}))
            break
    for m in list(_HEX_CANDIDATE.finditer(text))[:30]:
        tok = m.group(0)
        if len(tok) % 2:
            tok = tok[:-1]
        try:
            decoded = bytes.fromhex(tok).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        for dm in _DECODED_SUSPECT.finditer(decoded):
            decoded_hits += 1
            findings.append(make_finding(
                taxonomy_id="B-IA-4", pattern_id="AB-4", confidence=0.5,
                message=f"hex 解码后含可疑特征: {dm.group(0)[:50]}", state=state,
                pos=m.start(), matched_text=tok[:60] + "…", needs_review=True,
                evidence={"decoded_hit": dm.group(0)[:80]}))
            break
    if decoded_hits == 0 and _B64_CANDIDATE.search(text) is None and _HEX_CANDIDATE.search(text) is None:
        pass  # 无候选，正常

    # AB-5 B-IA-5 归档穿越（附件名面 + 文本中的归档清单）
    for a in attachments:
        fname = str(a.get("file_name") or "")
        if _ARCHIVE_TRAVERSAL.search(fname):
            findings.append(make_record_finding(
                taxonomy_id="B-IA-5", pattern_id="AB-5", confidence=0.8,
                message=f"附件名含路径穿越特征: {fname}", needs_review=True,
                evidence={"file_name": fname}))
    for m in re.finditer(
        r"(?i)(?:zip|tar|unzip|archive)\s+(?:-x|--extract|xf|rv)\s+.{0,60}(\.\./|/etc/|/root/)", text
    ):
        findings.append(make_finding(
            taxonomy_id="B-IA-5", pattern_id="AB-5", confidence=0.55,
            message="归档解压命令含穿越路径", state=state,
            pos=m.start(), matched_text=m.group(0)[:100], needs_review=True))

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
