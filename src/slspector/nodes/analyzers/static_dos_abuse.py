"""Static abuse/DoS family: B-A-2/3/4 + B-IA-4 + B-IA-5.

Patterns:
- AB-1 volume / nesting depth / table scale thresholds (B-A-2)
- AB-2 pathological repetition (B-A-3 ReDoS adversarial payloads)
- AB-3 compression-ratio anomalies (B-A-4 zip bombs / entity expansion)
- AB-4 base64/hex decode probes -> C2 features (B-IA-4, red-flag: candidate + manual review)
- AB-5 archive path-traversal markers (B-IA-5, candidate)
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

# AB-2 pathological repetition: adversarial payload structures (literal nested-quantifier
# regex text / word repeated >=30x / very long same-char runs). Note: (a+)+b itself must NOT
# be used as a detector - it matches every "ab" in prose; detect the payload, not the disease.
_NESTED_QUANTIFIER_TEXT = re.compile(
    r"\([A-Za-z0-9_\[\]{}|]+[+*]\)[+*]"
    r"|\([A-Za-z0-9_|]+\|[A-Za-z0-9_|]+\)[+*]{1}?"
)
_WORD_REPEAT = re.compile(r"\b(\w{1,12})(\s+\1\b){29,}", re.IGNORECASE)
_CHAR_RUN = re.compile(r"(.)\1{999,}")

# AB-4 decode probes
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{60,}(?![0-9a-fA-F])")
_DECODED_SUSPECT = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IP
    r"|[A-Za-z0-9-]+\.(?:com|net|org|io|cn|ru|xyz|top|tk|cc|vip|club|online|shop)\b"  # domain
    r"|(?:/bin/(?:ba)?sh|nc\s+-e|bash\s+-i|powershell|cmd\.exe|curl\s|wget\s)"  # command
    r"|(?:https?://[^\s\"']{8,})",  # URL
)

# AB-5 archive traversal
_ARCHIVE_TRAVERSAL = re.compile(
    r"(?:^|[/\\])\.\.(?:[/\\]|$)"
    r"|(?:^|[\"'/])/(?:etc|usr|var|root|home|tmp)/"
    r"|\bsymlink\s*->",
)


def analyze(state: SlspectorState) -> list[Finding]:
    text = state["full_text"]
    stats = state.get("text_stats") or {}
    attachments = state.get("attachments") or []
    findings: list[Finding] = []

    # AB-1 B-A-2 volume
    chars = int(stats.get("chars") or len(text))
    if chars >= SIZE_HIGH_CHARS:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-2",
                pattern_id="AB-1",
                confidence=0.7,
                message=f"Oversized content volume ({chars:,} chars)",
                evidence={"chars": chars},
            )
        )
    elif chars >= SIZE_WARN_CHARS:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-2",
                pattern_id="AB-1",
                confidence=0.4,
                message=f"Large content volume ({chars:,} chars)",
                needs_review=True,
                evidence={"chars": chars},
            )
        )
    # nesting depth (markdown quote/list nesting)
    max_line_depth = 0
    for ln in text.splitlines():
        d = len(ln) - len(ln.lstrip(" >\t"))
        max_line_depth = max(max_line_depth, d)
    if max_line_depth >= NESTED_DEPTH_WARN:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-2",
                pattern_id="AB-1",
                confidence=0.5,
                message=f"Deeply nested structure (depth={max_line_depth})",
                needs_review=True,
                evidence={"depth": max_line_depth},
            )
        )
    # table column count
    for ln in text.splitlines():
        if ln.count("|") >= TABLE_COLS_WARN:
            findings.append(
                make_record_finding(
                    taxonomy_id="B-A-2",
                    pattern_id="AB-1",
                    confidence=0.5,
                    message=f"Oversized table row ({ln.count('|')} columns)",
                    needs_review=True,
                )
            )
            break

    # AB-2 B-A-3 pathological repetition
    for m in _NESTED_QUANTIFIER_TEXT.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-A-3",
                pattern_id="AB-2",
                confidence=0.75,
                message="Nested-quantifier ReDoS payload structure",
                state=state,
                pos=m.start(),
                matched_text=m.group(0)[:80],
            )
        )
        break
    for m in _WORD_REPEAT.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-A-3",
                pattern_id="AB-2",
                confidence=0.5,
                message=f"Word repeated consecutively >=30 times ({m.group(1)!r})",
                state=state,
                pos=m.start(),
                matched_text=m.group(0)[:80],
                needs_review=True,
                evidence={"word": m.group(1)},
            )
        )
        break
    for m in _CHAR_RUN.finditer(text):
        findings.append(
            make_finding(
                taxonomy_id="B-A-3",
                pattern_id="AB-2",
                confidence=0.75,
                message=f"Very long single-character run ({len(m.group(0)):,})",
                state=state,
                pos=m.start(),
                matched_text=m.group(0)[:20] + "…",
                evidence={"run_len": len(m.group(0))},
            )
        )
        break
    longest_repeat = int(stats.get("longest_repeat") or 0)
    if longest_repeat >= 20_000:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-3",
                pattern_id="AB-2",
                confidence=0.7,
                message=f"Long repeated prefix (~{longest_repeat:,} chars)",
                evidence={"longest_repeat": longest_repeat},
            )
        )

    # AB-3 B-A-4 compression ratio
    ratio = float(stats.get("compression_ratio") or 1.0)
    if chars > 10_000 and ratio < 0.01:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-4",
                pattern_id="AB-3",
                confidence=0.75,
                message=f"Extreme low compression ratio ({ratio}, suspected zip-bomb structure)",
                evidence={"compression_ratio": ratio, "chars": chars},
            )
        )
    elif chars > 10_000 and ratio < 0.05:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-4",
                pattern_id="AB-3",
                confidence=0.45,
                message=f"Low compression ratio ({ratio}, candidate)",
                needs_review=True,
                evidence={"compression_ratio": ratio, "chars": chars},
            )
        )
    # entity expansion ratio: &xxe; repeated thousands of times
    entity_refs = re.findall(r"&\w+;", text)
    if len(entity_refs) > 2_000 and len(set(entity_refs)) < 10:
        findings.append(
            make_record_finding(
                taxonomy_id="B-A-4",
                pattern_id="AB-3",
                confidence=0.6,
                message=f"Massive entity-reference repetition ({len(entity_refs):,} times)",
                evidence={"distinct": len(set(entity_refs)), "total": len(entity_refs)},
            )
        )
    # attachment surface: file_type/size hints from attachment_info
    for a in attachments:
        ft = str(a.get("file_type") or "")
        if any(k in ft.lower() for k in ("zip", "gzip", "rar", "7z", "tar")):
            findings.append(
                make_record_finding(
                    taxonomy_id="B-A-4",
                    pattern_id="AB-3",
                    confidence=0.4,
                    message=f"Archive attachment ({a.get('file_name') or ft}, size needs manual verification)",
                    needs_review=True,
                    evidence={"attachment": a},
                )
            )

    # AB-4 B-IA-4 decode probes (candidate + manual review)
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
        decoded = raw.decode("utf-8", errors="ignore")
        for dm in _DECODED_SUSPECT.finditer(decoded):
            decoded_hits += 1
            findings.append(
                make_finding(
                    taxonomy_id="B-IA-4",
                    pattern_id="AB-4",
                    confidence=0.5,
                    message=f"base64-decoded suspicious feature: {dm.group(0)[:50]}",
                    state=state,
                    pos=m.start(),
                    matched_text=tok[:60] + "…",
                    needs_review=True,
                    evidence={"decoded_hit": dm.group(0)[:80]},
                )
            )
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
            findings.append(
                make_finding(
                    taxonomy_id="B-IA-4",
                    pattern_id="AB-4",
                    confidence=0.5,
                    message=f"hex-decoded suspicious feature: {dm.group(0)[:50]}",
                    state=state,
                    pos=m.start(),
                    matched_text=tok[:60] + "…",
                    needs_review=True,
                    evidence={"decoded_hit": dm.group(0)[:80]},
                )
            )
            break
    if (
        decoded_hits == 0
        and _B64_CANDIDATE.search(text) is None
        and _HEX_CANDIDATE.search(text) is None
    ):
        pass  # no candidates, fine

    # AB-5 B-IA-5 archive traversal (attachment names + archive listings in text)
    for a in attachments:
        fname = str(a.get("file_name") or "")
        if _ARCHIVE_TRAVERSAL.search(fname):
            findings.append(
                make_record_finding(
                    taxonomy_id="B-IA-5",
                    pattern_id="AB-5",
                    confidence=0.8,
                    message=f"Attachment filename contains path-traversal marker: {fname}",
                    needs_review=True,
                    evidence={"file_name": fname},
                )
            )
    for m in re.finditer(
        r"(?i)(?:zip|tar|unzip|archive)\s+(?:-x|--extract|xf|rv)\s+.{0,60}(\.\./|/etc/|/root/)",
        text,
    ):
        findings.append(
            make_finding(
                taxonomy_id="B-IA-5",
                pattern_id="AB-5",
                confidence=0.55,
                message="Archive extraction command contains traversal path",
                state=state,
                pos=m.start(),
                matched_text=m.group(0)[:100],
                needs_review=True,
            )
        )

    return findings


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
