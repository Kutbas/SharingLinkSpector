#!/usr/bin/env python
"""Export taxonomy-0901-v5.xlsx (symptom sheet) -> data/categories.yaml.

Produces the single source of truth consumed by slspector at runtime:
- 49 categories with ID / L1 / leaf / definition / source / detection-method text
- leaf_en: English leaf names for the English-venue paper and tool output
- detectability: which tracks are possible (static/llm/dynamic/metadata/platform)
- kevin_note: verbatim I-column "verdict rationale (red-flagged items)"
- llm.prompt: English judging prompts for Phase 1 LLM categories

Re-run:  uv run --extra export python tools/export_taxonomy.py
"""

from __future__ import annotations

import re
from pathlib import Path

import openpyxl
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_XLSX = ROOT / "taxonomy-0901-v5.xlsx"
OUT = ROOT / "data" / "categories.yaml"

# English leaf names (single source for paper + tool output)
LEAF_EN = {
    "A-C-1": "Identity information disclosure",
    "A-C-2": "Sensitive privacy disclosure",
    "A-C-3": "Credential leakage",
    "A-C-4": "Technical information leakage",
    "A-C-5": "Digital footprint leakage",
    "A-C-6": "High-risk personal safety information",
    "A-I-1": "Jailbreak showcase",
    "B-C-1": "System prompt disclosure",
    "B-C-2": "External resource tracking (viewer de-anonymization)",
    "B-C-3": "Model distillation/extraction via public shares",
    "B-C-4": "Preview-triggered SSRF",
    "B-C-5": "XML external entity injection (XXE)",
    "B-C-6": "Cross-site leaks (XS-Leaks)",
    "B-I-1": "Harmful content hosting/distribution",
    "B-I-2": "AI search results manipulation (GEO)",
    "B-I-3": "Traditional SEO manipulation",
    "B-I-4": "Share preview card forgery (OpenGraph/oEmbed)",
    "B-I-5": "Media provenance forgery (C2PA)",
    "B-I-6": "Mutable share TOCTOU mismatch",
    "B-I-7": "Moderation classifier evasion (obfuscation)",
    "B-I-8": "False factual claims",
    "B-I-9": "Misleading summaries",
    "B-I-10": "Harmful decision advice",
    "B-A-1": "Application-layer resource exhaustion",
    "B-A-2": "Complex content rendering exhaustion",
    "B-A-3": "Regex denial of service via crafted content",
    "B-A-4": "Decompression/media bombs",
    "B-CI-1": "Image/cross-modal prompt injection",
    "B-CI-2": "Zero-width/Bidi hidden-character injection",
    "B-CI-3": "Trusted-domain phishing/social engineering",
    "B-CI-4": "Hyperlink anchor-text spoofing",
    "B-CI-5": "Open redirect",
    "B-CI-6": "Reverse tabnabbing",
    "B-CI-7": "Embedded malicious QR codes (quishing)",
    "B-CI-8": "Cross-session persistent memory poisoning",
    "B-IA-1": "Enterprise RAG/knowledge-base poisoning",
    "B-IA-2": "Passive cross-site state changes via share pages",
    "B-IA-3": "Base-model training data poisoning",
    "B-IA-4": "Share links as C2 dead drops",
    "B-IA-5": "Archive path traversal (zip slip)",
    "B-CIA-1": "Natural-language instruction hijacking (direct prompt injection)",
    "B-CIA-2": "AI-summary-driven social engineering",
    "B-CIA-3": "Stored XSS in shared content",
    "B-CIA-4": "CSV/formula injection via tables",
    "B-CIA-5": "Terminal ANSI escape injection",
    "B-CIA-6": "Server-side template injection (SSTI)",
    "B-CIA-7": "Insecure deserialization",
    "B-CIA-8": "Shared custom assistant/GPT configuration trojan",
    "B-CIA-9": "Malicious/imitation dependency recommendation",
}

# Kevin's I-column dispositions (confirmed 2026-09-04 review)
RED_FLAG_DISPOSITION = {
    "B-C-3": {"status": "skipped", "reason": "No detectable feature; paper story only, not labeled"},
    "B-A-1": {"status": "skipped", "reason": "No detectable feature; paper story only, not labeled"},
    "B-CIA-7": {"status": "skipped", "reason": "Payload not in collected metadata; future work/discussion"},
    "B-C-5": {"status": "implemented", "reason": "Payload lives in raw bytes; static scan detects it"},
    "B-C-6": {"status": "candidate", "reason": "Flag anomalous cross-origin resource candidates -> manual review; victim presence not required"},
    "B-CI-6": {"status": "candidate", "reason": "Candidate external links detectable; verdict needs target-site info -> manual review"},
    "B-CI-8": {"status": "implemented", "reason": "Poisoning-instruction templates + LLM intent/contextual-fit judgment"},
    "B-IA-1": {"status": "implemented", "reason": "Hidden-instruction templates; false-fact poisoning undetectable (documented)"},
    "B-IA-2": {"status": "implemented", "reason": "Same as B-IA-1: hidden-instruction templates primary"},
    "B-IA-4": {"status": "candidate", "reason": "base64/hex decode probes produce candidates -> manual/LLM target verification"},
    "B-CIA-3": {"status": "implemented", "reason": "Executable-structure static detection; attack realization irrelevant"},
    "B-CIA-6": {"status": "candidate", "reason": "Template meta-syntax candidates, high FP rate -> manual review"},
}

# LLM prompt coverage: all H-column 【LLM】-marked categories minus ruled-out ones.
# 44 marked - 4 excluded = 40 prompts (11 from Phase 1 + 29 new in Phase 2).
LLM_EXCLUDED = {
    # cid: reason (documented in coverage; no prompt generated)
    "B-C-3": "distillation attack itself not observable by third parties; Kevin's I-column verdict: skipped",
    "B-A-1": "creation-side rate data not available to third parties; Kevin's I-column verdict: skipped",
    "B-IA-3": "corpus-level clustering capability (batch layer), out of scope for per-record detection",
    "B-IA-5": "H column explicitly marks LLM as not applicable (structural static detection suffices)",
}

LLM_COVERAGE = {
    "A-C-1", "A-C-2", "A-C-3", "A-C-4", "A-C-5", "A-C-6",
    "A-I-1", "B-CIA-1", "B-CI-8", "B-IA-1", "B-IA-2",
    # Phase 2 additions
    "B-C-1", "B-C-2", "B-C-4", "B-C-5", "B-C-6",
    "B-I-1", "B-I-2", "B-I-3", "B-I-4", "B-I-7", "B-I-8", "B-I-9", "B-I-10",
    "B-A-2", "B-A-3", "B-A-4",
    "B-CI-2", "B-CI-3", "B-CI-4", "B-CI-5", "B-CI-7",
    "B-IA-4",
    "B-CIA-2", "B-CIA-3", "B-CIA-4", "B-CIA-5", "B-CIA-6", "B-CIA-8", "B-CIA-9",
}
assert len(LLM_COVERAGE) == 40, f"expected 40 LLM prompts, got {len(LLM_COVERAGE)}"

# Per-class extra guidance appended to the generic prompt template.
# English-only (codebase convention); used where content-only judging has a
# known limitation the model must be told about explicitly.
EXTRA_GUIDANCE = {
    "B-I-8": (
        "## Known limitation\n"
        "You have NO retrieval/fact-checking capability. You CANNOT verify factual "
        "truth. Judge ONLY the weaker content-side signal: the density of high-specificity "
        "assertions made without any source, citation, or hedge. This is a weak signal: "
        "cap confidence at 0.6 and state in reasoning that factuality was not verified."
    ),
    "B-CI-7": (
        "## Known limitation\n"
        "You see TEXT ONLY; QR/barcode images are not visible to you. Judge ONLY when "
        "the conversation text itself contains scan-bait phrasing (e.g. \"scan to "
        "claim/log in\") or decoded QR target URLs; otherwise hit=false."
    ),
    "B-C-4": (
        "## Judging scope\n"
        "The attack triggers when the platform preview-fetches a URL. You judge the "
        "content-side inducement: does the conversation embed URLs pointing at internal "
        "targets (localhost, 127.0.0.1, 169.254.x, cloud metadata endpoints, intranet "
        "hosts) that a preview bot would be tricked into fetching?"
    ),
    "B-I-4": (
        "## Judging scope\n"
        "The share-card metadata (title) is provided at the top of the conversation. "
        "Judge semantic consistency between that title and the conversation body; "
        "mismatch alone is a weak signal — cap confidence at 0.6 unless the title is "
        "clearly baiting (clickbait/impersonation)."
    ),
    "B-A-2": (
        "## Judging scope\n"
        "Judge whether the content structure looks maliciously constructed to burn "
        "rendering resources (deeply nested structures, pathological repetition, "
        "combinatorial expansions) versus a legitimately long document."
    ),
    "B-A-3": (
        "## Judging scope\n"
        "Your role is CONFIRMATORY: distinguish legitimate encoded/compressed data "
        "(data exchange, backups) from constructed ReDoS/decompression-bomb payloads. "
        "When in doubt, hit=false (the static track already flags candidates)."
    ),
    "B-IA-4": (
        "## Judging scope\n"
        "Judge whether steganographic-looking payloads (base64/hex blobs, zero-width "
        "runs) combine with ordinary conversation in a way consistent with C2 "
        "command channels. Benign encoding use (data exchange) must not hit."
    ),
}

# Status overrides for Phase 2 (LLM track now live for these classes)
STATUS_OVERRIDES = {
    "B-C-1": "implemented",   # was phase2_llm
    "B-I-8": "implemented",   # was future_work; weak-signal prompt with limitation
    "B-I-9": "implemented",   # was phase2_llm
    "B-I-10": "implemented",  # was phase2_llm
    "B-CI-7": "implemented",  # was future_work; text-only limited prompt
}

# Coverage notes for classes that stay out of the LLM track on capability grounds
CAPABILITY_NOTES = {
    "B-CI-1": "requires a multimodal provider (image content); text-only LLM track cannot judge",
    "B-IA-3": "corpus-level clustering (batch layer over the full dataset), not per-record detection",
}

# Phase/track plan for non-red-flagged categories
PLANNED = {
    "B-C-1": "phase2_llm",
    "B-I-4": "phase2_dynamic",
    "B-I-5": "future_work",
    "B-I-6": "future_work",
    "B-I-8": "future_work",
    "B-I-9": "phase2_llm",
    "B-I-10": "phase2_llm",
    "B-CI-1": "future_work",
    "B-CI-7": "future_work",
    "B-IA-3": "future_work",
    "B-A-2": "implemented",
    "B-A-3": "implemented",
    "B-A-4": "implemented",
    "B-C-2": "implemented",
    "B-C-4": "implemented",
    "B-I-1": "implemented",
    "B-I-2": "implemented",
    "B-I-3": "implemented",
    "B-I-7": "implemented",
    "B-CI-2": "implemented",
    "B-CI-3": "implemented",
    "B-CI-4": "implemented",
    "B-CI-5": "implemented",
    "B-IA-5": "candidate",
    "B-CIA-2": "implemented",
    "B-CIA-4": "implemented",
    "B-CIA-5": "implemented",
    "B-CIA-8": "implemented",
    "B-CIA-9": "implemented",
}


def parse_tracks(h_text: str) -> list[str]:
    return re.findall(r"【(静态|LLM|动态|元数据|平台方)】", h_text or "")


TRACK_EN = {"静态": "static", "LLM": "llm", "动态": "dynamic", "元数据": "metadata", "平台方": "platform"}


def llm_prompt(definition: str, h_text: str, leaf_en: str, cid: str = "") -> str:
    """English judging prompt; original Chinese definition kept verbatim for nuance."""
    m = re.search(r"【LLM[^】]*】([^；;]+)", h_text or "")
    llm_point = m.group(1).strip() if m else ""
    extra = EXTRA_GUIDANCE.get(cid, "")
    return (
        "You are a security risk annotator for AI conversation sharing links. "
        f"Determine whether the conversation below exhibits the risk category "
        f"\"{leaf_en}\".\n\n"
        "## Category definition\n"
        f"{definition}\n"
        "## Detection guidance (from taxonomy)\n"
        f"{llm_point}\n\n"
        + (extra + "\n\n" if extra else "")
        + "## Judging requirements\n"
        "1. Judge only from the conversation content itself; make no network requests.\n"
        "2. Distinguish a real risk from teaching/discussion/example contexts "
        "(discussing the risk is NOT exhibiting the risk).\n"
        "3. The conversation may be in any language (Chinese/English/other).\n"
        "4. If suspicious signs exist but cannot be confirmed, set hit=true with "
        "confidence<=0.5.\n"
        "5. Output strict JSON only: {\"hit\": bool, \"confidence\": 0-1, "
        "\"evidence\": \"verbatim key excerpt (<=200 chars, original language)\", "
        "\"reasoning\": \"judgment rationale (English, <=150 words)\"}"
    )


def main() -> None:
    src = DEFAULT_XLSX
    wb = openpyxl.load_workbook(src, data_only=True)
    ws = wb["症状"]
    headers = [ws.cell(row=1, column=c).value for c in range(1, 10)]
    categories = []
    for r in range(2, ws.max_row + 1):
        row = {headers[c - 1]: ws.cell(row=r, column=c).value for c in range(1, 10)}
        cid = str(row["ID"] or "").strip()
        if not cid:
            continue
        h = str(row["检测方法（检测器设计要点）"] or "")
        definition = str(row["定义与症状"] or "")
        leaf = str(row["攻击手段 Technique（叶子）"] or "")
        disp = RED_FLAG_DISPOSITION.get(cid)
        status = STATUS_OVERRIDES.get(cid, disp["status"] if disp else PLANNED.get(cid, "implemented"))
        note = disp["reason"] if disp else CAPABILITY_NOTES.get(cid, "")
        kevin_note = str(row["判定理由（红标项）"] or "") or None
        cat = {
            "id": cid,
            "model": str(row["威胁模型"] or ""),
            "l1": str(row["机制大类 (L1)"] or ""),
            "leaf": leaf,
            "leaf_en": LEAF_EN[cid],
            "definition": definition,
            "source_refs": str(row["来源"] or ""),
            "detection_methods": h,
            "tracks": [TRACK_EN[t] for t in parse_tracks(h)],
            "status": status,
            "note": note,
            "kevin_note": kevin_note,
        }
        if cid in LLM_COVERAGE:
            cat["llm"] = {
                "prompt": llm_prompt(definition, h, LEAF_EN[cid], cid),
                "needs_review": status == "candidate",
            }
        elif cid in LLM_EXCLUDED:
            cat["note"] = (note + "; " if note else "") + LLM_EXCLUDED[cid]
        categories.append(cat)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "source": src.name,
        "sheet": "症状",
        "count": len(categories),
        "llm_prompt_count": len(LLM_COVERAGE),
        "llm_excluded": LLM_EXCLUDED,
        "exported_at": "2026-09-04",
        "status_legend": {
            "implemented": "detection implemented in Phase 1",
            "candidate": "candidate findings only, needs_review=true for manual verification",
            "phase2_llm": "LLM track extension in Phase 2",
            "phase2_dynamic": "requires refetch/dynamic capability, Phase 2",
            "future_work": "paper future work / discussion",
            "skipped": "not labeled (Kevin's I-column verdict)",
        },
    }
    with OUT.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            {"meta": meta, "categories": categories},
            f, allow_unicode=True, sort_keys=False, width=120,
        )
    print(f"exported {len(categories)} categories -> {OUT}")
    from collections import Counter
    print(Counter(c["status"] for c in categories))
    missing = [c["id"] for c in categories if c["id"] not in LEAF_EN]
    assert not missing, f"missing English leaf names: {missing}"


if __name__ == "__main__":
    main()
