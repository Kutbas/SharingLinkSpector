"""Two-stage screening feasibility probe (Phase 2 task 3, standalone).

Stage 1: ONE relevance-screening call per record (compact 40-category catalog,
returns candidate category IDs). Stage 2 would judge only candidates with the
full per-category prompts. This script measures stage-1 recall against the
full-40 judgments from out/llm_live_8 (ground truth = any LLM hit with
confidence >= 0.4), plus screening token cost.

Usage:
  .venv/bin/python tools/screening_probe.py out/llm_live_8/findings.jsonl \
      ../Taxonomy_Building/taxonomy_subset_650.jsonl --limit 8
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from slspector import taxonomy  # noqa: E402
from slspector.providers import resolve_provider  # noqa: E402
from slspector.nodes.analyzers.llm_analyzer import _thread_client  # noqa: E402

CATALOG_TMPL = """You are triaging an AI conversation shared via a public link. Below is a catalog of 40 security/privacy risk categories. List EVERY category id that this conversation might plausibly exhibit — err toward inclusion (over-flagging is cheap, misses are not), but do not list categories with zero connection to the content. If none apply, return an empty list.

## Category catalog (id: name — gloss)
{catalog}

## Conversation title
{title}

## Conversation
{text}

Output strict JSON only: {{"candidates": ["<id>", ...], "reason": "<one line, English>"}}"""


def build_catalog() -> str:
    gloss_path = Path(__file__).parent / "screening_gloss.json"
    glosses = json.loads(gloss_path.read_text(encoding="utf-8")) if gloss_path.exists() else {}
    lines = []
    for cid, c in taxonomy.llm_categories().items():
        g = glosses.get(cid, "")
        lines.append(f"{cid}: {c['leaf_en']}" + (f" — {g}" if g else ""))
    return "\n".join(lines)


def screen_record(cfg, record: dict) -> tuple[set[str], dict]:
    msgs = record.get("messages") or []
    text = "\n\n".join(f"{m.get('role','?')}: {m.get('content','')}" for m in msgs)[:24000]
    title = record.get("conversation_title") or "(none)"
    client = _thread_client(cfg)
    resp = client.chat.completions.create(
        model=cfg.model,
        messages=[{"role": "user", "content": CATALOG_TMPL.format(
            catalog=build_catalog(), title=title, text=text)}],
        temperature=0.1,
        response_format={"type": "json_object"},
        extra_body={"thinking": {"level": cfg.thinking}} if cfg.thinking else None,
    )
    content = resp.choices[0].message.content or "{}"
    obj = json.loads(content[content.find("{"):content.rfind("}") + 1])
    cands = {str(x).strip() for x in obj.get("candidates", [])}
    known = set(taxonomy.llm_categories().keys())
    usage = {"prompt_tokens": resp.usage.prompt_tokens or 0,
             "completion_tokens": resp.usage.completion_tokens or 0}
    return cands & known, usage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", type=Path, help="full-40 findings.jsonl (ground truth)")
    ap.add_argument("subset", type=Path, help="subset jsonl (same order as scan)")
    ap.add_argument("--limit", type=int, default=8)
    args = ap.parse_args()

    truth = {}
    with args.findings.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            hits = {fd["taxonomy_id"] for fd in r["findings"]
                    if fd["detector"] == "llm" and fd["confidence"] >= 0.4}
            truth[r["share_id"]] = hits

    cfg = resolve_provider("dmxapi")
    records = []
    with args.subset.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= args.limit:
                break
            records.append(json.loads(line))

    total_truth = set()
    total_cands = set()
    matched = set()
    usage_sum = {"prompt_tokens": 0, "completion_tokens": 0}
    for rec in records:
        sid = rec["share_id"]
        cands, usage = screen_record(cfg, rec)
        for k in usage_sum:
            usage_sum[k] += usage[k]
        t = truth.get(sid, set())
        total_truth |= t
        total_cands |= cands
        matched |= (t & cands)
        missed = t - cands
        status = "OK " if not missed else "MISS"
        print(f"[{status}] {sid} truth={sorted(t)} cand({len(cands)}) missed={sorted(missed)}")

    recall = len(matched) / len(total_truth) if total_truth else 1.0
    precision = len(matched) / len(total_cands) if total_cands else 1.0
    print(f"\nunion truth cats: {len(total_truth)} | union cands: {len(total_cands)} | matched: {len(matched)}")
    print(f"micro recall: {recall:.2f}  (precision-ish: {precision:.2f})")
    print(f"screening usage: {usage_sum['prompt_tokens']} in / {usage_sum['completion_tokens']} out "
          f"({args.limit} records -> avg {usage_sum['prompt_tokens'] // args.limit} in / "
          f"{usage_sum['completion_tokens'] // args.limit} out per record)")


if __name__ == "__main__":
    main()
