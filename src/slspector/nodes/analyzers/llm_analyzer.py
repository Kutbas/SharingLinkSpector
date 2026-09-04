"""LLM semantic analysis family: per-category judging driven by categories.yaml.

Phase 1 covers 11 categories. Long conversations are CHUNKED (see
slspector.chunking) — every character is judged, no silent middle truncation,
and no request can exceed the model input budget.

Per category: judge each chunk independently, then merge results across chunks
(best confidence kept, multi-chunk corroboration boosts confidence slightly).
Categories already hit by the static track at confidence >= 0.7 are skipped to
save tokens (dedup with static findings happens in meta_analyzer).
"""

from __future__ import annotations

import json
import re
import time

from slspector import taxonomy
from slspector.chunking import Chunk, chunk_conversation, chunk_limits
from slspector.models import Finding, MessageLocation
from slspector.providers import ProviderConfig, make_client
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "llm_analyzer"
requires_llm = True

STATIC_HIT_SKIP_CONF = 0.7
MULTI_CHUNK_BOOST = 1.15
MAX_FINDINGS_PER_CATEGORY = 5
_PARSE_RETRY = 1

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


class _LLMUnavailable(Exception):
    pass


def _parse_json(reply: str) -> dict:
    m = _JSON_BLOCK.search(reply)
    if not m:
        raise ValueError("no JSON block in reply")
    obj = json.loads(m.group(0))
    for k in ("hit", "confidence", "evidence", "reasoning"):
        if k not in obj:
            raise ValueError(f"missing field {k}")
    obj["confidence"] = float(obj["confidence"])
    return obj


def _judge_chunk(client, model: str, cid: str, prompt: str, chunk: Chunk,
                 title: str | None) -> dict:
    header = f"## Conversation title\n{title or '(none)'}\n\n"
    footer = "" if chunk.index == 0 else f"\n\n[chunk {chunk.index + 1} of ongoing conversation]"
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": header + chunk.text + footer},
    ]
    last_err: Exception | None = None
    for attempt in range(1 + _PARSE_RETRY):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            return _parse_json(resp.choices[0].message.content or "")
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
            messages = messages[:2] + [
                {"role": "user", "content": "Your previous output could not be parsed. "
                 "Output strict JSON only: {\"hit\": bool, \"confidence\": 0-1, "
                 "\"evidence\": \"...\", \"reasoning\": \"...\"}"}
            ]
    raise _LLMUnavailable(f"{cid}@chunk{chunk.index}: {last_err}")


def analyze(state: SlspectorState, cfg: ProviderConfig) -> tuple[list[Finding], list[dict]]:
    title = (state.get("meta") or {}).get("title")
    messages = state.get("messages") or []
    static_hits: dict[str, float] = {}
    for f in state.get("findings", []):
        if f.detector == "static":
            static_hits[f.taxonomy_id] = max(static_hits.get(f.taxonomy_id, 0.0), f.confidence)

    max_chars, overlap = chunk_limits()
    chunks = chunk_conversation(messages, max_chars=max_chars, overlap=overlap)

    findings: list[Finding] = []
    statuses: list[dict] = []
    client = make_client(cfg)

    for cid, cat in taxonomy.llm_categories().items():
        if static_hits.get(cid, 0.0) >= STATIC_HIT_SKIP_CONF:
            statuses.append({"analyzer_id": ANALYZER_ID, "category": cid,
                             "status": "skipped_static_hit"})
            continue
        t0 = time.monotonic()
        per_chunk: list[dict] = []
        err: str | None = None
        for chunk in chunks:
            try:
                result = _judge_chunk(client, cfg.model, cid, cat["llm"]["prompt"], chunk, title)
            except _LLMUnavailable as exc:
                err = str(exc)[:200]
                break
            if result.get("hit"):
                per_chunk.append(result)
        if err:
            statuses.append({"analyzer_id": ANALYZER_ID, "category": cid,
                             "status": "error", "detail": err})
            continue

        if per_chunk:
            best = max(per_chunk, key=lambda r: float(r["confidence"]))
            conf = max(0.1, min(1.0, float(best["confidence"])))
            corroborated = len(per_chunk) > 1
            if corroborated:
                conf = min(0.98, conf * MULTI_CHUNK_BOOST)
            cat_status = cat.get("status")
            findings.append(Finding(
                taxonomy_id=cid,
                pattern_id="LLM-1",
                detector="llm",
                confidence=conf,
                message=f"LLM verdict: {cat.get('leaf_en', cid)}",
                location=MessageLocation(snippet=str(best.get("evidence", ""))[:200]),
                matched_text=str(best.get("evidence", ""))[:200],
                needs_review=(cat_status == "candidate") or conf <= 0.5,
                reasoning=str(best.get("reasoning", ""))[:300],
                analyzer_id=ANALYZER_ID,
                evidence={
                    "model": cfg.model,
                    "chunks_hit": len(per_chunk),
                    "chunks_total": len(chunks),
                    "corroborated": corroborated,
                },
            ))
        statuses.append({
            "analyzer_id": ANALYZER_ID, "category": cid, "status": "ok",
            "hit": bool(per_chunk), "chunks": len(chunks),
            "duration_ms": int((time.monotonic() - t0) * 1000),
        })
    return findings, statuses


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    from slspector.providers import resolve_provider

    cfg = state.get("_provider_cfg") or resolve_provider(state.get("provider"))
    if cfg is None:
        return {"findings": [], "analyzer_status": [
            {"analyzer_id": ANALYZER_ID, "status": "skipped",
             "detail": "no provider configured"}]}
    findings, statuses = analyze(state, cfg)
    return {"findings": findings,
            "analyzer_status": [
                {"analyzer_id": ANALYZER_ID, "status": "ok",
                 "detail": f"{len(findings)} llm findings"}] + statuses}
