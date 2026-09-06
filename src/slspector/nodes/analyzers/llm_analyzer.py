"""LLM semantic analysis family: per-category judging driven by categories.yaml.

Phase 1 covers 11 categories. Long conversations are CHUNKED (see
slspector.chunking) — every character is judged, no silent middle truncation,
and no request can exceed the model input budget.

Per category: judge each chunk independently, then merge results across chunks
(best confidence kept, multi-chunk corroboration boosts confidence slightly).
Categories already hit by the static track at confidence >= 0.7 are skipped to
save tokens (dedup with static findings happens in meta_analyzer).

All (category, chunk) judging calls run in a thread pool bounded by
ProviderConfig.concurrency. Token usage is accumulated and reported in the
analyzer status for cost accounting.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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


_tls = threading.local()


def _thread_client(cfg: ProviderConfig):
    """One OpenAI client per worker thread (shared sync httpx clients can
    deadlock across threads with some httpx builds)."""
    key = (cfg.base_url, cfg.api_key, cfg.model, cfg.timeout)
    if getattr(_tls, "key", None) != key:
        _tls.client = make_client(cfg)
        _tls.key = key
    return _tls.client


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


def _judge_chunk(
    cfg: ProviderConfig, cid: str, prompt: str, chunk: Chunk, title: str | None
) -> tuple[dict, dict]:
    """Judge one chunk for one category; returns (verdict, token_usage)."""
    client = _thread_client(cfg)
    model = cfg.model
    header = f"## Conversation title\n{title or '(none)'}\n\n"
    footer = "" if chunk.index == 0 else f"\n\n[chunk {chunk.index + 1} of ongoing conversation]"
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": header + chunk.text + footer},
    ]
    extra: dict = {}
    if cfg.thinking:
        extra["thinking"] = {"level": cfg.thinking}
    last_err: Exception | None = None
    for attempt in range(1 + _PARSE_RETRY):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                response_format={"type": "json_object"},
                extra_body=extra or None,
            )
            result = _parse_json(resp.choices[0].message.content or "")
            usage = {
                "prompt_tokens": getattr(getattr(resp, "usage", None), "prompt_tokens", 0) or 0,
                "completion_tokens": getattr(getattr(resp, "usage", None), "completion_tokens", 0)
                or 0,
            }
            return result, usage
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
            messages = messages[:2] + [
                {
                    "role": "user",
                    "content": "Your previous output could not be parsed. "
                    'Output strict JSON only: {"hit": bool, "confidence": 0-1, '
                    '"evidence": "...", "reasoning": "..."}',
                }
            ]
    raise _LLMUnavailable(f"{cid}@chunk{chunk.index}: {last_err}")


def _locate_finding(messages: list[dict], verdict: dict, chunks: list[Chunk]) -> MessageLocation:
    evidence = str(verdict.get("evidence", ""))
    matches = []
    for mi, msg in enumerate(messages):
        body = str(msg.get("content") or "")
        start = body.find(evidence) if evidence else -1
        if start >= 0:
            matches.append((mi, str(msg.get("role") or ""), start, start + len(evidence)))
    if len(matches) == 1:
        mi, role, start, end = matches[0]
        return MessageLocation(mi, role, start, end, evidence[:200])
    return MessageLocation(snippet=evidence[:200])


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
    cats = taxonomy.llm_categories()
    eligible: list[str] = []
    for cid, cat in cats.items():
        if static_hits.get(cid, 0.0) >= STATIC_HIT_SKIP_CONF:
            statuses.append(
                {"analyzer_id": ANALYZER_ID, "category": cid, "status": "skipped_static_hit"}
            )
        else:
            eligible.append(cid)

    # judge all (category, chunk) pairs concurrently
    tasks = [(cid, chunk) for cid in eligible for chunk in chunks]
    per_cat: dict[str, list[dict]] = {}
    errors: dict[str, list[str]] = {}
    successes: dict[str, int] = {}
    usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, cfg.concurrency)) as pool:
        futures = {
            pool.submit(_judge_chunk, cfg, cid, cats[cid]["llm"]["prompt"], chunk, title): cid
            for cid, chunk in tasks
        }
        for fut in as_completed(futures):
            cid = futures[fut]
            try:
                result, usage = fut.result()
            except _LLMUnavailable as exc:
                errors.setdefault(cid, []).append(str(exc)[:200])
                continue
            usage_total["prompt_tokens"] += usage["prompt_tokens"]
            usage_total["completion_tokens"] += usage["completion_tokens"]
            usage_total["calls"] += 1
            successes[cid] = successes.get(cid, 0) + 1
            if result.get("hit"):
                per_cat.setdefault(cid, []).append(result)

    for cid in eligible:
        if cid in errors:
            statuses.append(
                {
                    "analyzer_id": ANALYZER_ID,
                    "category": cid,
                    "status": "partial" if successes.get(cid) else "failed",
                    "error_count": len(errors[cid]),
                    "detail": "; ".join(errors[cid]),
                }
            )
            continue
        cat = cats[cid]
        per_chunk = per_cat.get(cid, [])
        if per_chunk:
            best = max(per_chunk, key=lambda r: float(r["confidence"]))
            conf = max(0.1, min(1.0, float(best["confidence"])))
            corroborated = len(per_chunk) > 1
            if corroborated:
                conf = min(0.98, conf * MULTI_CHUNK_BOOST)
            cat_status = cat.get("status")
            location = _locate_finding(messages, best, chunks)
            findings.append(
                Finding(
                    taxonomy_id=cid,
                    pattern_id="LLM-1",
                    detector="llm",
                    confidence=conf,
                    message=f"LLM verdict: {cat.get('leaf_en', cid)}",
                    location=location,
                    matched_text=str(best.get("evidence", ""))[:200],
                    needs_review=(cat_status == "candidate") or conf <= 0.5,
                    reasoning=str(best.get("reasoning", ""))[:300],
                    analyzer_id=ANALYZER_ID,
                    evidence={
                        "model": cfg.model,
                        "location_status": "resolved"
                        if location.message_index is not None
                        else "unresolved",
                        "chunks_hit": len(per_chunk),
                        "chunks_total": len(chunks),
                        "corroborated": corroborated,
                    },
                )
            )
        statuses.append(
            {
                "analyzer_id": ANALYZER_ID,
                "category": cid,
                "status": "ok",
                "hit": bool(per_chunk),
                "chunks": len(chunks),
            }
        )
    statuses.append(
        {
            "analyzer_id": ANALYZER_ID,
            "status": "usage",
            "detail": f"{usage_total['calls']} calls, "
            f"{usage_total['prompt_tokens']} in / {usage_total['completion_tokens']} out tokens, "
            f"{time.monotonic() - t0:.1f}s",
            **usage_total,
        }
    )
    return findings, statuses


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    from slspector.providers import resolve_provider

    cfg = state.get("_provider_cfg") or resolve_provider(state.get("provider"))
    if cfg is None:
        return {
            "findings": [],
            "analyzer_status": [
                {
                    "analyzer_id": ANALYZER_ID,
                    "status": "skipped",
                    "detail": "no provider configured",
                }
            ],
        }
    findings, statuses = analyze(state, cfg)
    return {
        "findings": findings,
        "analyzer_status": [
            {"analyzer_id": ANALYZER_ID, "status": "ok", "detail": f"{len(findings)} llm findings"}
        ]
        + statuses,
    }
