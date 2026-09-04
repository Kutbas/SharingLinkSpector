"""LLM 语义分析 family: 按 categories.yaml 提示词逐类判定（Phase 1: 11 类）。

每类一次调用（省 token：对话拼接后随 prompt 发送），输出严格 JSON
{hit, confidence, evidence, reasoning}；解析失败重试一次。
静态轨已命中的类别跳过 LLM 调用（双轨去重由 meta_analyzer 处理，此处省成本优先）。
"""

from __future__ import annotations

import json
import re
import time

from slspector import taxonomy
from slspector.models import Finding, MessageLocation
from slspector.providers import ProviderConfig, make_client
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "llm_analyzer"
requires_llm = True

MAX_TEXT_CHARS = 24_000  # 单次送入上限（≈8k token 中文），超出截断保头部+尾部
_PARSE_RETRY = 1

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


class _LLMUnavailable(Exception):
    pass


def _truncate(text: str) -> str:
    if len(text) <= MAX_TEXT_CHARS:
        return text
    head = MAX_TEXT_CHARS * 2 // 3
    tail = MAX_TEXT_CHARS - head
    return text[:head] + "\n…[中段截断]…\n" + text[-tail:]


def _parse_json(reply: str) -> dict:
    m = _JSON_BLOCK.search(reply)
    if not m:
        raise ValueError("回复中无 JSON 块")
    obj = json.loads(m.group(0))
    for k in ("hit", "confidence", "evidence", "reasoning"):
        if k not in obj:
            raise ValueError(f"缺少字段 {k}")
    obj["confidence"] = float(obj["confidence"])
    return obj


def _judge_one(client, model: str, cid: str, prompt: str, conversation: str,
               title: str | None) -> dict | None:
    user_content = (
        f"## 对话标题\n{title or '（无）'}\n\n## 对话记录\n{_truncate(conversation)}"
    )
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": user_content},
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
            # JSON 解析失败 → 追加纠错提示重试；网络错误 → 退避重试
            time.sleep(1.5 * (attempt + 1))
            messages = messages[:2] + [
                {"role": "user", "content": "上次输出无法解析为要求的 JSON，请严格只输出 "
                 '{"hit": bool, "confidence": 0~1, "evidence": "...", "reasoning": "..."}'}
            ]
    raise _LLMUnavailable(f"{cid}: {last_err}")


def analyze(state: SlspectorState, cfg: ProviderConfig) -> tuple[list[Finding], list[dict]]:
    text = state["full_text"]
    title = (state.get("meta") or {}).get("title")
    static_hit_ids = {f.taxonomy_id for f in state.get("findings", [])}
    findings: list[Finding] = []
    statuses: list[dict] = []
    client = make_client(cfg)

    for cid, cat in taxonomy.llm_categories().items():
        # 静态同类别已命中（confidence≥0.7）→ 跳过 LLM 省 token
        if cid in static_hit_ids:
            statuses.append({"analyzer_id": ANALYZER_ID, "category": cid,
                             "status": "skipped_static_hit"})
            continue
        t0 = time.monotonic()
        try:
            result = _judge_one(client, cfg.model, cid, cat["llm"]["prompt"], text, title)
        except _LLMUnavailable as exc:
            statuses.append({"analyzer_id": ANALYZER_ID, "category": cid,
                             "status": "error", "detail": str(exc)[:200]})
            continue
        if result.get("hit"):
            cat_status = cat.get("status")
            findings.append(Finding(
                taxonomy_id=cid,
                pattern_id="LLM-1",
                detector="llm",
                confidence=max(0.1, min(1.0, float(result["confidence"]))),
                message=f"LLM 判定: {cat['leaf']}",
                location=MessageLocation(snippet=str(result.get("evidence", ""))[:200]),
                matched_text=str(result.get("evidence", ""))[:200],
                needs_review=cat_status == "candidate" or float(result["confidence"]) <= 0.5,
                reasoning=str(result.get("reasoning", ""))[:300],
                analyzer_id=ANALYZER_ID,
                evidence={"model": cfg.model},
            ))
        statuses.append({"analyzer_id": ANALYZER_ID, "category": cid,
                         "status": "ok", "hit": bool(result.get("hit")),
                         "duration_ms": int((time.monotonic() - t0) * 1000)})
    return findings, statuses


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    from slspector.providers import resolve_provider

    cfg = state.get("_provider_cfg") or resolve_provider(state.get("provider"))
    if cfg is None:
        return {"findings": [], "analyzer_status": [
            {"analyzer_id": ANALYZER_ID, "status": "skipped", "detail": "provider 未配置"}]}
    findings, statuses = analyze(state, cfg)
    return {"findings": findings,
            "analyzer_status": [{"analyzer_id": ANALYZER_ID, "status": "ok",
                                 "detail": f"{len(findings)} llm findings"}] + statuses}
