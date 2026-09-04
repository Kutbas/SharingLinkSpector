"""LLM analyzer logic tests (mock provider, no real key needed)."""

from __future__ import annotations

import json

import pytest
from conftest import make_record

from slspector.nodes.analyzers import llm_analyzer
from slspector.providers import ProviderConfig


class _FakeCompletion:
    def __init__(self, content: str):
        obj = type("C", (), {})()
        obj.message = type("M", (), {})()
        obj.message.content = content
        self.choices = [obj]
        self.usage = type("U", (), {"prompt_tokens": 100, "completion_tokens": 50})()


class _FakeClient:
    """按 prompt 内容智能应答：predicate(prompt) 为真则回 hit_reply，否则 miss_reply。"""

    def __init__(self, hit_reply: str, miss_reply: str, predicate):
        self._hit_reply = hit_reply
        self._miss_reply = miss_reply
        self._predicate = predicate
        self.calls: list[dict] = []

        class _Completions:
            def create(inner_self, **kw):
                self.calls.append(kw)
                prompt = kw["messages"][0]["content"]
                reply = self._hit_reply if self._predicate(prompt) else self._miss_reply
                return _FakeCompletion(reply)

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


def _cfg():
    return ProviderConfig(name="mock", base_url="http://mock", api_key="k",
                          model="mock-model", concurrency=1)


def test_llm_hit_produces_finding(static_graph, monkeypatch):
    from conftest import make_record

    # 选一个静态不会先命中的文本（无银行卡/敏感词表命中）——LLM 轨才会跑 A-C-2
    record = make_record(("USER", "体检报告显示我的 HDL 偏低，医生建议调整生活方式"))
    state = static_graph.invoke(
        {"record": record, "use_llm": True, "provider": "mock",
         "findings": []}
    )
    hit_reply = json.dumps({
        "hit": True, "confidence": 0.9,
        "evidence": "体检报告显示 HDL 偏低",
        "reasoning": "Health details self-disclosed by the user",
    }, ensure_ascii=False)
    miss_reply = json.dumps({
        "hit": False, "confidence": 0.1, "evidence": "", "reasoning": "无相关迹象",
    }, ensure_ascii=False)
    fake = _FakeClient(
        hit_reply, miss_reply,
        predicate=lambda prompt: "Sensitive privacy disclosure" in prompt,
    )
    monkeypatch.setattr(llm_analyzer, "make_client", lambda cfg: fake)

    findings, statuses = llm_analyzer.analyze(state, _cfg())
    hits = [f for f in findings if f.taxonomy_id == "A-C-2"]
    assert hits and hits[0].detector == "llm" and hits[0].confidence == pytest.approx(0.9)
    assert hits[0].reasoning.startswith("Health details")
    assert all(s["status"] == "ok" for s in statuses if s.get("category"))


def test_llm_retry_on_bad_json(static_graph, monkeypatch):
    from conftest import make_record

    record = make_record(("USER", "hello"))
    state = static_graph.invoke({"record": record, "use_llm": True, "provider": "mock"})
    good = json.dumps({"hit": False, "confidence": 0.2, "evidence": "", "reasoning": "无"})

    class _BadThenGood:
        def __init__(self):
            self.n = 0

            class _Completions:
                def create(inner_self, **kw):
                    self.n += 1
                    return _FakeCompletion("garbage" if self.n == 1 else good)

            class _Chat:
                completions = _Completions()

            self.chat = _Chat()

    fake = _BadThenGood()
    monkeypatch.setattr(llm_analyzer, "make_client", lambda cfg: fake)
    monkeypatch.setattr(llm_analyzer.time, "sleep", lambda s: None)
    findings, statuses = llm_analyzer.analyze(state, _cfg())
    errs = [s for s in statuses if s.get("status") == "error"]
    assert not errs, errs
    assert fake.n >= 2, "bad JSON should trigger retry"


def test_provider_resolution_none(monkeypatch):
    from slspector.providers import resolve_provider

    monkeypatch.delenv("SLSPECTOR_PROVIDER", raising=False)
    assert resolve_provider("none") is None
    with pytest.raises(ValueError):
        resolve_provider("bogus")


def test_ollama_preset(monkeypatch):
    from slspector.providers import resolve_provider

    monkeypatch.setenv("OLLAMA_BASE_URL", "http://gpu-box:11434/v1")
    monkeypatch.setenv("OLLAMA_API_KEY", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3:32b")
    cfg = resolve_provider("ollama")
    assert cfg is not None and cfg.base_url.startswith("http://gpu-box") and cfg.model == "qwen3:32b"


def test_llm_multichunk_merge_and_corroboration(static_graph, monkeypatch):
    """Long conversations are chunked; hits across chunks merge with a boost."""

    monkeypatch.setenv("SLSPECTOR_LLM_CHUNK_CHARS", "600")
    monkeypatch.setenv("SLSPECTOR_LLM_CHUNK_OVERLAP", "120")
    long_convo = "\n\n".join(f"filler paragraph {i} " + "y" * 80 for i in range(40))
    record = make_record(("USER", long_convo))
    state = static_graph.invoke({"record": record, "use_llm": True, "provider": "mock"})

    hit_reply = json.dumps({
        "hit": True, "confidence": 0.6,
        "evidence": "filler paragraph 3 yyy",
        "reasoning": "Seen in multiple chunks",
    }, ensure_ascii=False)
    miss_reply = json.dumps({
        "hit": False, "confidence": 0.1, "evidence": "", "reasoning": "none",
    }, ensure_ascii=False)
    # hit only for "Cross-session persistent memory poisoning" (B-CI-8), all else miss
    fake = _FakeClient(
        hit_reply, miss_reply,
        predicate=lambda prompt: "Cross-session persistent memory poisoning" in prompt,
    )
    monkeypatch.setattr(llm_analyzer, "make_client", lambda cfg: fake)

    findings, statuses = llm_analyzer.analyze(state, _cfg())
    st = [s for s in statuses if s.get("category") == "B-CI-8"]
    assert st and st[0]["status"] == "ok" and st[0]["chunks"] > 3
    hits = [f for f in findings if f.taxonomy_id == "B-CI-8"]
    assert len(hits) == 1  # merged across chunks
    assert hits[0].confidence > 0.6  # corroboration boost applied
    assert hits[0].evidence["chunks_hit"] >= 2 and hits[0].evidence["corroborated"]
