# SharingLinkSpector (`slspector`)

[English](README.md) | [中文](README_zh.md)

Risk **annotation tool** for AI-conversation sharing links.

Publicly shared AI chat conversations (share links from ChatGPT, Claude,
Gemini, Kimi, Grok, DeepSeek, etc.) can leak their owners' private data or
become hosting grounds for phishing, injection, and abuse payloads.
SharingLinkSpector scans cleaned conversation records (unified-schema JSONL)
with a **static + LLM dual track** and emits per-finding risk annotations
with confidence values and a `needs_review` candidate queue.
**No risk scoring — labeling only.**

## Risk taxonomy

Detection is driven by a 49-category taxonomy of sharing-link risks
(`data/categories.yaml`, the canonical machine-readable artifact):

- **Dual threat model**: endogenous risks (Model A — the user unknowingly
  exposes sensitive data) vs. external risks (Model B — an attacker abuses
  the shared link or its content), crossed with confidentiality / integrity /
  availability impact dimensions.
- Leaf categories are grounded in public standards and attack catalogs
  (NIST SP 800-122, MITRE ATT&CK / CAPEC, CWE, OWASP), not invented ad hoc.
- Per category: tracks (static / llm / dynamic / metadata / platform),
  status, definitions, detection guidance, and English judging prompts.
- 31 categories have deterministic static detection; 40 have LLM judging
  prompts; the remainder require dynamic, multimodal, or platform-side
  capabilities and are explicitly documented as such (see Coverage).

## Architecture

```
record JSONL ──> build_context ──> [ static families ∥ llm_analyzer ] ──> dedup ──> meta_analyzer ──> report
```

- **LangGraph** orchestration; analyzer modules are auto-discovered and run
  in parallel; one analyzer failure never kills a scan.
- **Static track**: 10 pattern families (PII, harmful/jailbreak, injection
  signatures, link analysis, payload structures, system-prompt leakage,
  unicode/hidden chars, DoS/abuse, SEO abuse, supply chain). Deterministic
  hits report directly; ambiguous signatures become `needs_review` candidates.
- **LLM track**: per-category judging with strict-JSON verdicts
  (hit / confidence / evidence / reasoning), concurrent across
  (category × chunk) pairs, with token-usage accounting. Categories already
  hit by the static track at high confidence are skipped to save tokens.
- **Chunking**: long conversations are split along message boundaries
  (paragraph packing + sliding windows with overlap). Every character is
  judged, no silent truncation, no oversized requests. Multi-chunk hits
  merge with a corroboration boost.
- Patterns and prompts are **data-driven**; code only provides detection
  primitives.
- **English-first codebase**; Chinese lexicons intentionally remain inside
  detection regexes — they detect Chinese-language risk payloads.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv venv && uv sync --group dev    # environment

# static-only scan (no LLM key required)
uv run slspector scan conversations.jsonl --limit 20 -o out/

# static + LLM track
cp .env.example .env              # configure a provider (see below)
uv run slspector scan conversations.jsonl -o out/ --provider dmxapi

# coverage matrix of all 49 categories
uv run slspector coverage
```

## LLM providers

Any OpenAI-compatible chat endpoint works via the two presets in `.env`:

- **dmxapi** preset: set `DMXAPI_BASE_URL`, `DMXAPI_API_KEY`, `DMXAPI_MODEL`
- **ollama** preset: private deployment, set `OLLAMA_BASE_URL`, `OLLAMA_MODEL`

Tuning knobs (env): `SLSPECTOR_LLM_CONCURRENCY` (default 4),
`SLSPECTOR_LLM_TIMEOUT` (120s), `SLSPECTOR_LLM_THINKING` (reasoning-effort
level for models that always reason; pass `low` where supported),
`SLSPECTOR_LLM_CHUNK_CHARS` (24000), `SLSPECTOR_LLM_CHUNK_OVERLAP` (800).
Set `HTTPS_PROXY` if egress requires a proxy.

## Output

- `findings.jsonl` — per-record findings: taxonomy id, pattern id, detector,
  confidence, message location, evidence, reasoning (LLM), token usage
- `needs_review.jsonl` — manual-verification queue (candidate categories and
  low-confidence verdicts are always routed here)
- `summary.md` — hits by category + the full 49-category coverage matrix

## Coverage philosophy

No 100%-detection claims: categories only observable by the platform, or
only testable with dynamic / multimodal / corpus-level capability, are kept
in the coverage report with an explicit *who-can-test* note instead of being
silently pretended.

| status | meaning |
|--------|---------|
| `implemented` | static and/or LLM detection implemented |
| `candidate` | emits candidates only, always `needs_review=true` |
| `phase2_dynamic` | requires dynamic refetch capability (planned) |
| `future_work` | needs multimodal / retrieval / corpus-level capability |
| `skipped` | judged not labelable from third-party content; documented, not annotated |

## Tests

```bash
uv run --group dev pytest tests/
```

Mocked-provider tests cover the LLM analyzer logic (hit handling, JSON
retry, multi-chunk merge), chunking invariants, and the static families.
