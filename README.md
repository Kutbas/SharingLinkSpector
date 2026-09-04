# SharingLinkSpector (slspector)

Risk **annotation tool** for AI conversation sharing links.

Built on `taxonomy-0901-v5.xlsx` (49 risk categories, dual threat model:
Model A endogenous / Model B external x CIA). It scans cleaned conversation
records (unified-schema JSONL) with a **static + LLM dual track** and emits
per-finding annotations (including a `needs_review` candidate queue).
**No risk scoring** — labeling only.

Architecture references [SkillSpector](../SkillSpector) (NVIDIA): LangGraph
orchestration, auto-discovered analyzer modules, parallel execution ->
dedup -> aggregation -> report.

## Principles

- **No 100% detection claims**: categories only testable by the platform or
  via dynamic analysis are documented in the coverage report ("who can test")
- Red-flagged categories follow Kevin's I-column verdicts: `skipped` (not
  labeled) / `candidate` (needs_review queue) / template + LLM
- Patterns and prompts are data-driven (`data/categories.yaml`); code only
  provides detection primitives
- **English-first codebase** (comments, messages, prompts, reports) for the
  English-venue paper; Chinese lexicons remain inside detection regexes on
  purpose (they detect Chinese-language risks)

## Quick start

```bash
uv venv && uv sync --group dev          # environment
uv run --extra export python tools/export_taxonomy.py   # xlsx -> categories.yaml (committed; rarely needed)

# static-only scan (no LLM key required)
slspector scan ../Taxonomy_Building/taxonomy_subset_650.jsonl --limit 20 -o out/

# static + LLM
cp .env.example .env                    # fill dmxapi or ollama config
slspector scan input.jsonl -o out/ --provider dmxapi
```

## LLM providers

Two presets in `.env`:

- **dmxapi**: OpenAI-compatible (`https://www.dmxapi.cn/v1`), needs `DMXAPI_API_KEY` + `DMXAPI_MODEL`
- **ollama**: private deployment (`http://<host>:11434/v1`), suited for large batch runs, needs `OLLAMA_MODEL`

Set `HTTPS_PROXY` when external access needs a proxy (in-container:
`http://host.docker.internal:7890`).

## Chunking (long conversations)

Long conversations are split into chunks respecting message boundaries
(paragraph packing + sliding-window splits for oversized single messages,
with overlap). Every character is judged — no request can exceed the model
input budget, and nothing is silently truncated. Multi-chunk hits are merged
with a corroboration boost. Chunk size: `--chunk-chars` or
`SLSPECTOR_LLM_CHUNK_CHARS` (default 24000), overlap
`SLSPECTOR_LLM_CHUNK_OVERLAP` (default 800).

## Output

- `findings.jsonl`: per-record findings (taxonomy_id / pattern_id / detector /
  confidence / message location / evidence)
- `needs_review.jsonl`: manual-verification queue (red-flagged candidate
  categories are always routed here)
- `summary.md`: hits by category + coverage matrix (49 categories with status
  and who-can-test notes)

## Coverage (Phase 1)

| status | meaning |
|--------|---------|
| implemented | static/LLM detection implemented |
| candidate | candidate findings only, `needs_review=true` |
| phase2_llm / phase2_dynamic | Phase 2 extension |
| future_work | paper future work / discussion |
| skipped | not labeled (Kevin's I-column: B-C-3, B-A-1, B-CIA-7) |

See `data/categories.yaml` (per category: `tracks`, `status`, `kevin_note`).
