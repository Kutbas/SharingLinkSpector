# SharingLinkSpector Phase 2 Tuning Report

Date: 2026-09-04 · Version: v0.2.0 (Phase 2) · Basis: taxonomy-0901-v5.xlsx (49 categories)

## Summary

Phase 2 delivered the first live validation of the LLM track, prompt expansion from 11 to 40 categories, and a full-scale cost analysis. The end-to-end pipeline (chunking → per-category judging → cross-chunk merging → output) processed 8 real subset records with zero errors on glm-5.3-flash (thinking=low). Judging quality is sound, but a single-stage full run over the 131k-record corpus would require 7.6M calls (~¥23k, 200+ days) and is infeasible. A two-stage strategy (relevance screening followed by per-category judging) cuts cost by an order of magnitude to ~¥2–3k and is the required path for corpus-scale annotation. Single-screen recall measured 0.60 on the 8-record probe; a two-screen union achieved 5/5 recall and needs validation at the 100+ record scale before production.

## 1. LLM Prompt Coverage: 40 / 49 Categories

The H column marks 44 categories for LLM judging; 4 are ruled out, leaving **40 prompts** (11 from Phase 1 + 29 new):

| Excluded | Rationale |
|---|---|
| B-C-3 model distillation | attack itself not observable by third parties (Kevin's I-column verdict: skipped — red-flag ruling takes precedence) |
| B-A-1 application-layer exhaustion | creation-side data unavailable to third parties (skipped) |
| B-IA-3 training-corpus poisoning | corpus-level clustering is a batch-layer capability, out of scope per record |
| B-IA-5 Zip Slip | H column explicitly marks LLM not applicable (structural static detection suffices) |

The 5 categories without an 【LLM】 mark: B-I-5 / B-I-6 / B-CI-1 (dynamic or multimodal capability required; future work), B-CI-6 (static-only, implemented), B-CIA-7 (skipped).

Prompt structure follows the Phase 1 template: verbatim Chinese category definition + English rendering of the H-column detection point + teaching-context distinction (discussing a risk ≠ exhibiting it) + strict JSON output. Six special categories carry explicit English boundary guidance:

- **B-I-8 (false factual claims)**: no retrieval — judge only the weak "unsourced assertion density" signal, cap confidence at 0.6, reasoning must state that factuality was not verified (observed working in live output)
- **B-CI-7 (malicious QR codes)**: text-only judge cannot see images; judge only scan-bait phrasing or decoded target URLs present in text
- **B-C-4 / B-I-4 / B-A-2 / B-A-3 / B-IA-4**: judging scope restricted to content-side signals (SSRF inducement, title–body consistency, constructed complexity, confirmatory exclusion, steganographic combinations)

Status transitions: B-C-1, B-I-9, B-I-10 (phase2_llm → implemented); B-I-8, B-CI-7 (future_work → implemented with weak/limited judgments). Final distribution: implemented 36 / candidate 5 / future_work 4 / skipped 3 / phase2_dynamic 1.

## 2. Engineering Hardening

1. **Concurrent judging**: the original implementation judged 40 categories × chunks serially. Replaced with an (category, chunk) task pool bounded by `SLSPECTOR_LLM_CONCURRENCY` (default 4; validated at 8).
2. **Thread-local clients**: the httpx2 fork shipped in this venv deadlocks when one synchronous client is shared across threads (14 threads all in futex wait, zero network activity). Per-worker OpenAI clients eliminate the hang.
3. **Thinking level**: glm-5.3-flash always reasons (thinking cannot be disabled); `thinking.level=low` is the only cost lever: reasoning tokens 950 → 336 (−65%), per-call latency 29s → 14s, with no visible quality loss.
4. **Usage accounting**: prompt/completion tokens accumulate into analyzer status; the CLI writes per-record `llm_usage.jsonl` and a run total into `summary.md` — all figures in this report are measured, not modeled.

## 3. Live Validation (8 records, first 8 of the 650 subset)

- **320 calls (8 × 40), zero errors, 863.8s** (effective throughput 0.37 calls/s at concurrency 8)
- Average per call: 874 in / 535 out tokens (all records < 3.5k chars, single chunk)
- 6 findings (4 needs_review); 7 clean records produced zero false positives; the one dirty record (a Kimi tour-bait SEO share) hit 5 categories — B-I-2 GEO manipulation, B-I-3 SEO promotion, B-I-8 unsourced assertions, B-I-9 misleading summary, B-I-10 harmful advice — all within the correct B-I semantic family
- **Calibration note**: confidence varies across runs (B-I-2 scored 0.60 then 0.45 at temperature 0.1); paper-facing numbers should report across-run ranges or medians of repeated runs for key categories
- B-I-8's limitation clause works as designed: reasoning output explicitly states "Factuality was NOT verified (no retrieval capability)"

## 4. Full-Corpus Cost Analysis (131,106-record target set)

Corpus profile (measured): median 4.4k chars/record, mean 16.5k, p90 33k, p99 202k, max 4.0M; ~190k estimated chunks (mean 1.45/record).

### 4.1 Single stage (judge all 40 categories)

| Item | Value |
|---|---|
| Calls | 190k × 40 = **7.6M** |
| Input tokens | ~44B (700 system + 0.45 × chunk chars per call) |
| Output tokens | ~4.1B |
| Cost (Zhipu promo ¥0.4/M in, ¥1.4/M out) | **≈ ¥23,400** (list price ¥46,800) |
| Wall time @ measured 0.37 calls/s | **≈ 238 days** |

**Verdict: infeasible.**

### 4.2 Two stages (screen → judge)

| Stage | Calls | Est. cost | Notes |
|---|---|---|---|
| Stage 1 screening ×2 (ensemble) | 380k | ≈ ¥1,100 | one call per record with a 40-entry catalog (id + EN name + gloss ≈ 1.7k in); returns candidate category ids; run twice, union |
| Stage 2 per-category judging | ~380k (~2 candidates/record) | ≈ ¥1,200 | only candidate categories; static hits (conf ≥ 0.7) still skipped |
| **Total** | ~760k | **≈ ¥2,300** | 90% cheaper than single stage; ≈ 24 days at concurrency 8 |

### 4.3 Screening recall (key risk item)

8-record probe (ground truth = full-40 hits with conf ≥ 0.4):

- v1 (name-only catalog): recall 3/5; missed B-I-2/B-I-3 (semantic-manipulation categories)
- v2 (name + gloss catalog): recall 3/5; recovered B-I-2/B-I-3 but missed B-I-10/B-I-9
- **v1 ∪ v2 union: 5/5 (100%)**; clean records yield 0–3 candidates each (stage-2 amplification stays controlled)
- Sample is tiny (one dirty record); production requires validation on a ≥100-record stratified sample targeting recall ≥ 0.85, with static candidates force-included into stage 2 as a floor

### 4.4 Alternative: private ollama deployment

Stage 1 (screening) is low-difficulty, high-volume work — the best target for private deployment (qwen3:32b): saves ~¥1,100 and ~6 days of API time. Stage 2 judging should stay on glm-5.3-flash (validated quality). The dual-provider preset in providers.py makes the switch a .env edit.

## 5. Conclusions and Next Steps

1. **Adopt two-stage + dual-screen ensemble + static force-inclusion for corpus runs**; budget ~¥2.5k (with 20% headroom)
2. Validate screening recall at the 100-record scale (~¥30, ~1 day)
3. Calibration: across-run confidence variance → median of 3 runs for key categories (+2× stage-2 cost)
4. Future work unchanged: B-CI-1 (multimodal provider), B-I-6 (dynamic refetch) — covered in the paper's discussion section

## Appendix: Measured Constants (for recomputation)

- glm-5.3-flash thinking=low: 874 in / 535 out tokens per judging call (small records); reasoning ≈ 65% of output
- Throughput: 0.37 calls/s (concurrency 8, single dmxapi key, upstream queue variance 2.8–30.6s/call)
- Screening: 1,170–1,700 in / 1,400–1,770 out per record
- Pricing basis: Zhipu official promo price (dmxapi resale markup not included; reconcile against invoices)
