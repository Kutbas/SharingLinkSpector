# SharingLinkSpector (slspector)

AI 对话分享链接（Sharing Link）隐私与安全风险**标注工具**。

依据 `taxonomy-0901-v5.xlsx`（49 类风险分类法，双威胁模型 Model A 内生 / Model B 外部 × CIA）
对清洗后的对话记录（JSONL，统一 schema）进行 **静态规则 + LLM 语义** 双轨检测，输出逐条
finding 标注（含 `needs_review` 候选队列），**不做风险打分**。

架构参考 [SkillSpector](../SkillSpector)（NVIDIA）：LangGraph 编排，analyzer 模块族自动发现，
并行执行 → 去重 → 汇总 → 报告。

## 设计原则

- **不追求 100% 检出**：只有【平台方】/【动态】可测的类别在 coverage 报告中写明"谁才能测"
- 红标类别遵循 Kevin I 列判定：`skipped`（不标注）/ `candidate`（候选+人工核验）/ 模板+LLM
- 模式与提示词数据驱动（`data/categories.yaml`），代码只提供检测原语

## 快速开始

```bash
uv venv && uv sync --group dev          # 环境
uv run --group export python tools/export_taxonomy.py   # xlsx → categories.yaml（已提交，一般无需重跑）

# 静态检测（无需 LLM key）
slspector scan ../Taxonomy_Building/taxonomy_subset_650.jsonl --limit 20 -o out/

# 静态 + LLM
cp .env.example .env                    # 填 dmxapi 或 ollama 配置
slspector scan input.jsonl -o out/ --provider dmxapi
```

## LLM Provider

`.env` 预置两种：

- **dmxapi**：OpenAI 兼容（`https://www.dmxapi.cn/v1`），需 `DMXAPI_API_KEY` + `DMXAPI_MODEL`
- **ollama**：私有部署（`http://<host>:11434/v1`），适合大规模批量，需 `OLLAMA_MODEL`

外网访问需代理时设置 `HTTPS_PROXY`（容器内：`http://host.docker.internal:7890`）。

## 输出

- `findings.jsonl`：逐记录 findings（taxonomy_id / pattern_id / detector / confidence / message 定位 / evidence）
- `summary.md`：按类别统计 + coverage 矩阵（49 类四态：implemented / candidate / future_work / skipped + 平台方说明）
- `needs_review.jsonl`：候选人工核验队列（红标 category 强制进此队列）

## Coverage（Phase 1）

| 状态 | 含义 |
|------|------|
| implemented | 静态/LLM 检测已实现 |
| candidate | 仅输出候选，`needs_review=true` |
| phase2_llm / phase2_dynamic | Phase 2 扩展 |
| future_work | 论文 future work / discussion |
| skipped | 不标注（Kevin I 列：B-C-3、B-A-1、B-CIA-7） |

详见 `data/categories.yaml`（每类含 `tracks`、`status`、`kevin_note`）。
