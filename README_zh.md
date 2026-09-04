# SharingLinkSpector（`slspector`）

[English](README.md) | [中文](README_zh.md)

AI 对话分享链接风险**标注工具**。

公开分享的 AI 对话（ChatGPT / Claude / Gemini / Kimi / Grok / DeepSeek 等
平台的分享链接）可能泄露用户隐私，也可能被滥用于钓鱼、注入与其他攻击载荷的
托管。SharingLinkSpector 以**静态 + LLM 双轨**扫描清洗后的对话记录
（统一 schema 的 JSONL），输出逐条风险标注（含置信度与 `needs_review`
人工复核队列）。**只标注、不打分。**

## 风险分类法

检测由一个 49 类的分享链接风险分类法驱动
（`data/categories.yaml`，机器可读的规范产物）：

- **双威胁模型**：内生风险（Model A——用户无意暴露敏感数据）与外部风险
  （Model B——攻击者滥用分享链接或其内容），与机密性 / 完整性 / 可用性
  影响维度交叉。
- 叶子类别全部锚定公开标准与攻击目录（NIST SP 800-122、MITRE ATT&CK /
  CAPEC、CWE、OWASP），而非自创。
- 每类含：检测轨道（static / llm / dynamic / metadata / platform）、状态、
  定义、检测要点与英文判定提示词。
- 31 类具备确定性静态检测；40 类具备 LLM 判定提示词；其余需要动态、
  多模态或平台侧能力，在覆盖率报告中如实标注（见"覆盖率哲学"）。

## 架构

```
记录 JSONL ──> build_context ──> [ 静态 family 并行 ∥ llm_analyzer ] ──> dedup ──> meta_analyzer ──> report
```

- **LangGraph** 编排；分析器模块自动发现、并行执行；单个分析器失败不会
  中断整体扫描。
- **静态轨**：10 个模式 family（PII、有害/越狱、注入签名、链接分析、
  载荷结构、系统提示词泄露、Unicode 隐藏字符、DoS/滥用、SEO 滥用、
  供应链）。确定性命中直接报告；歧义签名进入 `needs_review` 候选队列。
- **LLM 轨**：逐类判定，严格 JSON 裁决（hit / confidence / evidence /
  reasoning），（类别 × chunk）对并发执行并核算 token 用量；静态轨已
  高置信命中的类别自动跳过以节省 token。
- **分块**：长对话沿消息边界切分（段落打包 + 滑窗 overlap），每个字符
  都会被判定——不静默截断、不超模型输入预算；跨块命中合并并附佐证加成。
- 模式与提示词**数据驱动**（yaml 配置），代码只提供检测原语。
- **代码英文优先**；检测正则中保留中文词表——它们就是中文风险载荷的
  检测数据。

## 快速开始

需要 Python 3.12+ 与 [uv](https://docs.astral.sh/uv/)。

```bash
uv venv && uv sync --group dev    # 环境

# 仅静态扫描（无需 LLM key）
uv run slspector scan conversations.jsonl --limit 20 -o out/

# 静态 + LLM 双轨
cp .env.example .env              # 配置 provider（见下）
uv run slspector scan conversations.jsonl -o out/ --provider dmxapi

# 49 类覆盖率矩阵
uv run slspector coverage
```

## LLM Provider

任意 OpenAI 兼容 chat 端点，通过 `.env` 中的两个预设接入：

- **dmxapi** 预设：设 `DMXAPI_BASE_URL`、`DMXAPI_API_KEY`、`DMXAPI_MODEL`
- **ollama** 预设：私有部署，设 `OLLAMA_BASE_URL`、`OLLAMA_MODEL`

调优参数（环境变量）：`SLSPECTOR_LLM_CONCURRENCY`（默认 4）、
`SLSPECTOR_LLM_TIMEOUT`（120s）、`SLSPECTOR_LLM_THINKING`（强制思考模型的
推理档位，支持处传 `low`）、`SLSPECTOR_LLM_CHUNK_CHARS`（24000）、
`SLSPECTOR_LLM_CHUNK_OVERLAP`（800）。出网需代理时设置 `HTTPS_PROXY`。

## 输出

- `findings.jsonl` —— 每条记录的 findings：分类 id、模式 id、检测器、
  置信度、消息位置、证据、推理（LLM）、token 用量
- `needs_review.jsonl` —— 人工复核队列（candidate 类别与低置信裁决
  一律进入此处）
- `summary.md` —— 分类命中统计 + 49 类完整覆盖率矩阵

## 覆盖率哲学

不做 100% 检测声明：仅平台可观测、或需要动态 / 多模态 / 语料级能力的
类别，在覆盖率报告中附带明确的 *who-can-test* 说明，而不是假装可测。

| 状态 | 含义 |
|------|------|
| `implemented` | 已实现静态和/或 LLM 检测 |
| `candidate` | 仅产出候选，恒为 `needs_review=true` |
| `phase2_dynamic` | 需动态重取能力（规划中） |
| `future_work` | 需多模态 / 检索 / 语料级能力 |
| `skipped` | 判定无法从第三方内容面标注；如实记录、不做标注 |

## 测试

```bash
uv run --group dev pytest tests/
```

使用 mock provider 的测试覆盖 LLM 分析器逻辑（命中处理、JSON 重试、
跨块合并）、分块不变式与各静态 family。
