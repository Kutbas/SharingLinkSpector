# 下一个会话启动 Prompt（2026-09-04 会话总结 + Phase 2 任务）

> 复制下方代码块内容即可开始新会话。

```
续接 SharingLinkSpector 项目（AI 对话分享链接安全风险检测工具），进入 Phase 2。

## 项目现状（上一会话已完成 Phase 1 + Phase 1.5）

- 项目目录: projects/SharingLinkSpector/（git 已 init，2 个 commit: cfe696d → 30d71db，v0.1.0）
- 依据: projects/SharingLinkSpector/taxonomy-0901-v5.xlsx（49 类风险分类法；H 列=检测方法设计要点，I 列=我的 12 条红标判定）
- 架构（参考 NVIDIA SkillSpector）: LangGraph 编排 build_context → 10 个静态 family 模块并行 → dedup → meta_analyzer；LLM 轨为独立 analyzer 模块
- 数据注册表: data/categories.yaml（由 tools/export_taxonomy.py 从 xlsx 导出，已提交）
  - 每类含: leaf_en（英文名）/ tracks / status / note / kevin_note / llm.prompt
  - status 分布: implemented 31 / candidate 5 / phase2_llm 3 / phase2_dynamic 1 / future_work 6 / skipped 3
  - skipped = B-C-3、B-A-1、B-CIA-7（我 I 列判定：无检测特征或载荷不可得，只进 coverage 报告，不标注）
- 静态轨: 10 个 family（PI/HJ/SPL/LA/INJ/PS/UH/AB/SEO/SC 模式编号）覆盖 31 类，确定性高的直接报，歧义场景出 needs_review 候选
- LLM 轨: providers.py 预留 dmxapi（OpenAI 兼容 www.dmxapi.cn/v1）+ ollama（私有部署 /v1）双预设，.env 配置；Phase 1 已有 11 类英文提示词（A-C-1..6、A-I-1、B-CIA-1、B-CI-8、B-IA-1、B-IA-2）
- 分块: chunking.py，message 边界段落打包 + 超长单段滑窗 + 800 字符 overlap，全覆盖无静默截断；跨块命中合并并佐证提置信（×1.15）
- CLI: .venv/bin/slspector scan <jsonl> [--no-llm|--provider|--chunk-chars|--limit] -o out/；slspector coverage
- 测试: 36 个全过（.venv/bin/python -m pytest tests/）
- 冒烟: taxonomy_subset_650.jsonl 静态-only → 403 findings（282 needs_review）/ 21.5s
- 重要约定:
  1. 代码英文为准（投英文会议）——注释/输出/提示词全英文；检测词表正则里的中文是载荷数据，必须保留
  2. 无打分只标注（confidence + needs_review，无聚合风险分）
  3. 红标 candidate 类（B-C-6/B-CI-6/B-CIA-6/B-IA-4）静态命中强制 needs_review
  4. uv 管理环境（.venv 已建好）；外网访问必须走代理 host.docker.internal:7890
  5. 测试数据: ../Taxonomy_Building/taxonomy_subset_650.jsonl（650 条）；全量: ../Data_Cleaning/output/*.jsonl
  6. LLM 轨尚未用真实 key 实测过（.env 还没填）

## Phase 2 任务（按顺序）

1. **LLM 轨实测**: 我会在 .env 填 DMXAPI_API_KEY（或配 ollama）。你先用 5-10 条子集记录实测 dmxapi provider 全链路（分块→逐类判定→合并→输出），确认无报错、结果合理。
2. **LLM 提示词扩展 11 → 44 类**: H 列带【LLM】标记的共 44 类。补齐剩余 33 类的英文提示词（写进 tools/export_taxonomy.py 的 LLM 覆盖表再重新导出 yaml；提示词结构参考现有的：类别定义原文嵌入 + 检测要点 + 区分教学语境 + 严格 JSON 输出）。注意边界:
   - B-I-8（虚假事实）无检索能力时只能做"无来源断言密度"弱判定，提示词里写明局限
   - B-CI-1（图像跨模态注入）纯文本 LLM 测不了，除非 provider 支持多模态——跳过并在 coverage 注明
   - B-IA-3（语料级投毒聚类）是批处理层能力，单条检测不做
3. **650 子集全量跑 + 精度调优**: 静态+LLM 双轨跑完 650 条，导出 needs_review 队列给我人工核验抽样；根据误报/漏报调整词表、正则、提示词、置信度阈值，迭代 1-2 轮。
4. **与历史编码对比**: projects/Taxonomy_Building/v3_coding_results/ 有 v3 人工编码结果，做一致性对比（哪些类一致/分歧，分析原因）。
5. **批量成本评估**: 估算 131k 全量的 LLM 调用量与费用，评估是否需要两阶段策略（先便宜的块级相关性预筛，再逐类判定）或切 ollama 私有部署。
6. 产出: 注释完成的 650 子集 + 更新后的 categories.yaml + 调优报告（英文，可直接进论文）。

## 工作方式

- 接到复杂任务先复述需求，我确认后再动手
- 拿不准的去看 SkillSpector 源码（projects/SkillSpector/）或问我
- 每步完成跑 pytest + 冒烟验证，git commit 记录进展
```
