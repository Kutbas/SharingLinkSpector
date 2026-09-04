#!/usr/bin/env python
"""Export taxonomy-0901-v5.xlsx「症状」sheet → data/categories.yaml.

Produces the single source of truth consumed by slspector at runtime:
- 49 categories with ID / L1 / leaf / definition / source / detection-method text
- detectability: which tracks are possible (static/llm/dynamic/metadata/platform)
- kevin_note: I 列「判定理由（红标项）」原文（红标处置的依据）
- llm.prompt: Phase 1 LLM 类别的判定提示词（由 E 列定义 + H 列 LLM 要点生成，可手工精调）

Re-run:  uv run --group export python tools/export_taxonomy.py
"""

from __future__ import annotations

import re
from pathlib import Path

import openpyxl
import yaml

ROOT = Path(__file__).resolve().parent.parent
XLSX = ROOT.parent / "20260831" / "taxonomy-0901-v4.xlsx"
DEFAULT_XLSX = ROOT / "taxonomy-0901-v5.xlsx"
OUT = ROOT / "data" / "categories.yaml"

# Kevin I 列红标处置（2026-09-04 review 确认）
RED_FLAG_DISPOSITION = {
    "B-C-3": {"status": "skipped", "reason": "无检测特征，仅论文故事，不标注"},
    "B-A-1": {"status": "skipped", "reason": "无检测特征，仅论文故事，不标注"},
    "B-CIA-7": {"status": "skipped", "reason": "载荷不在收集到的 metadata，future work/discussion"},
    "B-C-5": {"status": "implemented", "reason": "载荷在原始字节中，静态扫描可发现"},
    "B-C-6": {"status": "candidate", "reason": "识别异常跨源资源候选→人工核验；无需受害者在场"},
    "B-CI-6": {"status": "candidate", "reason": "识别候选外链，判定需目标网络信息→人工核验"},
    "B-CI-8": {"status": "implemented", "reason": "投毒指令模板 + LLM 判植入意图与语义突兀性"},
    "B-IA-1": {"status": "implemented", "reason": "隐藏指令模板；错误事实型投毒难检测（降级说明）"},
    "B-IA-2": {"status": "implemented", "reason": "同 B-IA-1，隐藏指令模板为主"},
    "B-IA-4": {"status": "candidate", "reason": "base64/hex 解码探针出候选→人工核验/LLM 检验目标"},
    "B-CIA-3": {"status": "implemented", "reason": "可执行结构静态检测；不管攻击是否实际发生"},
    "B-CIA-6": {"status": "candidate", "reason": "模板元语法候选，误报多→人工核验"},
}

# Phase 1 LLM 提示词覆盖的类别（红标相关 + A-C 系列 + 高价值注入类）
LLM_PHASE1 = {
    "A-C-1", "A-C-2", "A-C-3", "A-C-4", "A-C-5", "A-C-6",
    "A-I-1", "B-CIA-1", "B-CI-8", "B-IA-1", "B-IA-2",
}

# Phase 1 不实现、且非红标处置的类 → 计划档位
PLANNED = {
    "B-C-1": "phase2_llm",          # 静态 Phase1 已含；LLM 判定 phase2（此处仅备注）
    "B-I-4": "phase2_dynamic",      # 需回源抓取 OG/oEmbed
    "B-I-5": "future_work",         # C2PA 签名链校验
    "B-I-6": "future_work",         # 动态重取比对
    "B-I-8": "future_work",         # 检索式事实验证
    "B-I-9": "phase2_llm",          # NLI 蕴含审计
    "B-I-10": "phase2_llm",         # 行动指向建议审查
    "B-CI-1": "future_work",        # 图像取证/多模态
    "B-CI-7": "future_work",        # 二维码解码
    "B-IA-3": "future_work",        # 语料级聚类（批处理层）
    "B-A-2": "implemented",
    "B-A-3": "implemented",
    "B-A-4": "implemented",
    "B-C-2": "implemented",
    "B-C-4": "implemented",
    "B-I-1": "implemented",
    "B-I-2": "implemented",
    "B-I-3": "implemented",
    "B-I-7": "implemented",
    "B-CI-2": "implemented",
    "B-CI-3": "implemented",
    "B-CI-4": "implemented",
    "B-CI-5": "implemented",
    "B-IA-5": "candidate",
    "B-CIA-2": "implemented",
    "B-CIA-4": "implemented",
    "B-CIA-5": "implemented",
    "B-CIA-8": "implemented",
    "B-CIA-9": "implemented",
}


def parse_tracks(h_text: str) -> list[str]:
    return re.findall(r"【(静态|LLM|动态|元数据|平台方)】", h_text or "")


def llm_prompt(e: str, h: str, leaf: str) -> str:
    """Generate the Phase 1 LLM judging prompt from 定义与症状 + H 列 LLM 要点."""
    m = re.search(r"【LLM[^】]*】([^；;]+)", h or "")
    llm_point = m.group(1).strip() if m else ""
    return (
        f"你是 AI 对话分享链接安全风险标注专家。请判定下面的对话记录中是否存在「{leaf}」风险。\n"
        f"## 类别定义\n{e}\n"
        f"## 检测要点\n{llm_point}\n"
        "## 判定要求\n"
        "1. 只依据对话内容本身判定，不做任何网络请求；\n"
        "2. 注意区分真实风险与教学/讨论/示例语境（讨论该风险 ≠ 构成该风险）；\n"
        "3. 跨语种判定（中/英/其他语言均可能）；\n"
        "4. 若无法确认但存在可疑迹象，hit=true 且 confidence≤0.5；\n"
        "5. 输出严格 JSON：{\"hit\": bool, \"confidence\": 0~1, \"evidence\": \"原文关键片段(≤200字)\", "
        "\"reasoning\": \"判定理由(中文,≤150字)\"}"
    )


def main() -> None:
    src = DEFAULT_XLSX if DEFAULT_XLSX.exists() else XLSX
    wb = openpyxl.load_workbook(src, data_only=True)
    ws = wb["症状"]
    headers = [ws.cell(row=1, column=c).value for c in range(1, 10)]
    categories = []
    for r in range(2, ws.max_row + 1):
        row = {headers[c - 1]: ws.cell(row=r, column=c).value for c in range(1, 10)}
        cid = str(row["ID"] or "").strip()
        if not cid:
            continue
        h = str(row["检测方法（检测器设计要点）"] or "")
        e = str(row["攻击手段 Technique（叶子）"] or "") and str(
            row["定义与症状"] or ""
        )
        leaf = str(row["攻击手段 Technique（叶子）"] or "")
        disp = RED_FLAG_DISPOSITION.get(cid)
        status = disp["status"] if disp else PLANNED.get(cid, "implemented")
        note = disp["reason"] if disp else ""
        kevin_note = str(row["判定理由（红标项）"] or "") or None
        cat = {
            "id": cid,
            "model": str(row["威胁模型"] or ""),
            "l1": str(row["机制大类 (L1)"] or ""),
            "leaf": leaf,
            "definition": e,
            "source_refs": str(row["来源"] or ""),
            "detection_methods": h,
            "tracks": parse_tracks(h),
            "status": status,
            "note": note,
            "kevin_note": kevin_note,
        }
        if cid in LLM_PHASE1:
            cat["llm"] = {"prompt": llm_prompt(e, h, leaf), "needs_review": status == "candidate"}
        categories.append(cat)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "source": src.name,
        "sheet": "症状",
        "count": len(categories),
        "exported_at": "2026-09-04",
        "status_legend": {
            "implemented": "Phase 1 实现检测",
            "candidate": "仅输出候选，needs_review=true，人工核验",
            "phase2_llm": "LLM 轨 Phase 2 扩展",
            "phase2_dynamic": "需回源/动态能力，Phase 2",
            "future_work": "论文 future work / discussion",
            "skipped": "不标注（Kevin I 列判定）",
        },
    }
    with OUT.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            {"meta": meta, "categories": categories},
            f, allow_unicode=True, sort_keys=False, width=120,
        )
    print(f"exported {len(categories)} categories -> {OUT}")
    from collections import Counter
    print(Counter(c["status"] for c in categories))


if __name__ == "__main__":
    main()
