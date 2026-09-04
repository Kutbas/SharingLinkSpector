"""slspector CLI：scan / coverage。

用法:
  slspector scan <input.jsonl> [--limit 20] [--no-llm] [--provider dmxapi] [-o out/]
  slspector coverage
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from slspector import taxonomy
from slspector.graph import create_graph
from slspector.nodes.report import report
from slspector.providers import resolve_provider

app = typer.Typer(add_completion=False, help="SharingLinkSpector: 分享链接风险标注（静态+LLM 双轨）")
console = Console()


def _iter_records(path: Path, limit: int | None, offset: int = 0):
    n = 0
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i < offset:
                continue
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)
            n += 1
            if limit and n >= limit:
                return


@app.command()
def scan(
    input_path: Path = typer.Argument(..., exists=True, help="JSONL 文件（统一 schema）"),
    output: Path = typer.Option(Path("out"), "-o", help="输出目录"),
    limit: int = typer.Option(None, "--limit", help="最多扫描条数"),
    offset: int = typer.Option(0, "--offset", help="跳过前 N 条"),
    provider: str = typer.Option(
        None, "--provider", help="dmxapi | ollama | none（默认读 .env）"),
    model: str = typer.Option(None, "--model", help="覆盖 provider 默认模型"),
    no_llm: bool = typer.Option(False, "--no-llm", help="仅静态检测"),
    analyzers: str = typer.Option(None, "--analyzers", help="仅运行指定 analyzer（逗号分隔）"),
):
    """扫描对话记录，输出 findings.jsonl / needs_review.jsonl / summary.md。"""
    use_llm = not no_llm
    cfg = resolve_provider(provider, model) if use_llm else None
    if use_llm and cfg is None:
        console.print("[yellow]LLM provider 未配置/无 key，降级为静态-only[/yellow]")
        use_llm = False
    analyzer_filter = {a.strip() for a in analyzers.split(",")} if analyzers else None

    graph = create_graph(use_llm=use_llm, analyzer_filter=analyzer_filter)
    output.mkdir(parents=True, exist_ok=True)

    findings_path = output / "findings.jsonl"
    review_path = output / "needs_review.jsonl"
    n_records = 0
    n_findings = 0
    n_review = 0
    cat_counter: Counter = Counter()
    plat_counter: Counter = Counter()
    t0 = time.monotonic()

    with findings_path.open("w", encoding="utf-8") as ff, review_path.open(
        "w", encoding="utf-8"
    ) as rf:
        for record in _iter_records(input_path, limit, offset):
            state = graph.invoke(
                {"record": record, "use_llm": use_llm, "provider": cfg.name if cfg else None}
            )
            result = report(state)
            ff.write(json.dumps(result, ensure_ascii=False) + "\n")
            for f in result["findings"]:
                cat_counter[f["taxonomy_id"]] += 1
            if result["needs_review_count"]:
                rf.write(json.dumps(result, ensure_ascii=False) + "\n")
            n_records += 1
            n_findings += result["finding_count"]
            n_review += result["needs_review_count"]
            plat_counter[result["platform"]] += 1
            if n_records % 10 == 0:
                console.print(
                    f"[dim]{n_records} records, {n_findings} findings, "
                    f"{time.monotonic() - t0:.1f}s[/dim]"
                )

    _write_summary(output, n_records, n_findings, n_review, cat_counter, plat_counter,
                   time.monotonic() - t0, cfg.model if cfg else None)
    console.print(
        f"[green]done[/green]: {n_records} records → {n_findings} findings "
        f"({n_review} needs_review) in {time.monotonic() - t0:.1f}s\n"
        f"输出: {findings_path}\n      {review_path}\n      {output / 'summary.md'}"
    )


def _write_summary(out: Path, n_records, n_findings, n_review, cat_counter, plat_counter,
                   elapsed, model):
    lines = [
        "# SharingLinkSpector 扫描汇总",
        "",
        f"- 记录数: {n_records}（平台分布: {dict(plat_counter)}）",
        f"- findings: {n_findings}，needs_review: {n_review}",
        f"- 耗时: {elapsed:.1f}s" + (f"，LLM: {model}" if model else "，静态-only"),
        "",
        "## 命中类别分布",
        "",
        "| 类别 | 名称 | hits |",
        "|------|------|------|",
    ]
    for cid, n in cat_counter.most_common():
        cat = taxonomy.get(cid) or {}
        lines.append(f"| {cid} | {cat.get('leaf', '')} | {n} |")
    lines += ["", "## Coverage（49 类，谁才能测）", "",
              "| ID | 叶类 | 状态 | tracks | 说明 |", "|----|------|------|--------|------|"]
    for row in taxonomy.coverage_report():
        note = row["note"] or row["kevin_note"] or row["who_can_test"]
        lines.append(
            f"| {row['id']} | {row['leaf']} | {row['status']} | "
            f"{'/'.join(row['tracks'])} | {note[:80]} |"
        )
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")


@app.command()
def coverage():
    """打印 49 类 coverage 矩阵。"""
    table = Table(title="Taxonomy v5 Coverage")
    for col in ("ID", "叶类", "状态", "tracks", "谁才能测/说明"):
        table.add_column(col)
    for row in taxonomy.coverage_report():
        table.add_row(
            row["id"], row["leaf"], row["status"], "/".join(row["tracks"]),
            (row["note"] or row["kevin_note"] or row["who_can_test"])[:60],
        )
    console.print(table)
    console.print(dict(taxonomy.status_counts()))


if __name__ == "__main__":
    app()
