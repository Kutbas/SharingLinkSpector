"""slspector CLI: scan / coverage.

Usage:
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

app = typer.Typer(add_completion=False,
                  help="SharingLinkSpector: sharing-link risk annotation (static + LLM dual track)")
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
    input_path: Path = typer.Argument(..., exists=True, help="JSONL file (unified schema)"),
    output: Path = typer.Option(Path("out"), "-o", help="output directory"),
    limit: int = typer.Option(None, "--limit", help="max records to scan"),
    offset: int = typer.Option(0, "--offset", help="skip first N records"),
    provider: str = typer.Option(
        None, "--provider", help="dmxapi | ollama | none (default: .env)"),
    model: str = typer.Option(None, "--model", help="override provider default model"),
    no_llm: bool = typer.Option(False, "--no-llm", help="static detection only"),
    analyzers: str = typer.Option(None, "--analyzers", help="run only these analyzers (comma-separated)"),
    chunk_chars: int = typer.Option(None, "--chunk-chars",
                                    help="LLM chunk size in chars (default 24000, env SLSPECTOR_LLM_CHUNK_CHARS)"),
):
    """Scan conversation records; writes findings.jsonl / needs_review.jsonl / summary.md."""
    import os

    if chunk_chars:
        os.environ["SLSPECTOR_LLM_CHUNK_CHARS"] = str(chunk_chars)

    use_llm = not no_llm
    cfg = resolve_provider(provider, model) if use_llm else None
    if use_llm and cfg is None:
        console.print("[yellow]LLM provider not configured / no API key; falling back to static-only[/yellow]")
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
        f"[green]done[/green]: {n_records} records -> {n_findings} findings "
        f"({n_review} needs_review) in {time.monotonic() - t0:.1f}s\n"
        f"output: {findings_path}\n        {review_path}\n        {output / 'summary.md'}"
    )


def _write_summary(out: Path, n_records, n_findings, n_review, cat_counter, plat_counter,
                   elapsed, model):
    lines = [
        "# SharingLinkSpector Scan Summary",
        "",
        f"- records: {n_records} (platforms: {dict(plat_counter)})",
        f"- findings: {n_findings}, needs_review: {n_review}",
        f"- elapsed: {elapsed:.1f}s" + (f", LLM: {model}" if model else ", static-only"),
        "",
        "## Hits by category",
        "",
        "| ID | Category | hits |",
        "|----|----------|------|",
    ]
    for cid, n in cat_counter.most_common():
        cat = taxonomy.get(cid) or {}
        lines.append(f"| {cid} | {cat.get('leaf_en', '')} | {n} |")
    lines += ["", "## Coverage (49 categories, who can test what)", "",
              "| ID | Category | status | tracks | notes |", "|----|----------|--------|--------|-------|"]
    for row in taxonomy.coverage_report():
        note = row["note"] or row["who_can_test"]
        lines.append(
            f"| {row['id']} | {row['leaf_en']} | {row['status']} | "
            f"{'/'.join(row['tracks'])} | {note[:90]} |"
        )
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")


@app.command()
def coverage():
    """Print the 49-category coverage matrix."""
    table = Table(title="Taxonomy v5 Coverage")
    for col in ("ID", "Category", "status", "tracks", "who can test / notes"):
        table.add_column(col)
    for row in taxonomy.coverage_report():
        table.add_row(
            row["id"], row["leaf_en"], row["status"], "/".join(row["tracks"]),
            (row["note"] or row["who_can_test"])[:70],
        )
    console.print(table)
    console.print(dict(taxonomy.status_counts()))


if __name__ == "__main__":
    app()
