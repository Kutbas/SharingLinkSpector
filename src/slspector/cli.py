"""Command-line batch scanning with durable checkpoints."""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from slspector import conversation, taxonomy
from slspector.graph import create_graph
from slspector.nodes.report import report
from slspector.providers import resolve_provider

app = typer.Typer(add_completion=False, help="SharingLinkSpector: sharing-link risk annotation")
console = Console()
DEFAULT_MAX_RECORD_CHARS = 2_000_000
DEFAULT_MAX_MESSAGES = 2_000
DEFAULT_MAX_LINKS = 10_000


def _atomic_write(path: Path, content: str) -> None:
    """Replace a small metadata file atomically after flushing it to disk."""
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _append_jsonl(handle, item: dict) -> None:
    handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def _iter_records(path: Path, start_line: int = 0) -> Iterator[tuple[int, dict | None, str | None]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle):
            if line_number < start_line or not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                yield line_number, None, f"line {line_number + 1}: invalid JSON: {exc.msg}"
                continue
            if not isinstance(record, dict):
                yield line_number, None, f"line {line_number + 1}: top-level JSON must be an object"
                continue
            messages = record.get("messages", [])
            if not isinstance(messages, list) or any(
                not isinstance(message, dict) for message in messages
            ):
                yield (
                    line_number,
                    None,
                    f"line {line_number + 1}: messages must be an array of objects",
                )
                continue
            yield line_number, record, None


def _record_error(
    record: dict, max_record_chars: int, max_messages: int, max_links: int
) -> str | None:
    messages = record.get("messages", [])
    if len(messages) > max_messages:
        return f"record exceeds max messages ({len(messages)} > {max_messages})"
    total_chars = sum(len(str(message.get("content") or "")) for message in messages)
    if total_chars > max_record_chars:
        return f"record exceeds max chars ({total_chars} > {max_record_chars})"
    normalized = conversation.normalize_record(record)
    full_text, _ = conversation.build_full_text(normalized["messages"])
    if len(conversation.extract_links(full_text)) > max_links:
        return f"record exceeds max links ({max_links})"
    return None


def _checkpoint(
    path: Path, next_line: int, input_errors: int, records: int, completed: bool
) -> None:
    _atomic_write(
        path,
        json.dumps(
            {
                "next_line": next_line,
                "input_errors": input_errors,
                "records": records,
                "completed": completed,
            },
            ensure_ascii=False,
        ),
    )


@app.command()
def scan(
    input_path: Path = typer.Argument(..., exists=True, help="JSONL file"),  # noqa: B008
    output: Path = typer.Option(Path("out"), "-o", help="Output directory"),  # noqa: B008
    limit: int | None = typer.Option(None, "--limit", help="Maximum valid records"),
    offset: int = typer.Option(0, "--offset", help="Skip source lines"),
    resume: bool = typer.Option(False, "--resume", help="Resume from output/checkpoint.json"),
    provider: str | None = typer.Option(None, "--provider"),
    model: str | None = typer.Option(None, "--model"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    analyzers: str | None = typer.Option(None, "--analyzers"),
    chunk_chars: int | None = typer.Option(None, "--chunk-chars"),
    image_dir: Path | None = typer.Option(None, "--image-dir", help="Local image mirror dir for B-CI-1 forensics (sha1(url) named files)"),  # noqa: B008
    max_record_chars: int = typer.Option(DEFAULT_MAX_RECORD_CHARS, "--max-record-chars"),
    max_messages: int = typer.Option(DEFAULT_MAX_MESSAGES, "--max-messages"),
    max_links: int = typer.Option(DEFAULT_MAX_LINKS, "--max-links"),
) -> None:
    """Write record-level findings and finding-level needs_review JSONL output."""
    if min(max_record_chars, max_messages, max_links) < 1:
        raise typer.BadParameter("record limits must be positive")
    if chunk_chars:
        os.environ["SLSPECTOR_LLM_CHUNK_CHARS"] = str(chunk_chars)
    if image_dir is not None:
        os.environ["SLSPECTOR_IMAGE_DIR"] = str(image_dir.resolve())
    output.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output / "checkpoint.json"
    findings_path, review_path = output / "findings.jsonl", output / "needs_review.jsonl"
    start_line = offset
    input_errors = 0
    if resume:
        if not checkpoint_path.exists():
            raise typer.BadParameter("--resume requires output/checkpoint.json")
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        start_line = max(start_line, int(checkpoint.get("next_line", 0)))
        input_errors = int(checkpoint.get("input_errors", 0))
        prior_records = int(checkpoint.get("records", 0))
    else:
        for path in (findings_path, review_path, checkpoint_path, output / "summary.md"):
            path.unlink(missing_ok=True)
    use_llm = not no_llm
    cfg = resolve_provider(provider, model) if use_llm else None
    if use_llm and cfg is None:
        console.print("[yellow]LLM provider not configured; falling back to static-only[/yellow]")
        use_llm = False
    graph = create_graph(
        use_llm=use_llm,
        analyzer_filter={item.strip() for item in analyzers.split(",")} if analyzers else None,
    )
    prior_records = locals().get("prior_records", 0)
    records = findings = reviews = 0
    counters: Counter = Counter()
    platforms: Counter = Counter()
    started = time.monotonic()
    mode = "a" if resume else "w"
    with (
        findings_path.open(mode, encoding="utf-8") as findings_file,
        review_path.open(mode, encoding="utf-8") as review_file,
    ):
        for line_number, record, error in _iter_records(input_path, start_line):
            if error is None and record is not None:
                error = _record_error(record, max_record_chars, max_messages, max_links)
            if error:
                input_errors += 1
                console.print(f"[red]input error[/red]: {error}")
                _checkpoint(
                    checkpoint_path, line_number + 1, input_errors, prior_records + records, False
                )
                continue
            state = graph.invoke(
                {"record": record, "use_llm": use_llm, "provider": cfg.name if cfg else None}
            )
            result = report(state)
            _append_jsonl(findings_file, result)
            for finding in result["findings"]:
                counters[finding["taxonomy_id"]] += 1
                if finding["needs_review"]:
                    _append_jsonl(
                        review_file,
                        {
                            "share_id": result["share_id"],
                            "platform": result["platform"],
                            "finding": finding,
                        },
                    )
                    reviews += 1
            records += 1
            findings += result["finding_count"]
            platforms[result["platform"]] += 1
            _checkpoint(
                checkpoint_path, line_number + 1, input_errors, prior_records + records, False
            )
            if limit and records >= limit:
                break
    completed = not limit or records < limit
    _checkpoint(
        checkpoint_path,
        line_number + 1 if "line_number" in locals() else start_line,
        input_errors,
        prior_records + records,
        completed,
    )
    status = (
        "failed"
        if not (prior_records + records) and input_errors
        else "partial"
        if input_errors
        else "complete"
    )
    _write_summary(
        output,
        records,
        findings,
        reviews,
        counters,
        platforms,
        time.monotonic() - started,
        status,
        input_errors,
    )
    console.print(
        f"[green]{status}[/green]: {records} records, {findings} findings, {reviews} review findings"
    )
    if status == "failed":
        raise typer.Exit(1)
    if status == "partial":
        raise typer.Exit(2)


def _write_summary(
    out: Path,
    records: int,
    findings: int,
    reviews: int,
    counters: Counter,
    platforms: Counter,
    elapsed: float,
    status: str,
    input_errors: int,
) -> None:
    lines = [
        "# SharingLinkSpector Scan Summary",
        "",
        f"- scan status: {status}",
        f"- records: {records} (platforms: {dict(platforms)})",
        f"- findings: {findings}, needs_review findings: {reviews}",
        "- needs_review.jsonl: finding-level records with share_id, platform, and finding",
        f"- input errors: {input_errors}",
        f"- elapsed: {elapsed:.1f}s",
        "",
        "## Hits by category",
    ]
    lines.extend(f"- {category}: {count}" for category, count in counters.most_common())
    _atomic_write(out / "summary.md", "\n".join(lines) + "\n")


@app.command()
def coverage() -> None:
    table = Table(title="Taxonomy v5 Coverage")
    for column in ("ID", "Category", "status", "tracks", "who can test / notes"):
        table.add_column(column)
    for row in taxonomy.coverage_report():
        table.add_row(
            row["id"],
            row["leaf_en"],
            row["status"],
            "/".join(row["tracks"]),
            (row["note"] or row["who_can_test"])[:70],
        )
    console.print(table)


if __name__ == "__main__":
    app()
