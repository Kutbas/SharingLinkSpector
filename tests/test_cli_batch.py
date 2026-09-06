"""Batch scan reliability tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from slspector.cli import app


def _record(share_id: str = "one") -> dict:
    return {
        "share_id": share_id,
        "platform": "test",
        "messages": [{"role": "USER", "content": "hello"}],
    }


def test_scan_writes_finding_level_review_and_checkpoint(tmp_path: Path):
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(_record()) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["scan", str(source), "--no-llm", "-o", str(out)])
    assert result.exit_code == 0, result.output
    checkpoint = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["completed"] is True and checkpoint["next_line"] == 1
    assert (out / "findings.jsonl").exists()
    assert not list(out.glob("*.tmp"))
    for line in (out / "needs_review.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        assert "finding" in item and "share_id" in item


def test_scan_partial_input_uses_exit_code_two_and_resume(tmp_path: Path):
    source = tmp_path / "input.jsonl"
    source.write_text("not json\n" + json.dumps(_record("two")) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    runner = CliRunner()
    first = runner.invoke(app, ["scan", str(source), "--no-llm", "-o", str(out)])
    assert first.exit_code == 2, first.output
    resumed = runner.invoke(app, ["scan", str(source), "--no-llm", "--resume", "-o", str(out)])
    assert resumed.exit_code == 2, resumed.output
    rows = (out / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1


def test_scan_rejects_oversize_record_without_crashing(tmp_path: Path):
    source = tmp_path / "input.jsonl"
    source.write_text(
        json.dumps(_record() | {"messages": [{"role": "USER", "content": "x" * 1000}]}) + "\n"
    )
    result = CliRunner().invoke(
        app,
        ["scan", str(source), "--no-llm", "--max-record-chars", "100", "-o", str(tmp_path / "out")],
    )
    assert result.exit_code == 1
    assert "record exceeds" in result.output
