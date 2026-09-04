"""taxonomy 注册表测试。"""

from __future__ import annotations

from slspector import taxonomy


def test_loads_49_categories():
    cats = taxonomy.load_categories()
    assert len(cats) == 49


def test_skip_list_matches_kevin_decision():
    cats = taxonomy.load_categories()
    skipped = {cid for cid, c in cats.items() if c["status"] == "skipped"}
    assert skipped == {"B-C-3", "B-A-1", "B-CIA-7"}
    for cid in skipped:
        assert cats[cid]["kevin_note"], f"{cid} must keep Kevin's rationale"
    assert all("platform" in cats[cid]["tracks"] or "llm" in cats[cid]["tracks"]
               for cid in ("B-C-3", "B-A-1"))


def test_candidate_categories():
    cats = taxonomy.load_categories()
    candidates = {cid for cid, c in cats.items() if c["status"] == "candidate"}
    assert {"B-C-6", "B-CI-6", "B-CIA-6", "B-IA-4"} <= candidates


def test_llm_categories_phase1():
    llm = taxonomy.llm_categories()
    assert "A-C-1" in llm and "B-CI-8" in llm and "B-IA-1" in llm
    assert "B-C-3" not in llm  # skipped categories never enter the LLM track
    # English prompts for the English-venue paper
    assert llm["A-C-1"]["llm"]["prompt"].startswith("You are a security risk annotator")


def test_coverage_report_rows():
    rows = taxonomy.coverage_report()
    assert len(rows) == 49
    by_id = {r["id"]: r for r in rows}
    assert by_id["B-C-3"]["who_can_test"].startswith("not labeled")
    assert "platform" in by_id["B-C-3"]["tracks"]
    assert by_id["A-C-1"]["leaf_en"] == "Identity information disclosure"
