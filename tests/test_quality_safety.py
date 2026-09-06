"""Failure-path, false-positive, and documentation consistency tests."""

from __future__ import annotations

import re
from pathlib import Path

from conftest import make_record, scan

from slspector import conversation, taxonomy


def test_url_normalization_rejects_non_http_and_normalizes_host():
    links = conversation.extract_links("javascript:alert(1) https://EXAMPLE.com:443/a")
    assert [link["url"] for link in links] == ["https://example.com/a"]
    assert conversation.domain_of("https://user:pass@EXAMPLE.com:443/a") == "example.com"
    assert conversation.extract_links("https://example.com:bad-port/path") == []


def test_unicode_controls_are_detected_without_flagging_normal_unicode(static_graph):
    clean = scan(static_graph, make_record(("USER", "Café 中文 Ελληνικά are ordinary text.")))
    assert not [item for item in clean if item["taxonomy_id"] == "B-CI-2"]
    hidden = scan(static_graph, make_record(("USER", "safe\u2066hidden\u2069")))
    assert [item for item in hidden if item["taxonomy_id"] == "B-CI-2"]


def test_pii_avoids_invalid_card_false_positive(static_graph):
    findings = scan(
        static_graph, make_record(("USER", "build id 4111111111111112 is not a payment card"))
    )
    assert not [item for item in findings if item["taxonomy_id"] == "A-C-2"]


def test_readmes_state_the_actual_taxonomy_count():
    categories = taxonomy.load_categories()
    count = len(categories)
    static_count = sum("static" in category["tracks"] for category in categories.values())
    llm_count = len(taxonomy.llm_categories())
    for name in ("README.md", "README_zh.md"):
        text = Path(name).read_text(encoding="utf-8")
        assert re.search(rf"\b{count}[- ]categor", text, re.IGNORECASE) or f"{count} 类" in text
        assert str(static_count) in text
        assert str(llm_count) in text
