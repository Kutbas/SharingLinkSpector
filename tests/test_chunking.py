"""Chunking tests: coverage, overlap, oversize messages, LLM multi-chunk merge."""

from __future__ import annotations

from slspector.chunking import chunk_conversation, chunk_limits


def _msgs(*contents: str, role="USER") -> list[dict]:
    return [{"role": role, "content": c} for c in contents]


def test_short_conversation_single_chunk():
    chunks = chunk_conversation(_msgs("hello", "world"), max_chars=1000, overlap=100)
    assert len(chunks) == 1
    assert "hello" in chunks[0].text and "world" in chunks[0].text
    assert chunks[0].spans == [(0, 0, 5), (1, 0, 5)]


def test_multi_message_split_respects_boundaries():
    msgs = _msgs(*[f"message-{i} " + "x" * 200 for i in range(20)])
    chunks = chunk_conversation(msgs, max_chars=1000, overlap=100)
    assert len(chunks) > 1
    # every chunk within budget (role headers included)
    assert all(len(c.text) <= 1400 for c in chunks)
    # full coverage: union of spans covers every message
    covered = {span[0] for c in chunks for span in c.spans}
    assert covered == set(range(20))


def test_oversize_single_paragraph_hard_split():
    """One paragraph longer than max_chars (no blank lines) triggers the slider."""
    big = "x" * 50_000  # single paragraph, no blank-line breaks
    chunks = chunk_conversation(_msgs(big), max_chars=8000, overlap=500)
    assert len(chunks) > 4
    assert all(c.truncated for c in chunks)
    # sliding-window overlap: consecutive chunks share content
    for a, b in zip(chunks, chunks[1:]):
        assert a.text[-100:] in b.text


def test_oversize_message_with_paragraphs_packs_normally():
    """Blank-line-separated paragraphs inside one message pack like normal units."""
    big = "para one.\n\n" * 5000
    chunks = chunk_conversation(_msgs(big), max_chars=8000, overlap=500)
    assert all(not c.truncated for c in chunks)
    assert all(len(c.text) <= 8200 for c in chunks)


def test_no_silent_middle_drop():
    """The old truncation bug: middle content must still be judged."""
    head = "start marker " + "a" * 30000
    middle = "\n\nMIDDLE-SECRET-ANCHOR-9f3b2c\n\n"
    tail = "b" * 30000 + " end marker"
    chunks = chunk_conversation(_msgs(head + middle + tail), max_chars=12000, overlap=800)
    joined = "\n\n".join(c.text for c in chunks)
    assert "MIDDLE-SECRET-ANCHOR-9f3b2c" in joined


def test_chunk_limits_env(monkeypatch):
    monkeypatch.setenv("SLSPECTOR_LLM_CHUNK_CHARS", "5000")
    monkeypatch.setenv("SLSPECTOR_LLM_CHUNK_OVERLAP", "200")
    assert chunk_limits() == (5000, 200)
    monkeypatch.setenv("SLSPECTOR_LLM_CHUNK_CHARS", "10")  # clamped to floor
    assert chunk_limits()[0] == 200


def test_empty_conversation():
    chunks = chunk_conversation([], max_chars=1000, overlap=100)
    assert len(chunks) == 1 and chunks[0].text == ""
