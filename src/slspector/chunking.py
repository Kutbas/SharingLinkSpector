"""Conversation chunking for the LLM track."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_CHUNK_CHARS = 24_000
DEFAULT_OVERLAP_CHARS = 800


def chunk_limits() -> tuple[int, int]:
    try:
        max_chars = int(os.environ.get("SLSPECTOR_LLM_CHUNK_CHARS", DEFAULT_CHUNK_CHARS))
    except ValueError:
        max_chars = DEFAULT_CHUNK_CHARS
    try:
        overlap = int(os.environ.get("SLSPECTOR_LLM_CHUNK_OVERLAP", DEFAULT_OVERLAP_CHARS))
    except ValueError:
        overlap = DEFAULT_OVERLAP_CHARS
    return max(200, max_chars), max(0, min(overlap, max_chars // 4))


@dataclass(slots=True)
class Chunk:
    index: int
    text: str
    spans: list[tuple[int, int, int]] = field(default_factory=list)
    truncated: bool = False


def _paragraphs(message_index: int, text: str) -> list[tuple[int, int, int, str]]:
    units = []
    start = 0
    for part in text.split("\n\n"):
        end = start + len(part)
        if part.strip():
            units.append((message_index, start, end, part))
        start = end + 2
    if not units and text:
        units.append((message_index, 0, len(text), text))
    return units


def chunk_conversation(
    messages: list[dict], max_chars: int | None = None, overlap: int | None = None
) -> list[Chunk]:
    """Chunk messages within max_chars while preserving body coverage."""
    if max_chars is None or overlap is None:
        dmax, dover = chunk_limits()
        max_chars = dmax if max_chars is None else max_chars
        overlap = dover if overlap is None else overlap
    max_chars = max(1, max_chars)
    overlap = max(0, overlap)
    units = []

    def header_for(role: str) -> str:
        header = f"[{role}]\n" if role else ""
        return header if len(header) < max_chars else ""

    for mi, msg in enumerate(messages):
        role = str(msg.get("role") or "")
        body = str(msg.get("content") or "")
        capacity = max(1, max_chars - len(header_for(role)))
        paragraphs = _paragraphs(mi, body)
        if not paragraphs:
            units.append((mi, 0, 0, "", role, False))
        for _, start, end, part in paragraphs:
            if len(part) <= capacity:
                units.append((mi, start, end, part, role, False))
                continue
            step = max(1, capacity - min(overlap, capacity - 1))
            pos = 0
            while pos < len(part):
                finish = min(len(part), pos + capacity)
                units.append((mi, start + pos, start + finish, part[pos:finish], role, True))
                if finish == len(part):
                    break
                pos += step
    chunks = []
    current = []
    truncated = False

    def render(items):
        seen = set()
        parts = []
        for mi, _s, _e, text, role, _hard in items:
            prefix = header_for(role) if role and mi not in seen else ""
            seen.add(mi)
            parts.append(prefix + text)
        return "\n\n".join(parts)

    def close():
        nonlocal current, truncated
        if current:
            chunks.append(
                Chunk(
                    len(chunks),
                    render(current),
                    [(mi, s, e) for mi, s, e, text, _, _ in current if e > s],
                    truncated,
                )
            )
        current = []
        truncated = False

    for unit in units:
        if current and len(render(current + [unit])) > max_chars:
            carry = []
            carried = 0
            for previous in reversed(current):
                text = previous[3]
                if not text or carried + len(text) > overlap:
                    break
                carry.insert(0, previous)
                carried += len(text)
            close()
            current = carry
            truncated = any(x[5] for x in current)
            while current and len(render(current + [unit])) > max_chars:
                current.pop(0)
        current.append(unit)
        truncated = truncated or unit[5]
    close()
    if chunks:
        for mi, msg in enumerate(messages):
            body = str(msg.get("content") or "")
            covered = [False] * len(body)
            for chunk in chunks:
                for span_mi, start, end in chunk.spans:
                    if span_mi == mi:
                        for pos in range(max(0, start), min(len(body), end)):
                            covered[pos] = True
            pos = 0
            while pos < len(body):
                if covered[pos]:
                    pos += 1
                    continue
                end = pos + 1
                while end < len(body) and not covered[end]:
                    end += 1
                chunks[0].spans.append((mi, pos, end))
                pos = end
    return chunks or [Chunk(0, "", [])]
