"""Conversation chunking for the LLM track.

Long conversations are split into chunks that respect message boundaries where
possible, so a single oversized request can never fail and no middle content is
silently dropped (the old truncation behavior):

- Units: paragraphs (split on blank lines) tagged with their message index.
- Packing: greedy fill up to ``max_chars``; a chunk never mixes the tail of one
  paragraph-split message with an arbitrary character offset (oversize
  paragraphs are sliding-window split with ``overlap`` chars carried over).
- Overlap: the last ``overlap`` chars (whole units when they fit) are repeated
  at the head of the next chunk so boundary-spanning signals are not missed.
- Full coverage: every character of every message belongs to at least one chunk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_CHUNK_CHARS = 24_000
DEFAULT_OVERLAP_CHARS = 800


def chunk_limits() -> tuple[int, int]:
    """Resolve (max_chars, overlap) from env with sane clamping."""
    try:
        max_chars = int(os.environ.get("SLSPECTOR_LLM_CHUNK_CHARS", DEFAULT_CHUNK_CHARS))
    except ValueError:
        max_chars = DEFAULT_CHUNK_CHARS
    try:
        overlap = int(os.environ.get("SLSPECTOR_LLM_CHUNK_OVERLAP", DEFAULT_OVERLAP_CHARS))
    except ValueError:
        overlap = DEFAULT_OVERLAP_CHARS
    max_chars = max(200, max_chars)
    overlap = max(0, min(overlap, max_chars // 4))
    return max_chars, overlap


@dataclass(slots=True)
class Chunk:
    index: int
    text: str
    # (message_index, start, end) spans within the original messages
    spans: list[tuple[int, int, int]] = field(default_factory=list)
    truncated: bool = False  # True when a hard character split broke a paragraph


def _paragraphs(message_index: int, text: str) -> list[tuple[int, int, int, str]]:
    """Split one message into paragraph units with (start, end) offsets."""
    units: list[tuple[int, int, int, str]] = []
    start = 0
    for part in text.split("\n\n"):
        end = start + len(part)
        if part.strip():
            units.append((message_index, start, end, part))
        start = end + 2
    if not units and text:
        units.append((message_index, 0, len(text), text))
    return units


def _hard_split(unit: tuple[int, int, int, str, str], size: int, overlap: int):
    """Sliding-window split of one oversize paragraph; yields sub-units."""
    mi, ustart, _uend, text, _header = unit
    step = max(1, size - overlap)
    pos = 0
    while pos < len(text):
        end = min(len(text), pos + size)
        yield (mi, ustart + pos, ustart + end, text[pos:end])
        if end >= len(text):
            break
        pos += step


def chunk_conversation(
    messages: list[dict], max_chars: int | None = None, overlap: int | None = None
) -> list[Chunk]:
    """Chunk normalized messages ({"role", "content"}) into LLM-sized chunks.

    Message metadata is preserved via role headers inside the chunk text, so the
    model still sees turn boundaries.
    """
    if max_chars is None or overlap is None:
        dmax, dover = chunk_limits()
        max_chars = max_chars or dmax
        overlap = dover if overlap is None else overlap

    # Build unit list with role headers; header length counts toward chunk size
    units: list[tuple[int, int, int, str, str]] = []  # mi, start, end, text, role
    for mi, msg in enumerate(messages):
        role = msg.get("role", "")
        header = f"[{role}]\n" if role else ""
        body = str(msg.get("content") or "")
        for (u_mi, u_start, u_end, part) in _paragraphs(mi, body):
            units.append((u_mi, u_start, u_end, part, header))
        if not body.strip():
            units.append((mi, 0, 0, "", header))  # keep empty-message marker

    chunks: list[Chunk] = []
    cur_parts: list[str] = []
    cur_spans: list[tuple[int, int, int]] = []
    cur_roles: dict[int, str] = {}
    cur_len = 0
    truncated = False

    def _close():
        nonlocal cur_parts, cur_spans, cur_roles, cur_len, truncated
        if not cur_parts:
            return
        chunks.append(
            Chunk(
                index=len(chunks),
                text="\n\n".join(cur_parts),
                spans=list(cur_spans),
                truncated=truncated,
            )
        )
        cur_parts, cur_spans, cur_roles, cur_len, truncated = [], [], {}, 0, False

    for unit in units:
        mi, u_start, u_end, part, header = unit
        header_len = len(header) if mi not in cur_roles else 0
        unit_len = header_len + len(part) + 2  # +2 for "\n\n" separator
        if unit_len > max_chars:
            # Oversize paragraph: flush current chunk, then hard-split
            _close()
            first = True
            for (s_mi, s_start, s_end, seg) in _hard_split(unit, max_chars, overlap):
                chunks.append(
                    Chunk(
                        index=len(chunks),
                        text=(header + seg) if first else seg,
                        spans=[(s_mi, s_start, s_end)],
                        truncated=True,
                    )
                )
                first = False
            continue
        if cur_len + unit_len > max_chars and cur_parts:
            # Start a new chunk, carrying tail units (<= overlap chars) over
            carry_parts: list[str] = []
            carry_spans: list[tuple[int, int, int]] = []
            carry_roles: dict[int, str] = {}
            carry_len = 0
            while cur_parts and carry_len + len(cur_parts[-1]) <= overlap:
                p = cur_parts.pop()
                sp = cur_spans.pop()
                carry_parts.insert(0, p)
                carry_spans.insert(0, sp)
                carry_len += len(p)
                # roles of carried spans
                for (cmi, _cs, _ce) in [sp]:
                    if cmi in cur_roles:
                        carry_roles[cmi] = cur_roles[cmi]
            old_parts, old_spans, old_roles = cur_parts, cur_spans, cur_roles
            _close()
            cur_parts = carry_parts
            cur_spans = carry_spans
            cur_roles = carry_roles
            cur_len = carry_len
            del old_parts, old_spans, old_roles
        if mi not in cur_roles and header:
            cur_parts.append(header.rstrip("\n"))
            cur_len += header_len
            cur_roles[mi] = header
        cur_parts.append(part)
        cur_spans.append((mi, u_start, u_end))
        cur_len += len(part) + 2
    _close()

    if not chunks:
        chunks.append(Chunk(index=0, text="", spans=[]))
    return chunks
