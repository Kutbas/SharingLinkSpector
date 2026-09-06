"""Conversation-record normalization: unified-schema JSONL -> analysis surfaces
(full text / offsets / links / attachments / stats).

Analogous to SkillSpector's build_context but producing conversation-text
surfaces instead of a file bundle. Link extraction runs once and is shared by
the link/injection/seo families.
"""

from __future__ import annotations

import re
import zlib
from urllib.parse import urlparse, urlunparse

# --- link extraction ---
_MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^\s)]+|www\.[^\s)]+)\)")
_HTML_LINK = re.compile(
    r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)
_RAW_URL = re.compile(r"(?<![\"'\(\[])(https?://[^\s<>\"'\)\]]+|www\.[^\s<>\"'\)]+)")
_IMG_TAG = re.compile(
    r"<(img|source|iframe|link|script|video|audio)\b[^>]*"
    r'(?:src|href)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_MD_IMG = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")

_KNOWN_RESOURCE_EXT = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".ico",
    ".mp4",
    ".mp3",
    ".pdf",
)


def normalize_record(record: dict) -> dict:
    """Extract record metadata, tolerating missing fields."""
    messages = record.get("messages") or []
    norm_msgs = []
    for m in messages:
        role = str(m.get("role") or "").upper()
        content = m.get("content")
        if isinstance(content, list):  # some platforms use segmented content
            content = "\n".join(
                seg.get("text", "") if isinstance(seg, dict) else str(seg) for seg in content
            )
        norm_msgs.append({"role": role, "content": str(content or "")})
    return {
        "share_id": str(record.get("share_id") or record.get("unique_uid") or ""),
        "platform": str(record.get("platform") or "unknown"),
        "source_url": record.get("source_url"),
        "title": record.get("conversation_title"),
        "crawl_time": record.get("crawl_time"),
        "messages": norm_msgs,
        "attachment_info": record.get("attachment_info"),
    }


def build_full_text(messages: list[dict]) -> tuple[str, list[tuple[int, int, str]]]:
    """Join full text with per-message (start, end, role) offsets."""
    parts: list[str] = []
    offsets: list[tuple[int, int, str]] = []
    pos = 0
    for m in messages:
        text = m["content"]
        parts.append(text)
        offsets.append((pos, pos + len(text), m["role"]))
        pos += len(text) + 2  # "\n\n" separator
    return "\n\n".join(parts), offsets


def locate_message(offsets: list[tuple[int, int, str]], pos: int) -> tuple[int, str]:
    """Char offset -> (message_index, role). Linear scan is fine for message counts here."""
    for i, (s, e, role) in enumerate(offsets):
        if s <= pos <= e:
            return i, role
    if offsets:
        return len(offsets) - 1, offsets[-1][2]
    return 0, ""


def extract_links(full_text: str) -> list[dict]:
    """Extract Markdown/HTML/bare links and resource references (deduped, ordered).

    kind: link(markdown) | html_link | raw | resource(img/css/font/iframe...)
    """
    links: list[dict] = []
    seen: set[str] = set()

    def _add(url: str, anchor: str, kind: str, pos: int):
        url = url.strip().rstrip(".,;:!?）)】」\"'")
        parsed = urlparse(url if "://" in url else f"https://{url}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return
        host = parsed.hostname.lower()
        try:
            port = parsed.port
        except ValueError:
            return
        netloc = (
            host if port in (None, 80 if parsed.scheme == "http" else 443) else f"{host}:{port}"
        )
        url = urlunparse(
            (parsed.scheme.lower(), netloc, parsed.path or "", parsed.params, parsed.query, "")
        )
        if url in seen:
            return
        seen.add(url)
        links.append({"url": url, "anchor": anchor.strip()[:120], "kind": kind, "pos": pos})

    for m in _MD_LINK.finditer(full_text):
        _add(m.group(2), m.group(1), "link", m.start())
    for m in _HTML_LINK.finditer(full_text):
        _add(m.group(1), re.sub(r"<[^>]+>", "", m.group(2)), "html_link", m.start())
    for m in _IMG_TAG.finditer(full_text):
        _add(m.group(2), "", "resource", m.start())
    for m in _MD_IMG.finditer(full_text):
        _add(m.group(1), "", "resource", m.start())
    for m in _RAW_URL.finditer(full_text):
        _add(m.group(1), "", "raw", m.start())
    return links


def extract_attachments(record: dict) -> list[dict]:
    """Normalize attachment_info (structured on Grok/Qwen, may be missing elsewhere)."""
    info = record.get("attachment_info")
    out: list[dict] = []
    if isinstance(info, list):
        for a in info:
            if isinstance(a, dict):
                out.append(
                    {
                        "file_name": a.get("file_name") or a.get("fileName"),
                        "file_type": a.get("file_type")
                        or a.get("mime_type")
                        or a.get("fileMimeType"),
                        "uri": a.get("file_uri") or a.get("fileUri") or a.get("url"),
                    }
                )
    elif isinstance(info, dict):
        for k in ("files", "images", "attachments"):
            items = info.get(k)
            if isinstance(items, list):
                out.extend(x for x in items if isinstance(x, dict))
    return out


def text_stats(full_text: str) -> dict[str, object]:
    """Statistics surfaces for the DoS/abuse family."""
    if not full_text:
        return {"chars": 0, "compression_ratio": 1.0, "max_line_len": 0, "longest_repeat": 0}
    comp = len(zlib.compress(full_text.encode(), 6)) / max(1, len(full_text.encode()))
    max_line = max((len(ln) for ln in full_text.splitlines()), default=0)
    # longest repeated prefix (sampled stepping to avoid O(n^2) blowup)
    longest_repeat = 0
    step = max(200, len(full_text) // 200)
    for size in range(step, min(len(full_text), 200_000) + 1, step):
        probe = full_text[:size]
        half = len(probe) // 2
        if probe[:half] == probe[half : half * 2] and half > 0:
            longest_repeat = max(longest_repeat, half * 2)
    return {
        "chars": len(full_text),
        "compression_ratio": round(comp, 4),
        "max_line_len": max_line,
        "longest_repeat": longest_repeat,
    }


def domain_of(url: str) -> str:
    """Return a normalized HTTP(S) hostname, or an empty string for invalid URLs."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower() if parsed.scheme in {"http", "https"} else ""


# --- image-reference extraction (B-CI-1 steganography family) ---
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico")
DATA_URI_RE = re.compile(r"data:image/[a-z+.-]+;base64,[A-Za-z0-9+/=]{16,}", re.IGNORECASE)


def is_image_url(url: str) -> bool:
    """Extension-based image heuristic on the URL path."""
    path = urlparse(url if "://" in url else f"https://{url}").path.lower()
    return path.endswith(IMAGE_EXTS)


def _iter_message_dicts(record: dict):
    """Yield (index, message_dict) across both tolerated layouts:
    top-level messages[] and content.messages[] (raw cleaned-dataset shape)."""
    seen = 0
    for container in (record.get("messages"), (record.get("content") or {}).get("messages")):
        if isinstance(container, list):
            for m in container:
                if isinstance(m, dict):
                    yield seen, m
                    seen += 1


def iter_structured_image_refs(record: dict) -> list[dict]:
    """Image URLs / data-URIs from STRUCTURED message fields (extra / fragments /
    platform_extra), i.e. imagery the assistant pipeline carried into the answer
    (source bars, tweet cards, doc-preview panes). Content text is NOT walked here.

    Returns [{value, kind(url|data_uri), path, message_index, role}] deduped per record.
    """
    refs: list[dict] = []
    seen: set[str] = set()

    def _walk(obj, path: str, msg_idx: int, role: str):
        if isinstance(obj, dict):
            for k, v in obj.items():
                # NB: do NOT prune nested 'content' keys — Qwen doc-preview image URLs
                # live under fragments[].meta_data.multi_load.content.subcard_msg...
                _walk(v, f"{path}.{k}", msg_idx, role)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]", msg_idx, role)
        elif isinstance(obj, str) and len(obj) < 4096:
            if DATA_URI_RE.fullmatch(obj.strip()):
                val = obj.strip()
                if val not in seen:
                    seen.add(val)
                    refs.append(
                        {"value": val, "kind": "data_uri", "path": path, "message_index": msg_idx, "role": role}
                    )
            elif obj.startswith(("http://", "https://")) and is_image_url(obj):
                if obj not in seen:
                    seen.add(obj)
                    refs.append(
                        {"value": obj, "kind": "url", "path": path, "message_index": msg_idx, "role": role}
                    )

    for idx, m in _iter_message_dicts(record):
        role = str(m.get("role") or "").upper()
        for key in ("extra", "fragments", "platform_extra"):
            sub = m.get(key)
            if sub is not None:
                _walk(sub, f"messages[{idx}].{key}", idx, role)
    return refs
