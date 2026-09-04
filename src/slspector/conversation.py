"""对话记录归一化：统一 schema JSONL → 分析面（全文/偏移/链接/附件/统计）。

对应 SkillSpector 的 build_context，但产物是对话文本面而非文件包。
链接提取一次，供 link/injection/seo 等 family 共用。
"""

from __future__ import annotations

import re
import zlib
from urllib.parse import urlparse

# --- 链接提取 ---
_MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^\s)]+|www\.[^\s)]+)\)")
_HTML_LINK = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_RAW_URL = re.compile(r"(?<![\"'\(\[])(https?://[^\s<>\"'\)\]]+|www\.[^\s<>\"'\)]+)")
_IMG_TAG = re.compile(
    r'<(img|source|iframe|link|script|video|audio)\b[^>]*'
    r'(?:src|href)=["\']([^"\']+)["\']', re.IGNORECASE)
_MD_IMG = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")

_KNOWN_RESOURCE_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".woff",
    ".woff2", ".ttf", ".eot", ".ico", ".mp4", ".mp3", ".pdf",
)


def normalize_record(record: dict) -> dict:
    """提取记录元信息，容忍字段缺失。"""
    messages = record.get("messages") or []
    norm_msgs = []
    for m in messages:
        role = str(m.get("role") or "").upper()
        content = m.get("content")
        if isinstance(content, list):  # 有些平台 content 是分段
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
    """拼接全文与每条消息的 (start, end, role) 偏移。"""
    parts: list[str] = []
    offsets: list[tuple[int, int, str]] = []
    pos = 0
    for m in messages:
        text = m["content"]
        parts.append(text)
        offsets.append((pos, pos + len(text), m["role"]))
        pos += len(text) + 2  # "\n\n" 分隔
    return "\n\n".join(parts), offsets


def locate_message(offsets: list[tuple[int, int, str]], pos: int) -> tuple[int, str]:
    """字符偏移 → (message_index, role)。二分即可，但消息数小，线性够用。"""
    for i, (s, e, role) in enumerate(offsets):
        if s <= pos <= e:
            return i, role
    if offsets:
        return len(offsets) - 1, offsets[-1][2]
    return 0, ""


def extract_links(full_text: str) -> list[dict]:
    """提取 Markdown/HTML/裸链接与资源引用（去重保序）。

    kind: link(markdown) | html_link | raw | resource(img/css/font/iframe...)
    """
    links: list[dict] = []
    seen: set[str] = set()

    def _add(url: str, anchor: str, kind: str, pos: int):
        url = url.strip().rstrip(".,;:!?）)】」\"'")
        if not url or url in seen:
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
    """归一化 attachment_info（Grok/Qwen 有结构，其他平台可能缺失）。"""
    info = record.get("attachment_info")
    out: list[dict] = []
    if isinstance(info, list):
        for a in info:
            if isinstance(a, dict):
                out.append(
                    {
                        "file_name": a.get("file_name") or a.get("fileName"),
                        "file_type": a.get("file_type") or a.get("mime_type")
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
    """DoS/资源滥用 family 用的统计面。"""
    if not full_text:
        return {"chars": 0, "compression_ratio": 1.0, "max_line_len": 0, "longest_repeat": 0}
    comp = len(zlib.compress(full_text.encode(), 6)) / max(1, len(full_text.encode()))
    max_line = max((len(ln) for ln in full_text.splitlines()), default=0)
    # 最长重复子串（采样：步长窗口，避免 O(n²) 爆炸）
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
    try:
        netloc = urlparse(url if "://" in url else f"https://{url}").netloc.lower()
        return netloc.split("@")[-1].split(":")[0]
    except Exception:
        return ""
