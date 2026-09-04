"""build_context: raw record -> analysis surfaces (full text / offsets / links /
attachments / stats / normalized messages for chunking)."""

from __future__ import annotations

from slspector import conversation
from slspector.state import SlspectorState


def build_context(state: SlspectorState) -> dict:
    record = state["record"]
    norm = conversation.normalize_record(record)
    full_text, offsets = conversation.build_full_text(norm["messages"])
    links = conversation.extract_links(full_text)
    attachments = conversation.extract_attachments(record)
    stats = conversation.text_stats(full_text)
    return {
        "meta": {
            "share_id": norm["share_id"],
            "platform": norm["platform"],
            "source_url": norm["source_url"],
            "title": norm["title"],
            "crawl_time": norm["crawl_time"],
        },
        "messages": norm["messages"],
        "full_text": full_text,
        "message_offsets": offsets,
        "links": links,
        "attachments": attachments,
        "text_stats": stats,
    }
