"""Static stego-imagery family: B-CI-1 (hidden instructions in shared imagery).

Scope note (2026-09-06 dataset verification): pixel payloads of *shared-page
rendered* images are out of reach, but conversations carry image references the
assistant pipeline touched (search source-bar images, tweet-card avatars,
doc-preview pages) plus rare inline data-URIs. Those form the detectable
sub-surface for B-CI-1 retrieval-side poisoning (attacker contaminates a public
source, e.g. a wiki image; the联网 assistant carries it; the share link spreads it).

Patterns:
- CI1-1 image-reference candidates (structured extra/fragments refs; content-layer
  image URLs by role; inline data-URIs) — always needs_review
- CI1-2 deterministic forensic screening (microtext signal / ELA / OCR probe)
  on decodable pixels: inline data-URIs directly, URL mirrors via
  SLSPECTOR_IMAGE_DIR/<sha1(url)>.* — never fetches the network itself
"""

from __future__ import annotations

import base64
import hashlib
import os

from slspector import conversation, stego
from slspector.models import Finding
from slspector.nodes.analyzers.common import make_finding, make_record_finding
from slspector.state import AnalyzerNodeResponse, SlspectorState

ANALYZER_ID = "static_stego_imagery"

# confidence by evidence tier (all candidates; human review decides)
_CONF_STRUCTURED = 0.5  # assistant-pipeline structured reference (strongest)
_CONF_CONTENT_ASSISTANT = 0.4  # image URL in assistant text
_CONF_CONTENT_USER = 0.35  # image URL in user text
_CONF_FORENSIC = 0.65  # deterministic forensic signal on pixels

_MIRROR_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp")


def _mirror_path(url: str) -> str | None:
    """Local mirror file for a URL, if SLSPECTOR_IMAGE_DIR is configured."""
    d = os.environ.get("SLSPECTOR_IMAGE_DIR")
    if not d or not os.path.isdir(d):
        return None
    digest = hashlib.sha1(url.encode()).hexdigest()
    for ext in _MIRROR_EXTS:
        p = os.path.join(d, digest + ext)
        if os.path.exists(p):
            return p
    return None


def _decode_data_uri(uri: str) -> bytes | None:
    try:
        b64 = uri.split(",", 1)[1]
        return base64.b64decode(b64, validate=False)
    except Exception:  # noqa: BLE001
        return None


def analyze(state: SlspectorState) -> list[Finding]:
    findings: list[Finding] = []
    record = state["record"]

    # --- CI1-1a: structured image refs (assistant pipeline imagery) ---
    for ref in conversation.iter_structured_image_refs(record):
        is_data_uri = ref["kind"] == "data_uri"
        conf = _CONF_STRUCTURED
        message = "Structured image reference in assistant answer pipeline"
        if is_data_uri:
            message = "Inline data-URI image embedded in message structure"
        findings.append(
            make_record_finding(
                taxonomy_id="B-CI-1",
                pattern_id="CI1-1",
                confidence=conf,
                message=message,
                needs_review=True,
                matched_text=ref["value"][:120],
                evidence={
                    "ref_kind": ref["kind"],
                    "field_path": ref["path"],
                    "message_index": ref["message_index"],
                    "ref_role": ref["role"],
                },
            )
        )
        # --- CI1-2 for structured refs: decode data-URIs directly ---
        if is_data_uri and stego.available():
            img = stego.load_image(_decode_data_uri(ref["value"]) or b"")
            if img is not None:
                report = stego.forensic_report(img)
                if report.get("verdict"):
                    findings.append(_forensic_finding(ref["value"], report, state))

    # --- CI1-1b: content-layer image URLs by role ---
    for link in state.get("links") or []:
        url = str(link.get("url") or "")
        if not conversation.is_image_url(url):
            continue
        _idx, role = _locate(state, int(link.get("pos") or 0))
        conf = _CONF_CONTENT_ASSISTANT if role == "ASSISTANT" else _CONF_CONTENT_USER
        findings.append(
            make_finding(
                taxonomy_id="B-CI-1",
                pattern_id="CI1-1",
                confidence=conf,
                message=f"Image URL referenced in {role or 'unknown'} message content",
                state=state,
                pos=int(link.get("pos") or 0),
                matched_text=url[:200],
                needs_review=True,
                evidence={"ref_kind": "url", "content_role": role, "link_kind": link.get("kind")},
            )
        )
        # --- CI1-2 for URL refs: forensic screen on local mirror only ---
        mirror = _mirror_path(url)
        if mirror and stego.available():
            try:
                with open(mirror, "rb") as fh:
                    img = stego.load_image(fh.read())
            except OSError:
                img = None
            if img is not None:
                report = stego.forensic_report(img)
                if report.get("verdict"):
                    findings.append(_forensic_finding(url, report, state))

    # --- CI1-1c: data-URIs in raw content text (any role) ---
    for m in conversation.DATA_URI_RE.finditer(state.get("full_text") or ""):
        uri = m.group(0)
        findings.append(
            make_finding(
                taxonomy_id="B-CI-1",
                pattern_id="CI1-1",
                confidence=_CONF_STRUCTURED,
                message="Inline data-URI image in message content",
                state=state,
                pos=m.start(),
                matched_text=uri[:80],
                needs_review=True,
                evidence={"ref_kind": "data_uri"},
            )
        )
        if stego.available():
            img = stego.load_image(_decode_data_uri(uri) or b"")
            if img is not None:
                report = stego.forensic_report(img)
                if report.get("verdict"):
                    findings.append(_forensic_finding(uri, report, state))

    return findings


def _forensic_finding(ref: str, report: dict, state: SlspectorState) -> Finding:
    return make_record_finding(
        taxonomy_id="B-CI-1",
        pattern_id="CI1-2",
        confidence=_CONF_FORENSIC,
        message="; ".join(report.get("reasons") or ["forensic anomaly"]),
        needs_review=True,
        matched_text=ref[:120],
        evidence={"forensics": report},
    )


def _locate(state: SlspectorState, pos: int) -> tuple[int, str]:
    from slspector.conversation import locate_message

    return locate_message(state["message_offsets"], pos)


def node(state: SlspectorState) -> AnalyzerNodeResponse:
    return {"findings": analyze(state)}
