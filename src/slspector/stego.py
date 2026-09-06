"""Deterministic image forensics for B-CI-1 (steganography / hidden-instruction screening).

Not an LLM task: classic signal-analysis screening that flags candidates for
human review. Calibrated 2026-09-06 on synthetic fixtures:

- near-background + gradient-structure ratio ("microtext signal") separates
  low-contrast hidden text (struct >= 0.12) from flat logos (0.0) and natural
  photos (low near-bg coverage), e.g. 0.21-0.22 on white/near-white microtext.
- ELA (error-level analysis) flags edited/re-composited JPEG regions; it does
  NOT detect native low-contrast microtext (flat areas re-compress losslessly)
  and is reported as tamper context only.
- LSB pair-balance is reported but not verdict-driving: natural smooth
  histograms can be near-balanced at baseline (false-negative prone).

Optional: pytesseract OCR on contrast-stretched crops upgrades confidence when
injection-style command text is recognized. Missing tesseract degrades
gracefully.
"""

from __future__ import annotations

import io
import re
from typing import Any

try:  # optional heavy deps: analyzer degrades to URL-candidates only when absent
    import numpy as np
    from PIL import Image, ImageOps

    _IMAGING_OK = True
except ImportError:  # pragma: no cover - exercised only without pillow/numpy
    _IMAGING_OK = False

try:
    import pytesseract  # type: ignore

    _OCR_OK = True
except ImportError:  # pragma: no cover
    _OCR_OK = False

# thresholds (calibrated on synthetic fixtures, see module docstring)
NEAR_BG_RATIO_MIN = 0.5  # share of pixels within NEAR_BG_DELTA of background
NEAR_BG_DELTA = 10.0
MICROTEXT_STRUCT_MIN = 0.12  # gradient-structure share inside near-bg region
ELA_P99_TAMPER = 25.0  # strong re-compression inconsistency (edited region)
MIN_EDGE = 16  # below this, metrics are unstable -> report-only

_OCR_COMMAND_WORDS = re.compile(
    r"(?i)\b(ignore|disregard|instruction|password|secret|token|api[_ ]?key|"
    r"send|upload|exfiltrat\w*|visit|download|execute|run)\b|忽略|指令|密码|上传|访问|执行"
)


def available() -> bool:
    return _IMAGING_OK


def load_image(data: bytes) -> Any:
    """Decode image bytes; SVG (vector) returns None (no pixel grid to analyze)."""
    if not _IMAGING_OK:
        return None
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        if img.format == "SVG" or data[:512].lstrip().startswith((b"<?xml", b"<svg")):
            return None
        return img
    except Exception:  # noqa: BLE001
        return None


def _ela_metrics(img: Any) -> dict[str, float]:
    orig = np.asarray(img.convert("RGB"), dtype=np.float32)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=92)
    reenc = np.asarray(Image.open(buf), dtype=np.float32)
    diff = np.abs(orig - reenc).mean(axis=2)
    return {"ela_p99": round(float(np.percentile(diff, 99)), 2), "ela_max": round(float(diff.max()), 2)}


def _near_bg_metrics(img: Any) -> dict[str, float]:
    gray = np.asarray(img.convert("L"), dtype=np.float32)
    bg = float(np.percentile(gray, 90))
    near = np.abs(gray - bg) < NEAR_BG_DELTA
    gx = np.abs(np.diff(gray, axis=1)) > 0.5
    struct = near[:, 1:] & gx
    return {
        "near_bg_ratio": round(float(near.mean()), 4),
        "near_bg_struct": round(float(struct.mean()), 4),
    }


def _lsb_balance(img: Any) -> dict[str, float]:
    """Pair-of-values balance on the R channel raster (report-only signal)."""
    r = np.asarray(img.convert("RGB"))[:, :, 0].ravel()
    cats = r >> 1
    a = np.bincount(cats[::2]).astype(float)
    b = np.bincount(cats[1::2]).astype(float)
    n = min(len(a), len(b))
    a, b = a[:n], b[:n]
    mask = (a + b) >= 8
    if int(mask.sum()) < 8:
        return {"lsb_pairs": 0}
    a, b = a[mask], b[mask]
    expected = (a + b) / 2.0
    chi2 = ((a - expected) ** 2 + (b - expected) ** 2) / expected
    k = len(a)
    return {
        "lsb_pairs": int(k),
        "lsb_chi_mean": round(float(chi2.mean()), 3),
        "lsb_balance_z": round(float((chi2.sum() - k) / ((2 * k) ** 0.5)), 2),
    }


def _ocr_probe(img: Any) -> str | None:
    """Contrast-stretched OCR; returns matched command-like text if any."""
    if not _OCR_OK:
        return None
    try:
        stretched = ImageOps.autocontrast(img.convert("L")).resize(
            (img.width * 3, img.height * 3)
        )
        text = pytesseract.image_to_string(stretched)
    except Exception:  # noqa: BLE001
        return None
    hit = _OCR_COMMAND_WORDS.search(text)
    return hit.group(0) if hit else None


def forensic_report(img: Any) -> dict[str, Any]:
    """Full deterministic screening report for one decoded image."""
    if not _IMAGING_OK or img is None:
        return {"error": "imaging-unavailable"}
    w, h = img.size
    report: dict[str, Any] = {
        "format": img.format,
        "width": w,
        "height": h,
        "low_resolution": min(w, h) < MIN_EDGE,
    }
    report.update(_near_bg_metrics(img))
    if min(w, h) >= MIN_EDGE:
        report.update(_ela_metrics(img))
        report.update(_lsb_balance(img))
    ocr = _ocr_probe(img)
    if ocr:
        report["ocr_command_word"] = ocr
    report["verdict"], report["reasons"] = _verdict(report)
    return report


def _verdict(report: dict[str, Any]) -> tuple[bool, list[str]]:
    """Screening verdict: candidate for human review (never auto-conviction)."""
    reasons: list[str] = []
    if report.get("near_bg_ratio", 0) >= NEAR_BG_RATIO_MIN and report.get(
        "near_bg_struct", 0
    ) >= MICROTEXT_STRUCT_MIN:
        reasons.append("low-contrast structured text layer (microtext signal)")
    if report.get("ocr_command_word"):
        reasons.append(f"OCR command word after stretch: {report['ocr_command_word']}")
    if report.get("ela_p99", 0) >= ELA_P99_TAMPER:
        reasons.append("ELA tamper inconsistency")
    return (bool(reasons), reasons)
