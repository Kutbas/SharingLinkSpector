"""LLM provider presets: dmxapi (OpenAI-compatible) / ollama (private deployment).

Both go through the openai SDK's compatible endpoint (ollama exposes an
OpenAI-compatible /v1 API). Configuration comes from .env / environment
variables with CLI overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:  # minimal .env parsing (no python-dotenv dependency)
    _env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    if _env_file.exists():
        for _line in _env_file.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())
except Exception:  # noqa: BLE001
    pass


@dataclass(slots=True)
class ProviderConfig:
    name: str
    base_url: str
    api_key: str
    model: str
    timeout: float = 120.0
    concurrency: int = 4


_PRESETS = {
    "dmxapi": lambda: ProviderConfig(
        name="dmxapi",
        base_url=os.environ.get("DMXAPI_BASE_URL", "https://www.dmxapi.cn/v1"),
        api_key=os.environ.get("DMXAPI_API_KEY", ""),
        model=os.environ.get("DMXAPI_MODEL", "glm-5.2"),
        timeout=float(os.environ.get("SLSPECTOR_LLM_TIMEOUT", "120")),
        concurrency=int(os.environ.get("SLSPECTOR_LLM_CONCURRENCY", "4")),
    ),
    "ollama": lambda: ProviderConfig(
        name="ollama",
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
        model=os.environ.get("OLLAMA_MODEL", "qwen3:32b"),
        timeout=float(os.environ.get("SLSPECTOR_LLM_TIMEOUT", "300")),
        concurrency=int(os.environ.get("SLSPECTOR_LLM_CONCURRENCY", "2")),
    ),
}


def resolve_provider(name: str | None = None,
                     model_override: str | None = None) -> ProviderConfig | None:
    """Resolve provider config; returns None when unset/keyless (static-only mode)."""
    pname = (name or os.environ.get("SLSPECTOR_PROVIDER") or "").strip().lower()
    if pname in ("", "none"):
        return None
    factory = _PRESETS.get(pname)
    if factory is None:
        raise ValueError(f"unknown provider: {pname} (expected one of {'/'.join(_PRESETS)})")
    cfg = factory()
    if not cfg.api_key:
        return None
    if model_override:
        cfg.model = model_override
    return cfg


def make_client(cfg: ProviderConfig):
    from openai import OpenAI

    return OpenAI(base_url=cfg.base_url, api_key=cfg.api_key, timeout=cfg.timeout)
