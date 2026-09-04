"""LLM provider 预设：dmxapi（OpenAI 兼容）/ ollama（私有部署）。

均通过 openai SDK 的 OpenAICompatible 接入（ollama 暴露 /v1 OpenAI 兼容端点），
配置来自 .env / 环境变量，支持 CLI 覆盖。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:  # .env 极简解析（无 python-dotenv 依赖）
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
    """解析 provider 配置；无 key 或未配置返回 None（静态-only 模式）。"""
    pname = (name or os.environ.get("SLSPECTOR_PROVIDER") or "").strip().lower()
    if pname in ("", "none"):
        return None
    factory = _PRESETS.get(pname)
    if factory is None:
        raise ValueError(f"未知 provider: {pname}（可选: {'/'.join(_PRESETS)}）")
    cfg = factory()
    if not cfg.api_key:
        return None
    if model_override:
        cfg.model = model_override
    return cfg


def make_client(cfg: ProviderConfig):
    from openai import OpenAI

    return OpenAI(base_url=cfg.base_url, api_key=cfg.api_key, timeout=cfg.timeout)
