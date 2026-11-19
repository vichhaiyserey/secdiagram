"""Offline, self-contained Studio single-page application assets.

The UI ships as plain HTML/CSS/JS so it can be served byte-for-byte from the
standard library server on air-gapped machines.  No CDN, npm build, or React
runtime is required; the installer still models a user-level venv workflow.
"""

from __future__ import annotations

from pathlib import Path

_ASSET_DIR = Path(__file__).with_name("studio_ui")
_CONTENT_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
}


class StudioAssetError(RuntimeError):
    """Raised when a requested Studio asset is unknown or missing."""


def render_studio_html() -> str:
    """Return the Studio shell HTML."""
    return read_asset("index.html")[1]


def read_asset(name: str) -> tuple[str, str]:
    """Return ``(content_type, content)`` for a known Studio asset."""
    if name not in _CONTENT_TYPES:
        raise StudioAssetError(f"unknown Studio asset: {name!r}")
    path = _ASSET_DIR / name
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StudioAssetError(f"cannot read Studio asset {name!r}: {exc}") from exc
    return _CONTENT_TYPES[name], content


__all__ = ["StudioAssetError", "read_asset", "render_studio_html"]
