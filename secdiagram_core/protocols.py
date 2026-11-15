"""Formal extension protocols and service provider interfaces (SPI) for secdiagram.

Allows third-party, private, and commercial extensions to plug custom language
indexers, security rule providers, and report exporters into secdiagram without
modifying or forking the core open-source engine.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .model import Finding, Graph


@runtime_checkable
class LanguageIndexer(Protocol):
    """Protocol for language source indexers that populate definitions and calls."""

    @property
    def name(self) -> str:
        """Unique identifier of the language indexer (e.g. 'python', 'go', 'rust')."""
        ...

    @property
    def supported_suffixes(self) -> tuple[str, ...]:
        """File extensions handled by this indexer (e.g. ('.go',))."""
        ...

    def index_repo(self, root: Path, rel_files: list[str], graph: Graph) -> None:
        """Inspect discovered files and append nodes/edges to the semantic graph."""
        ...


@runtime_checkable
class SecurityRuleProvider(Protocol):
    """Protocol for pluggable SAST heuristics, compliance checks, and taint rules."""

    @property
    def name(self) -> str:
        """Unique identifier of the security rule provider."""
        ...

    def analyze(self, graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
        """Evaluate graph nodes, edges, or source files and return security findings."""
        ...


@runtime_checkable
class ReportExporter(Protocol):
    """Protocol for custom diagram, document, or machine-readable format exporters."""

    @property
    def name(self) -> str:
        """Format name (e.g. 'miro', 'confluence', 'd2', 'plantuml')."""
        ...

    def export(self, graph: Graph, out_dir: Path, **kwargs: Any) -> Path | list[Path]:
        """Serialize the graph and write output files to out_dir."""
        ...


# ------------------------------------------------------------------- Thread-Safe Registries

_REGISTRY_LOCK = threading.Lock()
_INDEXERS: dict[str, LanguageIndexer] = {}
_SECURITY_PROVIDERS: dict[str, SecurityRuleProvider] = {}
_EXPORTERS: dict[str, ReportExporter] = {}


def register_indexer(indexer: LanguageIndexer) -> None:
    """Register a custom language indexer plugin."""
    with _REGISTRY_LOCK:
        _INDEXERS[indexer.name.lower()] = indexer


def unregister_indexer(name: str) -> None:
    """Unregister a language indexer plugin by name."""
    with _REGISTRY_LOCK:
        _INDEXERS.pop(name.lower(), None)


def get_registered_indexers() -> list[LanguageIndexer]:
    """Return all registered custom language indexers."""
    with _REGISTRY_LOCK:
        return list(_INDEXERS.values())


def register_security_provider(provider: SecurityRuleProvider) -> None:
    """Register a custom security rule or compliance provider."""
    with _REGISTRY_LOCK:
        _SECURITY_PROVIDERS[provider.name.lower()] = provider


def unregister_security_provider(name: str) -> None:
    """Unregister a security provider by name."""
    with _REGISTRY_LOCK:
        _SECURITY_PROVIDERS.pop(name.lower(), None)


def get_registered_security_providers() -> list[SecurityRuleProvider]:
    """Return all registered custom security providers."""
    with _REGISTRY_LOCK:
        return list(_SECURITY_PROVIDERS.values())


def register_exporter(exporter: ReportExporter) -> None:
    """Register a custom report or diagram exporter."""
    with _REGISTRY_LOCK:
        _EXPORTERS[exporter.name.lower()] = exporter


def unregister_exporter(name: str) -> None:
    """Unregister a report exporter by name."""
    with _REGISTRY_LOCK:
        _EXPORTERS.pop(name.lower(), None)


def get_registered_exporters() -> dict[str, ReportExporter]:
    """Return a mapping of format names to registered exporters."""
    with _REGISTRY_LOCK:
        return dict(_EXPORTERS)


def reset_registries() -> None:
    """Clear all registered extension providers (primarily for unit tests)."""
    with _REGISTRY_LOCK:
        _INDEXERS.clear()
        _SECURITY_PROVIDERS.clear()
        _EXPORTERS.clear()
