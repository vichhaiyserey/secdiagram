# 🐍 Python Public Facade & Developer API Guide

Downstream tools, automated DevSecOps pipelines, and custom Python scripts can interact directly with `secdiagram` via its stable public API facade.

---

## 1. Stable Public Facade (`secdiagram_core`)

All primary capabilities are exported directly at the top level of `secdiagram_core`:

```python
from secdiagram_core import (
    analyze,
    render_mermaid,
    AnalysisConfig,
    AnalysisResult,
)

# Configure analysis options:
config = AnalysisConfig(
    root=".",
    security=True,
    min_confidence=0.5,
)

# Run full analysis:
result = analyze(config)
```

> [!NOTE]
> For backward compatibility, legacy imports from `secdiagram_core.analyzer` (`AnalysisConfig`, `run_analysis`) and `secdiagram_core.high_level` (`build_high_level_architecture`, `render_mermaid_highlevel`) remain fully supported via internal re-exports and module shims.

---

## 2. Native Taint & Reachability Query API

`AnalysisResult` provides high-performance query helpers to eliminate manual loops over raw nodes and findings when triaging alerts or integrating with SAST/SCA tools:

### Taint Inspection
```python
# Check if a specific file or exact line contains active tainted dataflow:
if result.has_taint_at("app/controllers/orders.py", line=42):
    print("File and line are on a tainted source-to-sink path!")

# Retrieve the full trace objects for the target line:
traces = result.get_taint_traces("app/controllers/orders.py", line=42)
for trace in traces:
    print(f"Source: {trace.source} -> Sink: {trace.sink}")
    for hop in trace.path:
        print(f"  Hop: {hop}")
```

### Entrypoint Reachability Inspection
```python
# Check if a file or symbol is reachable from any exposed public entrypoint:
if not result.is_reachable("app/utils/legacy_crypto.py", symbol="decrypt_token"):
    print("Function is dead code / unreachable from any API controller or CLI entrypoint.")
```

### SCA Package Reachability Bridge
```python
# Query whether a third-party dependency is reachable from external inputs:
if result.is_package_reachable("pyyaml"):
    print("Vulnerable package is reachable from an exposed entrypoint!")
else:
    print("Package is imported only in dead/internal paths: P3_JUSTIFIED.")

# Inspect the complete reachability summary across all detected packages:
for pkg, summary in result.dependency_usage.items():
    print(f"{pkg}: reachable={summary.is_reachable}, imports={summary.import_count}, sinks={summary.sinks_invoked}")
```

---

## 3. Serialization & Caching (`to_dict` / `from_dict` / `to_json` / `from_json`)

Persist and restore entire analysis results between pipeline stages without re-running AST parsing:

```python
# Export result to disk as deterministic JSON:
result.to_json(".secdiagram/analysis_cache.json")

# In a later process or downstream CLI:
cached_result = AnalysisResult.from_json(".secdiagram/analysis_cache.json")

# Full query API functions identically on deserialized results:
assert cached_result.has_taint_at("app/controllers/orders.py", line=42)
```

---

## 4. Pluggable Framework, Sanitizer & Sink Registry

Register custom internal frameworks, proprietary authentication decorators, sanitizers, or database sinks before executing analysis:

```python
from secdiagram_core.frameworks import (
    register_framework,
    register_sanitizer,
    register_sink,
)

# Register custom microservice conventions:
register_framework(
    name="internal-microservice",
    entrypoint_decorators=["@route", "@rpc_handler", "@aba_authorized"],
    sanitizers=["escape_sql", "sanitize_input"],
    sinks=["internal_db_execute", "vault_secret_query"],
)

# Register individual sanitizers or sinks:
register_sanitizer("custom_safe_serializer")
register_sink("dispatch_system_worker")
```

---

## 5. Rendering Diagrams Programmatically

Generate Mermaid syntax directly in Python:

```python
# Render standard detailed architecture flowchart:
mermaid_text = render_mermaid(result.graph)

# Render high-level C4 tier diagram:
from secdiagram_core.high_level import build_high_level_architecture, render_mermaid_highlevel

high_level_arch = build_high_level_architecture(result.graph, repo_dir=".")
c4_mermaid_text = render_mermaid_highlevel(high_level_arch)
```

---

## 6. Pluggable Extension SPI (Custom Languages, Rules & Exporters)

Extend `secdiagram` privately, commercially, or internally without forking or modifying the core open-source engine.

### A. Custom Language Indexers (`LanguageIndexer`)
Index additional languages (e.g. Kotlin or COBOL) and attach their definitions,
endpoints, and calls to the unified graph. Go and [Rust](RUST_SUPPORT.md) already
have built-in lexical indexers.

```python
from pathlib import Path
from secdiagram_core import Graph, Node, register_indexer

class KotlinLanguageIndexer:
    @property
    def name(self) -> str:
        return "kotlin"

    @property
    def supported_suffixes(self) -> tuple[str, ...]:
        return (".kt",)

    def index_repo(self, root: Path, rel_files: list[str], graph: Graph) -> None:
        for rel in rel_files:
            if rel.endswith(".kt"):
                # Add a module observation; a real indexer would parse definitions.
                from secdiagram_core.model import stable_id
                node = Node(id=stable_id("kotlin", rel), kind="module", name=rel, qualname=rel, path=rel)
                graph.add_node(node)

# Register before running analysis:
register_indexer(KotlinLanguageIndexer())
```

### B. Custom Security Rule Providers (`SecurityRuleProvider`)
Enforce internal enterprise policies, proprietary compliance checks, or custom taint sinks:

```python
from pathlib import Path
from secdiagram_core import Finding, Graph, Loc, register_security_provider

class EnterprisePciRuleProvider:
    @property
    def name(self) -> str:
        return "pci-dss-custom"

    def analyze(self, graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
        findings = []
        for node in graph.nodes.values():
            if "card_number" in node.name.lower():
                findings.append(Finding(
                    id="PCI-001",
                    category="compliance",
                    severity="high",
                    title="PCI Cardholder Data In Cleartext",
                    message=f"Node `{node.name}` references unencrypted cardholder data.",
                    evidence=[Loc(node.path, node.line)] if node.path else [],
                    recommendation="Encrypt or tokenize primary account numbers.",
                ))
        return findings

# Register before analysis:
register_security_provider(EnterprisePciRuleProvider())
```

**Finding ids and failures.** Built-in findings are deduplicated by `id`. If a
provider reuses one rule id for several distinct findings (as above), each
finding after the first gets a deterministic id derived with `stable_id()`, and
the original id is kept in `finding.metadata["rule_id"]`. Nothing is dropped.
For stable ids that you control, derive them yourself, e.g.
`stable_id("PCI-001", node.id)`.

If an indexer, security provider, or exporter raises, the error is recorded in
`graph.meta["plugin_errors"]`, a failed indexer's partial graph changes are
rolled back, the CLI prints a warning, and it exits `1` (or `2` if
`--fail-on` is triggered), so a crashed rule never looks like a clean scan.

### C. Custom Report & Diagram Exporters (`ReportExporter`)
Render the graph into custom enterprise formats (e.g. Miro, Confluence, D2, draw.io, or proprietary dashboards):

```python
from pathlib import Path
from secdiagram_core import Graph, register_exporter

class ConfluenceDocExporter:
    @property
    def name(self) -> str:
        return "confluence"

    def export(self, graph: Graph, out_dir: Path, **kwargs) -> Path:
        out_file = out_dir / "confluence_page.xml"
        out_file.write_text(f"<page><title>Architecture</title><body>Nodes: {len(graph.nodes)}</body></page>")
        return out_file

# Register exporter:
register_exporter(ConfluenceDocExporter())

# Plugins are registered in-process; the standalone `secdiagram` command does
# not auto-discover them. Call the CLI from the same process to use the format:
from secdiagram_core.cli import main
main(["--dir", ".", "--format", "confluence"])
```
