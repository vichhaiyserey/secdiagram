"""Unit tests for the secdiagram SPI protocols and extension registries."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from secdiagram_core import (
    AnalysisConfig,
    Finding,
    Graph,
    LanguageIndexer,
    Loc,
    Node,
    ReportExporter,
    SecurityRuleProvider,
    get_registered_exporters,
    get_registered_indexers,
    get_registered_security_providers,
    register_exporter,
    register_indexer,
    register_security_provider,
    reset_registries,
    run_analysis,
    unregister_exporter,
    unregister_indexer,
    unregister_security_provider,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class MockCustomIndexer:
    @property
    def name(self) -> str:
        return "custom-lang"

    @property
    def supported_suffixes(self) -> tuple[str, ...]:
        return (".custom",)

    def index_repo(self, root: Path, rel_files: list[str], graph: Graph) -> None:
        custom_node = Node(
            id="custom:sample_service",
            kind="service",
            name="custom_service",
            qualname="custom.pkg.service",
            path="custom/service.custom",
            line=10,
        )
        graph.add_node(custom_node)


class MockCustomRuleProvider:
    @property
    def name(self) -> str:
        return "custom-policy"

    def analyze(self, graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
        return [
            Finding(
                id="CUSTOM-RULE-001",
                category="compliance",
                severity="medium",
                title="Custom Policy Finding",
                message="Violates custom enterprise rule at custom/service.custom:10.",
                evidence=[Loc("custom/service.custom", 10)],
                recommendation="Follow internal security policy.",
            )
        ]


class MockCustomExporter:
    @property
    def name(self) -> str:
        return "custom-doc"

    def export(self, graph: Graph, out_dir: Path, **kwargs: Any) -> Path:
        out_file = out_dir / "custom-output.txt"
        out_file.write_text(f"Custom graph export with {len(graph.nodes)} nodes.\n", encoding="utf-8")
        return out_file


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_registries()

    def tearDown(self) -> None:
        reset_registries()

    def test_protocol_type_checking(self) -> None:
        """Verify that mock implementations conform to the runtime-checkable Protocols."""
        indexer = MockCustomIndexer()
        self.assertIsInstance(indexer, LanguageIndexer)

        provider = MockCustomRuleProvider()
        self.assertIsInstance(provider, SecurityRuleProvider)

        exporter = MockCustomExporter()
        self.assertIsInstance(exporter, ReportExporter)

    def test_language_indexer_lifecycle(self) -> None:
        indexer = MockCustomIndexer()
        register_indexer(indexer)
        self.assertIn(indexer, get_registered_indexers())

        unregister_indexer("custom-lang")
        self.assertNotIn(indexer, get_registered_indexers())

    def test_security_rule_provider_lifecycle(self) -> None:
        provider = MockCustomRuleProvider()
        register_security_provider(provider)
        self.assertIn(provider, get_registered_security_providers())

        unregister_security_provider("custom-policy")
        self.assertNotIn(provider, get_registered_security_providers())

    def test_report_exporter_lifecycle(self) -> None:
        exporter = MockCustomExporter()
        register_exporter(exporter)
        exporters = get_registered_exporters()
        self.assertIn("custom-doc", exporters)
        self.assertIs(exporters["custom-doc"], exporter)

        unregister_exporter("custom-doc")
        self.assertNotIn("custom-doc", get_registered_exporters())

    def test_analysis_pipeline_executes_registered_extensions(self) -> None:
        """Verify that run_analysis invokes registered indexers and security providers."""
        register_indexer(MockCustomIndexer())
        register_security_provider(MockCustomRuleProvider())

        config = AnalysisConfig(root=SAMPLE_APP_DIR, security=True)
        result = run_analysis(config)

        # 1. Custom indexer node is present in graph
        self.assertIn("custom:sample_service", result.graph.nodes)
        node = result.graph.nodes["custom:sample_service"]
        self.assertEqual(node.name, "custom_service")

        # 2. Custom security finding is present in graph
        finding_ids = [f.id for f in result.graph.findings]
        self.assertIn("CUSTOM-RULE-001", finding_ids)

    def test_custom_exporter_writes_output(self) -> None:
        """Verify that custom exporter writes output files correctly."""
        exporter = MockCustomExporter()
        register_exporter(exporter)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            graph = Graph()
            written = exporter.export(graph, out_dir)
            self.assertTrue(isinstance(written, Path))
            self.assertTrue(written.is_file())
            content = written.read_text(encoding="utf-8")
            self.assertIn("Custom graph export with 0 nodes", content)

    def test_custom_exporter_via_cli(self) -> None:
        """Verify that CLI recognizes and invokes registered custom format exporters."""
        import contextlib
        import io

        from secdiagram_core.cli import main

        exporter = MockCustomExporter()
        register_exporter(exporter)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "cli_out"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main([
                    "--dir", str(SAMPLE_APP_DIR),
                    "--out", str(out_dir),
                    "--format", "custom-doc",
                    "--no-security",
                    "--quiet",
                ])
            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "custom-output.txt").is_file())


if __name__ == "__main__":
    unittest.main()
