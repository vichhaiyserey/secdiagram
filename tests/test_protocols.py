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


class FailingIndexer:
    @property
    def name(self) -> str:
        return "failing-lang"

    @property
    def supported_suffixes(self) -> tuple[str, ...]:
        return (".fail",)

    def index_repo(self, root: Path, rel_files: list[str], graph: Graph) -> None:
        graph.add_node(Node(id="partial:node", kind="service", name="partial", qualname="partial", path="p.fail", line=1))
        raise RuntimeError("indexer blew up with token=mock_token_12345")


class FailingProvider:
    @property
    def name(self) -> str:
        return "failing-policy"

    def analyze(self, graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
        raise ValueError("provider crashed")


class RepeatedIdProvider:
    @property
    def name(self) -> str:
        return "pci-dss-custom"

    def analyze(self, graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
        return [
            Finding(
                id="PCI-001",
                category="compliance",
                severity="high",
                title="PCI Cardholder Data In Cleartext",
                message=f"match {index}",
                evidence=[Loc(f"app/card_{index}.py", index + 1)],
            )
            for index in range(5)
        ]


class FailingExporter:
    @property
    def name(self) -> str:
        return "broken-doc"

    def export(self, graph: Graph, out_dir: Path, **kwargs: Any) -> Path:
        raise OSError("disk full")


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

    def test_failing_indexer_is_recorded_and_rolled_back(self) -> None:
        register_indexer(FailingIndexer())
        result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=False))
        self.assertNotIn("partial:node", result.graph.nodes)
        errors = result.graph.meta["plugin_errors"]
        self.assertEqual([(e["kind"], e["plugin"]) for e in errors], [("indexer", "failing-lang")])
        self.assertIn("RuntimeError", errors[0]["error"])
        self.assertNotIn("mock_token_12345", errors[0]["error"])

    def test_failing_security_provider_is_recorded(self) -> None:
        register_security_provider(FailingProvider())
        register_security_provider(MockCustomRuleProvider())
        result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))
        errors = result.graph.meta["plugin_errors"]
        self.assertEqual([(e["kind"], e["plugin"]) for e in errors], [("security_provider", "failing-policy")])
        # The healthy provider still ran.
        self.assertIn("CUSTOM-RULE-001", [f.id for f in result.graph.findings])

    def test_repeated_plugin_finding_ids_are_kept_deterministically(self) -> None:
        register_security_provider(RepeatedIdProvider())
        first = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))
        pci = [f for f in first.graph.findings if f.title == "PCI Cardholder Data In Cleartext"]
        self.assertEqual(len(pci), 5)
        self.assertEqual(len({f.id for f in pci}), 5)
        self.assertIn("PCI-001", [f.id for f in pci])
        self.assertTrue(all(f.metadata.get("rule_id", f.id) == "PCI-001" for f in pci))

        second = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))
        again = [f for f in second.graph.findings if f.title == "PCI Cardholder Data In Cleartext"]
        self.assertEqual(sorted(f.id for f in pci), sorted(f.id for f in again))

    def test_cli_plugin_failure_warns_and_exits_nonzero(self) -> None:
        import contextlib
        import io

        from secdiagram_core.cli import main

        register_security_provider(FailingProvider())
        register_exporter(FailingExporter())
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main([
                    "--dir", str(SAMPLE_APP_DIR),
                    "--out", str(Path(tmp_dir) / "out"),
                    "--format", "json,broken-doc",
                    "--quiet",
                ])
            self.assertEqual(code, 1)
            self.assertIn("security_provider plugin 'failing-policy' failed", stderr.getvalue())
            self.assertIn("exporter plugin 'broken-doc' failed: OSError: disk full", stderr.getvalue())
            # Other outputs are still written.
            self.assertTrue((Path(tmp_dir) / "out" / "graph.json").is_file())


if __name__ == "__main__":
    unittest.main()
