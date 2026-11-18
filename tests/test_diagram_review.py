"""Regression contracts for diagram validation and canonical rendering."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from secdiagram_core.cli import main
from secdiagram_core.diagram_model import build_diagram_model
from secdiagram_core.diagram_quality import analyze_diagram_quality
from secdiagram_core.high_level import (
    HighLevelArchitecture,
    Subsystem,
    SubsystemConnection,
    render_mermaid_highlevel,
)
from secdiagram_core.model import Edge, Graph, Node
from secdiagram_core.render_mermaid import build_mermaid_model, render_mermaid


def subsystem(name: str) -> Subsystem:
    return Subsystem(id=name, name=name, kind="service", tier="services", technology="Python")


def cyclic_projects(root: Path) -> None:
    for name, peer in (("Alpha", "Beta"), ("Beta", "Alpha")):
        project = root / name
        project.mkdir(parents=True)
        (project / f"{name}.csproj").write_text(
            f'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../{peer}/{peer}.csproj" /></ItemGroup></Project>',
            encoding="utf-8",
        )


class ValidationIntegrationTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str]:
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            code = main([*args, "--no-cache", "--quiet"])
        return code, captured.getvalue()

    def test_cycle_inside_subsystem_blocks_detailed_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            app = root / "app"
            app.mkdir(parents=True)
            (app / "__init__.py").write_text("", encoding="utf-8")
            (app / "a.py").write_text("from app import b\ndef first():\n    return b.second()\n", encoding="utf-8")
            (app / "b.py").write_text("from app import a\ndef second():\n    return a.first()\n", encoding="utf-8")
            for detail in ("architecture", "full"):
                with self.subTest(detail=detail):
                    out = Path(tmp) / detail
                    code, log = self.run_cli("--dir", str(root), "--out", str(out), "--validate",
                                             "--diagram-detail", detail, "--no-security", "--format", "mermaid")
                    self.assertEqual(code, 1, log)
                    self.assertIn("DQ004", log)
                    self.assertFalse(out.exists())
            code, log = self.run_cli("--dir", str(root), "--out", str(Path(tmp) / "high"),
                                     "--validate", "--high-level", "--no-security", "--format", "mermaid")
            self.assertEqual(code, 0, log)

    def test_failed_validation_preserves_baseline_and_existing_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "repo", Path(tmp) / "out"
            cyclic_projects(root)
            out.mkdir()
            baseline, report = out / "accepted.json", out / "diagram.mmd"
            original = b'{"sentinel":"existing baseline"}\n'
            baseline.write_bytes(original)
            report.write_bytes(b"previous diagram\n")
            code, log = self.run_cli("--dir", str(root), "--out", str(out), "--validate",
                                     "--create-baseline", "--baseline", str(baseline))
            self.assertEqual(code, 1, log)
            self.assertIn("DQ004", log)
            self.assertEqual(baseline.read_bytes(), original)
            self.assertEqual(report.read_bytes(), b"previous diagram\n")
            self.assertEqual(sorted(p.name for p in out.iterdir()), ["accepted.json", "diagram.mmd"])

    def test_successful_validation_still_creates_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "repo", Path(tmp) / "out"
            root.mkdir()
            (root / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
            code, log = self.run_cli("--dir", str(root), "--out", str(out), "--validate", "--create-baseline")
            self.assertEqual(code, 0, log)
            self.assertIsInstance(json.loads((out / "security.baseline.json").read_text(encoding="utf-8")), dict)
            self.assertTrue((out / "diagram.mmd").exists())

    def test_workspace_cycle_blocks_before_manifest_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "workspace", Path(tmp) / "out"
            cyclic_projects(root / "service")
            code, log = self.run_cli("--workspace", str(root), "--out", str(out), "--validate", "--no-security")
            self.assertEqual(code, 1, log)
            self.assertIn("DQ004", log)
            self.assertFalse(out.exists())

    def test_clean_workspace_validation_still_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "workspace", Path(tmp) / "out"
            service = root / "service"
            service.mkdir(parents=True)
            (service / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
            code, log = self.run_cli("--workspace", str(root), "--out", str(out), "--validate", "--no-security", "--high-level")
            self.assertEqual(code, 0, log)
            self.assertIn("diagram quality:", log)
            self.assertTrue((out / "workspace.json").exists())
            self.assertIn("High-Level", (out / "diagram.mmd").read_text(encoding="utf-8"))


class CanonicalRendererTests(unittest.TestCase):
    def test_high_level_order_is_canonical_without_losing_labels_or_styles(self) -> None:
        nodes = [subsystem("producer"), subsystem("consumer"), subsystem("store")]
        edges = [SubsystemConnection("producer", "consumer", "Invokes", "thick"),
                 SubsystemConnection("consumer", "store", "Persists", "dotted")]
        first = render_mermaid_highlevel(HighLevelArchitecture(nodes, edges), direction="LR", theme="classic")
        second = render_mermaid_highlevel(HighLevelArchitecture(list(reversed(nodes)), list(reversed(edges))), direction="LR", theme="classic")
        self.assertEqual(first, second)
        self.assertLess(first.index("    producer["), first.index("    consumer["))
        self.assertIn("flowchart LR", first)
        self.assertIn("==|Invokes|==>", first)
        self.assertIn("-.|Persists|.->", first)

    def test_detailed_layout_follows_ranks_and_preserves_clicks(self) -> None:
        graph = Graph()
        for name, label in (("source", "z_source"), ("target", "a_target")):
            graph.nodes[name] = Node(name, "function", label, label, path=f"{name}.py", line=1, feature="app")
        graph.add_edge("source", "target", "calls")
        text = render_mermaid(graph, detail="full", theme="classic", direction="TB", link_base="https://example.invalid/repo")
        self.assertLess(text.index('    n_source('), text.index('    n_target('))
        self.assertIn("n_source --> n_target", text)
        self.assertIn('click n_source "https://example.invalid/repo/source.py"', text)
        self.assertIn("flowchart TB", text)
        reversed_graph = Graph(nodes=dict(reversed(list(graph.nodes.items()))), edges=list(reversed(graph.edges)))
        self.assertEqual(text, render_mermaid(reversed_graph, detail="full", theme="classic", direction="TB", link_base="https://example.invalid/repo"))

    def test_relationship_label_merge_is_order_independent(self) -> None:
        nodes = [subsystem("a"), subsystem("b")]
        edges = [SubsystemConnection("a", "b", "one"), SubsystemConnection("a", "b", "two")]
        first = build_diagram_model(Graph(), HighLevelArchitecture(nodes, edges)).to_dict()
        second = build_diagram_model(Graph(), HighLevelArchitecture(nodes, list(reversed(edges)))).to_dict()
        self.assertEqual(first, second)


class ProjectionDiagnosticsTests(unittest.TestCase):
    def test_both_model_projections_preserve_dangling_edges(self) -> None:
        graph = Graph(nodes={"a": Node("a", "function", "a", "a")}, edges=[Edge("a", "missing", "calls")])
        hla = HighLevelArchitecture([subsystem("a")], [SubsystemConnection("a", "missing", "Invokes")])
        models = [build_diagram_model(graph), build_diagram_model(Graph(), hla), build_mermaid_model(graph)]
        for model in models:
            with self.subTest(model=model):
                self.assertTrue(any(issue.code == "DQ006" for issue in analyze_diagram_quality(model)))

    def test_intentionally_hidden_nodes_are_not_dangling(self) -> None:
        graph = Graph(nodes={name: Node(name, kind, name, name, feature="app")
                             for name, kind in (("module", "module"), ("visible", "function"), ("_private", "function"))})
        graph.add_edge("visible", "module", "imports")
        graph.add_edge("visible", "_private", "calls")
        model = build_mermaid_model(graph)
        self.assertEqual([node.id for node in model.components], ["visible"])
        self.assertFalse(any(issue.code == "DQ006" for issue in analyze_diagram_quality(model)))


if __name__ == "__main__":
    unittest.main()
