from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.diagram_model import (
    DiagramComponent,
    DiagramModel,
    DiagramRelationship,
    build_diagram_model,
    compute_layout_ranks,
)
from secdiagram_core.diagram_quality import (
    analyze_diagram_quality,
    format_quality_report,
    has_errors,
)
from secdiagram_core.high_level import HighLevelArchitecture, Subsystem, SubsystemConnection
from secdiagram_core.model import Graph, Node

FIXTURE = ROOT / "tests" / "fixtures" / "sample_app"


def _node(node_id: str, kind: str = "module") -> Node:
    return Node(id=node_id, kind=kind, name=node_id, qualname=node_id)


def _subsystem(
    sub_id: str,
    name: str,
    tier: str = "services",
    kind: str = "service",
) -> Subsystem:
    return Subsystem(id=sub_id, name=name, tier=tier, kind=kind, technology="python")


def _codes(model: DiagramModel) -> list[str]:
    return [issue.code for issue in analyze_diagram_quality(model)]


class LayoutRankTests(unittest.TestCase):
    def test_chain_ranks_increase_with_depth(self) -> None:
        ranks = compute_layout_ranks(["c", "b", "a"], [("a", "b"), ("b", "c")])
        self.assertEqual(ranks, {"a": 0, "b": 1, "c": 2})

    def test_cycles_share_one_rank(self) -> None:
        ranks = compute_layout_ranks(["a", "b", "c"], [("a", "b"), ("b", "c"), ("c", "b")])
        self.assertEqual(ranks["a"], 0)
        self.assertEqual(ranks["b"], ranks["c"])
        self.assertEqual(ranks["b"], 1)

    def test_self_loops_do_not_change_ranks(self) -> None:
        self.assertEqual(compute_layout_ranks(["a"], [("a", "a")]), {"a": 0})

    def test_ranks_ignore_unknown_endpoints(self) -> None:
        self.assertEqual(compute_layout_ranks(["a"], [("a", "missing")]), {"a": 0})


class ModelTests(unittest.TestCase):
    def test_projection_is_insertion_order_independent(self) -> None:
        first = Graph()
        second = Graph()
        for name in ("alpha", "beta", "gamma"):
            first.nodes[name] = _node(name)
        for name in ("gamma", "alpha", "beta"):
            second.nodes[name] = _node(name)
        for graph in (first, second):
            graph.add_edge("alpha", "beta", "imports")
            graph.add_edge("beta", "gamma", "calls")

        model_a = build_diagram_model(first, HighLevelArchitecture())
        model_b = build_diagram_model(second, HighLevelArchitecture())

        self.assertEqual(
            [component.id for component in model_a.components],
            [component.id for component in model_b.components],
        )
        self.assertEqual(model_a.ranks, model_b.ranks)
        self.assertEqual(
            [relationship.to_dict() for relationship in model_a.relationships],
            [relationship.to_dict() for relationship in model_b.relationships],
        )

    def test_subsystems_take_precedence_and_are_classified(self) -> None:
        graph = Graph()
        graph.nodes["ignored"] = _node("ignored")
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("web", "Web", tier="ingress", kind="client"),
                _subsystem("api", "API", tier="services", kind="api"),
                _subsystem("db", "Postgres", tier="data", kind="database"),
                _subsystem("stripe", "Stripe", tier="external", kind="external"),
                _subsystem("infra", "Docker", tier="platform", kind="platform"),
            ],
            connections=[
                SubsystemConnection(src="web", dst="api", label="HTTPS"),
                SubsystemConnection(src="api", dst="db", label="SQL"),
                SubsystemConnection(src="api", dst="stripe", label="Charges"),
            ],
        )

        model = build_diagram_model(graph, hla)

        self.assertEqual(
            [component.id for component in model.components],
            ["web", "infra", "api", "db", "stripe"],
        )
        self.assertEqual(model.entry_points, ["web"])
        self.assertEqual(model.data_stores, ["db"])
        self.assertEqual(model.external_systems, ["stripe"])
        self.assertEqual(
            model.boundaries, ["ingress", "services", "data", "external", "platform"]
        )
        self.assertEqual(model.ranks["web"], 0)
        self.assertEqual(model.ranks["stripe"], 2)

    def test_relationships_are_deduplicated_and_stable(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[_subsystem("a", "A"), _subsystem("b", "B")],
            connections=[
                SubsystemConnection(src="a", dst="b", label="one"),
                SubsystemConnection(src="a", dst="b", label="two"),
            ],
        )
        model = build_diagram_model(Graph(), hla)
        self.assertEqual(len(model.relationships), 1)
        first_id = model.relationships[0].id
        rebuilt = build_diagram_model(Graph(), hla)
        self.assertEqual(rebuilt.relationships[0].id, first_id)


class QualityCheckTests(unittest.TestCase):
    def test_orphans_are_reported_but_data_stores_excluded(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("svc", "Untethered"),
                _subsystem("db", "Postgres", tier="data", kind="database"),
            ]
        )
        issues = analyze_diagram_quality(build_diagram_model(Graph(), hla))
        self.assertEqual([issue.code for issue in issues], ["DQ003"])
        self.assertEqual(issues[0].subjects, ("svc",))

    def test_duplicate_service_labels(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("svc_a", "Auth Service"),
                _subsystem("svc_b", "auth-service"),
            ],
            connections=[SubsystemConnection(src="svc_a", dst="svc_b", label="calls")],
        )
        issues = analyze_diagram_quality(build_diagram_model(Graph(), hla))
        self.assertIn("DQ002", [issue.code for issue in issues])
        duplicate = next(issue for issue in issues if issue.code == "DQ002")
        self.assertEqual(duplicate.subjects, ("svc_a", "svc_b"))

    def test_cycle_is_an_error(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[_subsystem("a", "A"), _subsystem("b", "B")],
            connections=[
                SubsystemConnection(src="a", dst="b", label="left"),
                SubsystemConnection(src="b", dst="a", label="right"),
            ],
        )
        issues = analyze_diagram_quality(build_diagram_model(Graph(), hla))
        cycle = next(issue for issue in issues if issue.code == "DQ004")
        self.assertEqual(cycle.severity, "error")
        self.assertEqual(cycle.subjects, ("a", "b"))
        self.assertTrue(has_errors(issues))

    def test_self_loop_duplicate_and_dangling_relationships(self) -> None:
        components = [
            DiagramComponent(id="a", name="A", kind="service", tier="services", source="subsystem"),
            DiagramComponent(id="b", name="B", kind="service", tier="services", source="subsystem"),
        ]
        relationships = [
            DiagramRelationship(id="r1", src="a", dst="a", kind="calls"),
            DiagramRelationship(id="r2", src="a", dst="b", kind="calls"),
            DiagramRelationship(id="r3", src="a", dst="b", kind="calls"),
            DiagramRelationship(id="r4", src="a", dst="ghost", kind="calls"),
        ]
        model = DiagramModel(
            components=components,
            relationships=relationships,
            ranks={"a": 0, "b": 1},
        )
        issues = analyze_diagram_quality(model)
        codes = [issue.code for issue in issues]
        self.assertIn("DQ005", codes)
        self.assertIn("DQ006", codes)
        self.assertIn("DQ007", codes)
        dangling = next(issue for issue in issues if issue.code == "DQ006")
        self.assertEqual(dangling.severity, "error")

    def test_tier_inversion_is_informational(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("db", "Postgres", tier="data", kind="database"),
                _subsystem("api", "API", tier="services", kind="api"),
            ],
            connections=[SubsystemConnection(src="db", dst="api", label="notify")],
        )
        issues = analyze_diagram_quality(build_diagram_model(Graph(), hla))
        inversion = next(issue for issue in issues if issue.code == "DQ008")
        self.assertEqual(inversion.severity, "info")
        self.assertEqual(inversion.subjects, ("db->api",))

    def test_rank_skips_are_flagged_when_pervasive(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("a", "A"),
                _subsystem("b", "B"),
                _subsystem("c", "C"),
                _subsystem("d", "D"),
            ],
            connections=[
                SubsystemConnection(src="a", dst="b", label="ab"),
                SubsystemConnection(src="a", dst="c", label="ac"),
                SubsystemConnection(src="a", dst="d", label="ad"),
                SubsystemConnection(src="b", dst="d", label="bd"),
                SubsystemConnection(src="b", dst="c", label="bc"),
                SubsystemConnection(src="c", dst="d", label="cd"),
            ],
        )
        issues = analyze_diagram_quality(build_diagram_model(Graph(), hla))
        self.assertIn("DQ009", [issue.code for issue in issues])

    def test_report_is_deterministic(self) -> None:
        hla = HighLevelArchitecture(
            subsystems=[
                _subsystem("svc_a", "Auth Service"),
                _subsystem("svc_b", "auth-service"),
                _subsystem("orphan", "Orphan"),
            ],
            connections=[SubsystemConnection(src="svc_a", dst="svc_b", label="calls")],
        )
        model = build_diagram_model(Graph(), hla)
        first = format_quality_report(analyze_diagram_quality(model))
        second = format_quality_report(analyze_diagram_quality(build_diagram_model(Graph(), hla)))
        self.assertEqual(first, second)


class ValidateCliTests(unittest.TestCase):
    def test_validate_reports_and_renders_clean_fixture(self) -> None:
        from secdiagram_core.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("builtins.print") as mocked:
                code = main(
                    [
                        "--dir",
                        str(FIXTURE),
                        "--out",
                        tmp,
                        "--format",
                        "mermaid",
                        "--no-security",
                        "--validate",
                        "--quiet",
                    ]
                )
            self.assertEqual(code, 0)
            printed = "\n".join(str(call.args[0]) for call in mocked.call_args_list if call.args)
            self.assertIn("diagram quality:", printed)
            self.assertTrue((Path(tmp) / "diagram.mmd").exists())
            self.assertTrue((Path(tmp) / "diagram-highlevel.mmd").exists())


if __name__ == "__main__":
    unittest.main()
