"""Tests for exposure detection, risk scoring, the threat model and their outputs."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.model import Finding, Graph, Loc, Node
from secdiagram_core.render_markdown import render_markdown
from secdiagram_core.render_sarif import render_sarif
from secdiagram_core.risk import endpoint_exposure, score_finding, score_findings
from secdiagram_core.security_report import build_security_report
from secdiagram_core.taint_flows import render_taint_mermaid
from secdiagram_core.threat_model import build_threat_model, render_threat_model

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CACHE: dict[str, AnalysisResult] = {}


def _analyze(name: str) -> AnalysisResult:
    if name not in _CACHE:
        _CACHE[name] = run_analysis(AnalysisConfig(root=FIXTURES / name, security=True))
    return _CACHE[name]


class ExposureDetectionTests(unittest.TestCase):
    def test_auth_markers_per_framework(self) -> None:
        graph = _analyze("exposure").graph
        observed = {
            (node.path, r["path"]): node.attrs.get("auth", "")
            for node in graph.nodes.values()
            if node.kind == "endpoint"
            for r in node.attrs.get("routes", [])
        }
        self.assertEqual(
            observed,
            {
                ("dotnet/AdminController.cs", "/api/admin/run"): "required",  # class [Authorize]
                ("dotnet/AdminController.cs", "/api/admin/ping"): "anonymous",  # [AllowAnonymous] wins
                ("dotnet/Program.cs", "/secure/report"): "required",  # MapGroup().RequireAuthorization()
                ("dotnet/Program.cs", "/open"): "anonymous",  # .AllowAnonymous()
                ("dotnet/Program.cs", "/plain"): "",
                ("node/routes.ts", "/public/search"): "",
                ("node/routes.ts", "/private/search"): "required",  # inline requireAuth
                ("node/admin.ts", "/admin/users"): "required",  # admin.use(authMiddleware)
                ("node/orders.controller.ts", "/orders"): "required",  # @UseGuards
                ("php/web.php", "/home"): "",
                ("php/web.php", "/account"): "required",  # Route::middleware(['auth:sanctum'])->group
                ("php/web.php", "/billing"): "required",  # ->middleware('auth')
                ("go/routes.go", "/status"): "",
                ("go/routes.go", "/stats"): "required",  # r.Group("/admin", AuthMiddleware())
                ("java/AdminApi.java", "/api/secret"): "required",  # @PreAuthorize
                ("java/AdminApi.java", "/api/health"): "anonymous",  # @PermitAll
                ("java/AdminApi.java", "/api/info"): "",
            },
        )

    def test_exposure_classes(self) -> None:
        self.assertEqual(endpoint_exposure(None), "internal")
        self.assertEqual(endpoint_exposure(Node("a", "cli", "a", "a")), "local")
        self.assertEqual(endpoint_exposure(Node("b", "endpoint", "b", "b", attrs={"auth": "anonymous"})), "public")
        self.assertEqual(endpoint_exposure(Node("c", "endpoint", "c", "c", attrs={"auth": "required"})), "authenticated")
        self.assertEqual(endpoint_exposure(Node("d", "endpoint", "d", "d")), "unknown")
        self.assertEqual(endpoint_exposure(Node("e", "function", "e", "e", attrs={"tags": ["endpoint", "auth"]})),
                         "authenticated")


class RiskScoringTests(unittest.TestCase):
    def test_exposure_changes_priority_for_the_same_sink(self) -> None:
        graph = _analyze("exposure").graph
        risk = {f.evidence[0].ref: f.metadata["risk"] for f in graph.findings if f.metadata.get("tainted")}
        public_cmd = risk["dotnet/AdminController.cs:25"]
        auth_cmd = risk["dotnet/AdminController.cs:16"]
        unknown_sql = risk["node/routes.ts:6"]
        auth_sql = risk["node/routes.ts:10"]
        self.assertEqual((public_cmd["exposure"], public_cmd["priority"]), ("public", "P0"))
        self.assertEqual((auth_cmd["exposure"], auth_cmd["priority"]), ("authenticated", "P1"))
        self.assertGreater(public_cmd["score"], auth_cmd["score"])
        self.assertGreater(unknown_sql["score"], auth_sql["score"])
        self.assertEqual(public_cmd["evidence"], "proven-flow")

    def test_known_exploited_floor_and_bands(self) -> None:
        graph = Graph()
        finding = Finding("f1", "dependency", "medium", "Vulnerable dependency", "m", confidence=0.5,
                          evidence=[Loc("requirements.txt", 3)],
                          metadata={"validation": {"known_exploited": True}})
        score = score_finding(graph, finding, None)
        self.assertTrue(score.known_exploited)
        self.assertGreaterEqual(score.score, 8.0)
        self.assertEqual(score.priority, "P0")

    def test_configuration_severity_and_secret_evidence(self) -> None:
        graph = Graph()
        high = Finding("a", "jwt", "high", "sig", "m", confidence=0.8, evidence=[Loc("a.cs", 1)])
        medium = Finding("b", "jwt", "medium", "lifetime", "m", confidence=0.8, evidence=[Loc("a.cs", 2)])
        secret = Finding("c", "secret", "high", "key", "m", confidence=0.8, evidence=[Loc("a.cs", 3)])
        s_high, s_medium = score_finding(graph, high, None), score_finding(graph, medium, None)
        self.assertGreater(s_high.score, s_medium.score)
        self.assertEqual(s_high.evidence, "unsafe-configuration")
        s_secret = score_finding(graph, secret, None)
        self.assertEqual((s_secret.evidence, s_secret.priority), ("credential-in-source", "P1"))

    def test_untainted_dynamic_query_is_discounted(self) -> None:
        graph = Graph()
        dynamic = Finding("d", "sql", "medium", "SQL injection", "m", confidence=0.6, evidence=[Loc("r.ts", 2)],
                          metadata={"tainted": False})
        self.assertEqual(score_finding(graph, dynamic, None).evidence, "dynamic-construction")
        self.assertLess(score_finding(graph, dynamic, None).score, 4.0)

    def test_meta_summary_and_determinism(self) -> None:
        graph = _analyze("polyglot").graph
        meta = graph.meta["risk"]
        self.assertEqual(sum(meta["by_priority"].values()), len([f for f in graph.findings if not f.baseline]))
        first = [f.metadata["risk"] for f in graph.sorted_findings()]
        score_findings(graph)
        self.assertEqual(first, [f.metadata["risk"] for f in graph.sorted_findings()])


class OutputTests(unittest.TestCase):
    def test_taint_diagram_shows_priority_and_exposure(self) -> None:
        text = render_taint_mermaid(_analyze("exposure").graph)
        self.assertIn("P0 9.5", text)
        self.assertIn("(PUBLIC - no auth)", text)
        self.assertIn("(authenticated)", text)
        self.assertIn('P0 9.5 · CRITICAL<br/>dotnet/AdminController.cs:25"}}:::critical', text)
        self.assertIn('P2 5.6 · CRITICAL<br/>node/routes.ts:10"}}:::medium', text)
        self.assertLess(text.index("P0 9.5"), text.index("P1 6.2"))

    def test_threat_model(self) -> None:
        graph = _analyze("polyglot").graph
        threats = build_threat_model(graph)
        by_title = {t.title: t for t in threats}
        self.assertEqual(by_title["Security-relevant actions not attributable"].status, "not-assessed")
        rce = by_title["Code or command execution on the host"]
        self.assertEqual((rce.status, rce.priority), ("observed", "P0"))
        entry = by_title["Entry points reachable without (detected) authentication"]
        # Even a source-to-sink trace cannot prove that inherited auth is absent.
        self.assertEqual(entry.status, "review")
        text = render_threat_model(graph, threats)
        text.encode("ascii")
        self.assertIn("## Internet -> Application", text)
        self.assertIn("linkStyle", text)
        # Edge labels contain "(s)"; Mermaid needs them quoted.
        self.assertIn('client -->|"', text)
        self.assertNotRegex(text, r"-->\|[^\"]")
        self.assertEqual(text, render_threat_model(graph))
        self.assertEqual(graph.meta["threat_model"]["threats"], len(threats))

    def test_markdown_fix_first_and_sarif_rank(self) -> None:
        graph = _analyze("polyglot").graph
        markdown = render_markdown(graph, dict(graph.meta))
        markdown.encode("ascii")
        self.assertIn("## Fix first (risk-ranked)", markdown)
        sarif = json.loads(render_sarif(graph))
        results = sarif["runs"][0]["results"]
        top = max(results, key=lambda r: r["rank"])
        self.assertEqual(top["properties"]["riskPriority"], "P0")
        self.assertEqual(top["rank"], round(top["properties"]["riskScore"] * 10, 1))

    def test_security_report_priorities_follow_risk(self) -> None:
        graph = _analyze("exposure").graph
        report = build_security_report(graph)
        scores = [f.metadata["risk"]["score"] for f in report.priorities]
        self.assertGreater(
            len(scores), 1, "an empty/single-item priority list cannot exercise ranking"
        )
        self.assertGreater(max(scores), min(scores), "fixture must have different risks")
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_cli_writes_threat_model_only_with_security(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out_ns = Path(tmp) / "out-ns"
            out.mkdir()
            out_ns.mkdir()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--dir", str(FIXTURES / "exposure"), "--out", str(out), "--format", "md", "--quiet"])
                main(["--dir", str(FIXTURES / "exposure"), "--out", str(out_ns), "--format", "md", "--quiet",
                      "--no-security"])
            self.assertTrue((out / "THREAT_MODEL.md").is_file())
            self.assertFalse((out_ns / "THREAT_MODEL.md").exists())


if __name__ == "__main__":
    unittest.main()
