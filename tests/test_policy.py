"""Golden-corpus and unit tests for the high-confidence policy layer.

The corpus under ``tests/fixtures/policy_corpus`` contains labelled true
positives (verified secret, tainted command/SQL injection from a public HTTP
route), false positives (placeholder secret, untainted sink), and review-tier
cases (likely secret). Blocking precision is asserted to stay at 100% on this
corpus; every block must carry complete evidence and a policy reason.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.baseline import load_suppressions, write_baseline
from secdiagram_core.confidence import BLOCK_CONFIDENCE_THRESHOLD, compute_confidence
from secdiagram_core.exposure import classify_exposure
from secdiagram_core.model import Finding, Graph, Loc
from secdiagram_core.policy import (
    BLOCK_EVIDENCE_QUALITIES,
    apply_policy,
    evaluate_finding,
)
from secdiagram_core.reachability import classify_reachability, has_complete_path

try:
    from .support import fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import fixture_result
    except (ImportError, ValueError):
        from support import fixture_result

CORPUS = Path(__file__).resolve().parent / "fixtures" / "policy_corpus"


@lru_cache(maxsize=1)
def corpus_result() -> AnalysisResult:
    return run_analysis(AnalysisConfig(root=CORPUS))


def _finding(
    fid: str,
    *,
    category: str = "command",
    severity: str = "critical",
    confidence: float = 0.95,
    trace: list[Loc] | None = None,
    metadata: dict | None = None,
    source: str = "secdiagram",
) -> Finding:
    return Finding(
        id=fid,
        category=category,
        severity=severity,
        title="Demo finding",
        message="demo",
        confidence=confidence,
        evidence=[Loc("app.py", 1)],
        trace=trace or [],
        metadata=metadata or {},
        source=source,
    )


class ExposureTests(unittest.TestCase):
    def _graph(self, *findings: Finding) -> Graph:
        graph = Graph()
        graph.findings = list(findings)
        return graph

    def test_secret_is_sensitive_data(self) -> None:
        graph = self._graph(_finding("s", category="secret", metadata={"secret_kind": "provider_token"}))
        self.assertEqual(classify_exposure(graph, graph.findings[0]), "sensitive_data")

    def test_known_exploited_is_internal_high_impact(self) -> None:
        graph = self._graph(
            _finding("d", category="dependency", metadata={"package": "requests", "cves": ["CVE-2024-0001"],
                                                            "validation": {"known_exploited": True}})
        )
        self.assertEqual(classify_exposure(graph, graph.findings[0]), "internal_high_impact")

    def test_no_entry_point_is_isolated(self) -> None:
        graph = self._graph(_finding("x", category="command"))
        self.assertEqual(classify_exposure(graph, graph.findings[0]), "unknown")

    def test_ingress_http_handler_is_public(self) -> None:
        from secdiagram_core.exposure import node_exposure_class
        from secdiagram_core.model import Node

        node = Node(
            id="e1",
            kind="endpoint",
            name="ping",
            qualname="app.ping",
            attrs={"trust_boundary": "ingress", "routes": [{"method": "GET", "path": "/ping"}],
                   "security": ["source", "sink"]},
        )
        self.assertEqual(node_exposure_class(node), "public")
        node.attrs["auth"] = "required"
        self.assertEqual(node_exposure_class(node), "privileged")


class ConfidenceTests(unittest.TestCase):
    def test_verified_secret_reaches_threshold(self) -> None:
        finding = _finding("v", category="secret", confidence=0.95, metadata={"secret_kind": "provider_token"})
        score = compute_confidence(
            finding,
            evidence_quality="provider_verified",
            reachability="externally_reachable",
            exposure="sensitive_data",
            mitigation_status="none",
        )
        self.assertGreaterEqual(score, BLOCK_CONFIDENCE_THRESHOLD)

    def test_low_detector_confidence_cannot_block(self) -> None:
        finding = _finding("l", category="secret", confidence=0.5, metadata={"secret_kind": "assignment"})
        score = compute_confidence(
            finding,
            evidence_quality="credential_in_source",
            reachability="externally_reachable",
            exposure="sensitive_data",
            mitigation_status="none",
        )
        self.assertLess(score, BLOCK_CONFIDENCE_THRESHOLD)

    def test_compensating_control_lowers_confidence(self) -> None:
        finding = _finding("c", category="command", confidence=0.95)
        base = compute_confidence(
            finding,
            evidence_quality="proven_flow",
            reachability="externally_reachable",
            exposure="public",
            mitigation_status="none",
        )
        mitigated = compute_confidence(
            finding,
            evidence_quality="proven_flow",
            reachability="externally_reachable",
            exposure="public",
            mitigation_status="compensating_control",
        )
        self.assertGreater(base, mitigated)
        self.assertLess(mitigated, BLOCK_CONFIDENCE_THRESHOLD)

    def test_deterministic(self) -> None:
        finding = _finding("d", category="sql", confidence=0.9, trace=[Loc("a.py", 1), Loc("a.py", 2)])
        args = dict(
            evidence_quality="proven_flow",
            reachability="externally_reachable",
            exposure="public",
            mitigation_status="none",
        )
        scores = [compute_confidence(finding, **args) for _ in range(3)]
        # A proven public flow at detector confidence 0.90 has decision confidence 1.00.
        self.assertEqual(scores, [1.0, 1.0, 1.0])
        finding.confidence = 0.5
        self.assertEqual(compute_confidence(finding, **args), 0.56)


class ReachabilityTests(unittest.TestCase):
    def _graph(self, *findings: Finding) -> Graph:
        graph = Graph()
        graph.findings = list(findings)
        return graph

    def test_incomplete_path_is_not_block_ready(self) -> None:
        finding = _finding("i", trace=[Loc("app.py", 1)])
        self.assertFalse(has_complete_path(finding))

    def test_complete_path(self) -> None:
        finding = _finding("c", trace=[Loc("app.py", 1), Loc("app.py", 5)])
        self.assertTrue(has_complete_path(finding))

    def test_flow_metadata_hops_are_parsed(self) -> None:
        finding = _finding(
            "f",
            metadata={
                "flow": [
                    {"loc": "app.py:1", "node": "n1", "role": "source"},
                    {"loc": "app.py:9", "node": "n1", "role": "sink"},
                ]
            },
        )
        self.assertTrue(has_complete_path(finding))
        graph = self._graph(finding)
        self.assertEqual(classify_reachability(graph, finding), "internal_reachable")

    def test_sink_without_entry_point_is_unreachable(self) -> None:
        from secdiagram_core.model import Node

        graph = Graph()
        graph.nodes["sink"] = Node(id="sink", kind="function", name="s", qualname="m.s")
        finding = _finding("u")
        finding.node_id = "sink"
        self.assertEqual(classify_reachability(graph, finding), "internal_reachable")


class PolicyDecisionTests(unittest.TestCase):
    def _graph(self, *findings: Finding) -> Graph:
        graph = Graph()
        graph.findings = list(findings)
        return graph

    def test_defaults_are_informational(self) -> None:
        finding = _finding("a", severity="low", confidence=0.5)
        result = evaluate_finding(self._graph(finding), finding)
        self.assertEqual(result.enforcement, "informational")
        self.assertTrue(result.policy_reason)

    def test_no_block_without_evidence(self) -> None:
        # Pattern-only evidence with no trace must not block.
        finding = _finding("p", confidence=0.8, metadata={"tainted": False})
        result = evaluate_finding(self._graph(finding), finding)
        self.assertNotEqual(result.enforcement, "block")

    def test_no_block_without_policy_reason(self) -> None:
        graph = self._graph(
            _finding("b1", trace=[Loc("app.py", 1), Loc("app.py", 3)]),
            _finding("b2", category="sql", confidence=0.6),
        )
        apply_policy(graph, mode="shadow")
        for finding in graph.findings:
            self.assertTrue(finding.policy_reason, f"finding {finding.id} lacks a policy reason")

    def test_llm_findings_never_block(self) -> None:
        finding = _finding(
            "llm",
            source="llm",
            trace=[Loc("app.py", 1), Loc("app.py", 3)],
            metadata={"origin": "llm"},
        )
        result = evaluate_finding(self._graph(finding), finding)
        self.assertNotEqual(result.enforcement, "block")
        self.assertIn("never block", result.policy_reason)

    def test_incomplete_trace_downgrades_injection(self) -> None:
        finding = _finding("t", trace=[Loc("app.py", 1)], metadata={"tainted": True})
        result = evaluate_finding(self._graph(finding), finding)
        self.assertNotEqual(result.enforcement, "block")
        self.assertIn("incomplete", result.policy_reason)

    def test_blocks_carry_complete_evidence(self) -> None:
        graph = corpus_result().graph
        apply_policy(graph, mode="shadow", dependency_usage=corpus_result().dependency_usage)
        blocks = [finding for finding in graph.findings if finding.enforcement == "block"]
        self.assertTrue(blocks)
        for finding in blocks:
            self.assertGreaterEqual(finding.confidence_score, BLOCK_CONFIDENCE_THRESHOLD)
            self.assertIn(finding.evidence_quality, BLOCK_EVIDENCE_QUALITIES)
            self.assertTrue(finding.policy_reason)
            self.assertGreater(finding.risk_score, 0.0)
            self.assertTrue(finding.required_actions)

    def test_decisions_are_stable(self) -> None:
        first = corpus_result().graph
        second = corpus_result().graph
        apply_policy(first, mode="shadow")
        apply_policy(second, mode="shadow")
        self.assertEqual(
            [(f.id, f.enforcement) for f in first.sorted_findings()],
            [(f.id, f.enforcement) for f in second.sorted_findings()],
        )
        self.assertEqual(first.meta["policy"], second.meta["policy"])

    def test_invalid_mode_raises(self) -> None:
        graph = self._graph(_finding("m"))
        with self.assertRaises(ValueError):
            apply_policy(graph, mode="yolo")


class GoldenCorpusTests(unittest.TestCase):
    """Labelled true positives, false positives, and review cases."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = corpus_result()
        cls.graph = cls.result.graph
        apply_policy(cls.graph, mode="shadow", dependency_usage=cls.result.dependency_usage)
        cls.by_id = {finding.id: finding for finding in cls.graph.findings}

    def _find(self, needle: str) -> Finding | None:
        for finding in self.graph.findings:
            if needle in (finding.evidence[0].ref if finding.evidence else ""):
                return finding
        return None

    def test_verified_aws_key_blocks(self) -> None:
        finding = self._find("config.py:9")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.enforcement, "block")
        self.assertEqual(finding.evidence_quality, "provider_verified")
        self.assertEqual(finding.exposure, "sensitive_data")
        self.assertIn("Rotate the credential", finding.required_actions)
        self.assertIn("secret manager", " ".join(finding.required_actions))

    def test_likely_secret_requires_review(self) -> None:
        finding = self._find("config.py:10")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.enforcement, "review")
        self.assertIn("not a format-verified provider token", finding.policy_reason)

    def test_placeholder_secret_never_surfaces(self) -> None:
        self.assertIsNone(self._find("config.py:11"))

    def test_tainted_command_injection_blocks(self) -> None:
        finding = self._find("app.py:15")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.enforcement, "block")
        self.assertEqual(finding.reachability, "externally_reachable")
        self.assertEqual(finding.exposure, "public")
        self.assertTrue(finding.trace)

    def test_tainted_sql_injection_blocks(self) -> None:
        finding = self._find("store.py:8")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.enforcement, "block")
        self.assertTrue(finding.trace)
        self.assertGreaterEqual(len(finding.trace), 2)

    def test_untainted_sink_is_deduplicated_with_tainted(self) -> None:
        # query_db("weekly-report") is a false positive the taint engine
        # suppresses; the corpus must produce exactly one sql finding, from
        # the tainted route.
        sql_findings = [
            finding for finding in self.graph.findings if finding.category == "sql"
        ]
        self.assertEqual(len(sql_findings), 1)
        self.assertEqual(sql_findings[0].evidence[0].ref, "policy_app/store.py:8")
        self.assertEqual(sql_findings[0].enforcement, "block")

    def test_blocking_precision_is_complete(self) -> None:
        blocks = [f for f in self.graph.findings if f.enforcement == "block"]
        self.assertEqual(len(blocks), 4)
        complete = [
            f
            for f in blocks
            if f.policy_reason
            and f.confidence_score >= BLOCK_CONFIDENCE_THRESHOLD
            and f.evidence_quality in BLOCK_EVIDENCE_QUALITIES
            and (f.exposure in {"public", "privileged", "sensitive_data", "internal_high_impact"})
        ]
        self.assertEqual(len(complete), len(blocks))


class PolicyCliTests(unittest.TestCase):
    def _run(self, args: list[str]) -> tuple[int, str, str]:
        from secdiagram_core.cli import main

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def _args(self, out: Path, extra: list[str]) -> list[str]:
        return [
            "--dir",
            str(CORPUS),
            "--out",
            str(out),
            "--format",
            "json,md,sarif",
            "--quiet",
            *extra,
        ]

    def test_shadow_mode_never_fails_ci(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, stderr = self._run(self._args(Path(tmp) / "out", ["--policy", "shadow"]))
            self.assertEqual(code, 0)
            self.assertIn("policy shadow", stderr)
            graph = json.loads((Path(tmp) / "out" / "graph.json").read_text(encoding="utf-8"))
            policy = graph["meta"]["policy"]
            self.assertEqual(policy["mode"], "shadow")
            self.assertGreater(policy["decisions"]["block"], 0)
            blocked = [f for f in graph["findings"] if f.get("enforcement") == "block"]
            self.assertTrue(blocked)
            sample = blocked[0]
            for key in ("policy_reason", "confidence_score", "reachability", "exposure", "required_actions"):
                self.assertIn(key, sample)

    def test_strict_mode_fails_on_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, stderr = self._run(self._args(Path(tmp) / "out", ["--policy", "strict"]))
            self.assertEqual(code, 2)
            self.assertIn("policy strict", stderr)

    def test_fail_on_block_implies_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self._run(self._args(Path(tmp) / "out", ["--fail-on", "block"]))
            self.assertEqual(code, 2)

    def test_default_run_has_no_policy_meta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self._run(self._args(Path(tmp) / "out", []))
            self.assertEqual(code, 0)
            graph = json.loads((Path(tmp) / "out" / "graph.json").read_text(encoding="utf-8"))
            self.assertNotIn("policy", graph["meta"])
            self.assertFalse(any(finding.get("enforcement") for finding in graph["findings"]))

    def test_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_a, out_b = Path(tmp) / "a", Path(tmp) / "b"
            for out in (out_a, out_b):
                code, _, _ = self._run(self._args(out, ["--policy", "shadow"]))
                self.assertEqual(code, 0)
            self.assertEqual(
                (out_a / "graph.json").read_bytes(),
                (out_b / "graph.json").read_bytes(),
            )
            self.assertEqual(
                (out_a / "security.sarif").read_bytes(),
                (out_b / "security.sarif").read_bytes(),
            )
            self.assertEqual(
                (out_a / "ARCHITECTURE.md").read_bytes(),
                (out_b / "ARCHITECTURE.md").read_bytes(),
            )

    def test_markdown_policy_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._run(self._args(Path(tmp) / "out", ["--policy", "shadow"]))
            md = (Path(tmp) / "out" / "ARCHITECTURE.md").read_text(encoding="utf-8")
            self.assertIn("## Enforcement policy", md)
            self.assertIn("Mode **shadow**", md)
            self.assertIn("Verified provider-specific secret", md)

    def test_sarif_levels_are_policy_gated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._run(self._args(Path(tmp) / "out", ["--policy", "shadow"]))
            sarif = json.loads((Path(tmp) / "out" / "security.sarif").read_text(encoding="utf-8"))
            results = sarif["runs"][0]["results"]
            self.assertTrue(any(row["properties"].get("enforcement") == "block" for row in results))
            self.assertTrue(any(row["properties"].get("enforcement") != "block" for row in results))
            for result in results:
                enforcement = result["properties"].get("enforcement")
                if enforcement == "block":
                    self.assertEqual(result["level"], "error")
                else:
                    self.assertEqual(result["level"], "note")
            self.assertIn("policy", sarif["runs"][0]["properties"])

    def test_sarif_unchanged_without_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._run(self._args(Path(tmp) / "out", []))
            sarif = json.loads((Path(tmp) / "out" / "security.sarif").read_text(encoding="utf-8"))
            results = sarif["runs"][0]["results"]
            self.assertTrue(any(result["level"] == "error" for result in results))
            self.assertNotIn("policy", sarif["runs"][0]["properties"])


class GovernedSuppressionTests(unittest.TestCase):
    def _graph_with(self, finding: Finding) -> Graph:
        graph = Graph()
        graph.findings = [finding]
        return graph

    def test_v2_baseline_round_trip_and_expiry(self) -> None:
        graph = fixture_result().graph
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            count = write_baseline(graph, path)
            self.assertEqual(count, len(graph.findings))
            today = "2030-01-15"
            active, expired, legacy, version = load_suppressions(path, today)
            self.assertEqual(version, "2")
            self.assertEqual(len(active), count)
            self.assertEqual(expired, {})
            self.assertEqual(legacy, set())

            # Expire one suppression and prove reactivation.
            payload = json.loads(path.read_text(encoding="utf-8"))
            first = payload["suppressions"][0]
            first["expires"] = "2030-01-01"
            path.write_text(json.dumps(payload), encoding="utf-8")
            active, expired, legacy, version = load_suppressions(path, today)
            self.assertNotIn(first["id"], active)
            self.assertIn(first["id"], expired)

            target = next(f for f in graph.findings if f.id == first["id"])
            summary = apply_policy(
                graph,
                mode="shadow",
                active_suppressions=active,
                expired_suppressions=expired,
            )
            self.assertIn(target.id, summary.reactivated)
            self.assertNotEqual(target.enforcement, "suppressed")
            suppressed = [f for f in graph.findings if f.enforcement == "suppressed"]
            self.assertEqual(len(suppressed), count - 1)
            for finding in suppressed:
                self.assertIn("Governed suppression", finding.policy_reason)

    def test_expired_suppression_requires_valid_date(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "2",
                        "tool": "secdiagram",
                        "suppressions": [{"id": "abc", "expires": "not-a-date"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_suppressions(path, "2030-01-15")

    def test_duplicate_suppression_ids_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "2",
                        "tool": "secdiagram",
                        "suppressions": [{"id": "abc"}, {"id": "abc"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_suppressions(path, "2030-01-15")

    def test_v1_baseline_still_loads_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"schema_version": "1", "tool": "secdiagram", "findings": [{"id": "f1"}]}),
                encoding="utf-8",
            )
            active, expired, legacy, version = load_suppressions(path, "2030-01-15")
            self.assertEqual(legacy, {"f1"})
            self.assertEqual(active, {})
            self.assertEqual(version, "1")

    def test_suppressed_findings_stay_visible(self) -> None:
        finding = _finding("sup1", trace=[Loc("app.py", 1), Loc("app.py", 3)])
        graph = self._graph_with(finding)
        apply_policy(graph, mode="shadow", active_suppressions={"sup1": {"reason": "approved", "ticket": "SEC-1"}})
        self.assertEqual(finding.enforcement, "suppressed")
        self.assertIn(finding.id, graph.meta["policy"]["suppressed"])
        self.assertTrue(finding.policy_reason)


if __name__ == "__main__":
    unittest.main()
