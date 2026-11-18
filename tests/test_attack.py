"""Tests for the MITRE ATT&CK evaluation engine, audit policy, and CLI audit gate."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.model import Finding, Graph, Loc, Node
from secdiagram_core.risk import score_findings
from secdiagram_core.threat_model import (
    ATTACK_RULES,
    DEFAULT_POLICY_YAML,
    evaluate_attack,
    parse_policy,
    policy_violations,
    render_attack_summary,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CACHE: dict[str | tuple[str, str], object] = {}


def _analyze(name: str):
    if name not in _CACHE:
        _CACHE[name] = run_analysis(AnalysisConfig(root=FIXTURES / name, security=True))
    return _CACHE[name]


def _scored(name: str):
    if ("scored", name) not in _CACHE:
        result = _analyze(name)
        score_findings(result.graph)
        _CACHE[("scored", name)] = result
    return _CACHE[("scored", name)]


def _graph_with(endpoint_auth: str | None, categories: tuple[str, ...]) -> Graph:
    graph = Graph()
    node = Node(
        "ep1",
        "endpoint",
        "ep1",
        "app.ep1",
        path="app/main.py",
        line=10,
        attrs={"auth": endpoint_auth} if endpoint_auth is not None else {},
    )
    graph.add_node(node)
    for index, category in enumerate(categories):
        graph.findings.append(
            Finding(
                id=f"f{index}",
                category=category,
                severity="high",
                title=f"Finding {category}",
                message="m",
                node_id=node.id,
                evidence=[Loc("app/main.py", 20 + index)],
                confidence=0.9,
            )
        )
    score_findings(graph)
    return graph


class AttackEvaluationTests(unittest.TestCase):
    def test_technique_ids_are_unique_and_well_formed(self) -> None:
        techniques = [rule.technique for rule in ATTACK_RULES]
        self.assertEqual(len(techniques), len(set(techniques)))
        for technique in techniques:
            self.assertRegex(technique, r"^T\d{4}$")

    def test_public_endpoint_without_mitigation_flags_t1190_review(self) -> None:
        graph = _graph_with(None, ())
        evals = {e.technique: e for e in evaluate_attack(graph)}
        t1190 = evals["T1190"]
        self.assertEqual(t1190.status, "review")
        self.assertIn("endpoint app.ep1 exposure=unknown", " ".join(t1190.evidence))
        self.assertEqual(t1190.priority, None)
        self.assertIn("authentication", t1190.missing_mitigation.lower())

    def test_authenticated_endpoints_do_not_flag_t1190(self) -> None:
        graph = _graph_with("required", ())
        evals = {e.technique: e for e in evaluate_attack(graph)}
        self.assertEqual(evals["T1190"].status, "no-evidence")

    def test_injection_finding_on_public_endpoint_makes_t1190_observed(self) -> None:
        graph = _graph_with("anonymous", ("sql",))
        evals = {e.technique: e for e in evaluate_attack(graph)}
        t1190 = evals["T1190"]
        self.assertEqual(t1190.status, "observed")
        self.assertEqual(t1190.finding_ids, ["f0"])
        self.assertGreater(t1190.max_score, 0.0)
        self.assertIn(t1190.priority or "", ("P0", "P1", "P2", "P3"))

    def test_tls_finding_flags_t1040_observed(self) -> None:
        graph = _graph_with(None, ("tls",))
        evals = {e.technique: e for e in evaluate_attack(graph)}
        self.assertEqual(evals["T1040"].status, "observed")
        self.assertIn("intercept", evals["T1040"].missing_mitigation.lower())

    def test_secret_finding_flags_t1552_observed(self) -> None:
        graph = _graph_with(None, ("secret",))
        evals = {e.technique: e for e in evaluate_attack(graph)}
        self.assertEqual(evals["T1552"].status, "observed")

    def test_baseline_findings_are_ignored(self) -> None:
        graph = _graph_with("anonymous", ("sql",))
        graph.findings[0].baseline = True
        evals = {e.technique: e for e in evaluate_attack(graph)}
        self.assertEqual(evals["T1190"].status, "review")

    def test_evaluation_is_deterministic(self) -> None:
        result = _scored("sample_app")
        first = evaluate_attack(result.graph)
        second = evaluate_attack(result.graph)
        self.assertEqual(
            [e.to_dict() for e in first],
            [e.to_dict() for e in second],
        )

    def test_sample_app_produces_observed_techniques(self) -> None:
        result = _scored("sample_app")
        evals = {e.technique: e for e in evaluate_attack(result.graph)}
        observed = {t for t, e in evals.items() if e.status == "observed"}
        self.assertIn("T1552", observed)  # API_KEY baked into source/Dockerfile


class PolicyParsingTests(unittest.TestCase):
    def test_default_policy_parses(self) -> None:
        policy = parse_policy(DEFAULT_POLICY_YAML)
        self.assertEqual(policy.fail_priorities, ("P0", "P1"))
        self.assertEqual(policy.min_score, 6.0)
        self.assertFalse(policy.include_review)
        self.assertEqual(policy.techniques, ())
        self.assertEqual(policy.ignore_techniques, ())

    def test_full_policy_document(self) -> None:
        text = "\n".join(
            [
                "# comment",
                "fail_priorities:",
                "  - P0",
                "  - P2",
                "min_score: 7.5",
                "include_review: true",
                "techniques: []",
                "ignore_techniques:",
                "  - T1068",
            ]
        )
        policy = parse_policy(text)
        self.assertEqual(policy.fail_priorities, ("P0", "P2"))
        self.assertEqual(policy.min_score, 7.5)
        self.assertTrue(policy.include_review)
        self.assertEqual(policy.techniques, ())
        self.assertEqual(policy.ignore_techniques, ("T1068",))

    def test_scalar_types(self) -> None:
        text = "min_score: 6\ninclude_review: false\n"
        policy = parse_policy(text)
        self.assertEqual(policy.min_score, 6.0)
        self.assertFalse(policy.include_review)

    def test_tabs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy("fail_priorities:\n\t- P0\n")

    def test_unknown_priority_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy("fail_priorities: [P9]\n")

    def test_unknown_technique_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy("ignore_techniques: [T9999]\n")

    def test_min_score_range_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy("min_score: 11.0\n")

    def test_malformed_line_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy("just some text\n")

    def test_policy_to_dict_round_trip(self) -> None:
        policy = parse_policy(DEFAULT_POLICY_YAML)
        data = policy.to_dict()
        self.assertEqual(data["fail_priorities"], ["P0", "P1"])


class PolicyGateTests(unittest.TestCase):
    def test_default_policy_flags_observed_high_risk(self) -> None:
        result = _scored("sample_app")
        evals = evaluate_attack(result.graph)
        violating = policy_violations(evals, parse_policy(DEFAULT_POLICY_YAML))
        self.assertTrue(violating)
        self.assertTrue(all(e.status == "observed" for e in violating))

    def test_ignore_techniques_suppresses_violation(self) -> None:
        result = _scored("sample_app")
        evals = evaluate_attack(result.graph)
        base = policy_violations(evals, parse_policy(DEFAULT_POLICY_YAML))
        self.assertTrue(base, "the unsuppressed control must contain violations")
        text = "fail_priorities: [P0, P1]\nmin_score: 6.0\nignore_techniques:\n"
        text += "".join(f"  - {e.technique}\n" for e in base)
        self.assertEqual(policy_violations(evals, parse_policy(text)), [])

    def test_higher_min_score_can_clear_gate(self) -> None:
        result = _scored("sample_app")
        evals = evaluate_attack(result.graph)
        self.assertEqual(policy_violations(evals, parse_policy("min_score: 10.0\n")), [])

    def test_include_review_adds_structural_signals(self) -> None:
        evals = evaluate_attack(_graph_with(None, ()))
        review_ids = {e.technique for e in evals if e.status == "review"}
        self.assertEqual(review_ids, {"T1190"})
        policy = parse_policy("include_review: true\nfail_priorities: [P0, P1, P2, P3]\nmin_score: 0.0\n")
        self.assertEqual({e.technique for e in policy_violations(evals, policy)}, {"T1190"})
        policy_strict = parse_policy("include_review: false\nfail_priorities: [P0, P1, P2, P3]\nmin_score: 0.0\n")
        self.assertEqual(policy_violations(evals, policy_strict), [])

    def test_technique_allowlist_restricts_gate(self) -> None:
        graph = _graph_with(None, ("tls", "secret"))
        evals = evaluate_attack(graph)
        policy = parse_policy("fail_priorities: [P0, P1, P2, P3]\nmin_score: 0.0\ntechniques:\n  - T1040\n")
        unfiltered = parse_policy("fail_priorities: [P0, P1, P2, P3]\nmin_score: 0.0\n")
        self.assertEqual({e.technique for e in policy_violations(evals, unfiltered)}, {"T1040", "T1552"})
        self.assertEqual({e.technique for e in policy_violations(evals, policy)}, {"T1040"})

    def test_summary_renders_violations_and_pass(self) -> None:
        evals = evaluate_attack(_graph_with(None, ("secret",)))
        policy = parse_policy(DEFAULT_POLICY_YAML)
        report = render_attack_summary(evals, policy, policy_violations(evals, policy))
        self.assertIn("T1552", report)
        self.assertIn("Policy violation:", report)
        self.assertNotIn("Policy: PASS", report)
        clean = render_attack_summary(evals, policy, [])
        self.assertIn("Policy: PASS", clean)


class AuditCliTests(unittest.TestCase):
    def test_audit_fails_on_sample_app_by_default(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["audit", str(FIXTURES / "sample_app"), "--quiet"])
        self.assertEqual(code, 1)

    def test_audit_prints_summary(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["audit", str(FIXTURES / "sample_app")])
        self.assertEqual(code, 1)
        out = stdout.getvalue()
        self.assertIn("ATT&CK audit:", out)
        self.assertIn("T1190", out)
        self.assertIn("T1552", out)
        self.assertIn("Policy violation:", out)

    def test_audit_policy_file_can_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.yaml"
            policy_path.write_text("min_score: 10.0\n", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["audit", str(FIXTURES / "sample_app"), "--policy", str(policy_path)])
            self.assertEqual(code, 0)
            self.assertIn("Policy: PASS", stdout.getvalue())

    def test_audit_json_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for index in range(2):
                path = Path(tmp) / f"audit-{index}.json"
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    main(["audit", str(FIXTURES / "sample_app"), "--json", str(path)])
                paths.append(path.read_text(encoding="utf-8"))
            self.assertEqual(paths[0], paths[1])
            payload = json.loads(paths[0])
            self.assertFalse(payload["pass"])
            self.assertTrue(payload["violations"])
            self.assertIn("policy_source", payload)

    def test_audit_local_policy_yaml_is_picked_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "policy.yaml").write_text("min_score: 10.0\n", encoding="utf-8")
            (Path(tmp) / "README.md").write_text("# sample\n", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["audit", tmp])
            self.assertEqual(code, 0)

    def test_audit_invalid_policy_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "bad.yaml"
            policy_path.write_text("fail_priorities: [P9]\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["audit", str(FIXTURES / "sample_app"), "--policy", str(policy_path)])
            self.assertEqual(code, 1)
            self.assertIn("invalid audit policy", stderr.getvalue())

    def test_audit_missing_directory_exits_one(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["audit", str(FIXTURES / "does_not_exist")])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
