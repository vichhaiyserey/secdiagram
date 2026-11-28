"""End-to-end tests for Flutter/Dart analysis, SAST, misconfigurations, and exploitability."""

from __future__ import annotations

import unittest
from pathlib import Path

from secdiagram_core.analyzer import analyze
from secdiagram_core.exploitability import assess_graph
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.render_json import render_json
from secdiagram_core.render_sarif import render_sarif
from secdiagram_core.workspace import detect_repo_role

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "polyglot" / "flutter_app"


class FlutterSupportTests(unittest.TestCase):
    def test_workspace_role_detection(self) -> None:
        role = detect_repo_role(FIXTURE)
        self.assertEqual(role.role, "frontend")
        self.assertGreaterEqual(role.confidence, 0.85)
        self.assertTrue(any("Flutter" in ev for ev in role.evidence))

    def test_high_level_architecture_and_data_stores(self) -> None:
        result = analyze(FIXTURE)
        hla = build_high_level_architecture(FIXTURE, result.graph)
        self.assertIn("Dart / Flutter", hla.languages)
        sub = next((s for s in hla.subsystems if s.name == "mobile_banking_app"), None)
        self.assertIsNotNone(sub)
        assert sub is not None
        self.assertEqual(sub.tier, "ingress")
        self.assertEqual(sub.kind, "client")
        self.assertIn("Flutter", sub.technology)
        self.assertTrue(any(s.id == "db_sqlite" for s in hla.subsystems))

    def test_critical_sast_misconfig_and_exploitability(self) -> None:
        result = analyze(FIXTURE)
        graph = result.graph
        assess_graph(graph)

        self.assertGreaterEqual(graph.meta.get("polyglot_files", {}).get("dart", 0), 4)
        self.assertTrue(any(e.kind == "imports" for e in graph.edges))

        by_rule = {f.metadata.get("rule_id"): f for f in graph.findings if f.metadata.get("rule_id")}
        for expected_rule in (
            "PG-DART-SQL",
            "PG-DART-CMD",
            "PG-DART-WEBVIEW-JS",
            "PG-DART-SSRF",
            "PG-DART-TLS",
            "PG-DART-CRYPTO",
            "CFG-DART-INSECURE-STORAGE",
            "CFG-DART-WEBVIEW-ACCESS",
            "CFG-DART-RANDOM",
        ):
            self.assertIn(expected_rule, by_rule, f"Missing expected finding {expected_rule}")

        # Parameterized query in loadSafeUser must not produce a SQLi finding.
        sql_findings = [f for f in graph.findings if f.metadata.get("rule_id") == "PG-DART-SQL"]
        self.assertEqual(len(sql_findings), 1)
        sql_finding = sql_findings[0]
        self.assertEqual(sql_finding.severity, "critical")
        self.assertIn("flow", sql_finding.metadata)
        self.assertGreaterEqual(len(sql_finding.metadata["flow"]), 2)

        # Exploitability triage checks: focus on critical impact & evidence.
        sql_exp = sql_finding.metadata["exploitability"]
        self.assertEqual(sql_exp["impact_class"], "injection")
        self.assertEqual(sql_exp["provenance"], "proven-flow")
        self.assertIn(sql_exp["level"], ("likely", "plausible"))

        cmd_exp = by_rule["PG-DART-CMD"].metadata["exploitability"]
        self.assertEqual(cmd_exp["impact_class"], "rce")
        self.assertEqual(cmd_exp["level"], "likely")

        js_exp = by_rule["PG-DART-WEBVIEW-JS"].metadata["exploitability"]
        self.assertEqual(js_exp["impact_class"], "rce")
        self.assertEqual(js_exp["level"], "likely")

        tls_exp = by_rule["PG-DART-TLS"].metadata["exploitability"]
        self.assertEqual(tls_exp["impact_class"], "credential")

        storage_exp = by_rule["CFG-DART-INSECURE-STORAGE"].metadata["exploitability"]
        self.assertEqual(storage_exp["impact_class"], "misconfiguration")

    def test_deterministic_output(self) -> None:
        first = analyze(FIXTURE)
        second = analyze(FIXTURE)
        self.assertEqual(render_json(first.graph), render_json(second.graph))
        self.assertEqual(render_sarif(first.graph), render_sarif(second.graph))


if __name__ == "__main__":
    unittest.main()
