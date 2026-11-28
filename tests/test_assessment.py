"""Canonical assessment and public-client secret classification tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.model import Finding, Graph, Loc
from secdiagram_core.policy import apply_policy
from secdiagram_core.render_sarif import render_sarif
from secdiagram_core.risk import score_findings
from secdiagram_core.threat_model import evaluate_attack


class PublicClientIdentifierTests(unittest.TestCase):
    def _analyze(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            return run_analysis(AnalysisConfig(root=root, security=True))

    def test_firebase_client_key_is_not_a_provider_secret(self) -> None:
        key = "AIza" + "a" * 35
        result = self._analyze({
            "google-services.json": json.dumps(
                {"client": [{"api_key": [{"current_key": key}]}]}, indent=2
            ),
        })
        secrets = [f for f in result.graph.findings if f.category == "secret"]
        self.assertEqual(len(secrets), 1)
        finding = secrets[0]
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.metadata.get("secret_kind"), "public_client_identifier")
        self.assertTrue(finding.metadata.get("public_client"))
        self.assertIn("Public client identifier", finding.title)

        t1552 = next(e for e in evaluate_attack(result.graph) if e.technique == "T1552")
        self.assertEqual(t1552.status, "no-evidence")

        apply_policy(result.graph, mode="strict")
        self.assertNotEqual(finding.enforcement, "block")

    def test_plist_client_key_is_not_a_provider_secret(self) -> None:
        key = "AIza" + "b" * 35
        result = self._analyze({
            "GoogleService-Info.plist": (
                "<plist><dict><key>API_KEY</key>\n"
                f"<string>{key}</string></dict></plist>\n"
            ),
        })
        secrets = [f for f in result.graph.findings if f.category == "secret"]
        self.assertTrue(secrets)
        self.assertTrue(all(
            f.metadata.get("secret_kind") == "public_client_identifier" for f in secrets
        ))

    def test_real_provider_token_still_blocks(self) -> None:
        token = "AKIA" + "A" * 16
        result = self._analyze({"app.py": f'AWS_KEY = "{token}"\n'})
        secrets = [f for f in result.graph.findings if f.category == "secret"]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].severity, "high")
        self.assertEqual(secrets[0].metadata.get("secret_kind"), "provider_token")
        t1552 = next(e for e in evaluate_attack(result.graph) if e.technique == "T1552")
        self.assertEqual(t1552.status, "observed")


class AssessmentConsistencyTests(unittest.TestCase):
    def _dependency_finding(self) -> Finding:
        return Finding(
            id="dep-1",
            category="dependency",
            severity="high",
            title="CVE-2023-39137 in archive",
            message="Imported dependency advisory without proven reachability.",
            node_id="pkg-archive",
            cwe="CWE-829",
            confidence=0.8,
            evidence=[Loc("pubspec.lock", 12)],
            recommendation="Upgrade archive to 3.3.8.",
            source="trivy",
            external_id="CVE-2023-39137",
            reachability="unmapped",
            exposure="isolated",
            metadata={
                "package": "archive",
                "cves": ["CVE-2023-39137"],
                "version": "3.1.6",
                "fixed_version": "3.3.8",
                "target": "pubspec.lock",
                "target_type": "pub",
                "report": "trivy.json",
            },
        )

    def test_dependency_signals_agree_across_risk_exploitability_and_json(self) -> None:
        graph = Graph()
        finding = self._dependency_finding()
        graph.findings = [finding]
        score_findings(graph)

        risk = finding.metadata["risk"]
        exploit = finding.metadata["exploitability"]
        assessment = finding.assessment
        self.assertEqual(risk["exposure"], "isolated")
        self.assertEqual(exploit["exposure"], "isolated")
        self.assertEqual(assessment["exposure"], "isolated")
        self.assertEqual(risk["reachability"], "unknown")
        self.assertEqual(exploit["reachability"], "unknown")
        self.assertEqual(assessment["reachability"], "unknown")
        self.assertEqual(risk["priority"], "P3")
        self.assertEqual(assessment["priority"], "P3")
        self.assertEqual(exploit["level"], "unlikely")
        self.assertEqual(assessment["level"], "unlikely")

        self.assertEqual(finding.rule["id"], "dependency:CWE-829")
        self.assertEqual(finding.provenance["trust"], "external-unverified")
        self.assertEqual(finding.remediation["commands"], ["flutter pub upgrade archive:^3.3.8"])

        payload = graph.to_dict()
        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("finding.assessment/v1", payload["schema_features"])
        item = payload["findings"][0]
        self.assertEqual(item["assessment"]["exposure"], "isolated")
        self.assertIn("rule", item)
        self.assertIn("provenance", item)
        self.assertIn("remediation", item)

        sarif = json.loads(render_sarif(graph))
        properties = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["assessment"]["exposure"], "isolated")
        self.assertEqual(properties["rule"]["id"], "dependency:CWE-829")
        self.assertIn("provenance", properties)
        self.assertIn("remediation", properties)
        self.assertFalse(properties["blocking"])

    def test_public_client_identifier_is_not_high_risk(self) -> None:
        graph = Graph()
        finding = Finding(
            id="pub-1",
            category="secret",
            severity="info",
            title="Public client identifier: API key",
            message="public config",
            confidence=0.9,
            evidence=[Loc("google-services.json", 5)],
            metadata={"secret_kind": "public_client_identifier", "public_client": True},
        )
        graph.findings = [finding]
        score_findings(graph)
        self.assertEqual(finding.metadata["risk"]["priority"], "P3")
        self.assertEqual(finding.exploitability, "unlikely")
        self.assertEqual(finding.assessment["recommended_action"], "restrict-provider-key")


if __name__ == "__main__":
    unittest.main()
