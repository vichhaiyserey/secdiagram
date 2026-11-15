"""Tests for web/API misconfiguration rules (C#, JS/TS, PHP, Go, Java)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.misconfig import analyze_misconfig
from secdiagram_core.model import Graph

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "misconfig"


def _rules(files: dict[str, str]) -> list[tuple[str, int]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        findings = analyze_misconfig(Graph(), root, sorted(files))
    return sorted((f.metadata["rule_id"], f.evidence[0].line) for f in findings)


class MisconfigFixtureTests(unittest.TestCase):
    def test_exact_findings(self) -> None:
        graph = run_analysis(AnalysisConfig(root=FIXTURE, security=True)).graph
        found = {
            (f.metadata["rule_id"], f.evidence[0].path, f.evidence[0].line)
            for f in graph.findings
            if str(f.metadata.get("rule_id", "")).startswith(("CFG-", "PG-JS-PROTO"))
        }
        cs, js, php, go, java = (
            "dotnet/Startup.cs", "node/app.ts", "php/security.php", "go/server.go", "java/SecurityConfig.java"
        )
        self.assertEqual(
            found,
            {
                ("CFG-CS-DEVPAGE", cs, 9), ("CFG-CS-JWT-SIG", cs, 15), ("CFG-CS-JWT-CLAIMS", cs, 16),
                ("CFG-CS-CORS", cs, 22), ("CFG-CS-COOKIE", cs, 28), ("CFG-CS-XXE", cs, 35),
                ("CFG-CS-RANDOM", cs, 39),
                ("CFG-JS-CORS", js, 7), ("CFG-JS-COOKIE", js, 12), ("CFG-JS-JWT-DECODE", js, 16),
                ("CFG-JS-JWT-NONE", js, 21), ("CFG-JS-JWT-DECODE", js, 21), ("CFG-JS-JWT-EXP", js, 21),
                ("CFG-JS-RANDOM", js, 25), ("PG-JS-PROTO", js, 34),
                ("CFG-PHP-CSRF", php, 6), ("CFG-PHP-CORS", php, 10), ("CFG-PHP-COOKIE", php, 14),
                ("CFG-PHP-XXE", php, 18), ("CFG-PHP-RANDOM", php, 21),
                ("CFG-GO-CORS", go, 13), ("CFG-GO-JWT-UNVERIFIED", go, 20), ("CFG-GO-COOKIE", go, 28),
                ("CFG-GO-RANDOM", go, 34),
                ("CFG-JAVA-CSRF", java, 10), ("CFG-JAVA-CORS", java, 16), ("CFG-JAVA-JWT-UNSIGNED", java, 22),
                ("CFG-JAVA-COOKIE", java, 27), ("CFG-JAVA-RANDOM", java, 32),
            },
        )

    def test_findings_have_cwe_evidence_and_recommendation(self) -> None:
        graph = run_analysis(AnalysisConfig(root=FIXTURE, security=True)).graph
        for finding in graph.findings:
            if str(finding.metadata.get("rule_id", "")).startswith("CFG-"):
                self.assertTrue(finding.cwe and finding.cwe.startswith("CWE-"))
                self.assertTrue(finding.recommendation)
                self.assertEqual(len(finding.evidence), 1)


class MisconfigSuppressionTests(unittest.TestCase):
    def test_jwt_decode_is_fine_when_file_verifies(self) -> None:
        self.assertEqual(
            _rules({"a.ts": "const h = jwt.decode(t, { complete: true }).header;\nconst c = jwt.verify(t, key);\n"}), []
        )

    def test_cors_wildcard_without_credentials_is_not_flagged(self) -> None:
        self.assertEqual(_rules({"a.ts": "app.use(cors({ origin: '*' }));\n"}), [])
        self.assertEqual(_rules({"a.go": "_ = cors.Config{AllowAllOrigins: true}\n"}), [])

    def test_go_rand_requires_math_rand_import(self) -> None:
        crypto = 'package a\nimport "crypto/rand"\nfunc t() { token := rand.Read(b) }\n'
        self.assertEqual(_rules({"a.go": crypto}), [])

    def test_patterns_in_comments_and_strings_are_ignored(self) -> None:
        text = (
            "// ValidateIssuerSigningKey = false\n"
            'var doc = "ValidateIssuerSigningKey = false";\n'
            "/* new Random() token */\n"
        )
        self.assertEqual(_rules({"a.cs": text}), [])

    def test_dev_page_guarded_by_environment(self) -> None:
        text = "if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }\n"
        self.assertEqual(_rules({"a.cs": text}), [])

    def test_non_security_randomness_is_ignored(self) -> None:
        self.assertEqual(_rules({"a.java": "int roll = new Random().nextInt(6);\n"}), [])


if __name__ == "__main__":
    unittest.main()
