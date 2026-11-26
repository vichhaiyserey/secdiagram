import tempfile
import unittest
from pathlib import Path

from secdiagram_core.dependency_graph import add_inventory
from secdiagram_core.dependency_inventory import pub_inventory
from secdiagram_core.dependency_reports import import_reports
from secdiagram_core.model import Graph


class DependencyInventoryTests(unittest.TestCase):
    def test_pub_and_trivy_match_the_exact_lockfile_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "pubspec.yaml").write_text("dependencies:\n  dio: ^5.0.0\n", encoding="utf-8")
            (root / "pubspec.lock").write_text(
                'packages:\n  dio:\n    dependency: "direct main"\n    version: "5.4.0"\n'
                '  adapter:\n    dependency: transitive\n    version: "1.0.0"\n',
                encoding="utf-8",
            )
            packages, warnings = pub_inventory(root, ["pubspec.yaml", "pubspec.lock"])
            self.assertEqual(warnings, [])
            self.assertEqual([(p.name, p.scope, p.version) for p in packages], [
                ("adapter", "transitive", "1.0.0"), ("dio", "direct", "5.4.0"),
            ])
            graph = Graph()
            add_inventory(graph, packages)
            report = root / "report.json"
            report.write_text(
                '{"Results":[{"Target":"pubspec.lock","Vulnerabilities":['
                '{"VulnerabilityID":"TEST-1","PkgName":"dio","InstalledVersion":"5.4.0"},'
                '{"VulnerabilityID":"TEST-2","PkgName":"dio","InstalledVersion":"5.0.0"},null]}]}',
                encoding="utf-8",
            )
            matched, unmatched = import_reports(graph, report, None)
            self.assertEqual(graph.nodes[matched.node_id].name, "dio")
            self.assertEqual(matched.reachability, "unmapped")
            self.assertIsNone(unmatched.node_id)
            self.assertEqual(graph.meta["dependency_reports"][0]["invalid_records"], 1)

    def test_qualified_call_path_and_conservative_vex(self):
        import json

        from secdiagram_core.analyzer import analyze
        from secdiagram_core.policy import evaluate_finding
        from secdiagram_core.render_vex import render_vex

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pubspec.yaml").write_text("dependencies:\n  dio: any\n", encoding="utf-8")
            (root / "pubspec.lock").write_text(
                "packages:\n  dio:\n    version: 5.4.0\n", encoding="utf-8",
            )
            (root / "main.dart").write_text(
                "import 'package:dio/dio.dart' as dio;\nvoid main() { dio.Dio(); }\n",
                encoding="utf-8",
            )
            report = root / "scanner.json"
            report.write_text(json.dumps({"Results": [{"Target": "pubspec.lock", "Vulnerabilities": [{
                "PkgName": "dio", "InstalledVersion": "5.4.0", "VulnerabilityID": "TEST-1",
                "Severity": "CRITICAL",
            }]}]}), encoding="utf-8")
            result = analyze(root, trivy_report=report)
            finding = next(f for f in result.graph.findings if f.source == "trivy")
            self.assertEqual(finding.reachability, "reachable")
            self.assertEqual(finding.exposure, "internal")
            self.assertEqual(finding.metadata["dependency_path"][-1], finding.node_id)
            self.assertNotEqual(evaluate_finding(result.graph, finding).enforcement, "blocking")
            vex = json.loads(render_vex(result))
            self.assertEqual(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_sbom_advisory_uses_component_reference(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "components": [
                    {"bom-ref": "first", "name": "example", "version": "1"},
                    {"bom-ref": "second", "name": "example", "version": "2"},
                ],
                "dependencies": [{"ref": "first", "dependsOn": ["second"]}],
                "vulnerabilities": [{
                    "id": "TEST-1", "ratings": [{"severity": "critical"}],
                    "affects": [{"ref": "second"}, {"ref": "missing"}],
                }],
            }), encoding="utf-8")
            graph = Graph()
            finding, = import_reports(graph, None, path)
            self.assertEqual(finding.metadata["version"], "2")
            self.assertEqual(finding.reachability, "unmapped")
            self.assertEqual(graph.edges[0].dst, finding.node_id)
            self.assertEqual(graph.meta["dependency_reports"][0]["invalid_records"], 1)

    def test_offline_audit_exposes_invalid_report_warning(self):
        import contextlib
        import io
        import json

        from secdiagram_core.cli import audit_main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.dart").write_text("void main() {}", encoding="utf-8")
            source = root / "bad.json"
            source.write_text("{", encoding="utf-8")
            output = root / "audit.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                audit_main([
                    str(root), "--offline", "--trivy-report", str(source),
                    "--json", str(output), "--quiet",
                ])
            self.assertIn("coverage may be incomplete", stderr.getvalue())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["dependency_reports"][0]["invalid_records"], 1)
            self.assertEqual(payload["dependency_findings"], [])

    def test_reviewed_symbol_gate_checks_exact_version_symbol_and_source(self):
        import contextlib
        import hashlib
        import io
        import json

        from secdiagram_core.cli import audit_main

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "import 'package:demo/demo.dart' as demo;\nvoid receive(MethodCall call) { demo.check(); }\n"
            (root / "main.dart").write_text(source, encoding="utf-8")
            (root / "pubspec.yaml").write_text("dependencies:\n  demo: any\n", encoding="utf-8")
            (root / "pubspec.lock").write_text(
                "packages:\n  demo:\n    version: 1.2.3\n", encoding="utf-8",
            )

            def write(name, value):
                path = root / name
                path.write_text(json.dumps(value), encoding="utf-8")
                return str(path)

            advisory = "CVE-2099-99999"
            report = write("trivy.json", {"Results": [{
                "Target": "pubspec.lock", "Vulnerabilities": [{
                    "PkgName": "demo", "InstalledVersion": "1.2.3",
                    "VulnerabilityID": advisory, "Severity": "CRITICAL",
                }],
            }]})
            kev = write("kev.json", {"vulnerabilities": [{"cveID": advisory}]})
            review = {
                "target": "pubspec.lock", "package": "demo", "version": "1.2.3",
                "advisory": advisory, "library": "package:demo/demo.dart", "symbol": "check",
                "path": "main.dart", "line": 2,
                "source_sha256": hashlib.sha256((root / "main.dart").read_bytes()).hexdigest(),
            }
            args = [str(root), "--offline", "--quiet", "--trivy-report", report, "--advisory-db", kev]
            out = root / "audit.json"
            args.extend(["--json", str(out)])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit_main(args), 0)
                reviews = write("reviews.json", {"version": 1, "reviews": [review]})
                self.assertEqual(audit_main([*args, "--dependency-review", reviews]), 1, out.read_text())
                self.assertEqual(json.loads(out.read_text())["dependency_violations"][0]["symbol"], "check")
                for key, value in (("symbol", "other"), ("version", "1.2.4"), ("source_sha256", "0" * 64)):
                    write("reviews.json", {"version": 1, "reviews": [{**review, key: value}]})
                    self.assertEqual(audit_main([*args, "--dependency-review", reviews]), 0)
                    self.assertEqual(json.loads(out.read_text())["dependency_violations"], [])
                shadowed = source.replace("demo.check();", "final demo = localObject; demo.check();")
                (root / "main.dart").write_text(shadowed, encoding="utf-8")
                updated_hash = hashlib.sha256((root / "main.dart").read_bytes()).hexdigest()
                write("reviews.json", {"version": 1, "reviews": [{**review, "source_sha256": updated_hash}]})
                self.assertEqual(audit_main([*args, "--dependency-review", reviews]), 0)
                self.assertEqual(json.loads(out.read_text())["dependency_violations"], [])

    def test_remediation_fields_agree_across_exports(self):
        import json

        from secdiagram_core.dependency_remediation import dependency_details
        from secdiagram_core.model import Finding, Loc, Node
        from secdiagram_core.render_html import render_html
        from secdiagram_core.render_json import render_json
        from secdiagram_core.render_markdown import render_markdown
        from secdiagram_core.render_sarif import render_sarif
        from secdiagram_core.render_vex import render_vex

        graph = Graph()
        graph.add_node(Node("pkg", "dependency", "example", "pub:example"))
        finding = Finding(
            "finding", "dependency", "high", "Dependency advisory", "Scanner evidence",
            node_id="pkg", source="trivy", external_id="TEST-1", reachability="reachable",
            recommendation="Review upgrade to 2.0.0",
            evidence=[Loc("pubspec.lock", 3), Loc("main.dart", 8)],
            metadata={
                "package": "example", "version": "1.0.0", "resolved_version": "1.0.0",
                "fixed_version": "2.0.0", "target": "pubspec.lock", "dependency_path": ["entry", "pkg"],
            },
        )
        graph.findings.append(finding)
        expected = dependency_details(finding)
        self.assertEqual(json.loads(render_json(graph))["findings"][0]["dependency"], expected)
        self.assertEqual(json.loads(render_sarif(graph))["runs"][0]["results"][0]["properties"]["dependency"], expected)
        for report in (render_markdown(graph), render_html(graph, offline=True)):
            for evidence in ("TEST-1", "example", "main.dart:8", "2.0.0", "in_triage"):
                self.assertIn(evidence, report)
        vex = json.loads(render_vex(graph))
        vulnerability = vex["vulnerabilities"][0]
        self.assertEqual(vulnerability["analysis"]["state"], expected["disposition"])
        self.assertEqual(vulnerability["recommendation"], expected["recommendation"])
        self.assertEqual(vulnerability["affects"][0]["ref"], vex["components"][0]["bom-ref"])
        self.assertIn(
            {"name": "secdiagram:dependency:fixed_version", "value": "2.0.0"},
            vulnerability["properties"],
        )

    def test_duplicate_advisories_merge_only_within_the_same_scope(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pubspec.yaml").write_text("dependencies:\n  demo: any\n", encoding="utf-8")
            (root / "pubspec.lock").write_text(
                "packages:\n  demo:\n    version: 2.0.0\n", encoding="utf-8",
            )
            packages, _ = pub_inventory(root, ["pubspec.yaml"])
            graph = Graph()
            add_inventory(graph, packages)
            base = {
                "VulnerabilityID": "cve-2099-99999", "PkgName": "demo",
                "InstalledVersion": "1.0.0", "FixedVersion": "2.0.0", "Severity": "LOW",
            }
            alternate = {**base, "VulnerabilityID": "CVE-2099-99999", "FixedVersion": "3.0.0", "Severity": "HIGH"}
            report = root / "trivy.json"
            results = [
                {"Target": "pubspec.lock", "Type": "pub", "Vulnerabilities": [base, alternate]},
                {"Target": "pubspec.lock", "Type": "npm", "Vulnerabilities": [base]},
                {"Target": "other/pubspec.lock", "Type": "pub", "Vulnerabilities": [base]},
            ]

            def load():
                report.write_text(json.dumps({"Results": results}), encoding="utf-8")
                return sorted((finding.to_dict() for finding in import_reports(graph, report, None)),
                              key=lambda item: item["id"])

            findings = load()
            self.assertEqual(len(findings), 3)
            merged = next(finding for finding in findings if finding["metadata"].get("duplicate_records"))
            self.assertEqual(merged["severity"], "high")
            self.assertFalse(merged["metadata"]["fixed_in_inventory"])
            self.assertEqual(merged["metadata"]["fixed_versions"], ["2.0.0", "3.0.0"])
            self.assertTrue(all(finding["node_id"] is None for finding in findings))
            results[0]["Vulnerabilities"].reverse()
            results.reverse()
            self.assertEqual(load(), findings)
