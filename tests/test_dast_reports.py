from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.dast_reports import (
    DASTReportError,
    correlate_runtime,
    load_dast_reports,
)
from secdiagram_core.policy import apply_policy

APP = """from flask import Flask

app = Flask(__name__)


@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    return str(user_id)


@app.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return str(order_id)
"""

ZAP = {
    "site": [
        {
            "@name": "http://localhost:8080",
            "@host": "localhost",
            "@port": "8080",
            "alerts": [
                {
                    "pluginid": "40012",
                    "alertRef": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "2",
                    "cweid": "79",
                    "desc": "<p>Cross-site scripting.</p>",
                    "solution": "<p>Encode output and validate input.</p>",
                    "tags": [{"tag": "OWASP_2021_A03"}],
                    "instances": [
                        {
                            "uri": "http://localhost:8080/users/42?name=%3Cscript%3E",
                            "method": "GET",
                            "param": "name",
                            "attack": "<script>alert(1)</script>",
                            "evidence": "<script>alert(1)</script>",
                            "response-header": "HTTP/1.1 200 OK\r\n",
                        },
                        {
                            "uri": "http://localhost:8080/admin/secret",
                            "method": "GET",
                            "param": "q",
                            "evidence": "admin",
                            "response-header": "HTTP/1.1 200 OK\r\n",
                        },
                    ],
                }
            ],
        }
    ]
}

NUCLEI = [
    {
        "template-id": "sqli-error-based",
        "info": {
            "name": "SQL Injection",
            "severity": "critical",
            "tags": ["sqli"],
            "classification": {"cwe-id": ["CWE-89"]},
            "description": "Error-based SQL injection",
        },
        "type": "http",
        "host": "http://localhost:8080",
        "matched-at": "http://localhost:8080/orders/7?id=1",
        "matcher-name": "error",
        "status-code": 200,
    },
    {
        "template-id": "exposed-env",
        "info": {"name": "Exposed .env", "severity": "high", "tags": ["exposure"]},
        "type": "http",
        "matched-at": "http://localhost:8080/.env",
        "matcher-name": "word",
        "status-code": 200,
    },
]


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
    return path


def _workspace() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    (root / "app.py").write_text(APP, encoding="utf-8")
    return tmp, root


class DastReportTests(unittest.TestCase):
    def test_zap_and_nuclei_normalization(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        zap = _write(root / "zap.json", ZAP)
        nuclei = _write_jsonl(root / "nuclei.jsonl", NUCLEI)
        findings, observations, summaries = load_dast_reports(
            root, ["app.py"], zap_report=zap, nuclei_report=nuclei
        )
        self.assertEqual(len(findings), 4)
        self.assertEqual(len(observations), 4)
        self.assertEqual([item["source"] for item in summaries], ["nuclei", "zap"])
        zap_finding = next(item for item in findings if item.source == "zap")
        self.assertEqual(zap_finding.severity, "high")
        self.assertEqual(zap_finding.cwe, "CWE-79")
        self.assertEqual(zap_finding.category, "xss")
        self.assertEqual(zap_finding.metadata["method"], "GET")
        self.assertEqual(zap_finding.metadata["runtime"]["path"], "/users/42")
        nuclei_finding = next(
            item for item in findings if item.metadata.get("template_id") == "sqli-error-based"
        )
        self.assertEqual(nuclei_finding.severity, "critical")
        self.assertEqual(nuclei_finding.cwe, "CWE-89")
        self.assertEqual(nuclei_finding.category, "sql")
        self.assertEqual(nuclei_finding.metadata["status_code"], 200)

    def test_runtime_correlation_matches_templated_routes(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        zap = _write(root / "zap.json", ZAP)
        nuclei = _write_jsonl(root / "nuclei.jsonl", NUCLEI)
        result = run_analysis(
            AnalysisConfig(root=root, zap_report=zap, nuclei_report=nuclei)
        )
        graph = result.graph
        runtime = graph.meta["runtime_analysis"]
        self.assertEqual(runtime["requests"], 4)
        self.assertEqual(runtime["matched_requests"], 2)
        self.assertEqual(runtime["unmatched_requests"], 2)
        self.assertEqual(runtime["endpoints_total"], 2)
        self.assertEqual(runtime["endpoints_observed"], 2)
        self.assertEqual(runtime["confirmed_findings"], 4)
        self.assertEqual(runtime["runtime_only_count"], 2)
        self.assertEqual(
            runtime["runtime_only_endpoints"], ["ANY /.env", "GET /admin/secret"]
        )
        observed = {
            node.qualname: node.attrs["runtime_observed"]
            for node in graph.nodes.values()
            if "runtime_observed" in node.attrs
        }
        self.assertEqual(observed["app.get_user"]["requests"], 1)
        self.assertEqual(observed["app.get_user"]["sources"], ["zap"])
        self.assertEqual(observed["app.get_order"]["requests"], 1)
        self.assertEqual(observed["app.get_order"]["sources"], ["nuclei"])
        matched = [
            finding
            for finding in graph.findings
            if finding.source == "zap" and finding.node_id is not None
        ]
        self.assertEqual(len(matched), 1)
        self.assertTrue(matched[0].metadata["runtime_confirmed"])
        self.assertEqual(matched[0].evidence[0].path, "app.py")
        self.assertEqual(matched[0].metadata["runtime"]["matched_route"], "GET /users/<user_id>")

    def test_runtime_confirmed_findings_can_block(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        zap = _write(root / "zap.json", ZAP)
        nuclei = _write_jsonl(root / "nuclei.jsonl", NUCLEI)
        result = run_analysis(
            AnalysisConfig(root=root, zap_report=zap, nuclei_report=nuclei)
        )
        apply_policy(result.graph, mode="strict")
        by_path = {
            finding.metadata["runtime"]["path"]: finding
            for finding in result.graph.findings
            if isinstance(finding.metadata.get("runtime"), dict)
        }
        matched_zap = by_path["/users/42"]
        self.assertEqual(matched_zap.enforcement, "block")
        self.assertEqual(matched_zap.evidence_quality, "externally_verified")
        self.assertEqual(matched_zap.reachability, "externally_reachable")
        self.assertEqual(matched_zap.exposure, "public")
        self.assertEqual(matched_zap.metadata["risk"]["exposure"], "public")
        self.assertEqual(matched_zap.metadata["risk"]["evidence"], "runtime-observed")
        self.assertIn("Reproduce the runtime finding", matched_zap.required_actions[0])
        unmatched_zap = by_path["/admin/secret"]
        self.assertEqual(unmatched_zap.enforcement, "review")
        self.assertIn("Blocking withheld", unmatched_zap.policy_reason)
        matched_nuclei = by_path["/orders/7"]
        self.assertEqual(matched_nuclei.enforcement, "block")
        self.assertEqual(matched_nuclei.confidence_score, 1.0)

    def test_runtime_meta_and_node_annotations_are_deterministic(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        zap = _write(root / "zap.json", ZAP)
        nuclei = _write_jsonl(root / "nuclei.jsonl", NUCLEI)
        first = run_analysis(AnalysisConfig(root=root, zap_report=zap, nuclei_report=nuclei))
        second = run_analysis(AnalysisConfig(root=root, zap_report=zap, nuclei_report=nuclei))
        self.assertEqual(
            json.dumps(first.graph.to_dict(), sort_keys=True),
            json.dumps(second.graph.to_dict(), sort_keys=True),
        )

    def test_cli_imports_dast_reports_and_renders_runtime_context(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        out = root / "out"
        zap = _write(root / "zap.json", ZAP)
        nuclei = _write_jsonl(root / "nuclei.jsonl", NUCLEI)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(
                [
                    "--dir",
                    str(root),
                    "--out",
                    str(out),
                    "--format",
                    "json,sarif",
                    "--zap-report",
                    str(zap),
                    "--nuclei-report",
                    str(nuclei),
                    "--security-report",
                    "md",
                    "--quiet",
                ]
            )
        self.assertEqual(code, 0, stderr.getvalue())
        payload = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        sources = {finding.get("source") for finding in payload["findings"]}
        self.assertIn("zap", sources)
        self.assertIn("nuclei", sources)
        self.assertEqual(payload["meta"]["runtime_analysis"]["matched_requests"], 2)
        report_sources = {item["source"] for item in payload["meta"]["external_reports"]}
        self.assertEqual(report_sources, {"nuclei", "zap"})
        sarif = json.loads((out / "security.sarif").read_text(encoding="utf-8"))
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("zap:xss:CWE-79", rule_ids)
        self.assertIn("nuclei:sql:CWE-89", rule_ids)
        runtime_results = [
            result
            for result in sarif["runs"][0]["results"]
            if result["properties"].get("runtimeConfirmed")
        ]
        self.assertTrue(runtime_results)
        markdown = (out / "SECURITY_REVIEW.md").read_text(encoding="utf-8")
        self.assertIn("Runtime evidence", markdown)
        self.assertIn("Runtime-confirmed", markdown)

    def test_invalid_reports_raise(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        bad_json = root / "bad.json"
        bad_json.write_text("{not json", encoding="utf-8")
        with self.assertRaises(DASTReportError):
            load_dast_reports(root, ["app.py"], zap_report=bad_json)
        bad_jsonl = root / "bad.jsonl"
        bad_jsonl.write_text("{not json}\n", encoding="utf-8")
        with self.assertRaises(DASTReportError):
            load_dast_reports(root, ["app.py"], nuclei_report=bad_jsonl)
        missing_sites = _write(root / "not-zap.json", {"alerts": []})
        with self.assertRaises(DASTReportError):
            load_dast_reports(root, ["app.py"], zap_report=missing_sites)

    def test_correlate_runtime_without_observations_is_empty(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        result = run_analysis(AnalysisConfig(root=root))
        summary = correlate_runtime(result.graph, [])
        self.assertEqual(summary["requests"], 0)
        self.assertEqual(summary["endpoints_observed"], 0)
        self.assertEqual(summary["confirmed_findings"], 0)


if __name__ == "__main__":
    unittest.main()
