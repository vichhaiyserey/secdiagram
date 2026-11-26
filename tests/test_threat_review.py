"""Threat evidence, conservative assessments and version comparison contracts."""

from __future__ import annotations

import contextlib
import copy
import errno
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.model import Finding, Graph, Loc, Node, stable_id
from secdiagram_core.risk import score_findings
from secdiagram_core.threat_model import build_threat_model, render_threat_model
from secdiagram_core.threat_review import (
    build_threat_snapshot,
    diff_threat_snapshots,
    load_threat_snapshot,
    render_snapshot,
    render_threat_diff,
    validate_snapshot,
)
from secdiagram_core.workspace import merge_graphs

FIXTURES = Path(__file__).parent / "fixtures"


def graph_with_flow() -> Graph:
    graph = Graph(meta={"name": "upload-service", "commit": "old", "security_enabled": True})
    graph.add_node(
        Node(
            "entry",
            "endpoint",
            "upload",
            "routes.upload",
            "routes.py",
            42,
            attrs={"routes": [{"method": "POST", "path": "/api/upload"}], "body_lines": 8},
        )
    )
    graph.add_node(
        Node(
            "sink", "function", "store", "storage.store", "storage.py", 10, attrs={"body_lines": 10}
        )
    )
    graph.findings = [
        Finding(
            "f1",
            "sql",
            "high",
            "Dynamic query receives request data",
            "May be exploitable",
            node_id="sink",
            confidence=0.85,
            evidence=[Loc("storage.py", 14)],
            trace=[Loc("routes.py", 44), Loc("storage.py", 14)],
            recommendation="Bind the upload identifier as a query parameter.",
        )
    ]
    score_findings(graph)
    return graph


def snapshot(graph: Graph) -> dict:
    return build_threat_snapshot(graph, build_threat_model(graph))


class ThreatRecordTests(unittest.TestCase):
    def test_source_facts_components_assets_and_ordered_flow(self) -> None:
        graph = graph_with_flow()
        threats = build_threat_model(graph)
        record = next(
            r for t in threats if t.boundary == "data" and t.stride == "T" for r in t.records
        )
        self.assertEqual(record["components"], ["entry", "sink"])
        self.assertEqual(
            {a["name"] for a in record["affected_assets"]}, {"routes.upload", "storage.store"}
        )
        self.assertEqual(
            record["evidence"],
            [
                {"path": "routes.py", "line": 44, "col": 0},
                {"path": "storage.py", "line": 14, "col": 0},
            ],
        )
        self.assertEqual(len(record["data_flows"]), 1)
        self.assertEqual(
            record["data_flows"][0]["hops"],
            [
                {"loc": "routes.py:44", "node": "entry", "role": "source"},
                {"loc": "storage.py:14", "node": "sink", "role": "sink"},
            ],
        )
        self.assertEqual(
            (record["severity"], record["confidence"], record["exploitability"]),
            ("high", 0.85, "plausible"),
        )
        self.assertNotIn("May be exploitable", " ".join(record["facts"]))
        self.assertIn("Potential injection", record["assessment"])
        self.assertIn("not prove", " ".join(record["assumptions"]))
        self.assertEqual(record["recommendation"], graph.findings[0].recommendation)
        self.assertIn("storage.py:14", record["verification"][0])
        validate_snapshot(build_threat_snapshot(graph, threats))
        self.assertEqual(
            next(t for t in threats if t.boundary == "data" and t.stride == "T").to_dict()[
                "records"
            ],
            [record],
        )

    def test_route_review_does_not_claim_missing_authorization_or_input_acceptance(self) -> None:
        graph = graph_with_flow()
        overview = next(
            t
            for t in build_threat_model(graph)
            if t.id == stable_id("threat", "internet", "S", "unauthenticated-entry")
        )
        self.assertEqual(overview.status, "review")
        records = [r for r in snapshot(graph)["threats"] if r["status"] == "review"]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(
            record["facts"],
            ["Route POST /api/upload has no detected authentication marker; see routes.py:42."],
        )
        self.assertEqual(
            (record["severity"], record["exploitability"], record["finding_ids"]),
            ("info", "unverified", []),
        )
        self.assertIn("not a confirmed authorization bypass", record["assessment"])
        self.assertIn("global middleware", record["assumptions"][0])
        self.assertIn("insufficient privileges", record["verification"][1])
        graph.nodes["entry"].attrs["auth"] = "anonymous"
        public = next(r for r in snapshot(graph)["threats"] if r["status"] == "review")
        self.assertIn("explicit anonymous-access marker", public["facts"][0])
        graph.nodes["entry"].attrs["auth"] = "required"
        self.assertEqual([r for r in snapshot(graph)["threats"] if r["status"] == "review"], [])

    def test_real_polyglot_route_evidence_and_authentication_markers(self) -> None:
        graph = run_analysis(AnalysisConfig(root=FIXTURES / "exposure", jobs=1)).graph
        reviews = [r for r in snapshot(graph)["threats"] if r["status"] == "review"]
        expected = {
            n.id
            for n in graph.nodes.values()
            if n.kind == "endpoint" and n.attrs.get("auth") != "required"
        }
        self.assertEqual({r["components"][0] for r in reviews}, expected)
        self.assertEqual(len(reviews), 8)
        for record in reviews:
            node = graph.nodes[record["components"][0]]
            self.assertEqual(record["evidence"], [node.evidence.to_dict()])
            self.assertIn(node.evidence.ref, record["facts"][0])
        self.assertEqual(
            {Path(r["evidence"][0]["path"]).suffix for r in reviews},
            {".cs", ".ts", ".php", ".go", ".java"},
        )

    def test_catalog_without_evidence_produces_no_findings_or_generic_advice(self) -> None:
        graph = Graph()
        model = snapshot(graph)
        self.assertEqual(model["threats"], [])
        self.assertEqual({c["stride"] for c in model["coverage"]}, set("STRIDE"))
        text = render_threat_model(graph)
        self.assertIn("No source-backed observations", text)
        self.assertNotIn("Apply rate limits", text)
        self.assertNotIn("Require authentication by default", text)
        self.assertIn("outside static analysis", text)

    def test_suppression_and_unlocated_or_unknown_findings_are_accounted_for(self) -> None:
        graph = graph_with_flow()
        graph.findings[0].baseline = True
        graph.nodes.clear()
        graph.findings.extend(
            [
                Finding("missing", "sql", "high", "Claim without a location", "m"),
                Finding(
                    "unknown",
                    "custom-category",
                    "medium",
                    "Custom claim",
                    "m",
                    evidence=[Loc("a.py", 3)],
                ),
            ]
        )
        model = snapshot(graph)
        self.assertEqual(model["threats"], [])
        self.assertEqual(model["unrepresented_findings"], ["missing", "unknown"])
        self.assertNotIn("f1", model["unrepresented_findings"])
        self.assertTrue(all(c["status"] != "observed" for c in model["coverage"]))

    def test_unresolved_component_falls_back_to_files_and_no_invented_flow(self) -> None:
        graph = Graph(
            findings=[
                Finding(
                    "tls",
                    "tls",
                    "medium",
                    "TLS verification disabled",
                    "m",
                    node_id="missing",
                    evidence=[Loc("client.py", 7), Loc("client.py", 8)],
                )
            ]
        )
        record = snapshot(graph)["threats"][0]
        self.assertEqual(record["components"], [])
        self.assertEqual(record["data_flows"], [])
        self.assertEqual(
            record["affected_assets"],
            [
                {
                    "id": stable_id("asset", "client.py"),
                    "kind": "file",
                    "name": "client.py",
                    "path": "client.py",
                }
            ],
        )
        self.assertEqual(record["exploitability"], "unverified")
        self.assertIn("ownership is unresolved", " ".join(record["assumptions"]))

    def test_duplicate_flow_rules_each_retain_their_trace(self) -> None:
        graph = graph_with_flow()
        other = copy.deepcopy(graph.findings[0])
        other.id, other.title = "f2", "Another SQL rule on the same sink"
        graph.findings.append(other)
        records = [
            r for r in snapshot(graph)["threats"] if r["boundary"] == "data" and r["stride"] == "T"
        ]
        self.assertEqual(len(records), 2)
        self.assertEqual({r["finding_ids"][0] for r in records}, {"f1", "f2"})
        self.assertEqual([len(r["data_flows"]) for r in records], [1, 1])

    def test_workspace_flow_references_are_remapped_without_mutating_inputs(self) -> None:
        graph = graph_with_flow()
        graph.findings[0].trace = []
        graph.findings[0].metadata["flow"] = [
            {"loc": "routes.py:44", "node": "entry", "role": "source"},
            {"loc": "storage.py:14", "node": "sink", "role": "sink"},
        ]
        original = copy.deepcopy(graph.findings[0].metadata)
        merged = merge_graphs({"uploads": graph}, {}, [])
        records = [
            r for r in snapshot(merged)["threats"] if r["boundary"] == "data" and r["stride"] == "T"
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(
            record["components"],
            sorted(
                [
                    stable_id("workspace", "uploads", "entry"),
                    stable_id("workspace", "uploads", "sink"),
                ]
            ),
        )
        self.assertEqual(
            [h["loc"] for h in record["data_flows"][0]["hops"]],
            ["uploads/routes.py:44", "uploads/storage.py:14"],
        )
        self.assertTrue(all(h["node"] in merged.nodes for h in record["data_flows"][0]["hops"]))
        self.assertEqual(graph.findings[0].metadata, original)

    def test_repeated_builds_and_input_order_are_byte_identical(self) -> None:
        graph = graph_with_flow()
        other = copy.deepcopy(graph.findings[0])
        other.id, other.title = "f2", "Another query rule"
        graph.findings.append(other)
        first = render_snapshot(snapshot(graph))
        markdown = render_threat_model(graph)
        graph.nodes = dict(reversed(list(graph.nodes.items())))
        graph.findings.reverse()
        self.assertEqual(first, render_snapshot(snapshot(graph)))
        self.assertEqual(markdown, render_threat_model(graph))

    def test_extended_sast_categories_are_classified_instead_of_silently_lost(self) -> None:
        expected = {
            "ldap": {"T", "I"},
            "xpath": {"T", "I"},
            "template": {"E"},
            "log": {"R"},
            "crypto": {"I"},
        }
        for category, strides in expected.items():
            with self.subTest(category=category):
                graph = Graph(
                    findings=[
                        Finding(
                            "test",
                            category,
                            "medium",
                            f"Detected {category} rule",
                            "m",
                            evidence=[Loc("app.py", 3)],
                        )
                    ]
                )
                model = snapshot(graph)
                self.assertEqual(model["unrepresented_findings"], [])
                self.assertEqual({r["stride"] for r in model["threats"]}, strides)
                self.assertEqual({r["finding_ids"][0] for r in model["threats"]}, {"test"})

    def test_unknown_flow_components_remain_explicitly_unresolved(self) -> None:
        graph = graph_with_flow()
        graph.findings[0].metadata["flow"] = [
            {"loc": "routes.py:44", "node": "entry", "role": "source"},
            {"loc": "storage.py:14", "node": "missing", "role": "sink"},
        ]
        record = next(r for r in snapshot(graph)["threats"] if r["stride"] == "T")
        self.assertEqual(record["components"], ["entry", "sink"])
        self.assertIsNone(record["data_flows"][0]["hops"][1]["node"])
        self.assertEqual(record["data_flows"][0]["hops"][1]["loc"], "storage.py:14")


class ThreatDiffTests(unittest.TestCase):
    def test_add_remove_change_and_noop_have_complete_review_evidence(self) -> None:
        graph = graph_with_flow()
        before = snapshot(graph)
        same = diff_threat_snapshots(before, copy.deepcopy(before))
        self.assertEqual(
            (
                same["added"],
                same["removed"],
                same["changed"],
                same["unchanged"],
                same["context_changes"],
            ),
            ([], [], [], 3, {}),
        )
        graph.meta["commit"] = "new"
        graph.findings[0].severity = "critical"
        after = snapshot(graph)
        diff = diff_threat_snapshots(before, after)
        self.assertEqual(len(diff["changed"]), 2)
        self.assertEqual(
            [c["fields"] for c in diff["changed"]],
            [["data_flows", "severity"], ["data_flows", "severity"]],
        )
        self.assertEqual(diff["changed"][0]["before"]["severity"], "high")
        self.assertEqual(diff["changed"][0]["after"]["severity"], "critical")
        self.assertEqual((diff["before"]["commit"], diff["after"]["commit"]), ("old", "new"))
        graph.findings.clear()
        removed = diff_threat_snapshots(before, snapshot(graph))
        self.assertEqual(len(removed["removed"]), 2)
        added = diff_threat_snapshots(snapshot(Graph()), before)
        self.assertEqual(added["added"], before["threats"])
        text = render_threat_diff(diff)
        self.assertIn("storage.py:14", text)
        self.assertIn("#### Before", text)
        self.assertIn("#### After", text)
        self.assertIn("not proven fixed", text)

    def test_line_shift_is_a_change_and_repeated_rule_instances_do_not_collapse(self) -> None:
        graph = graph_with_flow()
        graph.findings[0].trace = []
        duplicate = copy.deepcopy(graph.findings[0])
        duplicate.id, duplicate.evidence = "f2", [Loc("storage.py", 17)]
        graph.findings.append(duplicate)
        before = snapshot(graph)
        for finding in graph.findings:
            finding.evidence[0].line += 5
            finding.id += "moved"
        after = snapshot(graph)
        diff = diff_threat_snapshots(before, after)
        self.assertEqual(
            (len(diff["added"]), len(diff["removed"]), len(diff["changed"])), (0, 0, 4)
        )
        self.assertEqual(len({r["id"] for r in after["threats"]}), 5)
        self.assertTrue(
            all("evidence" in c["fields"] and "finding_ids" in c["fields"] for c in diff["changed"])
        )

    def test_scan_coverage_and_suppression_changes_are_visible(self) -> None:
        graph = graph_with_flow()
        before = snapshot(graph)
        graph.meta.update(
            {
                "exclude": ["storage.py"],
                "analysis": {"truncated": True},
                "security_baseline": {"suppressed": 1},
            }
        )
        graph.findings[0].baseline = True
        diff = diff_threat_snapshots(before, snapshot(graph))
        self.assertEqual(len(diff["removed"]), 2)
        self.assertIn("analysis", diff["context_changes"])
        self.assertEqual(diff["context_changes"]["analysis"]["after"]["exclude"], ["storage.py"])
        self.assertTrue(diff["context_changes"]["analysis"]["after"]["analysis"]["truncated"])
        self.assertIn("coverage", diff["context_changes"])
        self.assertIn("Analysis context changed", render_threat_diff(diff))

    def test_invalid_records_fail_instead_of_producing_a_clean_diff(self) -> None:
        good = snapshot(graph_with_flow())
        mutations = [
            lambda s: s.update(schema_version=2),
            lambda s: s.update(threats={}),
            lambda s: s["threats"].append(copy.deepcopy(s["threats"][0])),
            lambda s: s["threats"][0].update(confidence=float("nan")),
            lambda s: s["threats"][0].update(risk_score=True),
            lambda s: s["threats"][0].update(risk_score=10**1000),
            lambda s: s["threats"][0].update(evidence=[]),
            lambda s: s["threats"][0].update(facts=[]),
            lambda s: s["threats"][0].update(facts=[" "]),
            lambda s: s["threats"][0].update(verification=[]),
            lambda s: s["threats"][0].update(stride="UNKNOWN"),
            lambda s: s["threats"][0].update(id="untrusted\nmarkup"),
            lambda s: s["threats"][0].update(data_flows=[{"hops": [None]}]),
            lambda s: s["threats"][0].update(affected_assets=[{}]),
            lambda s: s["coverage"][0].update(record_count=1000),
            lambda s: s["threats"][0].pop("priority"),
            lambda s: s["threats"][0].update(
                data_flows=[{"hops": [{"loc": "a.py:2", "role": "sink"}]}]
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                bad = copy.deepcopy(good)
                mutation(bad)
                with self.assertRaises(ValueError):
                    diff_threat_snapshots(good, bad)

    def test_bounded_loader_duplicate_json_keys_and_nonfinite_constants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(render_snapshot(snapshot(graph_with_flow())), encoding="utf-8")
            self.assertEqual(len(load_threat_snapshot(path)["threats"]), 3)
            with mock.patch("secdiagram_core.threat_review.MAX_SNAPSHOT_BYTES", 50):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    load_threat_snapshot(path)
            for text in ('{"kind": "a", "kind": "b"}', '{"x": NaN}', '{"x": Infinity}'):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_threat_snapshot(path)


class ThreatReviewCliTests(unittest.TestCase):
    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_snapshots_and_no_security_or_dry_run_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, out = Path(tmp) / "repo", Path(tmp) / "out"
            root.mkdir()
            (root / "routes.py").write_text(
                "from flask import Flask, request\napp = Flask(__name__)\n@app.post('/api/upload')\ndef upload():\n    return request.args.get('name')\n",
                encoding="utf-8",
            )
            args = [
                "--dir",
                str(root),
                "--out",
                str(out),
                "--offline",
                "--format",
                "json,md",
                "--jobs",
                "1",
            ]
            with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network")):
                code, _, err = self.run_cli(args)
            self.assertEqual(code, 0, err)
            first = (out / "threat-model.json").read_bytes()
            model = load_threat_snapshot(out / "threat-model.json")
            self.assertEqual(len(model["threats"]), 1)
            self.assertIn("/api/upload", model["threats"][0]["facts"][0])
            self.assertIn(
                "**Verification:**", (out / "THREAT_MODEL.md").read_text(encoding="utf-8")
            )
            self.assertEqual(self.run_cli(args)[0], 0)
            self.assertEqual(first, (out / "threat-model.json").read_bytes())
            for extra in (["--no-security"], ["--dry-run"]):
                other = Path(tmp) / ("ns" if extra[0] == "--no-security" else "dry")
                code, _, err = self.run_cli(args + ["--out", str(other), *extra])
                self.assertEqual(code, 0, err)
                self.assertFalse((other / "threat-model.json").exists())
                self.assertFalse((other / "THREAT_MODEL.md").exists())

    def test_real_source_revision_diff_retains_evidence_and_rechecks_safe_counterpart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "service"
            root.mkdir()
            source = root / "routes.py"
            before_out, after_out = Path(tmp) / "before", Path(tmp) / "after"
            prefix = "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.get('/run')\ndef run():\n"
            source.write_text(
                prefix + "    return os.system(request.args.get('cmd'))\n", encoding="utf-8"
            )
            args = ["--dir", str(root), "--format", "json", "--offline", "--jobs", "1", "--quiet"]
            with mock.patch("os.system", side_effect=AssertionError("analyzed code executed")):
                code, _, err = self.run_cli(args + ["--out", str(before_out)])
                self.assertEqual(code, 0, err)
                before = load_threat_snapshot(before_out / "threat-model.json")
                observed = [r for r in before["threats"] if r["status"] == "observed"]
                self.assertEqual(len(observed), 1)
                self.assertEqual(
                    (observed[0]["stride"], observed[0]["exploitability"]), ("E", "likely")
                )
                self.assertIn({"path": "routes.py", "line": 6, "col": 0}, observed[0]["evidence"])
                source.write_text(prefix + "    return 'safe fixed response'\n", encoding="utf-8")
                code, _, err = self.run_cli(args + ["--out", str(after_out)])
                self.assertEqual(code, 0, err)
            code, stdout, err = self.run_cli(
                [
                    "threat-diff",
                    str(before_out / "threat-model.json"),
                    str(after_out / "threat-model.json"),
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(code, 0, err)
            diff = json.loads(stdout)
            self.assertEqual(diff["removed"], observed)
            self.assertEqual((diff["added"], diff["changed"], diff["unchanged"]), ([], [], 1))
            self.assertIn("not proven fixed", diff["note"])

    def test_workspace_writes_prefixed_evidence_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            repo = root / "api"
            repo.mkdir(parents=True)
            (repo / "app.py").write_text(
                "from flask import Flask\napp = Flask(__name__)\n@app.get('/health')\ndef health(): return 'ok'\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            code, _, err = self.run_cli(
                [
                    "--workspace",
                    str(root),
                    "--out",
                    str(out),
                    "--format",
                    "json,md",
                    "--offline",
                    "--jobs",
                    "1",
                    "--quiet",
                ]
            )
            self.assertEqual(code, 0, err)
            model = load_threat_snapshot(out / "threat-model.json")
            self.assertEqual(model["threats"][0]["evidence"][0]["path"], "api/app.py")
            context = model["analysis"]["workspace_analysis"]
            self.assertEqual(set(context["repositories"]), {"api"})
            self.assertEqual(context["unavailable_repositories"], [])
            self.assertEqual(context["repositories"]["api"]["analysis"]["files_parsed"], 1)
            self.assertTrue((out / "THREAT_MODEL.md").is_file())

    def test_diff_is_offline_machine_readable_and_does_not_analyze_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before, after = Path(tmp) / "old.json", Path(tmp) / "new.json"
            before.write_text(render_snapshot(snapshot(Graph())), encoding="utf-8")
            after.write_text(render_snapshot(snapshot(graph_with_flow())), encoding="utf-8")
            with (
                mock.patch(
                    "secdiagram_core.cli.run_analysis", side_effect=AssertionError("analysis")
                ),
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("network")),
            ):
                code, stdout, err = self.run_cli(
                    ["threat-diff", str(before), str(after), "--output", "json"]
                )
            self.assertEqual(code, 0, err)
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(len(payload["diff"]["added"]), 3)
            out = Path(tmp) / "diff.md"
            code, stdout, err = self.run_cli(
                ["threat-diff", str(before), str(after), "--out", str(out)]
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(stdout, "")
            self.assertIn("/api/upload", out.read_text(encoding="utf-8"))
            code, stdout, err = self.run_cli(
                ["threat-diff", str(before), str(after), "--format", "json"]
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(stdout), payload["diff"])

    def test_bad_input_is_actionable_and_input_files_cannot_be_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before, after = Path(tmp) / "old.json", Path(tmp) / "new.json"
            text = render_snapshot(snapshot(Graph()))
            before.write_text(text, encoding="utf-8")
            after.write_text("{}", encoding="utf-8")
            code, stdout, _ = self.run_cli(
                ["threat-diff", str(before), str(after), "--output", "json"]
            )
            self.assertEqual(code, 1)
            self.assertIn("readable threat-model.json", json.loads(stdout)["error"])
            code, stdout, _ = self.run_cli(
                ["threat-diff", str(before), str(after), "--out", str(before), "--output", "json"]
            )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stdout)["status"], "failed")
            self.assertEqual(before.read_text(encoding="utf-8"), text)
            code, stdout, _ = self.run_cli(
                ["threat-diff", str(before), str(Path(tmp) / "missing"), "--output", "json"]
            )
            self.assertEqual(code, 1)
            self.assertIn("cannot compare threat snapshots", json.loads(stdout)["error"])

    def test_hardlink_output_cannot_overwrite_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "snapshot.json"
            text = render_snapshot(snapshot(Graph()))
            before.write_text(text, encoding="utf-8")
            alias = Path(tmp) / "alias.json"
            try:
                alias.hardlink_to(before)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EPERM, errno.ENOTSUP, errno.ENOSYS}:
                    raise
                self.skipTest(f"Filesystem does not permit hard links: {exc}")
            code, stdout, _ = self.run_cli(
                ["threat-diff", str(before), str(before), "--out", str(alias), "--output", "json"]
            )
            self.assertEqual(code, 1)
            self.assertIn("aliases an input", json.loads(stdout)["error"])
            self.assertEqual(before.read_text(encoding="utf-8"), text)


if __name__ == "__main__":
    unittest.main()
