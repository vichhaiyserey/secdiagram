"""Tests for the C#/.NET, JavaScript/TypeScript, PHP and Go analyzers."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.model import Graph
from secdiagram_core.polyglot_index import (
    PolyglotIndex,
    _views,
    build_polyglot_graph,
    parse_polyglot_file,
)
from secdiagram_core.polyglot_security import analyze_polyglot_security
from secdiagram_core.render_mermaid import render_mermaid
from secdiagram_core.taint_flows import build_taint_flows, render_taint_mermaid

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "polyglot"

_RESULTS: dict[str, AnalysisResult] = {}


def _analyze(name: str) -> AnalysisResult:
    if name not in _RESULTS:
        _RESULTS[name] = run_analysis(AnalysisConfig(root=FIXTURES / name, security=True))
    return _RESULTS[name]


def _pg_findings(result: AnalysisResult) -> set[tuple[str, str, int]]:
    return {
        (f.metadata["rule_id"], f.evidence[0].path, f.evidence[0].line)
        for f in result.graph.findings
        if str((f.metadata or {}).get("rule_id", "")).startswith("PG-")
    }


def _routes(result: AnalysisResult) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for node in result.graph.nodes.values():
        if node.kind == "endpoint":
            out.setdefault(node.name, set()).update(f"{r['method']} {r['path']}" for r in node.attrs.get("routes", []))
    return out


def _edges(result: AnalysisResult, kind: str, resolution: str) -> set[tuple[str, str]]:
    graph = result.graph
    return {
        (graph.nodes[e.src].name, graph.nodes[e.dst].name)
        for e in graph.edges
        if e.kind == kind and e.resolution == resolution
    }


class TokenizerTests(unittest.TestCase):
    def test_views_keep_offsets_and_blank_strings_and_comments(self) -> None:
        text = 'var s = "a { b"; // } comment\nvar t = @"C:\\x "" }";\n/* { */ class A { }\n'
        code, masked = _views(text, "csharp")
        self.assertEqual(len(code), len(text))
        self.assertEqual(code.count("\n"), text.count("\n"))
        self.assertNotIn("comment", code)
        self.assertIn('"a { b"', code)
        self.assertEqual(masked.count("{"), 1)
        self.assertEqual(masked.count("}"), 1)

    def test_php_inline_html_and_hash_comments_are_ignored(self) -> None:
        text = "<html>{ it's }</html>\n<?php # comment {\n$a = '{'; ?>\n<p>{</p>\n<?php function f() { return 1; }\n"
        pf = parse_polyglot_file("page.php", text)
        assert pf is not None
        self.assertEqual([(s.kind, s.name, s.line) for s in pf.symbols], [("function", "f", 5)])

    def test_go_raw_strings_and_runes(self) -> None:
        text = "package x\n\nvar q = `SELECT {\n}`\nvar r = '{'\n\nfunc Run() {\n\treturn\n}\n"
        pf = parse_polyglot_file("x/run.go", text)
        assert pf is not None
        run = next(s for s in pf.symbols if s.name == "Run")
        self.assertEqual((run.line, run.end_line), (7, 9))

    def test_malformed_sources_do_not_crash(self) -> None:
        samples = {
            "a.cs": "public class A { public void M( { \"unterminated",
            "b.ts": "export function f(a { `${ ",
            "c.php": "<?php class C { function f($x { echo \"",
            "d.go": "package d\nfunc F( {\n\"",
        }
        for path, text in samples.items():
            self.assertIsNotNone(parse_polyglot_file(path, text), path)

    def test_declaration_files_are_skipped(self) -> None:
        self.assertIsNone(parse_polyglot_file("types/index.d.ts", "export declare function f(): void;"))

    def test_adversarial_input_is_bounded(self) -> None:
        # Thousands of unclosed calls/braces and sinks: indexing, graph and SAST
        # must stay linear (bracket pairs are computed once per file).
        hostile = {
            "h.ts": "app.get('/x', (req, res) => {" * 3000 + "\"'`" * 20000,
            "h.cs": "public void M(" * 5000 + "{" * 20000,
            "h.php": "<?php " + "Route::get('/a', function () {" * 3000,
            "h.go": "package h\n" + "r.GET(\"/x\", func(c *gin.Context) {\n" * 3000,
            "s.ts": "exec(" * 20000 + "fetch(req.query.x" * 5000,
        }
        for path, text in hostile.items():
            start = time.perf_counter()
            pf = parse_polyglot_file(path, text)
            assert pf is not None
            index = PolyglotIndex(files={path: pf})
            graph = Graph()
            build_polyglot_graph(graph, index)
            analyze_polyglot_security(graph, index)
            self.assertLess(time.perf_counter() - start, 5.0, path)


class CSharpTests(unittest.TestCase):
    def test_routes(self) -> None:
        routes = _routes(_analyze("csharp_api"))
        self.assertEqual(routes["GetByName"], {"GET /api/Products/{name}"})
        self.assertEqual(routes["Export"], {"POST /api/Products/export"})
        self.assertEqual(routes["GET /api/v2/search"], {"GET /api/v2/search"})
        self.assertEqual(routes["GET /api/v2/health"], {"GET /api/v2/health"})

    def test_architecture_edges(self) -> None:
        result = _analyze("csharp_api")
        self.assertIn(("ProductsController", "ProductService"), _edges(result, "calls", "injected"))
        self.assertIn(("ShopDbContext", "Product"), _edges(result, "calls", "dbset"))

    def test_findings_exact(self) -> None:
        ctrl = "src/Shop.Api/Controllers/ProductsController.cs"
        svc = "src/Shop.Api/Services/ProductService.cs"
        self.assertEqual(
            _pg_findings(_analyze("csharp_api")),
            {
                ("PG-CS-SQL", ctrl, 27),
                ("PG-CS-CMD", ctrl, 45),
                ("PG-CS-SSRF", ctrl, 54),
                ("PG-CS-REDIRECT", ctrl, 60),
                ("PG-CS-SQL", "src/Shop.Api/Program.cs", 14),
                ("PG-CS-SQL", "src/Shop.Api/Data/OrderRepository.cs", 17),
                ("PG-CS-DESER", svc, 21),
                ("PG-CS-CRYPTO", svc, 26),
                ("PG-CS-TLS", svc, 32),
            },
        )

    def test_tainted_sql_has_trace_and_severity(self) -> None:
        finding = next(
            f for f in _analyze("csharp_api").graph.findings
            if f.metadata.get("rule_id") == "PG-CS-SQL" and f.evidence[0].line == 27
        )
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual([loc.line for loc in finding.trace], [23, 26, 27])
        self.assertIsNotNone(finding.node_id)


class JavaScriptTests(unittest.TestCase):
    def test_routes(self) -> None:
        routes = _routes(_analyze("node_api"))
        self.assertEqual(routes["listUsers"], {"GET /users"})
        self.assertEqual(routes["findOne"], {"GET /orders/:id"})
        self.assertEqual(routes["create"], {"POST /orders"})
        self.assertEqual(routes["GET"], {"GET /api/items/{id}"})
        self.assertEqual(routes["DELETE"], {"DELETE /api/items/{id}"})
        self.assertEqual(routes["GET /users/search"], {"GET /users/search"})

    def test_architecture_edges(self) -> None:
        result = _analyze("node_api")
        self.assertIn(("OrdersController", "OrdersService"), _edges(result, "calls", "injected"))
        self.assertIn(("users", "userController"), _edges(result, "imports", "exact"))
        self.assertIn(("users", "db"), _edges(result, "imports", "exact"))

    def test_findings_exact(self) -> None:
        users = "src/routes/users.ts"
        self.assertEqual(
            _pg_findings(_analyze("node_api")),
            {
                ("PG-JS-SQL", users, 14),
                ("PG-JS-CMD", users, 34),
                ("PG-JS-PATH", users, 40),
                ("PG-JS-XSS", users, 45),
                ("PG-JS-SSRF", "src/nest/orders.controller.ts", 22),
                ("PG-JS-REDIRECT", "app/api/items/[id]/route.ts", 9),
                ("PG-JS-TLS", "src/controllers/userController.ts", 9),
                ("PG-JS-SQL", "src/services/orderService.ts", 6),
                ("PG-JS-CMD", "src/services/orderService.ts", 24),
            },
        )


class PhpTests(unittest.TestCase):
    def test_routes(self) -> None:
        routes = _routes(_analyze("php_app"))
        self.assertEqual(routes["import"], {"POST /invoices/import"})
        self.assertEqual(routes["GET /status"], {"GET /status"})
        self.assertEqual(routes["ANY /public/download.php"], {"ANY /public/download.php"})
        # Laravel and Symfony both declare a `show` action.
        self.assertEqual(routes["show"], {"GET /invoices/{id}", "GET /reports/{name}"})

    def test_findings_exact(self) -> None:
        page = "public/download.php"
        self.assertEqual(
            _pg_findings(_analyze("php_app")),
            {
                ("PG-PHP-SQL", "app/Http/Controllers/InvoiceController.php", 18),
                ("PG-PHP-DESER", "app/Http/Controllers/InvoiceController.php", 39),
                ("PG-PHP-SQL", "app/Services/InvoiceService.php", 11),
                ("PG-PHP-INCLUDE", page, 7),
                ("PG-PHP-XSS", page, 10),
                ("PG-PHP-CMD", page, 16),
                ("PG-PHP-TLS", page, 20),
                ("PG-PHP-XSS", page, 22),
                ("PG-PHP-PATH", "src/Controller/ReportController.php", 17),
            },
        )


class GoTests(unittest.TestCase):
    def test_routes(self) -> None:
        routes = _routes(_analyze("go_api"))
        self.assertEqual(routes["SearchUsers"], {"GET /users/search"})
        self.assertEqual(routes["Archive"], {"POST /users/archive"})
        self.assertEqual(routes["Fetch"], {"GET /fetch"})
        self.assertEqual(routes["ANY /healthz"], {"ANY /healthz"})

    def test_constructor_injection(self) -> None:
        self.assertIn(("Handler", "UserStore"), _edges(_analyze("go_api"), "calls", "injected"))

    def test_findings_exact(self) -> None:
        path = "internal/handlers/handlers.go"
        self.assertEqual(
            _pg_findings(_analyze("go_api")),
            {
                ("PG-GO-SQL", path, 34),
                ("PG-GO-CMD", path, 57),
                ("PG-GO-SQL", path, 69),
                ("PG-GO-SSRF", path, 76),
                ("PG-GO-CRYPTO", path, 85),
                ("PG-GO-TLS", path, 90),
            },
        )


class IntegrationTests(unittest.TestCase):
    def test_coverage_metadata(self) -> None:
        result = run_analysis(AnalysisConfig(root=FIXTURES, security=True))
        meta = result.graph.meta
        self.assertEqual(meta["polyglot_files"], {"csharp": 6, "dart": 5, "go": 2, "php": 5, "rust": 3, "typescript": 7})
        self.assertEqual(meta["unsupported_security_languages"], [])

    def test_graph_json_is_deterministic(self) -> None:
        first = run_analysis(AnalysisConfig(root=FIXTURES, security=True)).graph.to_dict()
        second = run_analysis(AnalysisConfig(root=FIXTURES, security=True)).graph.to_dict()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_high_level_php_and_go_subsystems(self) -> None:
        php = build_high_level_architecture(FIXTURES / "php_app", _analyze("php_app").graph)
        go = build_high_level_architecture(FIXTURES / "go_api", _analyze("go_api").graph)
        php_sub = next(s for s in php.subsystems if s.id.startswith("php_"))
        go_sub = next(s for s in go.subsystems if s.id.startswith("go_"))
        self.assertEqual((php_sub.technology, php_sub.tier, php_sub.details[0]), ("Laravel (PHP)", "gateway", "6 Routes"))
        self.assertEqual((go_sub.technology, go_sub.tier, go_sub.details[0]), ("Go Gin", "gateway", "6 Routes"))
        # Risk badges: P0/P1 findings located under each project directory.
        self.assertEqual(php_sub.details[-1], "⚠ P0x3 P1x3")
        self.assertEqual(go_sub.details[-1], "⚠ P0x1 P1x3")
        self.assertIn(("go_shop", "db_postgres"), {(c.src, c.dst) for c in go.connections})
        self.assertIn("PHP", php.languages)
        # Polyglot packages must not be mislabeled as Python subsystems.
        self.assertFalse([s.id for s in php.subsystems + go.subsystems if s.id.startswith("py_")])


def _flow_names(result: AnalysisResult, path: str, line: int) -> tuple[str, list[str], dict[str, object]]:
    finding = next(
        f for f in result.graph.findings
        if f.evidence and f.evidence[0].path == path and f.evidence[0].line == line and f.metadata.get("tainted")
    )
    names = []
    for hop in finding.metadata["flow"]:
        node = result.graph.nodes.get(hop["node"] or "")
        if node is not None and (not names or names[-1] != node.name):
            names.append(node.name)
    return finding.severity, names, finding.metadata


class InterproceduralTaintTests(unittest.TestCase):
    def test_csharp_controller_service_repository(self) -> None:
        severity, names, meta = _flow_names(_analyze("csharp_api"), "src/Shop.Api/Data/OrderRepository.cs", 17)
        self.assertEqual(severity, "critical")
        self.assertEqual(names, ["Search", "FindByCustomer", "QueryByCustomer"])
        self.assertTrue(meta["interprocedural"])
        flow = meta["flow"]
        self.assertEqual((flow[0]["role"], flow[0]["loc"]), ("source", "src/Shop.Api/Controllers/OrdersController.cs:19"))
        self.assertEqual(flow[-1]["role"], "sink")
        self.assertIn("call", [hop["role"] for hop in flow])
        self.assertIn("param", [hop["role"] for hop in flow])

    def test_javascript_route_service_repository_via_new_instance(self) -> None:
        severity, names, _ = _flow_names(_analyze("node_api"), "src/services/orderService.ts", 6)
        self.assertEqual(severity, "critical")
        self.assertEqual(names, ["GET /orders", "search", "findByStatus"])

    def test_javascript_tainted_return_value(self) -> None:
        severity, names, meta = _flow_names(_analyze("node_api"), "src/services/orderService.ts", 24)
        self.assertEqual(severity, "critical")
        # Input is read and returned by the helper, then executed by the caller.
        self.assertEqual(names, ["reportCommand", "runReport"])
        self.assertTrue(meta["interprocedural"])

    def test_php_controller_service(self) -> None:
        severity, names, _ = _flow_names(_analyze("php_app"), "app/Services/InvoiceService.php", 11)
        self.assertEqual(severity, "critical")
        self.assertEqual(names, ["search", "searchByCustomer"])

    def test_go_handler_store_via_receiver_field(self) -> None:
        severity, names, _ = _flow_names(_analyze("go_api"), "internal/handlers/handlers.go", 69)
        self.assertEqual(severity, "critical")
        self.assertEqual(names, ["Lookup", "FindByEmail"])

    def _mini(self, files: dict[str, str]) -> list[tuple[str, str, int, bool]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            result = run_analysis(AnalysisConfig(root=root, security=True))
        return sorted(
            (f.category, f.severity, f.evidence[0].line, bool(f.metadata.get("tainted")))
            for f in result.graph.findings
            if str(f.metadata.get("rule_id", "")).startswith("PG-")
        )

    def test_numeric_cast_in_call_argument_breaks_chain(self) -> None:
        findings = self._mini({
            "routes.ts": (
                'import { lookup } from "./repo";\n'
                'app.get("/n", (req, res) => res.json(lookup(parseInt(req.query.id, 10))));\n'
            ),
            "repo.ts": "export function lookup(id) {\n  return pool.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n",
        })
        # The query is still dynamically built (medium) but never request-tainted.
        self.assertEqual(findings, [("sql", "medium", 2, False)])

    def test_tainted_parameter_reaches_sink_only_when_a_caller_passes_input(self) -> None:
        repo = "export function find(name) {\n  return pool.query(`SELECT * FROM t WHERE n = '${name}'`);\n}\n"
        safe = self._mini({"repo.ts": repo, "job.ts": 'import { find } from "./repo";\nfind("nightly");\n'})
        self.assertEqual(safe, [("sql", "medium", 2, False)])
        tainted = self._mini({
            "repo.ts": repo,
            "routes.ts": 'import { find } from "./repo";\napp.get("/f", (req, res) => res.json(find(req.query.q)));\n',
        })
        self.assertEqual(tainted, [("sql", "critical", 2, True)])

    def test_unknown_receivers_are_not_resolved(self) -> None:
        # `client.lookup` is a library call on an untyped receiver; the local
        # function `lookup` with a sink must not be linked to it.
        findings = self._mini({
            "repo.ts": "export function lookup(name) {\n  return pool.query(`SELECT * FROM t WHERE n = '${name}'`);\n}\n",
            "routes.ts": 'app.get("/f", (req, res) => res.json(client.lookup(req.query.q)));\n',
        })
        self.assertEqual(findings, [("sql", "medium", 2, False)])

    def test_deep_call_chain_reaches_fixed_point(self) -> None:
        # 120 service layers: the worklist must compose summaries at any depth,
        # and trace truncation must keep the origin (source) and the sink.
        chain = "".join(
            f"export class Svc{i} {{\n  constructor(private readonly next: Svc{i + 1}) {{}}\n"
            f"  run(v: string) {{\n    return this.next.run(v);\n  }}\n}}\n"
            for i in range(119)
        ) + "export class Svc119 {\n  run(v: string) {\n    return pool.query(`SELECT * FROM t WHERE v = '${v}'`);\n  }\n}\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "chain.ts").write_text(chain, encoding="utf-8")
            (root / "route.ts").write_text(
                'const svc = new Svc0(null);\napp.get("/deep", (req, res) => res.json(svc.run(req.query.v)));\n',
                encoding="utf-8",
            )
            start = time.perf_counter()
            result = run_analysis(AnalysisConfig(root=root, security=True))
            elapsed = time.perf_counter() - start
        finding = next(f for f in result.graph.findings if f.category == "sql")
        flow = finding.metadata["flow"]
        self.assertEqual(finding.severity, "critical")
        self.assertEqual((flow[0]["loc"], flow[0]["role"]), ("route.ts:2", "source"))
        self.assertEqual(flow[-1]["role"], "sink")
        self.assertLess(elapsed, 10.0)


class TaintFlowDiagramTests(unittest.TestCase):
    def test_flows_for_every_language(self) -> None:
        flows = build_taint_flows(_analyze("csharp_api").graph)
        self.assertTrue(flows)
        self.assertEqual(flows[0].finding.severity, "critical")
        python = run_analysis(AnalysisConfig(root=FIXTURES.parent / "sample_app", security=True)).graph
        py_flows = build_taint_flows(python)
        self.assertTrue(any(flow.interprocedural for flow in py_flows))
        for flow in py_flows:
            self.assertTrue(all(node in python.nodes for node in flow.node_path))
        self.assertEqual(python.meta["taint_flows"]["count"], len(py_flows))

    def test_attack_path_diagram(self) -> None:
        graph = _analyze("csharp_api").graph
        text = render_taint_mermaid(graph)
        self.assertIn("Untrusted input", text)
        self.assertIn("OrderService.FindByCustomer()", text)
        self.assertIn("OrderRepository.QueryByCustomer()", text)
        self.assertIn("SQL injection · CWE-89", text)
        self.assertIn("linkStyle", text)
        self.assertEqual(text, render_taint_mermaid(graph))
        render_taint_mermaid(graph, ascii_only=True).encode("ascii")

    def test_detailed_diagram_overlay(self) -> None:
        graph = _analyze("csharp_api").graph
        overlay = render_mermaid(graph)
        plain = render_mermaid(graph, taint_overlay=False)
        self.assertIn("linkStyle", overlay)
        self.assertNotIn("linkStyle", plain)

    def test_empty_graph_diagram(self) -> None:
        self.assertIn("No source-to-sink taint flows detected", render_taint_mermaid(Graph()))


if __name__ == "__main__":
    unittest.main()
