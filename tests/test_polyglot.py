"""Tests for the C#/.NET, JavaScript/TypeScript, PHP and Go analyzers."""

from __future__ import annotations

import json
import time
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.polyglot_index import _views, parse_polyglot_file

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
        hostile = {
            "h.ts": "app.get('/x', (req, res) => {" * 3000 + "\"'`" * 20000,
            "h.cs": "public void M(" * 5000 + "{" * 20000,
            "h.php": "<?php " + "Route::get('/a', function () {" * 3000,
            "h.go": "package h\n" + "r.GET(\"/x\", func(c *gin.Context) {\n" * 3000,
        }
        for path, text in hostile.items():
            start = time.perf_counter()
            parse_polyglot_file(path, text)
            self.assertLess(time.perf_counter() - start, 10.0, path)


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
        self.assertEqual([loc.line for loc in finding.trace], [26, 27])
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
                ("PG-PHP-DESER", "app/Http/Controllers/InvoiceController.php", 32),
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
                ("PG-GO-SSRF", path, 64),
                ("PG-GO-CRYPTO", path, 73),
                ("PG-GO-TLS", path, 78),
            },
        )


class IntegrationTests(unittest.TestCase):
    def test_coverage_metadata(self) -> None:
        result = run_analysis(AnalysisConfig(root=FIXTURES, security=True))
        meta = result.graph.meta
        self.assertEqual(meta["polyglot_files"], {"csharp": 3, "go": 2, "php": 4, "typescript": 5})
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
        self.assertEqual((php_sub.technology, php_sub.tier, php_sub.details), ("Laravel (PHP)", "gateway", ["5 Routes"]))
        self.assertEqual((go_sub.technology, go_sub.tier, go_sub.details), ("Go Gin", "gateway", ["5 Routes"]))
        self.assertIn(("go_shop", "db_postgres"), {(c.src, c.dst) for c in go.connections})
        self.assertIn("PHP", php.languages)
        # Polyglot packages must not be mislabeled as Python subsystems.
        self.assertFalse([s.id for s in php.subsystems + go.subsystems if s.id.startswith("py_")])


if __name__ == "__main__":
    unittest.main()
