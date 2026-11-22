"""Tests for Rust language indexing, Axum/Actix framework support, SAST rules, and high-level architecture."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.misconfig import analyze_misconfig
from secdiagram_core.model import Graph
from secdiagram_core.polyglot_index import (
    PolyglotIndex,
    _views,
    build_polyglot_graph,
    parse_polyglot_file,
)
from secdiagram_core.polyglot_security import analyze_polyglot_security
from secdiagram_core.workspace import _detect_role_from_cargo

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "polyglot"
RUST_FIXTURE = FIXTURES / "rust_api"

_RESULT: AnalysisResult | None = None


def _analyze_rust() -> AnalysisResult:
    global _RESULT
    if _RESULT is None:
        _RESULT = run_analysis(AnalysisConfig(root=RUST_FIXTURE, security=True))
    return _RESULT


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
            out.setdefault(node.name, set()).update(
                f"{r['method']} {r['path']}" for r in node.attrs.get("routes", [])
            )
    return out


class RustTokenizerTests(unittest.TestCase):
    def test_views_handles_nested_comments_and_raw_strings(self) -> None:
        text = '/* outer /* nested */ comment */ let s = r#"raw " { string"#; // line comment\n'
        code, masked = _views(text, "rust")
        self.assertEqual(len(code), len(text))
        self.assertEqual(code.count("\n"), text.count("\n"))
        self.assertNotIn("comment", code)
        self.assertNotIn("nested", code)
        self.assertIn('r#"raw " { string"#', code)
        self.assertEqual(masked.count("{"), 0)

    def test_char_and_byte_literals_do_not_break_views(self) -> None:
        text = "let c = '{'; let b = b'{'; let s = b\"hello\";\n"
        code, masked = _views(text, "rust")
        self.assertEqual(len(code), len(text))
        self.assertEqual(masked.count("{"), 0)

    def test_malformed_sources_do_not_crash(self) -> None:
        samples = {
            "bad1.rs": 'fn bad( { "unterminated string',
            "bad2.rs": "struct S { /* unclosed comment",
            "bad3.rs": 'let x = r##"unclosed raw string#"',
        }
        for path, text in samples.items():
            self.assertIsNotNone(parse_polyglot_file(path, text), path)

    def test_adversarial_input_bounded(self) -> None:
        hostile = "async fn handler() {" * 3000 + '"\'`' * 20000
        start = time.perf_counter()
        pf = parse_polyglot_file("hostile.rs", hostile)
        self.assertIsNotNone(pf)
        assert pf is not None
        index = PolyglotIndex(files={"hostile.rs": pf})
        graph = Graph()
        build_polyglot_graph(graph, index)
        analyze_polyglot_security(graph, index)
        self.assertLess(time.perf_counter() - start, 5.0)


class RustIndexTests(unittest.TestCase):
    def test_struct_enum_trait_and_impl_parsing(self) -> None:
        text = """
pub trait Entity {
    fn id(&self) -> i64;
}

pub struct User {
    pub id: i64,
    pub name: String,
}

impl Entity for User {
    fn id(&self) -> i64 {
        self.id
    }
}

pub enum Status {
    Active,
    Inactive,
}
"""
        pf = parse_polyglot_file("src/models.rs", text)
        self.assertIsNotNone(pf)
        assert pf is not None
        symbols = {s.name: s for s in pf.symbols}
        self.assertIn("Entity", symbols)
        self.assertEqual(symbols["Entity"].kind, "class")
        self.assertEqual(symbols["Entity"].decl_kind, "trait")
        self.assertIn("User", symbols)
        self.assertEqual(symbols["User"].kind, "class")
        self.assertIn("Entity", symbols["User"].bases)
        self.assertIn("Status", symbols)
        self.assertEqual(symbols["Status"].kind, "class")
        self.assertIn("id", symbols)
        self.assertEqual(symbols["id"].container, "src/models.rs:User")

    def test_axum_routes_detection(self) -> None:
        result = _analyze_rust()
        routes = _routes(result)
        self.assertIn("health_check", routes)
        self.assertEqual(routes["health_check"], {"GET /health"})
        self.assertIn("search_users", routes)
        self.assertEqual(routes["search_users"], {"GET /users/search"})
        self.assertIn("export_data", routes)
        self.assertEqual(routes["export_data"], {"POST /users/export"})
        self.assertIn("fetch_remote", routes)
        self.assertEqual(routes["fetch_remote"], {"GET /fetch"})

    def test_actix_web_attribute_routes_detection(self) -> None:
        text = """
use actix_web::{get, post, web, Responder};

#[get("/api/v1/items")]
pub async fn list_items() -> impl Responder {
    "items"
}

#[post("/api/v1/items")]
pub async fn create_item() -> impl Responder {
    "created"
}
"""
        pf = parse_polyglot_file("src/actix_handlers.rs", text)
        self.assertIsNotNone(pf)
        assert pf is not None
        index = PolyglotIndex(files={"src/actix_handlers.rs": pf})
        graph = Graph()
        build_polyglot_graph(graph, index)
        endpoints = [n for n in graph.nodes.values() if n.kind == "endpoint"]
        self.assertEqual(len(endpoints), 2)
        endpoint_names = {e.name for e in endpoints}
        self.assertIn("list_items", endpoint_names)
        self.assertIn("create_item", endpoint_names)


class RustSecurityTests(unittest.TestCase):
    def test_exact_rust_sast_findings(self) -> None:
        result = _analyze_rust()
        handlers = "src/handlers.rs"
        findings = _pg_findings(result)
        self.assertIn(("PG-RS-SQL", handlers, 26), findings)
        self.assertIn(("PG-RS-CMD", handlers, 33), findings)
        self.assertIn(("PG-RS-UNSAFE", handlers, 35), findings)
        self.assertIn(("PG-RS-PATH", handlers, 46), findings)
        self.assertIn(("PG-RS-SSRF", handlers, 53), findings)

    def test_rust_tls_verification_rule(self) -> None:
        text = """
pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}
"""
        pf = parse_polyglot_file("src/client.rs", text)
        self.assertIsNotNone(pf)
        assert pf is not None
        index = PolyglotIndex(files={"src/client.rs": pf})
        graph = Graph()
        build_polyglot_graph(graph, index)
        findings = analyze_polyglot_security(graph, index)
        rule_ids = {f.metadata["rule_id"] for f in findings}
        self.assertIn("PG-RS-TLS", rule_ids)


class RustMisconfigTests(unittest.TestCase):
    def test_cors_and_insecure_random_misconfigs(self) -> None:
        text = """
use tower_http::cors::CorsLayer;
use rand::Rng;

pub fn cors() -> CorsLayer {
    CorsLayer::very_permissive()
}

pub fn generate_token() -> u64 {
    rand::thread_rng().gen()
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = Path(tmpdir)
            cfg_file = tmproot / "src" / "cfg.rs"
            cfg_file.parent.mkdir(parents=True, exist_ok=True)
            cfg_file.write_text(text, encoding="utf-8")
            graph = Graph()
            findings = analyze_misconfig(graph, tmproot, ["src/cfg.rs"])
            rule_ids = {f.metadata["rule_id"] for f in findings}
            self.assertIn("CFG-RS-CORS", rule_ids)
            self.assertIn("CFG-RS-RANDOM", rule_ids)


class RustHighLevelArchitectureTests(unittest.TestCase):
    def test_high_level_rust_subsystem(self) -> None:
        result = _analyze_rust()
        arch = build_high_level_architecture(RUST_FIXTURE, result.graph)
        self.assertIn("Rust", arch.languages)
        subsystems = [s for s in arch.subsystems if s.id.startswith("rust_")]
        self.assertEqual(len(subsystems), 1)
        sub = subsystems[0]
        self.assertIn("Axum", sub.technology)
        self.assertIn("Rust", sub.technology)
        self.assertEqual(sub.tier, "gateway")
        self.assertTrue(any("Routes" in d for d in sub.details))
        self.assertIn(("rust_rust_api", "db_postgres"), {(c.src, c.dst) for c in arch.connections})

    def test_workspace_role_detection_from_cargo(self) -> None:
        role, _conf, signals = _detect_role_from_cargo(RUST_FIXTURE)
        self.assertEqual(role, "backend")
        self.assertTrue(any("axum" in s for s in signals))


class RustDeterminismTests(unittest.TestCase):
    def test_rust_analysis_is_byte_for_byte_deterministic(self) -> None:
        first = run_analysis(AnalysisConfig(root=RUST_FIXTURE, security=True)).graph.to_dict()
        second = run_analysis(AnalysisConfig(root=RUST_FIXTURE, security=True)).graph.to_dict()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
