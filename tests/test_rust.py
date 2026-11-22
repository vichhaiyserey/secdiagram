"""Tests for Rust language indexing, Axum/Actix framework support, SAST rules, and high-level architecture."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from secdiagram_core.analyzer import AnalysisConfig, AnalysisResult, run_analysis
from secdiagram_core.cargo_manifest import cargo_inventory
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.misconfig import analyze_misconfig
from secdiagram_core.model import Graph
from secdiagram_core.polyglot_index import (
    PolyglotIndex,
    _views,
    build_polyglot_graph,
    index_polyglot,
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
    def test_lifetimes_labels_and_escaped_chars_preserve_structure(self) -> None:
        samples = {
            "static": "pub fn read(value: &'static str) {\n    std::fs::read(value);\n}\n",
            "generic": "pub fn read<'a, T: AsRef<str>>(value: &'a T) {\n    inspect(value);\n}\n",
            "labels": "pub fn read() {\n    'outer: loop { break 'outer; }\n}\n",
            "chars": r"pub fn read() { let chars = ('{', b'}', '\u{7b}', '\'', '\\'); }",
        }
        for name, text in samples.items():
            with self.subTest(name=name):
                pf = parse_polyglot_file("src/lib.rs", text)
                assert pf is not None
                self.assertEqual([(s.name, s.has_body) for s in pf.symbols], [("read", True)])
                self.assertEqual(pf.masked.count("{"), pf.masked.count("}"))
                self.assertEqual(len(pf.masked), len(text))
                self.assertEqual(pf.masked.count("\n"), text.count("\n"))

    def test_raw_string_contents_do_not_create_imports_or_routes(self) -> None:
        text = 'const DOC: &str = br##"\nuse fake::Service;\nmod phantom;\nfn fake() {}\n.route("/fake", get(fake))\n"##;\nfn real() {}\n'
        pf = parse_polyglot_file("src/lib.rs", text)
        assert pf is not None
        self.assertEqual([(s.name, s.kind) for s in pf.symbols], [("real", "function")])
        self.assertEqual(pf.imports, [])
        for suffix in ('r#"unterminated {', 'br##"unterminated {'):
            with self.subTest(suffix=suffix):
                _, masked = _views(suffix, "rust")
                self.assertNotIn("{", masked)

    def test_deep_nested_comments_keep_following_function(self) -> None:
        text = "/*" * 30000 + "*/" * 30000 + "\nfn actual() {}\n"
        start = time.perf_counter()
        pf = parse_polyglot_file("src/lib.rs", text)
        assert pf is not None
        self.assertEqual([(s.name, s.line) for s in pf.symbols], [("actual", 2)])
        self.assertLess(time.perf_counter() - start, 5.0)

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
    def test_multiline_routes_keep_all_methods_and_qualified_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir()
            sources = {
                "main.rs": 'fn app() {\n Router::new().route(\n "/items",\n get(crate::handlers::items)\n .post(crate::handlers::create)\n );\n}\n',
                "handlers.rs": "pub fn items() {}\npub fn create() {}\n",
                "unrelated.rs": "pub fn items() {}\npub fn create() {}\n",
            }
            for name, source in sources.items():
                (root / "src" / name).write_text(source, encoding="utf-8")
            index = index_polyglot(root, [f"src/{name}" for name in sources])
            handlers = index.files["src/handlers.rs"].symbols
            self.assertEqual(
                [(s.name, s.kind, s.routes) for s in handlers],
                [("items", "endpoint", [{"method": "GET", "path": "/items"}]),
                 ("create", "endpoint", [{"method": "POST", "path": "/items"}])],
            )
            self.assertTrue(all(s.kind == "function" for s in index.files["src/unrelated.rs"].symbols))
            self.assertFalse(any(s.handler_ref for s in index.files["src/main.rs"].symbols))
            # A nonexistent explicit module must never bind to an unrelated
            # unique function with the same final name.
            (root / "src/main.rs").write_text('fn app() {\n Router::new().route("/missing", get(missing::only));\n}\n', encoding="utf-8")
            (root / "src/unrelated.rs").write_text("pub fn only() {}\n", encoding="utf-8")
            unresolved = index_polyglot(root, ["src/main.rs", "src/unrelated.rs"])
            self.assertEqual(unresolved.files["src/unrelated.rs"].symbols[0].kind, "function")
            self.assertEqual(unresolved.files["src/main.rs"].symbols[-1].handler_ref, "missing::only")
            (root / "src/main.rs").write_text('struct Api;\nimpl Api {\n pub fn items() {}\n}\nfn app() {\n Router::new().route("/associated", get(Api::items));\n}\n', encoding="utf-8")
            associated = index_polyglot(root, ["src/main.rs"])
            endpoints = [s for s in associated.files["src/main.rs"].symbols if s.kind == "endpoint"]
            self.assertEqual([(s.qualname, s.routes) for s in endpoints], [
                ("src/main.rs:Api.items", [{"method": "GET", "path": "/associated"}]),
            ])

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

#[actix_web::post("/api/v1/items")]
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
        self.assertEqual({e.name: e.attrs["routes"] for e in endpoints}, {
            "list_items": [{"method": "GET", "path": "/api/v1/items"}],
            "create_item": [{"method": "POST", "path": "/api/v1/items"}],
        })


class RustSecurityTests(unittest.TestCase):
    def test_exact_rust_sast_findings(self) -> None:
        result = _analyze_rust()
        handlers = "src/handlers.rs"
        findings = _pg_findings(result)
        self.assertEqual(findings, {
            ("PG-RS-SQL", handlers, 26), ("PG-RS-CMD", handlers, 33),
            ("PG-RS-PATH", handlers, 46), ("PG-RS-SSRF", handlers, 53),
        })
        for finding in result.graph.findings:
            if str(finding.metadata.get("rule_id", "")).startswith("PG-RS-"):
                self.assertTrue(finding.metadata["tainted"])
                self.assertIsNotNone(finding.node_id)
                flow = finding.metadata["flow"]
                self.assertEqual(flow[0]["role"], "source")
                self.assertEqual(flow[-1]["loc"], f"{handlers}:{finding.evidence[0].line}")
                self.assertEqual(flow[-1]["role"], "sink")

    def test_shell_arguments_require_a_detected_shell_builder(self) -> None:
        cases = {
            "literal argument": ('Command::new("echo").arg(value).output();', False),
            "unrelated arg": ('let c = Command::new("sh");\n    unrelated.arg(value);', False),
            "unrelated same statement": ('let pair = (Command::new("sh"), unrelated.arg(value));', False),
            "shell chain": ('Command::new("sh")\n        .arg("-c")\n        .arg(value).output();', True),
            "shell variable": ('let mut c = Command::new("bash");\n    c.arg(value).output();', True),
            "safe variable": ('let mut c = Command::new("echo");\n    c.arg(value).output();', False),
            "windows shell": ('Command::new("cmd.exe").args(["/C", value]).output();', True),
            "tainted program": ('Command::new(value).output();', True),
            "reassigned builder": ('let mut c = Command::new("sh");\n    c = Command::new("echo");\n    c.arg(value).output();', False),
        }
        for name, (body, expected) in cases.items():
            with self.subTest(name=name):
                source = f'#[get("/run")]\npub fn run(Query(value): Query<String>) {{\n    {body}\n}}\n'
                pf = parse_polyglot_file("src/lib.rs", source)
                assert pf is not None
                findings = analyze_polyglot_security(Graph(), PolyglotIndex(files={pf.path: pf}))
                self.assertEqual([f.metadata["rule_id"] for f in findings], ["PG-RS-CMD"] if expected else [])
                if expected:
                    self.assertEqual(findings[0].cwe, "CWE-78")
                    self.assertTrue(findings[0].metadata["tainted"])

    def test_literal_owned_sql_and_unsafe_syntax_are_not_findings(self) -> None:
        source = '''pub fn safe() {
    let sql = "SELECT 1".to_string();
    sqlx::query(&sql);
    sqlx::query("SELECT 1".to_owned());
    unsafe { let pointer = std::ptr::null::<u8>(); }
}
#[get("/query")]
fn query(Query(value): Query<String>) {
    sqlx::query("SELECT * FROM users WHERE name = $1").bind(value);
}
'''
        pf = parse_polyglot_file("src/lib.rs", source)
        assert pf is not None
        self.assertEqual(analyze_polyglot_security(Graph(), PolyglotIndex(files={pf.path: pf})), [])

    def test_request_extractors_are_sources_but_application_state_is_not(self) -> None:
        cases = {
            "query": ("Query(value): Query<String>", "value", True),
            "qualified query": ("value: web::Query<String>", "value", True),
            "state": ("value: State<String>", "value", False),
            "data": ("value: web::Data<String>", "value", False),
            "extension": ("value: Extension<String>", "value", False),
            "custom type": ("value: TrustedSettings", "value", False),
        }
        for name, (param, value, expected) in cases.items():
            with self.subTest(name=name):
                source = f'#[get("/read")]\nfn read({param}) {{\n    fs::read({value});\n}}\n'
                pf = parse_polyglot_file("src/lib.rs", source)
                assert pf is not None
                findings = analyze_polyglot_security(Graph(), PolyglotIndex(files={pf.path: pf}))
                self.assertEqual([f.metadata["rule_id"] for f in findings], ["PG-RS-PATH"] if expected else [])
        pf = parse_polyglot_file("src/lib.rs", 'fn local() {\n    let value = Query("fixed");\n    fs::read(value);\n}\n')
        assert pf is not None
        self.assertEqual(analyze_polyglot_security(Graph(), PolyglotIndex(files={pf.path: pf})), [])

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
    fastrand::u64(..)
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
            self.assertEqual(rule_ids, {"CFG-RS-CORS", "CFG-RS-RANDOM"})

    def test_crypto_rng_and_literal_examples_are_not_misconfigs(self) -> None:
        source = '''pub fn generate_token() -> u64 {
    rand::thread_rng().gen()
}
pub fn random_token() -> u64 { rand::random() }
const DOC: &str = r#"CorsLayer::very_permissive() fastrand::u64(..) token"#;
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "safe.rs").write_text(source, encoding="utf-8")
            self.assertEqual(analyze_misconfig(Graph(), root, ["safe.rs"]), [])

    def test_small_rng_token_requires_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "rng.rs").write_text('fn token() {\n let rng = SmallRng::seed_from_u64(1);\n}\n\nfn simulation() {\n let rng = SmallRng::seed_from_u64(1);\n}\n', encoding="utf-8")
            findings = analyze_misconfig(Graph(), root, ["rng.rs"])
            self.assertEqual([(f.metadata["rule_id"], f.evidence[0].line) for f in findings], [("CFG-RS-RANDOM", 2)])


class RustHighLevelArchitectureTests(unittest.TestCase):
    def test_cargo_inventory_uses_runtime_sections_not_descriptions(self) -> None:
        source = '''[package]
name = "warped-redis-tool"
description = "axum postgres"
readme = """
[dependencies]
rocket = "mock"
"""
# actix-web = "mock"
[dev-dependencies]
axum = "mock"
[package.metadata.dependencies]
rocket = "mock"
[dependencies]
http = { package = "reqwest", version = "mock" }
sqlx = { version = "mock", features = [
 "postgres",
] }
[target.'cfg(unix)'.dependencies.actix-web]
version = "mock"
'''
        self.assertEqual(cargo_inventory(source), ("warped-redis-tool", {"http", "reqwest", "sqlx", "postgres", "actix-web"}, True))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.toml").write_text('[package]\nname = "warped-redis-tool"\ndescription = "axum postgres"\n[dev-dependencies]\naxum = "mock"\n', encoding="utf-8")
            self.assertEqual(_detect_role_from_cargo(root), ("unknown", 0.0, []))
            arch = build_high_level_architecture(root)
            rust = [s for s in arch.subsystems if s.id.startswith("rust_")]
            self.assertEqual([(s.name, s.technology, s.tier) for s in rust], [("warped-redis-tool", "Rust", "services")])
            self.assertEqual([(c.src, c.dst) for c in arch.connections], [("client_ingress", "rust_warped_redis_tool")])
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\n', encoding="utf-8")
            self.assertFalse(any(s.id.startswith("rust_") for s in build_high_level_architecture(root).subsystems))

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
