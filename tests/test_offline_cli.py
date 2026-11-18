"""Offline CLI contracts: side effects, coverage, diagnostics, CI and limits."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.discover import discover

FIXTURE = Path(__file__).parent / "fixtures" / "sample_app"


class OfflineCliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, dict, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([*args, "--output", "json"])
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_dry_run_has_no_writes_parsing_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            out, cache = root / "reports", root / "index-cache"
            with mock.patch("secdiagram_core.cli.run_analysis", side_effect=AssertionError("parsed")), mock.patch(
                "urllib.request.urlopen", side_effect=AssertionError("network")
            ):
                code, payload, _ = self.run_cli("--dir", str(root), "--out", str(out), "--cache-dir", str(cache),
                                                "--dry-run", "--image", "--llm", "--verbose")
            self.assertEqual(code, 0)
            self.assertEqual(payload["plan"]["files"], ["app.py"])
            self.assertEqual(payload["stages"], ["discovery"])
            self.assertFalse(out.exists())
            self.assertFalse(cache.exists())
            with mock.patch("secdiagram_core.server.serve") as serve:
                self.assertEqual(self.run_cli("--serve", "--dry-run")[0], 1)
                serve.assert_not_called()

    def test_progress_coverage_and_cache_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "app.py").write_text("def work():\n    return 1\n", encoding="utf-8")
            (root / "client.ts").write_text("export function run() { return 1; }", encoding="utf-8")
            out = Path(tmp) / "out"
            snapshots = []
            for _ in range(2):
                code, payload, stderr = self.run_cli("--dir", str(root), "--out", str(out), "--offline", "--format", "json", "--jobs", "1")
                self.assertEqual(code, 0, stderr)
                self.assertEqual(payload["stages"], ["discovery", "parsing", "mapping", "threat analysis", "rendering", "report generation"])
                self.assertEqual(payload["health"]["files_parsed"], 2)
                self.assertEqual(payload["health"]["languages"], {"python": 1, "typescript": 1})
                snapshots.append((out / "graph.json").read_bytes())
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertEqual(payload["cache"]["python"]["hits"], 1)

    def test_nested_outputs_are_not_rediscovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x=1", encoding="utf-8")
            out = root / "reports"
            contents = []
            for _ in range(2):
                code, payload, _ = self.run_cli("--dir", tmp, "--out", str(out), "--format", "json", "--validate")
                self.assertEqual(code, 0)
                self.assertEqual(payload["health"]["files_discovered"], 1)
                contents.append((out / "graph.json").read_bytes())
            self.assertEqual(contents[0], contents[1])

    def test_json_errors_and_security_exit_codes(self) -> None:
        code, payload, stderr = self.run_cli("--dir", str(FIXTURE / "missing"))
        self.assertEqual(code, 1)
        self.assertIn("check --dir", payload["error"])
        self.assertIn("does not exist", stderr)
        code, payload, _ = self.run_cli("--jobs", "-1")
        self.assertEqual(code, 2)
        self.assertEqual(payload["status"], "failed")
        with tempfile.TemporaryDirectory() as tmp:
            code, payload, _ = self.run_cli("--dir", str(FIXTURE), "--out", tmp, "--fail-on", "critical", "--quiet")
            self.assertEqual(code, 2)
            self.assertEqual(payload["exit_code"], 2)

    def test_syntax_ambiguity_and_unsupported_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("def broken(:", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "same.py").write_text("x=1", encoding="utf-8")
            (root / "same.py").write_text("x=2", encoding="utf-8")
            (root / "main.rs").write_text("fn main() {}", encoding="utf-8")
            code, payload, stderr = self.run_cli("--dir", tmp, "--format", "json", "--verbose")
            self.assertEqual(code, 0, stderr)
            diagnostics = payload["health"]["diagnostics"]
            self.assertTrue(any(item["code"] == "parse_error" and item["path"] == "app.py" for item in diagnostics))
            self.assertTrue(any(item["code"] == "not_parsed" and item["path"] == "main.rs" for item in diagnostics))
            self.assertTrue(any(item["code"] == "ambiguous_layout" for item in diagnostics))
            self.assertFalse(payload["health"]["complete"])
            self.assertIn("running Python version", stderr)

    def test_limits_filters_and_unreadable_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a.py", "b.py", "c.py"):
                (root / name).write_bytes(b"x=1\n")
            (root / "large.py").write_text("#" * 20, encoding="utf-8")
            repo = discover(root, max_file_bytes=10, max_total_bytes=8)
            self.assertEqual(repo.rel_files, ["a.py", "b.py"])
            self.assertTrue(any("file size limit: large.py" in item for item in repo.skipped))
            self.assertTrue(any("input budget: c.py" in item for item in repo.skipped))
            self.assertEqual(discover(root, max_files=1).rel_files, ["a.py"])
            self.assertEqual(discover(root, include=["b.py"]).rel_files, ["b.py"])
            original = Path.open

            def unreadable(path: Path, *args, **kwargs):
                if path.name == "a.py":
                    raise PermissionError("mock unreadable source")
                return original(path, *args, **kwargs)

            with mock.patch.object(Path, "open", unreadable):
                repo = discover(root)
            self.assertNotIn("a.py", repo.rel_files)
            self.assertTrue(any("unreadable file: a.py" in item for item in repo.skipped))

    def test_offline_never_calls_http_and_default_images_are_local(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            code, _, stderr = self.run_cli("--dir", str(FIXTURE), "--out", tmp, "--format", "json,html", "--offline")
            self.assertEqual(code, 0, stderr)
            with mock.patch("secdiagram_core.cli.generate_narrative") as narrative:
                code, payload, _ = self.run_cli("--dir", str(FIXTURE), "--offline", "--ollama")
                self.assertEqual(code, 1)
                narrative.assert_not_called()
                self.assertIn("HTTP", payload["error"])
            with mock.patch("secdiagram_core.cli.render_image") as renderer:
                code, _, _ = self.run_cli("--dir", str(FIXTURE), "--out", tmp, "--image")
                self.assertEqual(code, 0)
                self.assertTrue(all(call.kwargs["provider"] == "local" for call in renderer.call_args_list))

    def test_config_validation_and_explicit_cli_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "scan.json"
            code, payload, _ = self.run_cli("--config", str(config), "--dry-run")
            self.assertEqual(code, 1)
            self.assertIn("readable scan configuration", payload["error"])
            config.write_text('{"jobs": 1, "include": ["*.py"], "max_files": 1}', encoding="utf-8")
            code, payload, _ = self.run_cli("--dir", str(FIXTURE), "--config", str(config), "--max-files", "2", "--dry-run")
            self.assertEqual(code, 0)
            self.assertEqual(len(payload["plan"]["files"]), 2)
            config.write_text('{"jobs": true}', encoding="utf-8")
            self.assertEqual(self.run_cli("--config", str(config))[0], 1)

    def test_parser_resource_failure_is_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x=1", encoding="utf-8")
            with mock.patch("secdiagram_core.ast_index.ast.parse", side_effect=RecursionError("too deep")):
                result = run_analysis(AnalysisConfig(root=root, security=False, jobs=1))
            self.assertEqual(result.parse_errors, ["app.py"])


if __name__ == "__main__":
    unittest.main()
