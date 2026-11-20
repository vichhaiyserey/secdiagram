"""Tests for native query helpers on AnalysisResult and Graph (taint & reachability)."""

from __future__ import annotations

import unittest
from pathlib import Path

from secdiagram_core import AnalysisConfig, run_analysis

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class ReachabilityQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))

    def test_has_taint_at(self) -> None:
        """Verifies querying taint presence by file and line number."""
        for path, line, expected in (
            ("app/service.py", 16, True),
            ("app/service.py", None, True),
            ("non_existent_file.py", None, False),
            ("app/service.py", 999999, False),
        ):
            with self.subTest(path=path, line=line):
                self.assertEqual(self.result.has_taint_at(path, line), expected)

    def test_get_taint_traces(self) -> None:
        """Verifies returning TaintTrace objects for triage service."""
        # Query traces for a known tainted file in sample_app
        traces = self.result.get_taint_traces("app/service.py", 16)
        self.assertEqual(len(traces), 2)
        for trace in traces:
            with self.subTest(finding=trace.finding_id):
                payload = trace.to_dict()
                self.assertIn(payload["finding_id"], {f.id for f in self.result.graph.findings})
                self.assertEqual(
                    (payload["category"], payload["severity"], payload["cwe"]),
                    ("command", "critical", "CWE-78"),
                )
                self.assertEqual(payload["source"], {"path": "app/main.py", "line": 12, "col": 0})
                self.assertEqual(payload["sink"], {"path": "app/service.py", "line": 16, "col": 11})
                self.assertEqual(
                    [(loc["path"], loc["line"]) for loc in payload["trace"]],
                    [("app/main.py", 12), ("app/main.py", 13), ("app/service.py", 16)],
                )
        self.assertEqual(self.result.get_taint_traces("missing.py"), [])

    def test_is_reachable_for_endpoints_and_symbols(self) -> None:
        """Verifies checking execution reachability from HTTP entrypoints."""
        # app/main.py contains entrypoint routes
        self.assertTrue(self.result.is_reachable("app/main.py"))

        # Non-existent file should be unreachable
        self.assertFalse(self.result.is_reachable("non_existent_path.py"))

    def test_package_reachability_indexing(self) -> None:
        """Verifies package & dependency reachability indexing for SCA bridge."""
        # In sample_app, fastapi is imported in app/main.py
        self.assertIn("fastapi", self.result.dependency_usage)
        fastapi_summary = self.result.dependency_usage["fastapi"]
        self.assertTrue(fastapi_summary.imported)
        self.assertTrue(fastapi_summary.reachable_from_entrypoint)
        self.assertEqual(
            [(loc.path, loc.line) for loc in fastapi_summary.import_sites], [("app/main.py", 3)]
        )

        # Helper method on result
        self.assertTrue(self.result.is_package_reachable("fastapi"))
        self.assertTrue(self.result.is_package_reachable("FastAPI"))  # Case insensitive
        self.assertTrue(self.result.is_package_reachable("yaml"))
        self.assertFalse(self.result.is_package_reachable("completely_unused_fictional_pkg"))
