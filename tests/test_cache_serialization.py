"""Tests for AnalysisResult serialization and cache round-tripping."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core import AnalysisConfig, AnalysisResult, run_analysis

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class CacheSerializationTests(unittest.TestCase):
    def test_analysis_result_dict_and_json_roundtrip(self) -> None:
        """Verifies that AnalysisResult can be serialized to JSON/dict and restored losslessly."""
        original = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))

        # 1. to_dict / from_dict
        data = original.to_dict()
        self.assertEqual(data["repo"]["name"], original.repo.name)
        self.assertTrue(data["graph"]["nodes"])
        self.assertTrue(data["graph"]["findings"])
        self.assertIn("fastapi", data["dependency_usage"])
        # Round-trip equality alone could bless a field omitted on both sides.
        # Anchor representative serialized evidence to the known fixture.
        command = [finding for finding in data["graph"]["findings"]
                   if finding.get("category") == "command"]
        self.assertTrue(command)
        for finding in command:
            self.assertEqual(finding.get("cwe"), "CWE-78")
            self.assertEqual(finding.get("severity"), "critical")
            self.assertEqual(finding.get("evidence"), [{"path": "app/service.py", "line": 16, "col": 11}])
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "cache" / "analysis_result.json"
            original.to_json(json_path)
            raw_json = json_path.read_text(encoding="utf-8")
            # Full content equality subsumes the old repeated type/count checks.
            # Exercise queries on every restoration path, not only the dict path.
            for transport, restore in (
                ("dict", lambda: AnalysisResult.from_dict(data)),
                ("file", lambda: AnalysisResult.from_json(json_path)),
                ("text", lambda: AnalysisResult.from_json(raw_json)),
            ):
                with self.subTest(transport=transport):
                    restored = restore()
                    self.assertEqual(
                        restored.to_dict(),
                        data,
                        "graph, evidence and dependencies must survive losslessly",
                    )
                    self.assertTrue(restored.has_taint_at("app/service.py"))
                    self.assertTrue(restored.is_package_reachable("fastapi"))
                    self.assertFalse(restored.has_taint_at("missing.py"))
                    self.assertFalse(restored.is_package_reachable("mock_unused_package"))
