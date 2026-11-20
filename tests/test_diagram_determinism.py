from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.cli import main

FIXTURE = ROOT / "tests" / "fixtures" / "sample_app"
ARTIFACTS = ("graph.json", "ARCHITECTURE.md", "diagram.mmd", "diagram-highlevel.mmd")


def _run(root: Path, out: Path) -> None:
    code = main(
        [
            "--dir",
            str(root),
            "--out",
            str(out),
            "--format",
            "json,md,mermaid",
            "--no-security",
            "--no-cache",
            "--quiet",
        ]
    )
    if code != 0:
        raise AssertionError(f"analysis failed for {root} with exit code {code}")


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _node_ids(graph_json: Path) -> dict[str, dict[str, object]]:
    payload = json.loads(graph_json.read_text(encoding="utf-8"))
    return {str(node["id"]): node for node in payload["nodes"]}


class DiagramDeterminismTests(unittest.TestCase):
    def test_repeated_analysis_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first"
            second = Path(tmp) / "second"
            _run(FIXTURE, first)
            _run(FIXTURE, second)
            for artifact in ARTIFACTS:
                self.assertEqual(
                    _read(first / artifact),
                    _read(second / artifact),
                    f"{artifact} is not byte-identical across runs",
                )

    def test_single_service_change_is_a_minimal_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modified_root = Path(tmp) / "modified"
            shutil.copytree(FIXTURE, modified_root)
            (modified_root / "app" / "extra_service.py").write_text(
                "class ExtraService:\n    def run(self):\n        return 1\n",
                encoding="utf-8",
            )

            baseline = Path(tmp) / "baseline"
            changed = Path(tmp) / "changed"
            _run(FIXTURE, baseline)
            _run(modified_root, changed)

            base_nodes = _node_ids(baseline / "graph.json")
            changed_nodes = _node_ids(changed / "graph.json")
            added = set(changed_nodes) - set(base_nodes)
            removed = set(base_nodes) - set(changed_nodes)

            self.assertEqual(removed, set(), "existing components must keep their stable ids")
            self.assertTrue(added)
            self.assertEqual(
                {changed_nodes[node_id]["path"] for node_id in added},
                {"app/extra_service.py"},
                "only the changed service may contribute new components",
            )
            self.assertEqual(set(base_nodes) & set(changed_nodes), set(base_nodes))

            base_highlevel = (baseline / "diagram-highlevel.mmd").read_text(encoding="utf-8").splitlines()
            changed_highlevel = (changed / "diagram-highlevel.mmd").read_text(encoding="utf-8").splitlines()
            differences = [
                line
                for line in changed_highlevel
                if line not in base_highlevel
            ]
            disappeared = [
                line
                for line in base_highlevel
                if line not in changed_highlevel
            ]
            self.assertEqual(len(differences), 1, differences)
            self.assertEqual(len(disappeared), 1, disappeared)
            self.assertIn("py_app", differences[0], "only the App subsystem label may change")
            self.assertIn("5 Classes", differences[0])
            self.assertIn("18 Functions", differences[0])

            structural = [line for line in differences + disappeared if "-->" in line or "-.->" in line]
            self.assertEqual(structural, [], "no new subsystem connections may appear")


if __name__ == "__main__":
    unittest.main()
