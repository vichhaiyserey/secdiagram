from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core.diagram_edit import (
    OVERRIDES_RELPATH,
    DiagramOverrideError,
    DiagramOverrides,
    apply_overrides,
    clear_overrides,
    load_overrides,
    overrides_path,
    save_overrides,
    summarize_overrides,
)
from secdiagram_core.model import Feature, Graph, Node


def _graph() -> Graph:
    graph = Graph()
    graph.add_node(Node(id="api", kind="function", name="api", qualname="api"))
    graph.add_node(Node(id="db", kind="class", name="Database", qualname="Database"))
    graph.add_node(Node(id="cache", kind="class", name="Cache", qualname="Cache"))
    graph.add_edge("api", "db", "calls")
    graph.add_edge("api", "cache", "reads")
    graph.features.append(Feature(id="core", name="core", nodes=["api", "db", "cache"]))
    return graph


class OverrideParsingTests(unittest.TestCase):
    def test_round_trip_is_sorted_and_normalized(self) -> None:
        overrides = DiagramOverrides(
            renames={"db": "  Primary   Database  "},
            hidden=["cache", "db", "db"],
            direction="tb",
            theme="Modern",
        )
        parsed = DiagramOverrides.from_dict(overrides.to_dict())
        self.assertEqual(parsed.renames, {"db": "Primary Database"})
        self.assertEqual(parsed.hidden, ["cache", "db"])
        self.assertEqual(parsed.direction, "TB")
        self.assertEqual(parsed.theme, "modern")

    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"renames": {}, "evil": True})

    def test_invalid_direction_and_theme_are_rejected(self) -> None:
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"direction": "sideways"})
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"theme": "neon"})

    def test_control_characters_and_empty_ids_are_rejected(self) -> None:
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"renames": {"bad\nid": "Label"}})
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"hidden": [""]})
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"renames": {"id": "\x00"}})

    def test_entry_limits_are_enforced(self) -> None:
        too_many = {f"n{i}": "Label" for i in range(5001)}
        with self.assertRaises(DiagramOverrideError):
            DiagramOverrides.from_dict({"renames": too_many})

    def test_oversized_override_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = overrides_path(tmp)
            path.parent.mkdir(parents=True)
            path.write_text(" " * (1_048_576 + 1), encoding="utf-8")
            with self.assertRaises(DiagramOverrideError):
                load_overrides(tmp)


class OverridePersistenceTests(unittest.TestCase):
    def test_save_load_and_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertFalse(load_overrides(root).has_changes)
            overrides = DiagramOverrides(renames={"api": "Public API"}, hidden=["cache"])
            path = save_overrides(root, overrides)
            self.assertEqual(path, root / OVERRIDES_RELPATH)
            loaded = load_overrides(root)
            self.assertEqual(loaded.renames, {"api": "Public API"})
            self.assertEqual(loaded.hidden, ["cache"])

            first = path.read_bytes()
            save_overrides(root, loaded)
            self.assertEqual(path.read_bytes(), first)

            self.assertTrue(clear_overrides(root))
            self.assertFalse(clear_overrides(root))

    def test_direct_constructor_is_validated_on_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overrides = DiagramOverrides(direction="invalid")
            with self.assertRaises(DiagramOverrideError):
                save_overrides(tmp, overrides)


class OverrideApplicationTests(unittest.TestCase):
    def test_apply_does_not_mutate_source(self) -> None:
        graph = _graph()
        overrides = DiagramOverrides(renames={"db": "Primary"}, hidden=["cache"])
        edited = apply_overrides(graph, overrides)
        self.assertEqual(graph.nodes["db"].name, "Database")
        self.assertIn("cache", graph.nodes)
        self.assertEqual(edited.nodes["db"].name, "Primary")
        self.assertNotIn("cache", edited.nodes)
        self.assertEqual([edge.dst for edge in edited.edges], ["db"])
        self.assertEqual(edited.features[0].nodes, ["api", "db"])

    def test_empty_overrides_still_return_a_copy(self) -> None:
        graph = _graph()
        edited = apply_overrides(graph, DiagramOverrides())
        self.assertIsNot(edited, graph)
        self.assertIsNot(edited.nodes["api"], graph.nodes["api"])

    def test_summary_counts_matches(self) -> None:
        graph = _graph()
        summary = summarize_overrides(
            DiagramOverrides(renames={"db": "Primary", "missing": "X"}, hidden=["cache", "gone"]),
            graph,
        )
        self.assertEqual(summary["renames"], 2)
        self.assertEqual(summary["hidden"], 2)
        self.assertEqual(summary["matched_renames"], 1)
        self.assertEqual(summary["matched_hidden"], 1)
        self.assertTrue(summary["has_changes"])


if __name__ == "__main__":
    unittest.main()
