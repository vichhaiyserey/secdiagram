from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core import agentic
from secdiagram_core.model import Finding, Graph, Loc, Node


class SdlcStateTests(unittest.TestCase):
    def test_phases_are_deterministic(self) -> None:
        state = agentic.default_state()
        self.assertEqual(tuple(state.phases), ("discover", "model", "secure", "review", "handoff"))
        self.assertEqual(state.progress, {"done": 0, "total": 5})
        self.assertFalse(state.complete)

    def test_entry_gate_requires_previous_phase(self) -> None:
        state = agentic.default_state()
        self.assertTrue(agentic.can_start(state, "discover"))
        self.assertFalse(agentic.can_start(state, "model"))
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "start", "model")

        agentic.apply_action(state, "start", "discover")
        agentic.apply_action(state, "complete", "discover", evidence="graph.json")
        self.assertTrue(agentic.can_start(state, "model"))
        self.assertEqual(state.current, "model")

    def test_completion_requires_in_progress(self) -> None:
        state = agentic.default_state()
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "complete", "discover", evidence="graph.json")

    def test_block_requires_reason_and_can_be_unblocked(self) -> None:
        state = agentic.default_state()
        agentic.apply_action(state, "start", "discover")
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "block", "discover")
        agentic.apply_action(state, "block", "discover", note="waiting for access")
        self.assertEqual(state.phases["discover"].status, "blocked")
        self.assertEqual(state.phases["discover"].note, "waiting for access")
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "start", "discover")
        agentic.apply_action(state, "unblock", "discover")
        self.assertEqual(state.phases["discover"].status, "in_progress")

    def test_reset_clears_phase_and_downstream(self) -> None:
        state = agentic.default_state()
        for phase in ("discover", "model"):
            agentic.apply_action(state, "start", phase)
            agentic.apply_action(state, "complete", phase, evidence=f"{phase}.json")
        agentic.apply_action(state, "reset", "model")
        self.assertEqual(state.phases["discover"].status, "done")
        self.assertEqual(state.phases["model"].status, "pending")
        self.assertEqual(state.phases["secure"].status, "pending")
        self.assertEqual(state.current, "model")

    def test_evidence_is_bounded_and_deduplicated(self) -> None:
        state = agentic.default_state()
        agentic.apply_action(state, "start", "discover")
        for _ in range(agentic._MAX_EVIDENCE + 10):
            agentic.apply_action(state, "evidence", "discover", evidence="graph.json")
        self.assertEqual(state.phases["discover"].evidence, ["graph.json"])
        # Repeating one item only tests deduplication, never the list bound.
        unique = [f"evidence-{index}.json" for index in range(agentic._MAX_EVIDENCE + 10)]
        for ref in unique:
            agentic.apply_action(state, "evidence", "discover", evidence=ref)
        self.assertEqual(state.phases["discover"].evidence, unique[-agentic._MAX_EVIDENCE :])
        agentic.apply_action(state, "note", "discover", note="x" * 5000)
        self.assertEqual(len(state.phases["discover"].note), agentic._MAX_TEXT)

    def test_invalid_phase_and_action_are_rejected(self) -> None:
        state = agentic.default_state()
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "start", "deploy")
        with self.assertRaises(agentic.SdlcError):
            agentic.apply_action(state, "explode", "discover")


class SdlcPersistenceTests(unittest.TestCase):
    def test_save_and_load_are_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = agentic.default_state()
            agentic.apply_action(state, "start", "discover")
            agentic.apply_action(state, "complete", "discover", evidence="graph.json")
            path = agentic.save_state(root, state)
            first = path.read_bytes()
            loaded = agentic.load_state(root)
            agentic.save_state(root, loaded)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual(loaded.phases["discover"].status, "done")

    def test_missing_state_returns_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = agentic.load_state(tmp)
            self.assertFalse(state.complete)

    def test_corrupt_state_raises_sdlc_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = agentic.state_path(tmp)
            path.parent.mkdir(parents=True)
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(agentic.SdlcError):
                agentic.load_state(tmp)


class HandoffTests(unittest.TestCase):
    def _complete(self) -> agentic.SdlcState:
        state = agentic.default_state()
        for phase in agentic.PHASES:
            agentic.apply_action(state, "start", phase)
            agentic.apply_action(
                state,
                "complete",
                phase,
                evidence=f"{phase}.json",
            )
        return state

    def test_handoff_requires_every_phase(self) -> None:
        state = agentic.default_state()
        payload = agentic.build_handoff(state, repo_name="demo")
        self.assertFalse(payload["complete"])
        self.assertEqual(payload["progress"], {"done": 0, "total": 5})

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(agentic.HandoffBlocked):
                agentic.write_handoff(Path(tmp), state, repo_name="demo")

    def test_handoff_payload_and_markdown(self) -> None:
        state = self._complete()
        graph = Graph()
        graph.add_node(Node(id="n1", kind="function", name="handler", qualname="handler"))
        graph.findings.append(
            Finding(
                id="f1",
                category="sql-injection",
                severity="high",
                title="SQL injection",
                message="tainted query",
                node_id="n1",
                evidence=[Loc("app.py", 12)],
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "graph.json").write_text('{"nodes": []}\n', encoding="utf-8")
            md_path, json_path = agentic.write_handoff(
                root / "studio",
                state,
                repo_name="demo",
                graph=graph,
                artifact_dir=root,
            )
            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("# Handoff - demo", markdown)
            self.assertIn("SQL injection", markdown)
            self.assertIn("| graph.json |", markdown)
            payload_text = json_path.read_text(encoding="utf-8")
            self.assertIn('"complete": true', payload_text)
            self.assertIn('"total": 1', payload_text)

            first = (markdown, payload_text)
            agentic.write_handoff(
                root / "studio",
                state,
                repo_name="demo",
                graph=graph,
                artifact_dir=root,
            )
            self.assertEqual(
                (md_path.read_text(encoding="utf-8"), json_path.read_text(encoding="utf-8")),
                first,
            )

    def test_phase_brief_contains_gate_and_evidence(self) -> None:
        state = agentic.default_state()
        agentic.apply_action(state, "start", "discover")
        agentic.apply_action(state, "complete", "discover", evidence="graph.json")
        brief = agentic.render_phase_brief(state, "model", repo_name="demo")
        self.assertIn("Model phase brief - demo", brief)
        self.assertIn("Entry gate: **open**", brief)
        self.assertIn("graph.json", brief)

    def test_markdown_cells_escape_pipes_and_newlines(self) -> None:
        state = self._complete()
        payload = agentic.build_handoff(state, repo_name="demo|repo\nnext")
        markdown = agentic.render_handoff_markdown(payload)
        self.assertEqual(markdown.splitlines()[0], "# Handoff - demo\\|repo next")


if __name__ == "__main__":
    unittest.main()
