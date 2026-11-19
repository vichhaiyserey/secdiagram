from __future__ import annotations

import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from secdiagram_core.config import SecdiagramConfig
from secdiagram_core.server import create_server

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_app"


class _StudioServer:
    def __init__(self, source: Path, *, read_only: bool = False) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        shutil.copytree(source, self.root)
        config = SecdiagramConfig()
        config.server.host = "127.0.0.1"
        config.server.port = 0
        config.server.insecure_no_auth = True
        config.server.read_only = read_only
        self.server = create_server(self.root, config)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def get(self, path: str) -> tuple[int, str]:
        with urllib.request.urlopen(self.base_url + path, timeout=60) as response:
            return response.status, response.read().decode("utf-8")

    def post(
        self,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        origin: str | None = None,
    ) -> tuple[int, str]:
        body = json.dumps(payload or {}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode("utf-8")
            finally:
                exc.close()


class StudioServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.studio = _StudioServer(FIXTURE)

    def tearDown(self) -> None:
        self.studio.close()

    def test_studio_assets_and_status(self) -> None:
        status, html = self.studio.get("/studio")
        self.assertEqual(status, 200)
        self.assertIn("secdiagram Studio", html)
        self.assertIn("app.js", html)

        self.assertEqual(self.studio.get("/studio/app.css")[0], 200)
        self.assertEqual(self.studio.get("/studio/app.js")[0], 200)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.studio.get("/studio/../server.py")
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.studio.get("/studio/missing.js")
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()

        status, body = self.studio.get("/api/v1/studio/status")
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data["studio_dir"], ".secdiagram/studio")
        self.assertTrue(data["capabilities"]["offline_first"])
        self.assertTrue(data["capabilities"]["static_analysis_only"])
        self.assertEqual(data["capabilities"]["llm_providers"], ["ollama", "openai"])
        self.assertIn("sdlc", data)
        self.assertIn("overrides", data)
        self.assertIn("installer", data)

        status, body = self.studio.get("/api/v1/studio/sdlc")
        sdlc = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(len(sdlc["phases"]), 5)
        self.assertEqual(sdlc["progress"], {"done": 0, "total": 5})

        status, body = self.studio.get("/api/v1/studio/nodes")
        nodes = json.loads(body)
        self.assertEqual(status, 200)
        self.assertGreater(nodes["total"], 0)

    def test_sdlc_phase_flow_and_gate(self) -> None:
        status, body = self.studio.post(
            "/api/v1/studio/sdlc", {"action": "start", "phase": "discover"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["state"]["progress"], {"done": 0, "total": 5})

        status, _ = self.studio.post(
            "/api/v1/studio/sdlc", {"action": "start", "phase": "review"}
        )
        self.assertEqual(status, 400)

        status, _ = self.studio.post(
            "/api/v1/studio/sdlc",
            {"action": "complete", "phase": "discover", "evidence": "graph.json"},
        )
        self.assertEqual(status, 200)
        state_path = self.studio.root / ".secdiagram" / "studio" / "sdlc.json"
        self.assertTrue(state_path.is_file())
        persisted = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted["phases"]["discover"]["status"], "done")

        status, _ = self.studio.post(
            "/api/v1/studio/sdlc", {"action": "start", "phase": "model"}
        )
        self.assertEqual(status, 200)

        status, _ = self.studio.post(
            "/api/v1/studio/sdlc", {"action": "start", "phase": "not-a-phase"}
        )
        self.assertEqual(status, 400)

    def test_overrides_round_trip(self) -> None:
        _, body = self.studio.get("/api/v1/studio/nodes")
        nodes = json.loads(body)["nodes"]
        first = nodes[0]["id"]
        second = nodes[1]["id"]

        status, body = self.studio.post(
            "/api/v1/studio/overrides",
            {
                "renames": {first: "Renamed Service"},
                "hidden": [second],
                "direction": "TB",
                "theme": "classic",
            },
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["overrides"]["renames"], {first: "Renamed Service"})
        self.assertEqual(payload["summary"]["renames"], 1)

        status, body = self.studio.get("/api/v1/studio/overrides")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["overrides"]["direction"], "TB")

        status, diagram = self.studio.get("/api/v1/studio/diagram?direction=TB&theme=classic")
        self.assertEqual(status, 200)
        self.assertIn("flowchart", diagram)
        self.assertIn("TB", diagram)

        status, body = self.studio.post("/api/v1/studio/overrides", {"action": "reset"})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["summary"]["has_changes"])

    def test_post_guards(self) -> None:
        status, body = self.studio.post("/api/v1/studio/installer", {})
        self.assertEqual(status, 403)
        self.assertIn("studio install", json.loads(body)["message"])

        status, body = self.studio.post(
            "/api/v1/studio/generate",
            {"provider": "openai", "base_url": "http://169.254.169.254"},
        )
        self.assertEqual(status, 400)
        self.assertIn("base_url", json.loads(body)["message"])

        status, _ = self.studio.post(
            "/api/v1/studio/generate", {"provider": "bogus"}
        )
        self.assertEqual(status, 400)
        status, _ = self.studio.post(
            "/api/v1/studio/generate", {"provider": "ollama", "template": "bogus"}
        )
        self.assertEqual(status, 400)

        status, body = self.studio.post(
            "/api/v1/studio/sdlc",
            {"action": "start", "phase": "discover"},
            origin="http://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin", json.loads(body)["message"])

        status, _ = self.studio.post(
            "/api/v1/studio/sdlc",
            {"action": "start", "phase": "discover"},
            origin=self.studio.base_url,
        )
        self.assertEqual(status, 200)

    def test_handoff_preview_and_blocked_write(self) -> None:
        status, markdown = self.studio.get("/api/v1/studio/handoff")
        self.assertEqual(status, 200)
        self.assertIn("Handoff complete: **no**", markdown)

        status, body = self.studio.post("/api/v1/studio/handoff", {"write": True})
        self.assertEqual(status, 409)
        self.assertIn("HandoffBlocked", json.loads(body)["error"])

        for phase in ("discover", "model", "secure", "review", "handoff"):
            status, _ = self.studio.post(
                "/api/v1/studio/sdlc", {"action": "start", "phase": phase}
            )
            self.assertEqual(status, 200, phase)
            status, _ = self.studio.post(
                "/api/v1/studio/sdlc",
                {"action": "complete", "phase": phase, "evidence": f"{phase}.json"},
            )
            self.assertEqual(status, 200, phase)

        status, body = self.studio.post("/api/v1/studio/handoff", {"write": True})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")
        studio_dir = self.studio.root / ".secdiagram" / "studio"
        self.assertTrue((studio_dir / "HANDOFF.md").is_file())
        self.assertTrue((studio_dir / "handoff.json").is_file())

    def test_render_returns_image_or_service_unavailable(self) -> None:
        try:
            status, body = self.studio.get("/api/v1/studio/render?format=svg&detail=high-level")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 503)
            exc.close()
            return
        self.assertEqual(status, 200)
        self.assertIn("<svg", body)


class StudioReadOnlyTests(unittest.TestCase):
    def test_read_only_blocks_state_changes(self) -> None:
        studio = _StudioServer(FIXTURE, read_only=True)
        try:
            status, body = studio.post(
                "/api/v1/studio/sdlc", {"action": "start", "phase": "discover"}
            )
            self.assertEqual(status, 403)
            self.assertIn("read-only", json.loads(body)["message"])

            status, _ = studio.post(
                "/api/v1/studio/overrides", {"renames": {}, "hidden": []}
            )
            self.assertEqual(status, 403)

            status, _ = studio.post("/api/v1/studio/handoff", {"write": True})
            self.assertEqual(status, 403)

            self.assertFalse((studio.root / ".secdiagram" / "studio" / "sdlc.json").exists())
        finally:
            studio.close()


if __name__ == "__main__":
    unittest.main()
