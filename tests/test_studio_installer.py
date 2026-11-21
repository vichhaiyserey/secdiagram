from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secdiagram_core import __version__, studio

REPO = Path(__file__).resolve().parent.parent


class StudioInstallerTests(unittest.TestCase):
    def test_install_writes_skill_and_launchers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "studio-home"
            result = studio.install(
                studio.InstallOptions(home=home, project_root=REPO, create_venv=False)
            )
            self.assertTrue(result.created)
            self.assertFalse(result.venv_created)
            self.assertIsNone(result.manifest["venv"])
            self.assertTrue((home / "project-root.txt").is_file())
            self.assertTrue((home / "README.md").is_file())
            skill_dir = home / "skills" / studio.SKILL_NAME
            self.assertTrue((skill_dir / "SKILL.md").is_file())
            self.assertTrue((skill_dir / "skill.json").is_file())
            for launcher in studio.launcher_scripts():
                self.assertTrue((home / launcher).is_file(), launcher)

            skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("secdiagram-diagramming", skill_text)
            self.assertIn("Never execute code", skill_text)
            skill_json = json.loads((skill_dir / "skill.json").read_text(encoding="utf-8"))
            self.assertEqual(skill_json["name"], studio.SKILL_NAME)
            self.assertEqual(skill_json["version"], __version__)

            manifest = result.manifest
            self.assertEqual(manifest["project_root"], REPO.as_posix())
            recorded = {entry["path"]: entry for entry in manifest["files"]}
            self.assertTrue(recorded, "an empty manifest must not appear verified")
            self.assertEqual(set(result.files), set(recorded))
            for rel_path in result.files:
                self.assertIn(rel_path, recorded)
                self.assertEqual(recorded[rel_path]["bytes"], (home / rel_path).stat().st_size)
                self.assertEqual(
                    recorded[rel_path]["sha256"],
                    hashlib.sha256((home / rel_path).read_bytes()).hexdigest(),
                )

            status = studio.status(home)
            self.assertTrue(status["installed"])
            self.assertTrue(status["healthy"])
            self.assertFalse(status["stale"])
            self.assertTrue(status["skill_installed"])
            self.assertFalse(status["venv_present"])

    def test_reinstall_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "studio-home"
            options = studio.InstallOptions(home=home, project_root=REPO, create_venv=False)
            first = studio.install(options)
            manifest_path = home / studio.MANIFEST_FILENAME
            first_manifest = manifest_path.read_bytes()
            second = studio.install(options)
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(manifest_path.read_bytes(), first_manifest)
            self.assertEqual(first.manifest, second.manifest)

    def test_version_mismatch_requires_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "studio-home"
            studio.install(studio.InstallOptions(home=home, project_root=REPO, create_venv=False))
            manifest_path = home / studio.MANIFEST_FILENAME
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["version"] = "0.0.0"
            manifest_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(studio.StudioInstallError):
                studio.install(
                    studio.InstallOptions(home=home, project_root=REPO, create_venv=False)
                )
            forced = studio.install(
                studio.InstallOptions(
                    home=home,
                    project_root=REPO,
                    create_venv=False,
                    force=True,
                )
            )
            self.assertEqual(forced.manifest["version"], __version__)

    def test_missing_project_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(studio.StudioInstallError):
                studio.install(
                    studio.InstallOptions(
                        home=Path(tmp) / "home",
                        project_root=Path(tmp) / "missing",
                        create_venv=False,
                    )
                )

    def test_uninstall_removes_managed_files_and_preserves_unmanaged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "studio-home"
            studio.install(studio.InstallOptions(home=home, project_root=REPO, create_venv=False))
            keep = home / "operator-notes.txt"
            keep.write_text("keep me", encoding="utf-8")
            venv_marker = home / studio.VENV_DIRNAME / "marker"
            venv_marker.parent.mkdir(parents=True)
            venv_marker.write_text("venv", encoding="utf-8")

            result = studio.uninstall(home, keep_venv=True)
            self.assertTrue(result["kept_venv"])
            self.assertTrue(keep.is_file())
            self.assertTrue(venv_marker.is_file())
            self.assertFalse((home / "project-root.txt").exists())
            self.assertFalse((home / "skills" / studio.SKILL_NAME / "SKILL.md").exists())

            result = studio.uninstall(home, keep_venv=False)
            self.assertFalse(venv_marker.is_file())
            self.assertFalse((home / studio.VENV_DIRNAME).exists())
            self.assertIn(studio.VENV_DIRNAME, result["removed"])

    def test_uninstall_refuses_paths_outside_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "studio-home"
            home.mkdir()
            outside = Path(tmp) / "outside.txt"
            outside.write_text("safe", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "files": [{"path": "../outside.txt"}],
            }
            (home / studio.MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")
            result = studio.uninstall(home)
            self.assertIn("../outside.txt", result["skipped"])
            self.assertTrue(outside.is_file())

    def test_default_home_honours_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SECDIAGRAM_STUDIO_HOME": tmp}):
                self.assertEqual(studio.default_home(), Path(tmp))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECDIAGRAM_STUDIO_HOME", None)
            self.assertEqual(studio.default_home(), Path.home() / ".secdiagram" / "studio")

    def test_status_for_missing_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status = studio.status(Path(tmp) / "absent")
            self.assertFalse(status["installed"])
            self.assertFalse(status["healthy"])
            self.assertFalse(status["skill_installed"])


if __name__ == "__main__":
    unittest.main()
