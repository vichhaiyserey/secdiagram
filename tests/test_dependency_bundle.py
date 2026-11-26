import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from secdiagram_core.cli import audit_main
from secdiagram_core.dependency_bundle import load_bundle


class EvidenceBundleTests(unittest.TestCase):
    def test_current_stale_and_tampered_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.dart").write_text("void main() {}", encoding="utf-8")
            report = root / "trivy.json"
            content = b'{"Results": []}\r\n'
            report.write_bytes(content)
            manifest = root / "evidence.json"
            descriptor = {"path": report.name, "sha256": hashlib.sha256(content).hexdigest()}
            data = {"version": 1, "snapshot_date": "2026-11-20", "reports": {"trivy": descriptor}}
            manifest.write_text(json.dumps(data), encoding="utf-8")
            _, status = load_bundle(manifest)
            self.assertEqual(status["freshness"], "unchecked")
            self.assertEqual(load_bundle(manifest, as_of=date(2026, 11, 19))[1]["freshness"], "future")
            output = root / "audit.json"
            args = [
                str(root), "--offline", "--quiet", "--evidence-bundle", str(manifest),
                "--require-evidence", "--json", str(output),
            ]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit_main([*args, "--evidence-as-of", "2026-11-26"]), 0)
                first = output.read_bytes()
                self.assertEqual(audit_main([*args, "--evidence-as-of", "2026-11-26"]), 0)
                self.assertEqual(output.read_bytes(), first)
                self.assertEqual(audit_main([*args, "--evidence-as-of", "2026-12-01"]), 2)
                self.assertEqual(json.loads(output.read_text())["evidence"]["freshness"], "stale")
                report.write_bytes(content + b" ")
                self.assertEqual(audit_main([*args, "--evidence-as-of", "2026-11-26"]), 2)
                self.assertEqual(json.loads(output.read_text())["evidence"]["freshness"], "invalid")
                relaxed = [arg for arg in args if arg != "--require-evidence"]
                self.assertEqual(audit_main(relaxed), 0)
            descriptor["path"] = "../trivy.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "report path"):
                load_bundle(manifest)

    def test_repository_lockfile_binding_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lockfile = root / "pubspec.lock"
            lockfile.write_bytes(b"packages: {}\n")
            report = root / "trivy.json"
            report.write_bytes(b'{"Results":[]}')
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps({
                "version": 1, "snapshot_date": "2026-11-20",
                "reports": {"trivy": {
                    "path": "trivy.json", "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                }},
                "repository": {"revision": "a" * 40, "lockfiles": {
                    "pubspec.lock": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
                }},
            }), encoding="utf-8")
            self.assertEqual(load_bundle(manifest, analysis_root=root)[1]["revision"], "a" * 40)
            lockfile.write_bytes(b"packages:\n  changed: {}\n")
            with self.assertRaisesRegex(ValueError, "lockfile checksum mismatch"):
                load_bundle(manifest, analysis_root=root)
