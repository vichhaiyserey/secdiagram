import unittest

from secdiagram_core.dependency_versions import apply_pub_ranges, evaluate_range
from secdiagram_core.model import Finding


class PubRangeTests(unittest.TestCase):
    def test_prerelease_multiple_intervals_and_inclusive_last_affected(self):
        events = [
            {"introduced": "0"}, {"fixed": "1.2.0-beta.2"},
            {"introduced": "2.0.0"}, {"last_affected": "2.1.0"},
        ]
        for version, expected in (
            ("1.2.0-beta.1", "affected"), ("1.2.0-beta.2", "fixed"),
            ("2.0.0", "affected"), ("2.1.0+build", "affected"),
            ("2.1.1", "fixed"), ("2.0.0-01", "unknown"),
        ):
            with self.subTest(version=version):
                self.assertEqual(evaluate_range(version, events), expected)
        self.assertEqual(evaluate_range("2.1.1", [{"fixed": "1.0.0"}]), "unknown")

    def test_local_osv_scope_and_conflicting_ranges(self):
        finding = Finding(
            "example", "dependency", "high", "Advisory", "Evidence",
            source="trivy", external_id="TEST-1",
            metadata={"package": "example", "version": "1.0.0", "resolved_version": "2.1.0"},
        )
        record = {
            "id": "OTHER-1", "aliases": ["TEST-1"],
            "affected": [{
                "package": {"ecosystem": "Pub", "name": "example"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        apply_pub_ranges([finding], [record])
        self.assertTrue(finding.metadata["fixed_in_inventory"])
        apply_pub_ranges([finding], [record, {**record, "affected": [{
            "package": {"ecosystem": "Pub", "name": "example"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }]}])
        self.assertFalse(finding.metadata["fixed_in_inventory"])
        self.assertEqual(finding.metadata["advisory_version_status"], "affected")
