"""Benchmark offline Pub inventory, report correlation and deterministic exports."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import analyze  # noqa: E402
from secdiagram_core.render_json import render_json  # noqa: E402
from secdiagram_core.render_sarif import render_sarif  # noqa: E402
from secdiagram_core.render_vex import render_vex  # noqa: E402


def benchmark(root: Path, count: int) -> dict[str, float | int]:
    (root / "pubspec.yaml").write_text("dependencies:\n  package_0: any\n", encoding="utf-8")
    (root / "pubspec.lock").write_text(
        "packages:\n" + "".join(
            f"  package_{index}:\n    version: 1.0.0\n"
            for index in range(count)
        ),
        encoding="utf-8",
    )
    (root / "main.dart").write_text(
        "import 'package:package_0/library.dart' as dependency;\n"
        "void main() { dependency.check(); }\n",
        encoding="utf-8",
    )
    report = root / "trivy.json"
    report.write_text(json.dumps({"Results": [{"Target": "pubspec.lock", "Vulnerabilities": [
        {"PkgName": f"package_{index}", "InstalledVersion": "1.0.0",
         "VulnerabilityID": f"BENCH-{index}", "Severity": "HIGH"}
        for index in range(min(count, 1000))
    ]}]}), encoding="utf-8")

    digests = []
    durations = []
    for _ in range(2):
        start = perf_counter()
        result = analyze(root, trivy_report=report)
        if sum(node.kind == "dependency" for node in result.graph.nodes.values()) != count:
            raise RuntimeError("inventory lost packages")
        imported = [item for item in result.graph.findings if item.source == "trivy"]
        if len(imported) != min(count, 1000) or any(not item.node_id for item in imported):
            raise RuntimeError("report lost exact package matches")
        hashes = []
        for output in (render_json(result.graph), render_sarif(result.graph), render_vex(result)):
            hashes.append(hashlib.sha256(output.encode("utf-8")).hexdigest())
        digests.append(hashes)
        durations.append(perf_counter() - start)
    if digests[0] != digests[1]:
        raise RuntimeError("outputs changed between identical analyses")
    return {"packages": count, "advisories": len(imported), "max_seconds": round(max(durations), 3)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-seconds", type=float, default=30.0)
    args = parser.parse_args()
    results = []
    for count in (100, 1000, 10000):
        with tempfile.TemporaryDirectory(prefix="secdiagram-benchmark-") as folder:
            measurement = benchmark(Path(folder), count)
        if sys.platform == "linux":
            import resource

            measurement["process_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        results.append(measurement)
    print(json.dumps(results, indent=2))
    return int(any(item["max_seconds"] > args.max_seconds for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
