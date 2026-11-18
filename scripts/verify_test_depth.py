"""Run targeted fault-injection checks without editing production files.

Each case first runs its unmodified positive control, then injects a specific
regression in an isolated subprocess. Only assertion failures count as detected
faults: import errors, setup errors, skips and timeouts never earn credit.
This is a bounded regression audit, not an exhaustive mutation score.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CASES = {
    "dangling_edges_removed": "tests.test_diagram_review.ProjectionDiagnosticsTests.test_both_model_projections_preserve_dangling_edges",
    "detailed_validation_omitted": "tests.test_diagram_review.ValidationIntegrationTests.test_cycle_inside_subsystem_blocks_detailed_modes",
    "workspace_validation_bypassed": "tests.test_diagram_review.ValidationIntegrationTests.test_workspace_cycle_blocks_before_manifest_writes",
    "baseline_written_before_validation": "tests.test_diagram_review.ValidationIntegrationTests.test_failed_validation_preserves_baseline_and_existing_reports",
    "canonical_order_ignored": "tests.test_diagram_review.CanonicalRendererTests.test_high_level_order_is_canonical_without_losing_labels_or_styles",
    "serialization_fields_corrupted": "tests.test_cache_serialization.CacheSerializationTests.test_analysis_result_dict_and_json_roundtrip",
    "node_cap_returns_empty": "tests.test_render.RenderTests.test_mermaid_max_diagram_nodes_capping",
    "attack_allowlist_returns_empty": "tests.test_attack.PolicyGateTests.test_technique_allowlist_restricts_gate",
    "confidence_constant": "tests.test_policy.ConfidenceTests.test_deterministic",
    "scan_gate_over_released": "tests.test_server.LimitPrimitiveTests.test_scan_manager_release_without_acquire_is_safe",
    "yaml_parser_returns_empty": "tests.test_yaml_lite.YamlLiteTests.test_malformed_input_does_not_raise",
    "authentication_bypassed": "tests.test_server.AuthenticatorTests.test_basic_authenticator",
    "fixture_state_shared": "tests.test_contract.ConsumerContractTests.test_fixture_consumers_do_not_share_mutable_results",
    "redaction_disabled": "tests.test_redaction.RedactionTests.test_aws_credentials",
    "python_sast_disabled": "tests.test_security.SecurityTests.test_tainted_command_and_sql_are_critical",
    "polyglot_sast_disabled": "tests.test_polyglot.CSharpTests.test_findings_exact",
    "parallel_workers_fail": "tests.test_scale.ScaleTests.test_parallel_matches_serial",
}


def inject(case: str, stack: contextlib.ExitStack) -> None:
    from secdiagram_core import cli, diagram_model
    from secdiagram_core.analyzer import AnalysisResult

    if case == "dangling_edges_removed":
        original_projection = diagram_model._from_graph

        def filtered(graph):
            components, relationships = original_projection(graph)
            ids = {item.id for item in components}
            return components, [edge for edge in relationships if edge.src in ids and edge.dst in ids]

        stack.enter_context(mock.patch.object(diagram_model, "_from_graph", side_effect=filtered))
    elif case == "detailed_validation_omitted":
        stack.enter_context(mock.patch.object(cli, "build_mermaid_model", return_value=diagram_model.DiagramModel()))
    elif case == "workspace_validation_bypassed":
        stack.enter_context(mock.patch.object(cli, "_validate_diagrams", return_value=True))
    elif case == "baseline_written_before_validation":
        original_validation = cli._validate_diagrams

        def premature_write(graph, hla, args):
            if args.create_baseline:
                cli.write_baseline(graph, Path(args.baseline))
            return original_validation(graph, hla, args)

        stack.enter_context(mock.patch.object(cli, "_validate_diagrams", side_effect=premature_write))
    elif case == "canonical_order_ignored":
        original_model = diagram_model.build_diagram_model

        def unordered(graph, hla=None):
            model = original_model(graph, hla)
            if hla is not None:
                positions = {sub.id: index for index, sub in enumerate(hla.subsystems)}
                model.components.sort(key=lambda item: positions[item.id])
            return model

        stack.enter_context(mock.patch.object(diagram_model, "build_diagram_model", side_effect=unordered))
    elif case == "serialization_fields_corrupted":
        original_from_dict = AnalysisResult.from_dict

        def corrupt(_cls, data):
            result = original_from_dict(data)
            next(iter(result.graph.nodes.values())).qualname = "mock_corrupt_symbol"
            return result

        stack.enter_context(mock.patch.object(AnalysisResult, "from_dict", classmethod(corrupt)))
    elif case == "node_cap_returns_empty":
        stack.enter_context(mock.patch("secdiagram_core.render_mermaid._select_diagram_nodes", return_value=([], {})))
    elif case == "attack_allowlist_returns_empty":
        stack.enter_context(mock.patch("tests.test_attack.policy_violations", return_value=[]))
    elif case == "confidence_constant":
        stack.enter_context(mock.patch("tests.test_policy.compute_confidence", return_value=0.9))
    elif case == "scan_gate_over_released":
        stack.enter_context(mock.patch("secdiagram_core.server.threading.BoundedSemaphore", side_effect=threading.Semaphore))
    elif case == "yaml_parser_returns_empty":
        stack.enter_context(mock.patch("tests.test_yaml_lite.parse_yaml", return_value=[]))
    elif case == "authentication_bypassed":
        stack.enter_context(mock.patch("secdiagram_core.server.BasicAuthenticator.authenticate", return_value=(True, "admin")))
    elif case == "fixture_state_shared":
        from tests import support

        stack.enter_context(mock.patch.object(support, "fixture_result", side_effect=support._fixture_result))
    elif case == "redaction_disabled":
        stack.enter_context(mock.patch("tests.test_redaction.redact_secrets", side_effect=lambda value: value))
    elif case == "python_sast_disabled":
        stack.enter_context(mock.patch("secdiagram_core.analyzer.analyze_security", return_value=[]))
    elif case == "polyglot_sast_disabled":
        stack.enter_context(mock.patch("secdiagram_core.analyzer.analyze_polyglot_security", return_value=[]))
    elif case == "parallel_workers_fail":
        stack.enter_context(mock.patch("secdiagram_core.ast_index.ProcessPoolExecutor", side_effect=OSError("mock worker startup failure")))
    else:
        raise ValueError(f"unknown fault case: {case}")


def run_test(name: str) -> unittest.TestResult:
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        suite = unittest.defaultTestLoader.loadTestsFromName(name)
        return unittest.TextTestRunner(stream=sink, verbosity=0).run(suite)


def worker(case: str, control: bool = False) -> dict[str, Any]:
    name = CASES[case]
    if control:
        result = run_test(name)
        return {"passed": result.wasSuccessful() and result.testsRun == 1 and not result.skipped}
    with contextlib.ExitStack() as stack:
        inject(case, stack)
        result = run_test(name)
    return {
        "case": case,
        "test": name,
        "detected": result.testsRun == 1 and bool(result.failures) and not result.errors and not result.skipped,
        "assertion_failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=sorted(CASES), help=argparse.SUPPRESS)
    parser.add_argument("--control", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help="optional JSON audit report path")
    args = parser.parse_args(argv)
    if args.case:
        print(json.dumps(worker(args.case, args.control), sort_keys=True))
        return 0
    results: list[dict[str, Any]] = []
    for case in sorted(CASES):
        try:
            command = [sys.executable, str(Path(__file__).resolve()), "--case", case]
            control = subprocess.run(
                [*command, "--control"], cwd=ROOT,
                capture_output=True, text=True, timeout=120, check=False,
            )
            if control.returncode or not json.loads(control.stdout).get("passed"):
                results.append({"case": case, "detected": False, "error": "unmodified control did not pass"})
                continue
            process = subprocess.run(
                command,
                cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
            )
            if process.returncode:
                results.append({"case": case, "detected": False, "error": "worker failed"})
            else:
                results.append({**json.loads(process.stdout), "control_passed": True})
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            results.append({"case": case, "detected": False, "error": "worker could not complete"})
    report = {"cases": results, "detected": sum(bool(item["detected"]) for item in results), "total": len(results)}
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if report["detected"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
