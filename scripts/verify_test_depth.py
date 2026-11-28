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
from dataclasses import replace
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
    "redaction_disabled": "tests.test_redaction.RedactionTests.test_provider_tokens_in_neutral_text",
    "python_sast_disabled": "tests.test_security.SecurityTests.test_tainted_command_and_sql_are_critical",
    "polyglot_sast_disabled": "tests.test_polyglot.CSharpTests.test_findings_exact",
    "parallel_workers_fail": "tests.test_scale.ScaleTests.test_parallel_matches_serial",
    "threat_evidence_dropped": "tests.test_threat_review.ThreatRecordTests.test_source_facts_components_assets_and_ordered_flow",
    "auth_review_claims_confirmed": "tests.test_threat_review.ThreatRecordTests.test_route_review_does_not_claim_missing_authorization_or_input_acceptance",
    "threat_flow_dropped": "tests.test_threat_review.ThreatRecordTests.test_source_facts_components_assets_and_ordered_flow",
    "threat_diff_hides_changes": "tests.test_threat_review.ThreatDiffTests.test_add_remove_change_and_noop_have_complete_review_evidence",
    "threat_diff_hides_context": "tests.test_threat_review.ThreatDiffTests.test_scan_coverage_and_suppression_changes_are_visible",
    "github_pattern_disabled": "tests.test_redaction.RedactionTests.test_provider_tokens_in_neutral_text",
    "redaction_deletes_safe_context": "tests.test_redaction.RedactionTests.test_benign_text_and_token_configuration_are_preserved",
    "custom_sanitizer_analysis_empty": "tests.test_framework_registry.FrameworkRegistryTests.test_custom_sanitizer_clears_taint",
    "edge_filter_ignored": "tests.test_graph.GraphTests.test_min_confidence_filters_edges",
    "iac_containment_disabled": "tests.test_iac.AnalyzerBehaviorTests.test_path_escape_is_skipped",
    "evidence_limit_ignored": "tests.test_agentic.SdlcStateTests.test_evidence_is_bounded_and_deduplicated",
    "installer_digest_corrupted": "tests.test_studio_installer.StudioInstallerTests.test_install_writes_skill_and_launchers",
    "risk_priorities_empty": "tests.test_risk.OutputTests.test_security_report_priorities_follow_risk",
    "trace_source_corrupted": "tests.test_reachability_query.ReachabilityQueryTests.test_get_taint_traces",
    "image_flag_ignored": "tests.test_offline_cli.OfflineCliTests.test_offline_never_calls_http_and_default_images_are_local",
    "tab_indentation_accepted": "tests.test_attack.PolicyParsingTests.test_invalid_policy_conditions_report_the_correct_error",
    "studio_asset_body_empty": "tests.test_studio_server.StudioServerTests.test_studio_assets_and_status",
    "studio_tab_association_crossed": "tests.test_studio_ui_accessibility.StudioAccessibilityAssetTests.test_primary_views_use_tab_semantics",
    "unowned_findings_discarded": "tests.test_framework_registry.FrameworkRegistryTests.test_security_evidence_survives_unresolved_graph_ownership",
    "studio_rendered_bytes_corrupted": "tests.test_studio_server.StudioServerTests.test_render_success_and_unavailability_follow_renderer_outcome",
}


def inject(case: str, stack: contextlib.ExitStack) -> None:
    from secdiagram_core import cli, diagram_model
    from secdiagram_core.analyzer import AnalysisResult

    if case == "dangling_edges_removed":
        original_projection = diagram_model._from_graph

        def filtered(graph):
            components, relationships = original_projection(graph)
            ids = {item.id for item in components}
            return components, [
                edge for edge in relationships if edge.src in ids and edge.dst in ids
            ]

        stack.enter_context(mock.patch.object(diagram_model, "_from_graph", side_effect=filtered))
    elif case == "detailed_validation_omitted":
        stack.enter_context(
            mock.patch.object(cli, "build_mermaid_model", return_value=diagram_model.DiagramModel())
        )
    elif case == "workspace_validation_bypassed":
        stack.enter_context(mock.patch.object(cli, "_validate_diagrams", return_value=True))
    elif case == "baseline_written_before_validation":
        original_validation = cli._validate_diagrams

        def premature_write(graph, hla, args):
            if args.create_baseline:
                cli.write_baseline(graph, Path(args.baseline))
            return original_validation(graph, hla, args)

        stack.enter_context(
            mock.patch.object(cli, "_validate_diagrams", side_effect=premature_write)
        )
    elif case == "canonical_order_ignored":
        original_model = diagram_model.build_diagram_model

        def unordered(graph, hla=None):
            model = original_model(graph, hla)
            if hla is not None:
                positions = {sub.id: index for index, sub in enumerate(hla.subsystems)}
                model.components.sort(key=lambda item: positions[item.id])
            return model

        stack.enter_context(
            mock.patch.object(diagram_model, "build_diagram_model", side_effect=unordered)
        )
    elif case == "serialization_fields_corrupted":
        original_from_dict = AnalysisResult.from_dict

        def corrupt(_cls, data):
            result = original_from_dict(data)
            next(iter(result.graph.nodes.values())).qualname = "mock_corrupt_symbol"
            return result

        stack.enter_context(mock.patch.object(AnalysisResult, "from_dict", classmethod(corrupt)))
    elif case == "node_cap_returns_empty":
        stack.enter_context(
            mock.patch(
                "secdiagram_core.render_mermaid._select_diagram_nodes", return_value=([], {})
            )
        )
    elif case == "attack_allowlist_returns_empty":
        stack.enter_context(mock.patch("tests.test_attack.policy_violations", return_value=[]))
    elif case == "confidence_constant":
        stack.enter_context(mock.patch("tests.test_policy.compute_confidence", return_value=0.9))
    elif case == "scan_gate_over_released":
        stack.enter_context(
            mock.patch(
                "secdiagram_core.server.threading.BoundedSemaphore", side_effect=threading.Semaphore
            )
        )
    elif case == "yaml_parser_returns_empty":
        stack.enter_context(mock.patch("tests.test_yaml_lite.parse_yaml", return_value=[]))
    elif case == "authentication_bypassed":
        stack.enter_context(
            mock.patch(
                "secdiagram_core.server.BasicAuthenticator.authenticate",
                return_value=(True, "admin"),
            )
        )
    elif case == "fixture_state_shared":
        from tests import support

        stack.enter_context(
            mock.patch.object(support, "fixture_result", side_effect=support._fixture_result)
        )
    elif case == "redaction_disabled":
        stack.enter_context(
            mock.patch("tests.test_redaction.redact_secrets", side_effect=lambda value: value)
        )
    elif case == "python_sast_disabled":
        stack.enter_context(
            mock.patch("secdiagram_core.analyzer.analyze_security", return_value=[])
        )
    elif case == "polyglot_sast_disabled":
        stack.enter_context(
            mock.patch("secdiagram_core.analyzer.analyze_polyglot_security", return_value=[])
        )
    elif case == "parallel_workers_fail":
        stack.enter_context(
            mock.patch(
                "secdiagram_core.ast_index.ProcessPoolExecutor",
                side_effect=OSError("mock worker startup failure"),
            )
        )
    elif case in {"threat_evidence_dropped", "auth_review_claims_confirmed", "threat_flow_dropped"}:
        from secdiagram_core import threat_model

        original_attach = threat_model.attach_threat_records

        def corrupt_records(graph, threats):
            original_attach(graph, threats)
            for threat in threats:
                for record in threat.records:
                    if case == "threat_evidence_dropped":
                        record["evidence"] = []
                    elif case == "auth_review_claims_confirmed" and record["status"] == "review":
                        record["status"] = "observed"
                    elif case == "threat_flow_dropped":
                        record["data_flows"] = []

        stack.enter_context(
            mock.patch.object(threat_model, "attach_threat_records", side_effect=corrupt_records)
        )
    elif case in {"threat_diff_hides_changes", "threat_diff_hides_context"}:
        from secdiagram_core import threat_review

        original_diff = threat_review.diff_threat_snapshots

        def corrupt_diff(before, after):
            result = original_diff(before, after)
            if case == "threat_diff_hides_changes":
                result["changed"] = []
            else:
                result["context_changes"] = {}
            return result

        stack.enter_context(
            mock.patch("tests.test_threat_review.diff_threat_snapshots", side_effect=corrupt_diff)
        )
    elif case == "github_pattern_disabled":
        from secdiagram_core import redaction

        patterns = tuple(
            pattern for index, pattern in enumerate(redaction._TOKEN_PATTERNS) if index != 1
        )
        stack.enter_context(mock.patch.object(redaction, "_TOKEN_PATTERNS", patterns))
    elif case == "unowned_findings_discarded":
        from secdiagram_core.security import analyze

        def drop_unowned(*args, **kwargs):
            return [finding for finding in analyze(*args, **kwargs) if finding.node_id]

        stack.enter_context(mock.patch("tests.test_framework_registry.analyze_security", side_effect=drop_unowned))
    elif case == "studio_rendered_bytes_corrupted":
        original_read_bytes = Path.read_bytes

        def corrupted_image(path):
            return b"mock_corrupted_bytes" if path.name in {"diagram.svg", "diagram.png"} else original_read_bytes(path)

        stack.enter_context(mock.patch.object(Path, "read_bytes", corrupted_image))
    elif case == "redaction_deletes_safe_context":
        stack.enter_context(
            mock.patch("tests.test_redaction.redact_secrets", return_value="[REDACTED]")
        )
    elif case == "custom_sanitizer_analysis_empty":
        stack.enter_context(
            mock.patch("tests.test_framework_registry.analyze_security", return_value=[])
        )
    elif case == "edge_filter_ignored":
        from secdiagram_core.analyzer import run_analysis

        stack.enter_context(
            mock.patch(
                "tests.test_graph.run_analysis",
                side_effect=lambda config: run_analysis(replace(config, min_confidence=0.0)),
            )
        )
    elif case == "iac_containment_disabled":

        def unsafe_read(root, path, max_size=5 * 1024 * 1024):
            return (root / path).read_text(encoding="utf-8")

        stack.enter_context(
            mock.patch("secdiagram_core.iac._safe_read_text", side_effect=unsafe_read)
        )
    elif case == "evidence_limit_ignored":
        from secdiagram_core import agentic

        original_append = agentic._append_evidence

        def unlimited_evidence(record, evidence):
            previous = list(record.evidence)
            original_append(record, evidence)
            if len(previous) >= agentic._MAX_EVIDENCE and evidence not in previous:
                record.evidence[:] = previous + [evidence]

        stack.enter_context(
            mock.patch.object(agentic, "_append_evidence", side_effect=unlimited_evidence)
        )
    elif case == "installer_digest_corrupted":
        stack.enter_context(
            mock.patch("secdiagram_core.studio._sha256_file", return_value="0" * 64)
        )
    elif case == "risk_priorities_empty":
        from secdiagram_core.security_report import build_security_report

        def empty_priorities(*args, **kwargs):
            report = build_security_report(*args, **kwargs)
            report.priorities.clear()
            return report

        stack.enter_context(
            mock.patch("tests.test_risk.build_security_report", side_effect=empty_priorities)
        )
    elif case == "trace_source_corrupted":
        from secdiagram_core.model import TaintTrace

        original_trace_dict = TaintTrace.to_dict

        def wrong_source(trace):
            payload = original_trace_dict(trace)
            payload["source"] = {"path": "wrong.py", "line": 1, "col": 0}
            return payload

        stack.enter_context(mock.patch.object(TaintTrace, "to_dict", wrong_source))
    elif case == "image_flag_ignored":
        original_scan = cli._scan_main

        def ignore_image(argv, summary=None):
            return original_scan([arg for arg in argv if arg != "--image"], summary)

        stack.enter_context(mock.patch.object(cli, "_scan_main", side_effect=ignore_image))
    elif case == "tab_indentation_accepted":
        from secdiagram_core import threat_model

        original_policy_parser = threat_model._parse_policy_yaml
        stack.enter_context(
            mock.patch.object(
                threat_model,
                "_parse_policy_yaml",
                side_effect=lambda text: original_policy_parser(text.expandtabs(2)),
            )
        )
    elif case == "studio_asset_body_empty":
        from secdiagram_core import studio_ui

        original_asset = studio_ui.read_asset

        def empty_asset(name):
            content_type, content = original_asset(name)
            return content_type, content if name == "index.html" else ""

        stack.enter_context(mock.patch.object(studio_ui, "read_asset", side_effect=empty_asset))
    elif case == "studio_tab_association_crossed":
        original_read = Path.read_text

        def cross_tab(path, *args, **kwargs):
            content = original_read(path, *args, **kwargs)
            if path.name == "index.html":
                content = content.replace('aria-controls="view-diagram"', 'aria-controls="view-ai"')
            return content

        stack.enter_context(mock.patch.object(Path, "read_text", cross_tab))
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
