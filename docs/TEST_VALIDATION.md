# Unit-test accuracy and depth audit

This audit accompanies issue #71 and PR #72. It covers all 39 unit-test files,
including the diagram review fixes and the strengthened regression suite.
The review checks assertion meaning, fixture preconditions, mock boundaries,
exception handling, skips, shared mutable state and test discovery. Test or
assertion counts are inventory measures, not proof of correctness.

## Scope

| Area | Tests | Contracts checked |
| --- | ---: | --- |
| Parsing, graph construction and YAML | 84 | Definitions, routes, call edges, exact source locations, malformed input and recovery |
| SAST and infrastructure rules | 73 | Expected findings and CWE/evidence, safe counterparts, comments/strings and source containment |
| Policy, ATT&CK, baselines, risk and reachability | 99 | Positive and negative gates, expiry/reactivation, confidence, provenance and known-reachable queries |
| Discovery, configuration, cache, workspace and consumer contracts | 86 | Filtering, containment, successful workers and fallback, cache invalidation, complete serialization and isolated fixtures |
| CLI, offline controls and diagram validation | 57 | Exit codes, CI JSON, deterministic output, selected projections and preservation of existing artifacts |
| Rendering, HTML, images and security reports | 55 | Escaping, source links, styles, exact node caps, severity levels and report content |
| Imported reports, plugins and LLM adapters | 43 | Provenance, plugin failure rollback, credential boundaries and transport error handling |
| Server, redaction, task governance and supply chain | 84 | Authentication failures, limits, redaction, pins and scanner gates |
| **Total** | **581** | |

The structural scan found no duplicate test definitions, assertion-method
overrides or assertion-method reassignments. The review found no malicious test
behavior. This is an evidence-based review, not a proof that every possible
implementation defect is detectable.

## Weaknesses corrected

- Replaced the malformed-YAML assertion containing `or True` with observable
  document and parser-recovery assertions.
- Replaced silent returns in three symlink-security tests with explicit skips
  for known platform/permission limitations; unexpected errors now fail. Git
  initialization errors no longer silently pass the containment test.
- Replaced an ATT&CK allowlist test that could succeed over an empty result with
  a positive TLS/secret control and an exact filtered technique set.
- Strengthened serialization checks from object counts to full content equality,
  including evidence, dependency data and positive/negative query behavior.
- Required exactly five displayed nodes in the capped-diagram test, preventing
  an empty diagram from satisfying an upper-bound assertion.
- Anchored confidence checks to independent expected values and a changed-input
  counterexample, and strengthened the finding-fingerprint identity check.
- Required non-empty configuration findings and both blocking/non-blocking SARIF
  cases before checking per-result fields.
- Checked scan permits after an unmatched release, rather than checking only
  that the call did not throw.
- Compared complete merged graph content for insertion-order determinism, rather
  than only comparing sorted node IDs.
- Returned independent copies of the cached fixture analysis and added an
  isolation test for nodes, baseline flags and skipped-path metadata.
- Required successful Python and Java worker results in the parallel-equivalence
  test. Serial fallback no longer counts as evidence that parallel execution
  worked. A separate test verifies the graceful fallback behavior.

## Fault-injection checks

Run the audit with:

```bash
python scripts/verify_test_depth.py --output .secdiagram/test-depth.json
```

Each control and each injected fault runs in a separate fresh process, so cached
fixture results cannot mask a changed implementation. Controls must pass. A
fault counts as detected only when the selected test produces an assertion
failure: import/setup errors, skips and timeouts never count as detections.
Production files are never rewritten by the audit.

The 17 cases cover removal of dangling edges, omitted detailed validation,
workspace bypass, premature baseline writes, ignored canonical ordering,
corrupted serialized fields, empty capped diagrams, empty ATT&CK results,
constant confidence, excess scan permits, empty YAML results, authentication
bypass, shared fixture state, disabled redaction, disabled Python SAST,
disabled polyglot SAST and failed parallel workers. This is a bounded set of
targeted regressions, not an exhaustive mutation score.

## Coverage and execution checks

The full suite is checked under ordinary discovery and a fixed shuffled class
and method order (seed `20261118`). The shuffled runner must be a real script
with a `__main__` guard: launching it through stdin on Windows prevents worker
process startup and can exercise the serial fallback instead.

Coverage is measured with:

```bash
python -m coverage run --branch -m unittest discover -s tests -v
python -m coverage report
```

The measured baseline is approximately 89% statement coverage, 79% branch
coverage and 86% combined coverage. The diagram model and quality checker are
approximately 97% combined. Coverage is not treated as a substitute for the
positive controls, negative controls and fault-injection checks above.

Remaining gaps include advisory formats, cache error paths, resolver branches,
external-report variants, image-provider errors, server paths and workspace
language detection. Defensive worker-crash and top-level exception branches
also have existing `pragma: no cover` exclusions; these were reviewed rather
than treated as evidence of execution. The passing audit does not certify those
uncovered paths.
